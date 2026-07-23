//! Relying-party library for BrowserID-NG (device-cert model).
//!
//! The one opt-in an API RP makes to accept browserid identities (human or
//! agent): verify an **access presentation** once at a token-exchange
//! endpoint, mint its **own** bearer token, and keep every other piece of its
//! session machinery unchanged. The RP learns a verified email, the opaque
//! `holder` that acted, and the scopes the warrant grants here. Warrant
//! enforcement is unconditional and fail-closed — a presentation without a
//! warrant for this audience never parses/verifies.
//!
//! Three pieces, composable with any HTTP framework:
//!
//! - [`Verifier`] — checks an `access_cert~assertion~warrant~config_cert`
//!   presentation against the RP's audience and its trusted issuer keys
//!   (pinned, or fetched from an IdP's `/.well-known/browserid`).
//! - [`TokenStore`] — a minimal in-memory bearer-token issuer/authenticator
//!   for RPs that don't already have one. RPs with existing token machinery
//!   use [`Verifier`] + their own store.
//! - [`exchange`] — the token-endpoint core: grant-type check → verify →
//!   issue, returning OAuth-shaped success/error bodies.
//!
//! Discovery helpers: [`Verifier::challenge`] renders the 401
//! `WWW-Authenticate: BrowserID …` header; [`oauth_metadata`] renders the
//! RFC 8414 `.well-known/oauth-authorization-server` document.
//!
//! ```no_run
//! # async fn demo() -> Result<(), browserid_rp::RpError> {
//! use browserid_rp::{Verifier, TokenStore};
//!
//! let verifier = Verifier::new("https://api.example.com")
//!     .trust_issuer_from_well_known("https://browserid.me")
//!     .await?;
//! let tokens = TokenStore::new(chrono::Duration::hours(1));
//!
//! // In the /token handler:
//! // let response = browserid_rp::exchange(&verifier, &tokens, &token_request)?;
//! // In protected handlers:
//! // let email = tokens.authenticate(bearer_token);
//! # Ok(()) }
//! ```

use std::collections::HashMap;
use std::sync::RwLock;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;

use browserid_core::device::{AccessPresentation, Holder};
use browserid_core::rp_auth::{TokenErrorResponse, GRANT_TYPE_ASSERTION};
use browserid_core::{PublicKey, RpChallenge, StatusListToken, StatusRef, TokenRequest, TokenResponse};

pub use browserid_core::rp_auth;

/// Bearer-token prefix issued by [`TokenStore`]
const TOKEN_PREFIX: &str = "bidt_";

#[derive(Debug, thiserror::Error)]
pub enum RpError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("well-known document invalid: {0}")]
    WellKnown(String),
}

/// Why a token exchange was refused. Maps onto OAuth error codes via
/// [`ExchangeError::oauth_error`].
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("unsupported grant_type: {0}")]
    UnsupportedGrantType(String),

    #[error("assertion rejected: {0}")]
    InvalidAssertion(String),
}

impl ExchangeError {
    /// The OAuth `error` code (RFC 6749 §5.2) for this failure
    pub fn oauth_error(&self) -> &'static str {
        match self {
            ExchangeError::UnsupportedGrantType(_) => "unsupported_grant_type",
            ExchangeError::InvalidAssertion(_) => "invalid_grant",
        }
    }

    /// An OAuth-shaped error body (serve with HTTP 400)
    pub fn to_response(&self) -> TokenErrorResponse {
        TokenErrorResponse {
            error: self.oauth_error().to_string(),
            error_description: Some(self.to_string()),
        }
    }
}

/// A verified presentation: what the RP learns
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub email: String,
    /// The IdP that issued the access + config certs (the identity's IdP)
    pub issuer: String,
    /// The opaque broker-assigned holder that acted (which of the user's
    /// things); advisory — authorization keys off email + scopes, not this.
    pub holder: Holder,
    /// The warrant's scopes, verbatim; [`exchange`] applies the RP scope
    /// policy (intersection) when issuing a token
    pub scopes: Vec<String>,
}

/// Presentation verifier for one RP audience, trusting an explicit set of
/// issuer keys. Trust is per-domain: the core join already enforces that the
/// access cert and config cert share one issuer, and the RP's issuer-key
/// table decides which issuers it accepts (a primary for its own domain, or
/// an accepted fallback such as browserid.me).
pub struct Verifier {
    audience: String,
    issuer_keys: HashMap<String, PublicKey>,
    /// The RP's own scope vocabulary — advertised in the challenge, and the
    /// upper bound on what an agent token is granted
    scopes: Vec<String>,
    /// Revocation status cache (core §6.4); when set, presented credentials
    /// carrying `status` claims are checked against it
    status_cache: Option<std::sync::Arc<StatusCache>>,
    /// Spec §6.4 makes the three status checks mandatory and fail-closed, so
    /// by default a presentation carrying a `status` ref is rejected unless a
    /// [`StatusCache`] is configured to check it. `without_status_checks()`
    /// opts out (dev/test only — non-conformant).
    require_status_checks: bool,
}

impl Verifier {
    /// `audience` is what assertions/warrants must be signed for — usually
    /// the API origin, and the same string advertised in the challenge
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
            issuer_keys: HashMap::new(),
            scopes: Vec::new(),
            status_cache: None,
            require_status_checks: true,
        }
    }

    /// Accept presentations whose credentials carry `status` refs even when no
    /// [`StatusCache`] is configured to check them. **Non-conformant** (spec
    /// §6.4 requires the three checks, fail-closed) — dev/test only.
    pub fn without_status_checks(mut self) -> Self {
        self.require_status_checks = false;
        self
    }

    /// Check presented credentials against a revocation status cache
    /// (core §6.4). Refresh the cache out of band ([`Verifier::refresh_status`]
    /// or `StatusCache::refresh`); verification itself stays synchronous.
    /// Without a cache, a presentation carrying a `status` ref is rejected
    /// fail-closed (unless `without_status_checks()` opted out).
    pub fn with_status_cache(mut self, cache: std::sync::Arc<StatusCache>) -> Self {
        self.status_cache = Some(cache);
        self
    }

    /// Declare the RP's scope vocabulary (spec §7.2). Advertised in the
    /// challenge; agent tokens are bounded by the intersection of these with
    /// the warrant's scopes.
    pub fn with_scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// The RP's declared scope vocabulary
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Trust `domain`-issued presentations signed by `key` (pinned)
    pub fn trust_issuer(mut self, domain: impl Into<String>, key: PublicKey) -> Self {
        self.issuer_keys.insert(domain.into(), key);
        self
    }

    /// Trust an IdP by fetching its `/.well-known/browserid` support
    /// document. The trusted domain is the URL's host (with port, if any).
    pub async fn trust_issuer_from_well_known(self, idp_base: &str) -> Result<Self, RpError> {
        let idp_base = idp_base.trim_end_matches('/');
        let url = format!("{idp_base}/.well-known/browserid");
        let doc: browserid_core::discovery::SupportDocument = reqwest::Client::new()
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let domain = idp_base
            .strip_prefix("https://")
            .or_else(|| idp_base.strip_prefix("http://"))
            .ok_or_else(|| RpError::WellKnown(format!("idp_base must be a URL: {idp_base}")))?
            .to_string();
        if domain.contains('/') {
            return Err(RpError::WellKnown(format!(
                "idp_base must be an origin with no path: {idp_base}"
            )));
        }

        let public_key = doc.public_key.ok_or_else(|| {
            RpError::WellKnown(format!("{idp_base} published no public key"))
        })?;
        Ok(self.trust_issuer(domain, public_key))
    }

    /// The audience this verifier (and its challenge) is bound to
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Fetch a status list from `uri`, verify it against this RP's trusted
    /// issuer table (the list's `iss` claim must be a trusted issuer), and
    /// cache it. Call at startup and on a refresh timer (reference: the
    /// list's `ttl`, 5 min) — [`Verifier::verify`] stays synchronous and
    /// rejects fail-closed while a needed list is missing or stale.
    pub async fn refresh_status(&self, uri: &str) -> Result<(), RpError> {
        let cache = self.status_cache.as_ref().ok_or_else(|| {
            RpError::WellKnown("no status cache configured (Verifier::with_status_cache)".into())
        })?;
        let body = reqwest::get(uri).await?.error_for_status()?.text().await?;
        let token = StatusListToken::parse(body.trim())
            .map_err(|e| RpError::WellKnown(format!("status list: {e}")))?;
        let key = self.issuer_keys.get(&token.claims().iss).ok_or_else(|| {
            RpError::WellKnown(format!(
                "status list at {uri} is signed by '{}', not a trusted issuer",
                token.claims().iss
            ))
        })?;
        token
            .verify(key, uri)
            .map_err(|e| RpError::WellKnown(format!("status list: {e}")))?;
        cache.insert(uri, token);
        Ok(())
    }

    /// Verify an access presentation
    /// (`access_cert~assertion~warrant~config_cert`): audience, expiry, the
    /// full cryptographic join (assertion ← access cert; warrant ← config
    /// cert; both certs ← one trusted issuer; identity/subject/audience
    /// consistent), issuer trust, and — when a status cache is configured —
    /// the three revocation refs (access cert, config cert, warrant).
    pub fn verify(&self, presentation: &str) -> Result<VerifiedIdentity, ExchangeError> {
        let pres = AccessPresentation::parse(presentation)
            .map_err(|e| ExchangeError::InvalidAssertion(e.to_string()))?;

        let verified = pres
            .verify(&self.audience, |domain| {
                self.issuer_keys
                    .get(domain)
                    .cloned()
                    .ok_or_else(|| browserid_core::Error::DiscoveryFailed {
                        domain: domain.to_string(),
                        reason: "issuer not trusted by this RP".to_string(),
                    })
            })
            .map_err(|e| ExchangeError::InvalidAssertion(e.to_string()))?;

        // Revocation status (core §6.4): the three checks are mandatory and
        // fail-closed. Revoked → reject; unknown/stale → reject unless the
        // cache was explicitly built `fail_open()`; refs present with no
        // cache at all → reject unless `without_status_checks()` opted out.
        let refs: Vec<&StatusRef> = [
            verified.access_status.as_ref(),
            verified.config_status.as_ref(),
            verified.warrant_status.as_ref(),
        ]
        .into_iter()
        .flatten()
        .collect();
        match &self.status_cache {
            Some(cache) => {
                for r in refs {
                    match cache.check(r) {
                        StatusVerdict::Revoked => {
                            return Err(ExchangeError::InvalidAssertion(
                                "credential revoked (status list)".into(),
                            ));
                        }
                        StatusVerdict::Valid => {}
                        StatusVerdict::Unknown if cache.is_fail_closed() => {
                            return Err(ExchangeError::InvalidAssertion(
                                "credential status unavailable (fail-closed policy)".into(),
                            ));
                        }
                        StatusVerdict::Unknown => {}
                    }
                }
            }
            None if self.require_status_checks && !refs.is_empty() => {
                return Err(ExchangeError::InvalidAssertion(
                    "credential carries a status ref but this RP has no status cache \
                     configured (fail-closed; see Verifier::with_status_cache)"
                        .into(),
                ));
            }
            None => {}
        }

        Ok(VerifiedIdentity {
            email: verified.email,
            issuer: verified.issuer,
            holder: verified.holder,
            scopes: verified.scopes,
        })
    }

    /// The 401 `WWW-Authenticate` challenge advertising this RP's auth API
    /// (including its scope vocabulary, if declared)
    pub fn challenge(&self, token_endpoint: impl Into<String>) -> RpChallenge {
        let challenge = RpChallenge::new(self.audience.clone(), token_endpoint);
        if self.scopes.is_empty() {
            challenge
        } else {
            challenge.with_scopes(self.scopes.iter().cloned())
        }
    }
}

struct TokenRecord {
    email: String,
    /// The opaque holder that acted; `None` for a bare [`TokenStore::issue`].
    holder: Option<String>,
    /// Granted scopes (post-intersection); `None` for plain login tokens
    scopes: Option<Vec<String>>,
    expires_at: DateTime<Utc>,
}

/// What a bearer token resolves to
#[derive(Debug, Clone)]
pub struct TokenGrant {
    pub email: String,
    /// The opaque holder that acted; `None` for a bare [`TokenStore::issue`].
    pub holder: Option<String>,
    /// Granted scopes; `None` for plain login tokens
    pub scopes: Option<Vec<String>>,
}

/// Minimal in-memory bearer-token store: `issue` at the token endpoint,
/// `authenticate` in protected handlers. Reference implementation — an RP
/// with existing session/token machinery should keep using its own.
pub struct TokenStore {
    tokens: RwLock<HashMap<String, TokenRecord>>,
    ttl: Duration,
}

impl TokenStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Mint a bearer token for a verified email (plain login, no holder/scopes)
    pub fn issue(&self, email: &str) -> TokenResponse {
        self.issue_with(email, None, None)
    }

    /// Mint a bearer token recording the acting holder + granted scopes.
    /// The token is bounded server-side by `scopes` — resolve them via
    /// [`TokenStore::grant`] in protected handlers.
    pub fn issue_with(
        &self,
        email: &str,
        holder: Option<Holder>,
        scopes: Option<Vec<String>>,
    ) -> TokenResponse {
        let holder = holder.map(|h| h.as_str().to_string());
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = format!(
            "{}{}",
            TOKEN_PREFIX,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        );
        self.tokens.write().unwrap().insert(
            token.clone(),
            TokenRecord {
                email: email.to_string(),
                holder: holder.clone(),
                scopes: scopes.clone(),
                expires_at: Utc::now() + self.ttl,
            },
        );
        TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: self.ttl.num_seconds(),
            email: Some(email.to_string()),
            holder,
            scopes,
        }
    }

    /// Resolve a bearer token to its email; `None` if unknown or expired
    pub fn authenticate(&self, token: &str) -> Option<String> {
        self.grant(token).map(|g| g.email)
    }

    /// Resolve a bearer token to its full grant (email + holder + granted
    /// scopes); `None` if unknown or expired
    pub fn grant(&self, token: &str) -> Option<TokenGrant> {
        let tokens = self.tokens.read().unwrap();
        let record = tokens.get(token)?;
        if record.expires_at < Utc::now() {
            return None;
        }
        Some(TokenGrant {
            email: record.email.clone(),
            holder: record.holder.clone(),
            scopes: record.scopes.clone(),
        })
    }

    /// Revoke a token immediately
    pub fn revoke(&self, token: &str) {
        self.tokens.write().unwrap().remove(token);
    }

    /// Drop expired tokens (call opportunistically)
    pub fn cleanup(&self) {
        let now = Utc::now();
        self.tokens
            .write()
            .unwrap()
            .retain(|_, r| r.expires_at >= now);
    }
}

/// The token-endpoint core: check the grant type, verify the presentation,
/// issue a token. Wire it to POST `/token` in any framework; on `Err`, serve
/// `err.to_response()` with HTTP 400.
///
/// Scope policy (spec §7.3): the user/agent axis is gone — a token is scoped
/// by the warrant it presents. A warrant carrying only the `login` sentinel
/// (or no scopes) is a plain login and carries **no** scope bound (`None`);
/// otherwise the token is bounded by the intersection of the warrant's
/// (non-`login`) scopes with the RP's declared vocabulary.
pub fn exchange(
    verifier: &Verifier,
    tokens: &TokenStore,
    request: &TokenRequest,
) -> Result<TokenResponse, ExchangeError> {
    if request.grant_type != GRANT_TYPE_ASSERTION {
        return Err(ExchangeError::UnsupportedGrantType(
            request.grant_type.clone(),
        ));
    }
    let identity = verifier.verify(&request.assertion)?;
    // The `login` scope is the plain-login sentinel — filter it; what remains
    // are the real grant scopes. No real scopes → an unscoped login token.
    let granted: Vec<String> = identity
        .scopes
        .iter()
        .filter(|s| *s != "login")
        .cloned()
        .collect();
    let scopes = if granted.is_empty() {
        None
    } else {
        Some(grant_scopes(&granted, verifier.scopes()))
    };
    Ok(tokens.issue_with(&identity.email, Some(identity.holder), scopes))
}

/// Intersection of warrant scopes with the RP's declared vocabulary; an
/// unqualified (empty) warrant scope set grants the full declared set.
fn grant_scopes(warrant_scopes: &[String], rp_scopes: &[String]) -> Vec<String> {
    if warrant_scopes.is_empty() {
        rp_scopes.to_vec()
    } else {
        warrant_scopes
            .iter()
            .filter(|s| rp_scopes.contains(s))
            .cloned()
            .collect()
    }
}

/// RFC 8414 authorization-server metadata for out-of-band discovery. Serve
/// as JSON at `/.well-known/oauth-authorization-server`. `issuer` is the
/// RP's base URL.
pub fn oauth_metadata(issuer: &str, token_endpoint: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "token_endpoint": token_endpoint,
        "grant_types_supported": [GRANT_TYPE_ASSERTION],
        "token_endpoint_auth_methods_supported": ["none"],
        // Required by RFC 8414 even though the assertion grant never uses it
        "response_types_supported": [],
    })
}

/// A status-check verdict (core §6.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusVerdict {
    /// The bit is set — the credential is revoked
    Revoked,
    /// A fresh list covers this index and the bit is clear
    Valid,
    /// No list, a stale list, or a signature/URI mismatch — the check could
    /// not be made; policy decides (fail-open degrades to TTL semantics)
    Unknown,
}

/// A cache of issuer-signed status lists (core §6.4). Refresh out of band —
/// on a timer, or opportunistically when [`StatusCache::check`] returns
/// `Unknown` — and verification stays synchronous:
///
/// ```no_run
/// # async fn demo(issuer_key: browserid_core::PublicKey) -> Result<(), browserid_rp::RpError> {
/// let cache = std::sync::Arc::new(browserid_rp::StatusCache::new());
/// cache.refresh("https://browserid.me/.well-known/browserid-status", &issuer_key).await?;
/// // Verifier::new(...).with_status_cache(cache.clone())
/// # Ok(()) }
/// ```
pub struct StatusCache {
    lists: RwLock<HashMap<String, StatusListToken>>,
    fail_closed: bool,
    /// Extra seconds a list stays usable past its advertised `ttl`
    grace_seconds: i64,
}

impl Default for StatusCache {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusCache {
    pub fn new() -> Self {
        Self {
            lists: RwLock::new(HashMap::new()),
            // Spec §6.4: an unreachable/stale status authority is "cannot
            // prove unrevoked" → reject. Fail-open is an explicit opt-out.
            fail_closed: true,
            // A short grace beyond the advertised ttl before entries go
            // Unknown (then policy applies) — absorbs refresh jitter.
            grace_seconds: 600,
        }
    }

    /// Treat `Unknown` (missing/stale list) as a rejection — the default.
    pub fn fail_closed(mut self) -> Self {
        self.fail_closed = true;
        self
    }

    /// Treat `Unknown` (missing/stale list) as acceptable, degrading to
    /// TTL-only semantics. **Non-conformant** (spec §6.4) — use only where
    /// availability is worth more than revocation latency.
    pub fn fail_open(mut self) -> Self {
        self.fail_closed = false;
        self
    }

    pub fn is_fail_closed(&self) -> bool {
        self.fail_closed
    }

    /// Fetch `uri`, verify the token against `issuer_key` (and that it is
    /// for `uri`), and cache it.
    pub async fn refresh(&self, uri: &str, issuer_key: &PublicKey) -> Result<(), RpError> {
        let body = reqwest::get(uri).await?.error_for_status()?.text().await?;
        let token = StatusListToken::parse(body.trim())
            .map_err(|e| RpError::WellKnown(format!("status list: {e}")))?;
        token
            .verify(issuer_key, uri)
            .map_err(|e| RpError::WellKnown(format!("status list: {e}")))?;
        self.lists.write().unwrap().insert(uri.to_string(), token);
        Ok(())
    }

    /// Insert an already-verified token (tests, detached snapshots)
    pub fn insert(&self, uri: &str, token: StatusListToken) {
        self.lists.write().unwrap().insert(uri.to_string(), token);
    }

    pub fn check(&self, r: &StatusRef) -> StatusVerdict {
        let lists = self.lists.read().unwrap();
        match lists.get(&r.uri) {
            Some(token) if token.is_fresh(self.grace_seconds) => {
                if token.is_revoked(r.idx) {
                    StatusVerdict::Revoked
                } else {
                    StatusVerdict::Valid
                }
            }
            _ => StatusVerdict::Unknown,
        }
    }
}

/// RFC 8414 metadata including the RP's scope vocabulary
pub fn oauth_metadata_with_scopes(
    issuer: &str,
    token_endpoint: &str,
    scopes: &[String],
) -> serde_json::Value {
    let mut metadata = oauth_metadata(issuer, token_endpoint);
    metadata["scopes_supported"] = serde_json::json!(scopes);
    metadata
}

#[cfg(test)]
mod tests {
    use super::*;
    use browserid_core::device::{AccessCert, DeviceCert, HolderMatcher, Purpose, Warrant};
    use browserid_core::{Assertion, KeyPair};

    const AUDIENCE: &str = "https://api.example.com";
    const ISSUER: &str = "browserid.example";

    /// Build a full device-model presentation for `email` at `audience`,
    /// with the warrant issued for `warrant_audience` and `warrant_scopes`.
    fn presentation(
        issuer_kp: &KeyPair,
        email: &str,
        holder: &str,
        audience: &str,
        warrant_audience: &str,
        warrant_scopes: Vec<String>,
        status: Option<StatusRef>,
    ) -> String {
        let access_kp = KeyPair::generate();
        let config_kp = KeyPair::generate();
        let access_cert = AccessCert::create(
            ISSUER, email, Holder::new(holder).unwrap(), &access_kp.public_key(),
            Duration::hours(24), issuer_kp, status.clone(),
        )
        .unwrap();
        let config_cert = DeviceCert::create(
            ISSUER, &config_kp.public_key(), Purpose::Authorization, Holder::new(holder).unwrap(),
            vec![email.to_string()], Duration::days(90), issuer_kp, None,
        )
        .unwrap();
        let warrant = Warrant::create(
            email, email, HolderMatcher::new(holder).unwrap(), warrant_audience, warrant_scopes,
            Duration::days(90), &config_kp, None,
        )
        .unwrap();
        let assertion = Assertion::create(audience, Duration::minutes(5), &access_kp).unwrap();
        format!(
            "{}~{}~{}~{}",
            access_cert.encoded(),
            assertion.encoded(),
            warrant.encoded(),
            config_cert.encoded()
        )
    }

    #[test]
    fn exchange_happy_path_user() {
        let issuer_kp = KeyPair::generate();
        let verifier = Verifier::new(AUDIENCE).trust_issuer(ISSUER, issuer_kp.public_key());
        let tokens = TokenStore::new(Duration::hours(1));

        let request = TokenRequest::new(presentation(
            &issuer_kp, "alice@example.com", "br.main", AUDIENCE, AUDIENCE,
            vec!["login".into()], None,
        ));
        let response = exchange(&verifier, &tokens, &request).unwrap();

        assert_eq!(response.token_type, "Bearer");
        assert!(response.access_token.starts_with(TOKEN_PREFIX));
        assert_eq!(response.email.as_deref(), Some("alice@example.com"));
        assert_eq!(response.holder.as_deref(), Some("br.main"));
        assert_eq!(response.scopes, None, "a login warrant carries no scope bound");
        assert_eq!(
            tokens.authenticate(&response.access_token).as_deref(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn exchange_rejects_wrong_grant_type() {
        let issuer_kp = KeyPair::generate();
        let verifier = Verifier::new(AUDIENCE).trust_issuer(ISSUER, issuer_kp.public_key());
        let tokens = TokenStore::new(Duration::hours(1));

        let request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            assertion: presentation(
                &issuer_kp, "alice@example.com", "br.main", AUDIENCE, AUDIENCE,
                vec![], None,
            ),
        };
        let err = exchange(&verifier, &tokens, &request).unwrap_err();
        assert_eq!(err.oauth_error(), "unsupported_grant_type");
    }

    #[test]
    fn exchange_rejects_wrong_audience_and_untrusted_issuer() {
        let issuer_kp = KeyPair::generate();
        let verifier = Verifier::new(AUDIENCE).trust_issuer(ISSUER, issuer_kp.public_key());
        let tokens = TokenStore::new(Duration::hours(1));

        // Assertion + warrant signed for someone else's audience
        let request = TokenRequest::new(presentation(
            &issuer_kp, "alice@example.com", "br.main",
            "https://evil.example.com", "https://evil.example.com", vec![], None,
        ));
        let err = exchange(&verifier, &tokens, &request).unwrap_err();
        assert_eq!(err.oauth_error(), "invalid_grant");

        // Issuer the RP doesn't trust (different keypair)
        let rogue_kp = KeyPair::generate();
        let request = TokenRequest::new(presentation(
            &rogue_kp, "alice@example.com", "br.main", AUDIENCE, AUDIENCE, vec![], None,
        ));
        let err = exchange(&verifier, &tokens, &request).unwrap_err();
        assert_eq!(err.oauth_error(), "invalid_grant");
    }

    #[test]
    fn warrant_for_other_audience_rejected() {
        let issuer_kp = KeyPair::generate();
        let verifier = Verifier::new(AUDIENCE).trust_issuer(ISSUER, issuer_kp.public_key());
        let tokens = TokenStore::new(Duration::hours(1));

        // Assertion targets us, warrant authorizes a different audience.
        let request = TokenRequest::new(presentation(
            &issuer_kp, "bot@example.com", "svc.agent", AUDIENCE,
            "https://other.example.com", vec![], None,
        ));
        let err = exchange(&verifier, &tokens, &request).unwrap_err();
        assert_eq!(err.oauth_error(), "invalid_grant");
    }

    #[test]
    fn agent_exchange_intersects_scopes() {
        let issuer_kp = KeyPair::generate();
        let verifier = Verifier::new(AUDIENCE)
            .trust_issuer(ISSUER, issuer_kp.public_key())
            .with_scopes(["post", "read", "admin"]);
        let tokens = TokenStore::new(Duration::hours(1));

        // Warrant grants post+delete; RP offers post+read+admin → token gets post.
        let request = TokenRequest::new(presentation(
            &issuer_kp, "bot@example.com", "svc.agent", AUDIENCE, AUDIENCE,
            vec!["post".into(), "delete".into()], None,
        ));
        let response = exchange(&verifier, &tokens, &request).unwrap();
        assert_eq!(response.email.as_deref(), Some("bot@example.com"));
        assert_eq!(response.holder.as_deref(), Some("svc.agent"));
        assert_eq!(response.scopes, Some(vec!["post".to_string()]));

        // Server-side grant carries the same bound.
        let grant = tokens.grant(&response.access_token).unwrap();
        assert_eq!(grant.holder.as_deref(), Some("svc.agent"));
        assert_eq!(grant.scopes, Some(vec!["post".to_string()]));

        // A warrant with no real (non-login) scopes is a plain login → no bound
        // (the holder model dropped the "unqualified agent → full set" rule).
        let request = TokenRequest::new(presentation(
            &issuer_kp, "bot@example.com", "svc.agent", AUDIENCE, AUDIENCE, vec![], None,
        ));
        let response = exchange(&verifier, &tokens, &request).unwrap();
        assert_eq!(response.scopes, None);
    }

    #[test]
    fn revoked_credential_rejected_via_status_cache() {
        use browserid_core::{StatusList, StatusListToken};
        let issuer_kp = KeyPair::generate();
        let uri = "https://browserid.example/.well-known/browserid-status";
        // Index 7 revoked.
        let list = StatusList::from_revoked(vec![7], 8);
        let token = StatusListToken::create(ISSUER, uri, &list, &issuer_kp).unwrap();
        let cache = std::sync::Arc::new(StatusCache::new());
        cache.insert(uri, token);

        let verifier = Verifier::new(AUDIENCE)
            .trust_issuer(ISSUER, issuer_kp.public_key())
            .with_status_cache(cache);
        let tokens = TokenStore::new(Duration::hours(1));

        // Presentation whose access cert carries the revoked index.
        let request = TokenRequest::new(presentation(
            &issuer_kp, "alice@example.com", "br.main", AUDIENCE, AUDIENCE,
            vec![], Some(StatusRef { uri: uri.into(), idx: 7 }),
        ));
        let err = exchange(&verifier, &tokens, &request).unwrap_err();
        assert_eq!(err.oauth_error(), "invalid_grant");

        // A clear index passes.
        let request = TokenRequest::new(presentation(
            &issuer_kp, "alice@example.com", "br.main", AUDIENCE, AUDIENCE,
            vec![], Some(StatusRef { uri: uri.into(), idx: 3 }),
        ));
        assert!(exchange(&verifier, &tokens, &request).is_ok());
    }

    #[test]
    fn status_ref_without_cache_rejected_by_default() {
        let issuer_kp = KeyPair::generate();
        let uri = "https://browserid.example/.well-known/browserid-status";
        let pres = presentation(
            &issuer_kp, "alice@example.com", "br.main", AUDIENCE, AUDIENCE,
            vec![], Some(StatusRef { uri: uri.into(), idx: 3 }),
        );

        // No cache configured → a status-carrying presentation fails closed.
        let verifier = Verifier::new(AUDIENCE).trust_issuer(ISSUER, issuer_kp.public_key());
        let err = verifier.verify(&pres).unwrap_err();
        assert!(err.to_string().contains("no status cache"), "{err}");

        // Explicit (non-conformant) opt-out accepts it.
        let verifier = Verifier::new(AUDIENCE)
            .trust_issuer(ISSUER, issuer_kp.public_key())
            .without_status_checks();
        assert!(verifier.verify(&pres).is_ok());
    }

    #[test]
    fn unknown_status_fails_closed_by_default_and_fail_open_opts_out() {
        let issuer_kp = KeyPair::generate();
        let uri = "https://browserid.example/.well-known/browserid-status";
        let pres = presentation(
            &issuer_kp, "alice@example.com", "br.main", AUDIENCE, AUDIENCE,
            vec![], Some(StatusRef { uri: uri.into(), idx: 3 }),
        );

        // Cache configured but has no list for the uri → Unknown → reject.
        let cache = std::sync::Arc::new(StatusCache::new());
        assert!(cache.is_fail_closed(), "fail-closed is the default");
        let verifier = Verifier::new(AUDIENCE)
            .trust_issuer(ISSUER, issuer_kp.public_key())
            .with_status_cache(cache);
        let err = verifier.verify(&pres).unwrap_err();
        assert!(err.to_string().contains("fail-closed"), "{err}");

        // fail_open() degrades Unknown to TTL semantics.
        let cache = std::sync::Arc::new(StatusCache::new().fail_open());
        let verifier = Verifier::new(AUDIENCE)
            .trust_issuer(ISSUER, issuer_kp.public_key())
            .with_status_cache(cache);
        assert!(verifier.verify(&pres).is_ok());
    }

    #[test]
    fn challenge_advertises_scopes() {
        let verifier = Verifier::new(AUDIENCE).with_scopes(["post", "read"]);
        let header = verifier.challenge("https://api.example.com/token").to_header_value();
        assert!(header.contains("scopes=\"post read\""), "{header}");
        let parsed = browserid_core::RpChallenge::parse(&header).unwrap();
        assert_eq!(parsed.scopes, vec!["post", "read"]);
    }

    #[test]
    fn tokens_expire_and_revoke() {
        let tokens = TokenStore::new(Duration::seconds(-1)); // born expired
        let response = tokens.issue("bot@example.com");
        assert_eq!(tokens.authenticate(&response.access_token), None);

        let tokens = TokenStore::new(Duration::hours(1));
        let response = tokens.issue("bot@example.com");
        assert!(tokens.authenticate(&response.access_token).is_some());
        tokens.revoke(&response.access_token);
        assert_eq!(tokens.authenticate(&response.access_token), None);
    }

    #[test]
    fn challenge_and_metadata_shapes() {
        let verifier = Verifier::new(AUDIENCE);
        let header = verifier.challenge("https://api.example.com/token").to_header_value();
        assert!(header.starts_with("BrowserID "));
        assert!(header.contains("audience=\"https://api.example.com\""));

        let metadata = oauth_metadata("https://api.example.com", "https://api.example.com/token");
        assert_eq!(metadata["token_endpoint"], "https://api.example.com/token");
        assert_eq!(metadata["grant_types_supported"][0], GRANT_TYPE_ASSERTION);
    }
}
