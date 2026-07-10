//! Relying-party library for BrowserID-NG (l8lw Phase 2).
//!
//! The one opt-in an API RP makes to accept agents: verify a browserid
//! assertion once at a token-exchange endpoint, mint its **own** bearer
//! token, and keep every other piece of its session machinery unchanged.
//! The RP learns just "an email" — no delegation-awareness, no agent flag.
//!
//! Three pieces, composable with any HTTP framework:
//!
//! - [`Verifier`] — checks a backed assertion against the RP's audience and
//!   its trusted issuer keys (pinned, or fetched from an IdP's
//!   `/.well-known/browserid`).
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
//!     .trust_issuer_from_well_known("https://agents.browserid.me")
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

use browserid_core::rp_auth::{TokenErrorResponse, GRANT_TYPE_ASSERTION};
use browserid_core::{BackedAssertion, PublicKey, RpChallenge, TokenRequest, TokenResponse};

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

/// A verified assertion: what the RP learns
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub email: String,
    /// Domain that signed the certificate
    pub issuer: String,
}

/// Assertion verifier for one RP audience, trusting an explicit set of
/// issuer keys. Trust is per-domain: a key for `agents.browserid.me` can
/// only vouch for `*@agents.browserid.me` (core chain verification already
/// enforces issuer == email domain).
pub struct Verifier {
    audience: String,
    issuer_keys: HashMap<String, PublicKey>,
}

impl Verifier {
    /// `audience` is what assertions must be signed for — usually the API
    /// origin, and the same string advertised in the challenge
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
            issuer_keys: HashMap::new(),
        }
    }

    /// Trust `domain` assertions signed by `key` (pinned)
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

    /// Verify a backed assertion (`cert~assertion`): audience, expiry,
    /// signature chain, and issuer trust
    pub fn verify(&self, backed_assertion: &str) -> Result<VerifiedIdentity, ExchangeError> {
        let backed = BackedAssertion::parse(backed_assertion)
            .map_err(|e| ExchangeError::InvalidAssertion(e.to_string()))?;

        let email = backed
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

        let issuer = backed
            .certificates()
            .last()
            .map(|c| c.issuer().to_string())
            .unwrap_or_default();

        Ok(VerifiedIdentity { email, issuer })
    }

    /// The 401 `WWW-Authenticate` challenge advertising this RP's auth API
    pub fn challenge(&self, token_endpoint: impl Into<String>) -> RpChallenge {
        RpChallenge::new(self.audience.clone(), token_endpoint)
    }
}

struct TokenRecord {
    email: String,
    expires_at: DateTime<Utc>,
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

    /// Mint a bearer token for a verified email
    pub fn issue(&self, email: &str) -> TokenResponse {
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
                expires_at: Utc::now() + self.ttl,
            },
        );
        TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: self.ttl.num_seconds(),
            email: Some(email.to_string()),
        }
    }

    /// Resolve a bearer token to its email; `None` if unknown or expired
    pub fn authenticate(&self, token: &str) -> Option<String> {
        let tokens = self.tokens.read().unwrap();
        let record = tokens.get(token)?;
        if record.expires_at < Utc::now() {
            return None;
        }
        Some(record.email.clone())
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

/// The token-endpoint core: check the grant type, verify the assertion,
/// issue a token. Wire it to POST `/token` in any framework; on `Err`, serve
/// `err.to_response()` with HTTP 400.
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
    Ok(tokens.issue(&identity.email))
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

#[cfg(test)]
mod tests {
    use super::*;
    use browserid_core::{Assertion, Certificate, KeyPair};

    const AUDIENCE: &str = "https://api.example.com";
    const ISSUER: &str = "agents.example.com";

    fn backed_assertion(issuer_kp: &KeyPair, audience: &str) -> String {
        let agent_kp = KeyPair::generate();
        let cert = Certificate::create(
            ISSUER,
            &format!("bot@{ISSUER}"),
            &agent_kp.public_key(),
            Duration::hours(1),
            issuer_kp,
        )
        .unwrap();
        let assertion = Assertion::create(audience, Duration::minutes(5), &agent_kp).unwrap();
        BackedAssertion::new(cert, assertion).encode()
    }

    #[test]
    fn exchange_happy_path() {
        let issuer_kp = KeyPair::generate();
        let verifier = Verifier::new(AUDIENCE).trust_issuer(ISSUER, issuer_kp.public_key());
        let tokens = TokenStore::new(Duration::hours(1));

        let request = TokenRequest::new(backed_assertion(&issuer_kp, AUDIENCE));
        let response = exchange(&verifier, &tokens, &request).unwrap();

        assert_eq!(response.token_type, "Bearer");
        assert!(response.access_token.starts_with(TOKEN_PREFIX));
        assert_eq!(response.email.as_deref(), Some("bot@agents.example.com"));
        assert_eq!(
            tokens.authenticate(&response.access_token).as_deref(),
            Some("bot@agents.example.com")
        );
    }

    #[test]
    fn exchange_rejects_wrong_grant_type() {
        let issuer_kp = KeyPair::generate();
        let verifier = Verifier::new(AUDIENCE).trust_issuer(ISSUER, issuer_kp.public_key());
        let tokens = TokenStore::new(Duration::hours(1));

        let request = TokenRequest {
            grant_type: "authorization_code".to_string(),
            assertion: backed_assertion(&issuer_kp, AUDIENCE),
        };
        let err = exchange(&verifier, &tokens, &request).unwrap_err();
        assert_eq!(err.oauth_error(), "unsupported_grant_type");
    }

    #[test]
    fn exchange_rejects_wrong_audience_and_untrusted_issuer() {
        let issuer_kp = KeyPair::generate();
        let verifier = Verifier::new(AUDIENCE).trust_issuer(ISSUER, issuer_kp.public_key());
        let tokens = TokenStore::new(Duration::hours(1));

        // Assertion signed for someone else's audience
        let request = TokenRequest::new(backed_assertion(&issuer_kp, "https://evil.example.com"));
        let err = exchange(&verifier, &tokens, &request).unwrap_err();
        assert_eq!(err.oauth_error(), "invalid_grant");

        // Issuer the RP doesn't trust (different keypair)
        let rogue_kp = KeyPair::generate();
        let request = TokenRequest::new(backed_assertion(&rogue_kp, AUDIENCE));
        let err = exchange(&verifier, &tokens, &request).unwrap_err();
        assert_eq!(err.oauth_error(), "invalid_grant");
    }

    #[test]
    fn tokens_expire_and_revoke() {
        let tokens = TokenStore::new(Duration::seconds(-1)); // born expired
        let response = tokens.issue("bot@agents.example.com");
        assert_eq!(tokens.authenticate(&response.access_token), None);

        let tokens = TokenStore::new(Duration::hours(1));
        let response = tokens.issue("bot@agents.example.com");
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
