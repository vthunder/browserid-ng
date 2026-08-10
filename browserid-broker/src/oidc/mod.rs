//! OIDC bridge core (browserid-ng-qer8): claim a mailbox by signing in with
//! its provider (Google first) instead of a mailed code.
//!
//! This module is the self-contained, security-critical engine — provider
//! config, Google-domain detection, PKCE, the authorization URL, JWKS
//! fetch/cache, and ID-token verification with the full claim checks. It is
//! **inert until wired**: nothing here is referenced by the login critical
//! path until `main.rs` configures a provider and `routes/` mounts the
//! `/oidc/claim` + `/oidc/callback` endpoints. Unconfigured, it changes
//! nothing.
//!
//! Scope is **per-mailbox**, exactly like SMTP: the ID token's verified
//! `email` must equal the claimed address (after Google normalization). A
//! Workspace domain's MX pointing at Google proves the domain uses Google,
//! never that the claimant owns a mailbox — so we never widen to the domain
//! from the `hd` claim. Design: docs/plans/2026-08-10-oidc-bridge-build-spec.md.

// Inert until wired: several items are unused until the routes/authority/
// dialog integration lands (a supervised step needing the Google client
// creds). Allow dead_code so the broker build stays warning-clean meanwhile.
#![allow(dead_code)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";
pub const GOOGLE_AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
pub const GOOGLE_JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// A configured OIDC provider (Google for v1).
#[derive(Debug, Clone)]
pub struct OidcProvider {
    pub name: &'static str,
    pub issuer: String,
    pub auth_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    pub client_secret: String,
}

impl OidcProvider {
    pub fn google(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            name: "google",
            issuer: GOOGLE_ISSUER.to_string(),
            auth_endpoint: GOOGLE_AUTH_ENDPOINT.to_string(),
            token_endpoint: GOOGLE_TOKEN_ENDPOINT.to_string(),
            jwks_uri: GOOGLE_JWKS_URI.to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        }
    }
}

/// Consumer Google mailbox domains (always OIDC-eligible).
const GOOGLE_CONSUMER_DOMAINS: &[&str] = &["gmail.com", "googlemail.com"];

/// Is this no-primary domain a Google-OIDC mailbox domain? True for the
/// consumer domains, or when the domain's MX host is Google's
/// (`*.google.com`, e.g. `aspmx.l.google.com`) — a Google Workspace domain.
/// `mx_host` is the (lowercased) MX target the authority probe resolved, if
/// any.
pub fn is_google_domain(domain: &str, mx_host: Option<&str>) -> bool {
    let d = domain.trim().to_ascii_lowercase();
    if GOOGLE_CONSUMER_DOMAINS.contains(&d.as_str()) {
        return true;
    }
    match mx_host {
        Some(mx) => {
            let mx = mx.trim().trim_end_matches('.').to_ascii_lowercase();
            mx == "google.com" || mx.ends_with(".google.com")
        }
        None => false,
    }
}

/// Normalize a Google address for the exact-equality check: lowercase; for
/// consumer Gmail domains, drop dots and any `+tag` in the local part (Gmail
/// treats `d.a.n+x@gmail.com` and `dan@gmail.com` as the same mailbox).
/// Non-Gmail (incl. Workspace) domains keep their local part verbatim, only
/// lowercased — Workspace admins may make dots/`+` significant.
pub fn normalize_google_email(email: &str) -> String {
    let email = email.trim().to_ascii_lowercase();
    let Some((local, domain)) = email.split_once('@') else {
        return email;
    };
    if GOOGLE_CONSUMER_DOMAINS.contains(&domain) {
        let base = local.split('+').next().unwrap_or(local);
        let no_dots = base.replace('.', "");
        format!("{no_dots}@{domain}")
    } else {
        format!("{local}@{domain}")
    }
}

// --- PKCE -------------------------------------------------------------------

/// A PKCE (RFC 7636) verifier + its S256 challenge.
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Self { verifier, challenge }
    }
}

/// A random URL-safe token (state / nonce).
pub fn random_token() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Build the provider authorization URL (auth-code + PKCE S256 + nonce +
/// state + `login_hint` = the claimed address). Scope is the minimum
/// `openid email`.
pub fn build_auth_url(
    provider: &OidcProvider,
    redirect_uri: &str,
    login_hint: &str,
    state: &str,
    nonce: &str,
    code_challenge: &str,
) -> String {
    let params = [
        ("client_id", provider.client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", "openid email"),
        ("state", state),
        ("nonce", nonce),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
        ("login_hint", login_hint),
        ("access_type", "online"),
    ];
    // reqwest re-exports url; parse_with_params percent-encodes correctly.
    reqwest::Url::parse_with_params(&provider.auth_endpoint, params)
        .map(|u| u.to_string())
        .unwrap_or_else(|_| provider.auth_endpoint.clone())
}

// --- In-flight flow state ---------------------------------------------------

struct FlowState {
    nonce: String,
    code_verifier: String,
    claimed_email: String,
    /// The broker session id to attach to (cold claim = None until callback).
    session_id: Option<String>,
    created: Instant,
}

/// Server-side store of in-flight OIDC flows, keyed by `state` (single-use,
/// TTL). CSRF (state) + replay (nonce) guard. In-memory; a restart drops
/// pending flows, which just makes the user retry.
pub struct OidcFlows {
    flows: std::sync::RwLock<HashMap<String, FlowState>>,
    ttl: Duration,
}

impl Default for OidcFlows {
    fn default() -> Self {
        Self::new()
    }
}

impl OidcFlows {
    pub fn new() -> Self {
        Self {
            flows: std::sync::RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(600),
        }
    }

    pub fn begin(
        &self,
        state: String,
        nonce: String,
        code_verifier: String,
        claimed_email: String,
        session_id: Option<String>,
    ) {
        let mut flows = self.flows.write().unwrap();
        let now = Instant::now();
        flows.retain(|_, f| now.duration_since(f.created) < self.ttl);
        flows.insert(
            state,
            FlowState { nonce, code_verifier, claimed_email, session_id, created: now },
        );
    }

    /// Consume a flow by `state` (single-use). `None` if unknown/expired.
    pub fn take(&self, state: &str) -> Option<ConsumedFlow> {
        let mut flows = self.flows.write().unwrap();
        let f = flows.remove(state)?;
        if Instant::now().duration_since(f.created) >= self.ttl {
            return None;
        }
        Some(ConsumedFlow {
            nonce: f.nonce,
            code_verifier: f.code_verifier,
            claimed_email: f.claimed_email,
            session_id: f.session_id,
        })
    }
}

pub struct ConsumedFlow {
    pub nonce: String,
    pub code_verifier: String,
    pub claimed_email: String,
    pub session_id: Option<String>,
}

// --- JWKS + ID-token verification -------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kid: String,
    pub n: String,
    pub e: String,
    #[serde(default)]
    pub alg: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    pub fn parse(body: &str) -> Result<Self, OidcError> {
        serde_json::from_str(body).map_err(|e| OidcError::Jwks(e.to_string()))
    }
    fn key(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

/// The verified claims we care about.
#[derive(Debug, Clone, Deserialize)]
struct IdTokenClaims {
    iss: String,
    aud: String,
    exp: usize,
    email: String,
    #[serde(default)]
    email_verified: EmailVerified,
    sub: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    hd: Option<String>,
}

/// Google sends `email_verified` as a bool; some providers send a string.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct EmailVerified(bool);
impl<'de> Deserialize<'de> for EmailVerified {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let v = serde_json::Value::deserialize(d)?;
        match v {
            serde_json::Value::Bool(b) => Ok(EmailVerified(b)),
            serde_json::Value::String(s) => Ok(EmailVerified(s == "true")),
            _ => Err(D::Error::custom("email_verified must be bool or string")),
        }
    }
}

#[derive(Debug)]
pub enum OidcError {
    Jwks(String),
    UnknownKid(String),
    TokenInvalid(String),
    EmailUnverified,
    NonceMismatch,
    EmailMismatch { claimed: String, token: String },
    WorkspaceDomainMismatch,
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OidcError::Jwks(e) => write!(f, "jwks: {e}"),
            OidcError::UnknownKid(k) => write!(f, "id token signed by unknown kid '{k}'"),
            OidcError::TokenInvalid(e) => write!(f, "id token invalid: {e}"),
            OidcError::EmailUnverified => write!(f, "email_verified is not true"),
            OidcError::NonceMismatch => write!(f, "nonce mismatch"),
            OidcError::EmailMismatch { claimed, token } => {
                write!(f, "token email '{token}' does not match claimed '{claimed}'")
            }
            OidcError::WorkspaceDomainMismatch => write!(f, "hosted-domain (hd) does not match the claimed domain"),
        }
    }
}
impl std::error::Error for OidcError {}

/// A successfully verified OIDC proof for one mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOidc {
    /// The normalized, verified email (equals the claimed address).
    pub email: String,
    /// `<iss>#<sub>` — the stable provider account id (proof_subject).
    pub proof_subject: String,
}

/// Verify a provider ID token against the JWKS and demand it proves the
/// `claimed_email`: RS256 signature by the token's `kid`, `iss`/`aud`/`exp`
/// (via jsonwebtoken validation), `nonce` match, `email_verified == true`,
/// and the normalized token email == the normalized claimed email. For a
/// Workspace (non-consumer) domain the `hd` claim must equal the claimed
/// domain. Returns the per-mailbox proof.
pub fn verify_id_token(
    id_token: &str,
    jwks: &Jwks,
    provider: &OidcProvider,
    expected_nonce: &str,
    claimed_email: &str,
) -> Result<VerifiedOidc, OidcError> {
    // Pick the signing key by the token header's kid.
    let header = jsonwebtoken::decode_header(id_token)
        .map_err(|e| OidcError::TokenInvalid(e.to_string()))?;
    let kid = header.kid.ok_or_else(|| OidcError::TokenInvalid("no kid".into()))?;
    let jwk = jwks.key(&kid).ok_or_else(|| OidcError::UnknownKid(kid.clone()))?;
    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| OidcError::TokenInvalid(format!("bad jwk: {e}")))?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[&provider.client_id]);
    // Google's `iss` is either the bare host or the https URL; accept both.
    validation.set_issuer(&[provider.issuer.as_str(), "accounts.google.com"]);
    validation.validate_exp = true;

    let data = jsonwebtoken::decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| OidcError::TokenInvalid(e.to_string()))?;
    let claims = data.claims;
    let _ = claims.exp; // validated by jsonwebtoken

    // nonce (replay), email_verified (mandatory), exact-email (per-mailbox).
    match &claims.nonce {
        Some(n) if n == expected_nonce => {}
        _ => return Err(OidcError::NonceMismatch),
    }
    if !claims.email_verified.0 {
        return Err(OidcError::EmailUnverified);
    }

    let token_norm = normalize_google_email(&claims.email);
    let claimed_norm = normalize_google_email(claimed_email);
    if token_norm != claimed_norm {
        return Err(OidcError::EmailMismatch {
            claimed: claimed_norm,
            token: token_norm,
        });
    }

    // Workspace guard: if the claimed domain is not a consumer Gmail domain,
    // the token's `hd` (hosted domain) must equal it — so a random Google
    // account can't claim an address at a Workspace domain it doesn't belong
    // to. (Consumer gmail.com tokens carry no `hd`.)
    let domain = claimed_norm.split('@').nth(1).unwrap_or("");
    if !GOOGLE_CONSUMER_DOMAINS.contains(&domain) {
        match &claims.hd {
            Some(hd) if hd.eq_ignore_ascii_case(domain) => {}
            _ => return Err(OidcError::WorkspaceDomainMismatch),
        }
    }

    Ok(VerifiedOidc {
        email: claimed_norm,
        proof_subject: format!("{}#{}", claims.iss, claims.sub),
    })
}

#[cfg(test)]
mod tests;
