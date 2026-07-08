//! Headless browserid client for agents (l8lw).
//!
//! An agent holds its own Ed25519 keypair, provisions an attributed identity
//! from an agent-enabled broker (`POST /agent/identities`, gated by a
//! browser-minted `bidk_…` API key), and from then on signs assertions
//! locally — re-minting its short-lived certificate through the same API key
//! whenever it expires. RPs verify the result as ordinary browserid.
//!
//! ```no_run
//! # async fn demo() -> Result<(), browserid_agent::AgentError> {
//! use browserid_agent::AgentIdentity;
//!
//! let mut agent = AgentIdentity::provision(
//!     "https://agents.browserid.me",
//!     std::env::var("BROWSERID_API_KEY").unwrap(),
//!     Some("checkpoint-attestor"),
//! )
//! .await?;
//!
//! // A backed assertion (`cert~assertion`) for one RP — pure local signing,
//! // with an automatic cert re-mint if the cached one has expired
//! let assertion = agent.assertion_for("https://api.example.com").await?;
//! # Ok(()) }
//! ```

use base64::Engine;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use browserid_core::{Assertion, BackedAssertion, Certificate, KeyPair};

/// Default validity for assertions minted by [`AgentIdentity::assertion_for`]
pub const ASSERTION_VALIDITY_MINUTES: i64 = 5;

/// Re-mint the certificate when it expires within this margin, so an
/// assertion is never handed out backed by a cert about to lapse
const CERT_REFRESH_MARGIN_SECONDS: i64 = 60;

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("IdP rejected the request ({status}): {reason}")]
    Idp { status: u16, reason: String },

    #[error("browserid error: {0}")]
    Core(#[from] browserid_core::Error),

    #[error("stored identity is invalid: {0}")]
    InvalidStored(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, AgentError>;

/// An agent-held browserid identity: its own keypair, the identity email the
/// IdP minted, and a cached short-lived certificate. The API key is the
/// standing credential used to (re-)mint certs; the keypair never leaves the
/// agent.
pub struct AgentIdentity {
    http: reqwest::Client,
    /// Base URL of the agent-enabled IdP, e.g. `https://agents.browserid.me`
    idp_url: String,
    api_key: String,
    keypair: KeyPair,
    email: String,
    cert: Certificate,
}

// Manual impl: the api_key and private key must never leak through logs
impl std::fmt::Debug for AgentIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentIdentity")
            .field("idp_url", &self.idp_url)
            .field("email", &self.email)
            .field("api_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Serializable form of an identity: the key seed, the identity email, the
/// last certificate, and the IdP it came from. Deliberately excludes the API
/// key — that stays in the caller's secret management and is re-supplied on
/// [`AgentIdentity::load`].
#[derive(Serialize, Deserialize)]
pub struct StoredIdentity {
    /// base64url (no pad) Ed25519 seed
    pub secret_key: String,
    pub email: String,
    pub cert: String,
    pub idp_url: String,
}

impl AgentIdentity {
    /// Provision a new identity: generate a keypair locally and ask the IdP
    /// to mint an identity + certificate for its public half. `name` is the
    /// desired local-part; the IdP generates one when `None`. Idempotent for
    /// an existing `name` owned by the same account (returns a fresh cert).
    pub async fn provision(
        idp_url: impl Into<String>,
        api_key: impl Into<String>,
        name: Option<&str>,
    ) -> Result<Self> {
        let idp_url = idp_url.into().trim_end_matches('/').to_string();
        let api_key = api_key.into();
        let http = reqwest::Client::new();
        let keypair = KeyPair::generate();

        let mut body = serde_json::json!({
            "pubkey": {
                "algorithm": "Ed25519",
                "publicKey": keypair.public_key().to_base64(),
            }
        });
        if let Some(name) = name {
            body["name"] = serde_json::Value::String(name.to_string());
        }

        let response =
            post_json(&http, &idp_url, "/agent/identities", &api_key, &body).await?;
        let email = response["email"]
            .as_str()
            .ok_or_else(|| AgentError::InvalidStored("IdP response missing email".into()))?
            .to_string();
        let cert = parse_cert_field(&response)?;

        Ok(Self {
            http,
            idp_url,
            api_key,
            keypair,
            email,
            cert,
        })
    }

    /// The identity email the IdP minted (e.g. `attestor@agents.browserid.me`)
    pub fn email(&self) -> &str {
        &self.email
    }

    /// The current certificate (may be close to expiry; [`Self::assertion_for`]
    /// refreshes it automatically)
    pub fn certificate(&self) -> &Certificate {
        &self.cert
    }

    /// Produce a backed assertion (`cert~assertion`) for `audience`, valid
    /// for [`ASSERTION_VALIDITY_MINUTES`]. Signing is local; the certificate
    /// is re-minted through the IdP first if expired or about to expire.
    pub async fn assertion_for(&mut self, audience: &str) -> Result<String> {
        self.ensure_fresh_cert().await?;
        let assertion = Assertion::create(
            audience,
            Duration::minutes(ASSERTION_VALIDITY_MINUTES),
            &self.keypair,
        )?;
        Ok(BackedAssertion::new(self.cert.clone(), assertion).encode())
    }

    /// Sign arbitrary bytes with the certified key — the typed-payload path
    /// (e.g. SBO envelopes). Domain separation of the payload is the
    /// caller's responsibility.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.keypair.sign(message)
    }

    /// The agent's keypair (the private key custody is the whole point —
    /// exposed for callers that need richer signing than [`Self::sign`])
    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    /// Re-mint the certificate now, regardless of expiry
    pub async fn remint(&mut self) -> Result<()> {
        let body = serde_json::json!({
            "email": self.email,
            "pubkey": {
                "algorithm": "Ed25519",
                "publicKey": self.keypair.public_key().to_base64(),
            }
        });
        let response =
            post_json(&self.http, &self.idp_url, "/agent/cert", &self.api_key, &body).await?;
        self.cert = parse_cert_field(&response)?;
        Ok(())
    }

    /// Revoke this identity at the IdP: re-mints stop failing-open and the
    /// outstanding certificate ages out within its TTL
    pub async fn revoke(self) -> Result<()> {
        let body = serde_json::json!({ "email": self.email });
        post_json(
            &self.http,
            &self.idp_url,
            "/agent/identities/revoke",
            &self.api_key,
            &body,
        )
        .await?;
        Ok(())
    }

    async fn ensure_fresh_cert(&mut self) -> Result<()> {
        let deadline = (Utc::now() + Duration::seconds(CERT_REFRESH_MARGIN_SECONDS)).timestamp();
        if self.cert.claims().exp <= deadline {
            self.remint().await?;
        }
        Ok(())
    }

    /// Serializable form (excludes the API key)
    pub fn to_stored(&self) -> StoredIdentity {
        StoredIdentity {
            secret_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(self.keypair.secret_bytes()),
            email: self.email.clone(),
            cert: self.cert.encoded().to_string(),
            idp_url: self.idp_url.clone(),
        }
    }

    /// Rehydrate from a stored identity plus the API key (from the caller's
    /// secret management). An expired stored cert is fine — it is re-minted
    /// on the next [`Self::assertion_for`].
    pub fn from_stored(stored: StoredIdentity, api_key: impl Into<String>) -> Result<Self> {
        let seed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&stored.secret_key)
            .map_err(|e| AgentError::InvalidStored(format!("bad secret_key: {e}")))?;
        let keypair = KeyPair::from_seed(&seed)?;
        let cert = Certificate::parse(&stored.cert)?;
        Ok(Self {
            http: reqwest::Client::new(),
            idp_url: stored.idp_url,
            api_key: api_key.into(),
            keypair,
            email: stored.email,
            cert,
        })
    }

    /// Persist to a JSON file (600-style secrecy is the caller's concern; the
    /// file contains the private key seed)
    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.to_stored())?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load from a JSON file written by [`Self::save`]
    pub fn load(
        path: impl AsRef<std::path::Path>,
        api_key: impl Into<String>,
    ) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let stored: StoredIdentity = serde_json::from_str(&contents)?;
        Self::from_stored(stored, api_key)
    }
}

/// POST a JSON body with the Bearer API key; map non-2xx into
/// [`AgentError::Idp`] carrying the IdP's `reason` when present.
async fn post_json(
    http: &reqwest::Client,
    idp_url: &str,
    path: &str,
    api_key: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value> {
    let response = http
        .post(format!("{idp_url}{path}"))
        .bearer_auth(api_key)
        .json(body)
        .send()
        .await?;

    let status = response.status();
    let value: serde_json::Value = response.json().await.unwrap_or_default();
    if !status.is_success() || value["success"] != serde_json::Value::Bool(true) {
        let reason = value["reason"]
            .as_str()
            .unwrap_or("no reason given")
            .to_string();
        return Err(AgentError::Idp {
            status: status.as_u16(),
            reason,
        });
    }
    Ok(value)
}

fn parse_cert_field(response: &serde_json::Value) -> Result<Certificate> {
    let encoded = response["cert"]
        .as_str()
        .ok_or_else(|| AgentError::InvalidStored("IdP response missing cert".into()))?;
    Ok(Certificate::parse(encoded)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_identity_roundtrip() {
        let keypair = KeyPair::generate();
        let issuer = KeyPair::generate();
        let cert = Certificate::create(
            "agents.example.com",
            "bot@agents.example.com",
            &keypair.public_key(),
            Duration::hours(24),
            &issuer,
        )
        .unwrap();

        let identity = AgentIdentity {
            http: reqwest::Client::new(),
            idp_url: "https://agents.example.com".to_string(),
            api_key: "bidk_secret".to_string(),
            keypair,
            email: "bot@agents.example.com".to_string(),
            cert,
        };

        let stored = identity.to_stored();
        assert!(serde_json::to_string(&stored).unwrap().contains("bot@"));
        // The API key must never end up in the stored form
        assert!(!serde_json::to_string(&stored).unwrap().contains("bidk_"));

        let restored = AgentIdentity::from_stored(stored, "bidk_secret").unwrap();
        assert_eq!(restored.email(), identity.email());
        assert_eq!(
            restored.keypair.public_key(),
            identity.keypair.public_key()
        );
        assert_eq!(restored.cert.encoded(), identity.cert.encoded());
    }

    #[test]
    fn signing_is_local() {
        let keypair = KeyPair::generate();
        let issuer = KeyPair::generate();
        let cert = Certificate::create(
            "agents.example.com",
            "bot@agents.example.com",
            &keypair.public_key(),
            Duration::hours(24),
            &issuer,
        )
        .unwrap();
        let identity = AgentIdentity {
            http: reqwest::Client::new(),
            idp_url: "https://agents.example.com".to_string(),
            api_key: "k".to_string(),
            keypair,
            email: "bot@agents.example.com".to_string(),
            cert,
        };

        let sig = identity.sign(b"typed payload bytes");
        assert!(!sig.is_empty());
    }
}
