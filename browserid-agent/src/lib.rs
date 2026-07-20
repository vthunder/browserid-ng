//! Headless browserid client for agents (device-cert model).
//!
//! An agent is a *device* holding an IdP-issued AGENT DEVICE CERT
//! (`purpose=authentication`, carrying an opaque holder) that certifies its device key.
//! It signs an access request with the device key, POSTs the IdP's
//! `/access/mint`, and receives a short-lived access cert for a fresh key. To
//! present at an RP it assembles `access_cert~assertion~warrant~config_cert`,
//! using a held user-config-cert-signed warrant (+ the config cert) per
//! audience.
//!
//! ```no_run
//! # async fn demo() -> Result<(), browserid_agent::AgentError> {
//! use browserid_agent::{DeviceCredential, DeviceAgent};
//!
//! let credential = DeviceCredential::load("device-credential.json")?;
//! let mut agent = DeviceAgent::new(credential)?;
//! // Hold a warrant obtained from the principal via the consent flow.
//! // agent.add_grant(warrant_jws, config_cert_jws)?;
//! let bundle = agent.assertion_for("https://api.example.com").await?;
//! # Ok(()) }
//! ```

use base64::Engine;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use browserid_core::device::{
    AccessCert, AccessPresentation, AccessRequest, DeviceCert, Holder, Warrant as DeviceWarrant,
};
use browserid_core::{Assertion, KeyPair};

/// Default validity for assertions minted by [`DeviceAgent::assertion_for`]
pub const ASSERTION_VALIDITY_MINUTES: i64 = 5;

/// Re-mint the access cert when it expires within this margin.
const ACCESS_REFRESH_MARGIN_SECONDS: i64 = 60;

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("IdP rejected the request ({status}): {reason}")]
    Idp { status: u16, reason: String },

    #[error("browserid error: {0}")]
    Core(#[from] browserid_core::Error),

    #[error("invalid credential: {0}")]
    InvalidCredential(String),

    #[error("invalid stored identity: {0}")]
    InvalidStored(String),

    #[error("no warrant for audience {audience} — ask your principal to approve one (spec §6)")]
    NoWarrant { audience: String },

    #[error("invalid warrant: {0}")]
    InvalidWarrant(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, AgentError>;

/// The `<idp-domain>` a request must target — the IdP URL's host (with port).
fn url_host(url: &str) -> &str {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    after_scheme.split('/').next().unwrap_or(after_scheme)
}

// ===========================================================================
// Device-cert model — the headless agent path.
// ===========================================================================

/// The device-cert credential a headless agent holds: its own device key plus
/// the IdP-signed agent device cert that certifies it, plus the IdP that mints
/// access certs for it. The device key never leaves the process; only signed
/// access requests cross the wire.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceCredential {
    /// base64url (no pad) Ed25519 seed of the agent's device key
    pub device_key: String,
    /// The IdP-signed agent device cert (encoded JWS)
    pub agent_device_cert: String,
    /// IdP base URL (mints access certs), e.g. `https://browserid.me`
    pub idp: String,
}

impl std::fmt::Debug for DeviceCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCredential")
            .field("device_key", &"<redacted>")
            .field("idp", &self.idp)
            .finish_non_exhaustive()
    }
}

impl DeviceCredential {
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }

    fn device_keypair(&self) -> Result<KeyPair> {
        let seed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(self.device_key.trim())
            .map_err(|e| AgentError::InvalidCredential(format!("bad device_key: {e}")))?;
        KeyPair::from_seed(&seed)
            .map_err(|e| AgentError::InvalidCredential(format!("bad device key: {e}")))
    }

    fn device_cert(&self) -> Result<DeviceCert> {
        DeviceCert::parse(&self.agent_device_cert)
            .map_err(|e| AgentError::InvalidCredential(format!("bad agent_device_cert: {e}")))
    }
}

/// A fresh access key + the IdP-minted access cert over it.
struct AccessSession {
    key: KeyPair,
    cert: AccessCert,
}

/// A headless device-cert agent. Holds the device key + agent device cert, a
/// cached short-lived access cert (re-minted near expiry), and per-audience
/// config-cert-signed warrants (+ the config cert) needed to present at an RP.
pub struct DeviceAgent {
    http: reqwest::Client,
    credential: DeviceCredential,
    idp_domain: String,
    device_key: KeyPair,
    device_cert: DeviceCert,
    email: String,
    holder: Holder,
    access: Option<AccessSession>,
    /// audience → (warrant signed by the user's config cert, that config cert)
    grants: std::collections::HashMap<String, (DeviceWarrant, DeviceCert)>,
}

impl std::fmt::Debug for DeviceAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAgent")
            .field("idp", &self.credential.idp)
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

impl DeviceAgent {
    /// Build from a device credential. The identity + holder are read from the
    /// (signed) agent device cert, never from client metadata.
    pub fn new(credential: DeviceCredential) -> Result<Self> {
        let device_key = credential.device_keypair()?;
        let device_cert = credential.device_cert()?;
        if device_cert.public_key() != &device_key.public_key() {
            return Err(AgentError::InvalidCredential(
                "device cert does not certify the held device key".into(),
            ));
        }
        let email = device_cert
            .claims()
            .identities
            .first()
            .cloned()
            .ok_or_else(|| AgentError::InvalidCredential("device cert has no identity".into()))?;
        let holder = device_cert.holder().clone();
        let idp_domain = url_host(&credential.idp).to_string();
        Ok(Self {
            http: reqwest::Client::new(),
            credential,
            idp_domain,
            device_key,
            device_cert,
            email,
            holder,
            access: None,
            grants: std::collections::HashMap::new(),
        })
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    /// Hold a config-cert-signed warrant (obtained from the principal via the
    /// warrant consent flow) plus the config cert that signed it. Returns the
    /// audience it covers. Rejects a warrant naming a different identity, a
    /// holder matcher that doesn't cover this agent's holder, or a config cert
    /// that didn't sign the warrant.
    pub fn add_grant(&mut self, warrant_encoded: &str, config_cert_encoded: &str) -> Result<String> {
        let warrant = DeviceWarrant::parse(warrant_encoded)
            .map_err(|e| AgentError::InvalidWarrant(e.to_string()))?;
        let config_cert = DeviceCert::parse(config_cert_encoded)
            .map_err(|e| AgentError::InvalidWarrant(format!("config cert: {e}")))?;
        let wc = warrant.claims();
        if wc.identifier != self.email {
            return Err(AgentError::InvalidWarrant(format!(
                "warrant is for '{}', this identity is '{}'",
                wc.identifier, self.email
            )));
        }
        if !wc.holder.matches(&self.holder) {
            return Err(AgentError::InvalidWarrant(
                "warrant holder matcher does not cover this agent's holder".into(),
            ));
        }
        // The config cert must actually have signed this warrant.
        warrant
            .verify(config_cert.public_key())
            .map_err(|e| AgentError::InvalidWarrant(format!("warrant not signed by config cert: {e}")))?;
        let audience = wc.audience.clone();
        self.grants.insert(audience.clone(), (warrant, config_cert));
        Ok(audience)
    }

    /// Audiences this agent currently holds a warrant for.
    pub fn warranted_audiences(&self) -> Vec<&str> {
        self.grants.keys().map(String::as_str).collect()
    }

    /// Mint (or re-mint) an access cert: generate a fresh access key, sign an
    /// access request with the device key, POST the IdP's `/access/mint`.
    pub async fn mint(&mut self) -> Result<()> {
        let access_key = KeyPair::generate();
        let jti = format!("{}{}", random_hex(), random_hex());
        let request = AccessRequest::create(
            &self.idp_domain,
            &self.email,
            self.holder.clone(),
            &access_key.public_key(),
            &jti,
            &self.device_key,
        )?;
        let response = self
            .http
            .post(format!("{}/access/mint", self.credential.idp.trim_end_matches('/')))
            .json(&serde_json::json!({
                "device_cert": self.device_cert.encoded(),
                "access_request": request.encoded(),
            }))
            .send()
            .await?;
        let status = response.status();
        let value: serde_json::Value = response.json().await.unwrap_or_default();
        if !status.is_success() || value["success"] != serde_json::Value::Bool(true) {
            return Err(AgentError::Idp {
                status: status.as_u16(),
                reason: value["reason"].as_str().unwrap_or("no reason given").to_string(),
            });
        }
        let cert = AccessCert::parse(
            value["access_cert"]
                .as_str()
                .ok_or_else(|| AgentError::InvalidStored("mint response missing access_cert".into()))?,
        )?;
        self.access = Some(AccessSession { key: access_key, cert });
        Ok(())
    }

    async fn ensure_fresh_access(&mut self) -> Result<()> {
        let deadline = (Utc::now() + Duration::seconds(ACCESS_REFRESH_MARGIN_SECONDS)).timestamp();
        let stale = match &self.access {
            None => true,
            Some(s) => s.cert.claims().exp <= deadline,
        };
        if stale {
            self.mint().await?;
        }
        Ok(())
    }

    /// Assemble an RP-facing `access_cert~assertion~warrant~config_cert` bundle
    /// for `audience`. Re-mints the access cert first if stale. Requires a held
    /// config-cert-signed warrant for `audience` ([`Self::add_grant`]).
    pub async fn assertion_for(&mut self, audience: &str) -> Result<String> {
        self.ensure_fresh_access().await?;
        let (warrant, config_cert) = self
            .grants
            .get(audience)
            .ok_or_else(|| AgentError::NoWarrant { audience: audience.to_string() })?
            .clone();
        let session = self.access.as_ref().expect("ensure_fresh_access set it");
        let assertion = Assertion::create(
            audience,
            Duration::minutes(ASSERTION_VALIDITY_MINUTES),
            &session.key,
        )?;
        let presentation = AccessPresentation {
            access_cert: session.cert.clone(),
            assertion,
            warrant,
            config_cert,
        };
        Ok(presentation.encode())
    }
}

/// 8 random hex chars, for a generated nonce / suffix.
fn random_hex() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_host_extraction() {
        assert_eq!(url_host("https://mingo.place"), "mingo.place");
        assert_eq!(url_host("http://127.0.0.1:7899/"), "127.0.0.1:7899");
        assert_eq!(url_host("https://mingo.place/path"), "mingo.place");
    }
}
