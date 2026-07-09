//! Headless browserid client for agents (tdxf, spec v0.2 — delegation chain).
//!
//! An agent holds a **provisioning credential**: a private key (`P_priv`)
//! whose public half a user delegated in-browser by signing a provisioning
//! certificate with their identity key, plus the `U_cert~P_cert` delegation
//! bundle, and the broker + target-IdP URLs. The agent never holds any user
//! secret; it signs short-lived provisioning requests with `P_priv`, has the
//! broker endorse each one, and presents the dual-signed request to the IdP,
//! which mints an agent certificate for the agent's own (separate) keypair.
//!
//! ```no_run
//! # async fn demo() -> Result<(), browserid_agent::AgentError> {
//! use browserid_agent::{AgentCredential, AgentIdentity};
//!
//! let credential = AgentCredential::load("agent-credential.json")?;
//! let mut agent = AgentIdentity::provision(&credential, Some("checkpoint-attestor")).await?;
//!
//! // A backed assertion (`cert~assertion`) for one RP — local signing, with
//! // an automatic endorse→re-mint if the cached cert is stale.
//! let assertion = agent.assertion_for("https://api.example.com").await?;
//! # Ok(()) }
//! ```

use base64::Engine;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use browserid_core::provisioning::{ProvisioningRequest, RequestBundle};
use browserid_core::rp_auth::TokenErrorResponse;
use browserid_core::{
    Assertion, BackedAssertion, Certificate, KeyPair, ProvisioningCert, RpChallenge, TokenRequest,
    TokenResponse,
};

/// Default validity for assertions minted by [`AgentIdentity::assertion_for`]
pub const ASSERTION_VALIDITY_MINUTES: i64 = 5;

/// Re-mint the certificate when it expires within this margin, so an
/// assertion is never handed out backed by a cert about to lapse
const CERT_REFRESH_MARGIN_SECONDS: i64 = 60;

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("broker refused endorsement ({status}): {reason}")]
    Endorse { status: u16, reason: String },

    #[error("IdP rejected the request ({status}): {reason}")]
    Idp { status: u16, reason: String },

    #[error("browserid error: {0}")]
    Core(#[from] browserid_core::Error),

    #[error("invalid credential: {0}")]
    InvalidCredential(String),

    #[error("invalid stored identity: {0}")]
    InvalidStored(String),

    #[error("no BrowserID challenge at {url} (status {status})")]
    NoChallenge { url: String, status: u16 },

    #[error("token exchange refused ({status}): {error}")]
    Exchange { status: u16, error: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, AgentError>;

/// The provisioning credential a user hands their agent — the v2 "API key".
/// Created by the browser key-management UI; `secret_key` (`P_priv`) is shown
/// once and never sent to any server.
#[derive(Clone, Serialize, Deserialize)]
pub struct AgentCredential {
    /// base64url (no pad) Ed25519 seed of the provisioning key `P_priv`
    pub secret_key: String,
    /// The `U_cert~P_cert` delegation bundle
    pub delegation: String,
    /// Broker base URL (endorses requests), e.g. `https://browserid.me`
    pub broker: String,
    /// Target IdP base URL (mints), e.g. `https://mingo.place`
    pub idp: String,
}

impl AgentCredential {
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }

    fn provisioning_key(&self) -> Result<KeyPair> {
        let seed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(self.secret_key.trim())
            .map_err(|e| AgentError::InvalidCredential(format!("bad secret_key: {e}")))?;
        KeyPair::from_seed(&seed)
            .map_err(|e| AgentError::InvalidCredential(format!("bad provisioning key: {e}")))
    }

    /// The constraint this credential's delegation authorizes (`names` +
    /// `patterns`) — from the `P_cert` inside the delegation bundle.
    pub fn constraint(&self) -> Result<browserid_core::Constraint> {
        let (_, p) = self
            .delegation
            .split_once('~')
            .ok_or_else(|| AgentError::InvalidCredential("delegation must be U_cert~P_cert".into()))?;
        Ok(ProvisioningCert::parse(p)?.constraint().clone())
    }
}

// Don't leak the provisioning secret through logs.
impl std::fmt::Debug for AgentCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentCredential")
            .field("secret_key", &"<redacted>")
            .field("broker", &self.broker)
            .field("idp", &self.idp)
            .finish_non_exhaustive()
    }
}

/// The `<idp-domain>` a request must target — the IdP URL's host (with port).
fn url_host(url: &str) -> &str {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    after_scheme.split('/').next().unwrap_or(after_scheme)
}

/// An agent-held browserid identity: its own keypair + a cached short-lived
/// cert, plus the provisioning credential used to (re-)mint. The agent keypair
/// and the provisioning key both stay local; only signatures cross the wire.
pub struct AgentIdentity {
    http: reqwest::Client,
    credential: AgentCredential,
    idp_domain: String,
    keypair: KeyPair,
    email: String,
    cert: Certificate,
}

impl std::fmt::Debug for AgentIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentIdentity")
            .field("idp", &self.credential.idp)
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

/// Serializable identity: the agent key seed, email, and last cert. Excludes
/// the credential — that is re-supplied on [`AgentIdentity::load`].
#[derive(Serialize, Deserialize)]
pub struct StoredIdentity {
    /// base64url (no pad) Ed25519 seed of the agent key
    pub secret_key: String,
    pub email: String,
    pub cert: String,
}

impl AgentIdentity {
    /// Provision a new identity: generate an agent keypair locally, sign a
    /// `mint` request with the provisioning key, have the broker endorse it,
    /// and present the dual-signed request to the IdP. `name` is the desired
    /// local-part; the IdP generates one when `None`. Idempotent for an
    /// existing active name under the same delegation.
    pub async fn provision(credential: &AgentCredential, name: Option<&str>) -> Result<Self> {
        let http = reqwest::Client::new();
        let keypair = KeyPair::generate();
        let idp_domain = url_host(&credential.idp).to_string();

        // Every name must be authorized by the credential's constraint. When
        // the caller omits one, derive a random name under the first `<prefix>+*`
        // pattern (`<prefix>+<hex>`) — a constraint with only fixed `names` has
        // no room for a generated name, so the caller must pass one explicitly.
        let name = match name {
            Some(n) => n.to_string(),
            None => credential
                .constraint()?
                .patterns
                .first()
                .and_then(|p| browserid_core::Constraint::pattern_prefix(p))
                .map(|prefix| format!("{}+{}", prefix, random_hex()))
                .ok_or_else(|| {
                    AgentError::InvalidCredential(
                        "no name given and the credential has no `<prefix>+*` pattern to \
                         generate one under; pass an explicit reserved name"
                            .into(),
                    )
                })?,
        };

        let (email, cert) =
            mint(&http, credential, &idp_domain, &name, &keypair).await?;

        Ok(Self {
            http,
            credential: credential.clone(),
            idp_domain,
            keypair,
            email,
            cert,
        })
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn certificate(&self) -> &Certificate {
        &self.cert
    }

    /// Backed assertion (`cert~assertion`) for `audience`, valid for
    /// [`ASSERTION_VALIDITY_MINUTES`]. Signing is local; the cert is re-minted
    /// (endorse→mint) first if stale.
    pub async fn assertion_for(&mut self, audience: &str) -> Result<String> {
        self.ensure_fresh_cert().await?;
        let assertion = Assertion::create(
            audience,
            Duration::minutes(ASSERTION_VALIDITY_MINUTES),
            &self.keypair,
        )?;
        Ok(BackedAssertion::new(self.cert.clone(), assertion).encode())
    }

    /// Sign arbitrary bytes with the certified agent key — the typed-payload
    /// path (e.g. SBO envelopes). Domain separation is the caller's concern.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.keypair.sign(message)
    }

    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    /// Re-mint the certificate now (endorse a fresh `mint` request → IdP),
    /// regardless of expiry. The agent keypair is unchanged.
    pub async fn remint(&mut self) -> Result<()> {
        // Re-derive the local part from the minted email.
        let name = self
            .email
            .split('@')
            .next()
            .ok_or_else(|| AgentError::InvalidStored("email has no local part".into()))?
            .to_string();
        let (_email, cert) = mint(
            &self.http,
            &self.credential,
            &self.idp_domain,
            &name,
            &self.keypair,
        )
        .await?;
        self.cert = cert;
        Ok(())
    }

    /// Revoke this identity at the IdP (endorsed `revoke` request): future
    /// mints fail and the outstanding cert ages out within its TTL.
    pub async fn revoke(self) -> Result<()> {
        let name = self.email.split('@').next().unwrap_or_default().to_string();
        let key = self.credential.provisioning_key()?;
        let request = ProvisioningRequest::revoke(&self.idp_domain, &name, &key)?;
        let bundle = build_bundle(&self.credential, request)?;
        let endorsement = endorse(&self.http, &self.credential.broker, &bundle).await?;
        idp_post(
            &self.http,
            &self.credential.idp,
            "/provision/revoke",
            &bundle,
            &endorsement,
        )
        .await?;
        Ok(())
    }

    /// Authenticate to an API RP cold: read its `WWW-Authenticate: BrowserID`
    /// challenge, sign an assertion for the advertised audience, exchange it
    /// for the RP's own bearer token. Zero pre-config.
    pub async fn token_for(&mut self, resource_url: &str) -> Result<TokenResponse> {
        let challenge = self.discover_challenge(resource_url).await?;
        self.exchange_for_token(&challenge).await
    }

    pub async fn discover_challenge(&self, resource_url: &str) -> Result<RpChallenge> {
        let response = self.http.get(resource_url).send().await?;
        let status = response.status().as_u16();
        response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .and_then(RpChallenge::parse)
            .ok_or_else(|| AgentError::NoChallenge {
                url: resource_url.to_string(),
                status,
            })
    }

    pub async fn exchange_for_token(&mut self, challenge: &RpChallenge) -> Result<TokenResponse> {
        self.ensure_fresh_cert().await?;
        let assertion = Assertion::create(
            &challenge.audience,
            Duration::minutes(ASSERTION_VALIDITY_MINUTES),
            &self.keypair,
        )?;
        let backed = BackedAssertion::new(self.cert.clone(), assertion).encode();

        let response = self
            .http
            .post(&challenge.token_endpoint)
            .form(&TokenRequest::new(backed))
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            let error = response
                .json::<TokenErrorResponse>()
                .await
                .map(|e| {
                    e.error_description
                        .map_or(e.error.clone(), |d| format!("{}: {}", e.error, d))
                })
                .unwrap_or_else(|_| "no error body".to_string());
            return Err(AgentError::Exchange { status: status.as_u16(), error });
        }
        Ok(response.json::<TokenResponse>().await?)
    }

    async fn ensure_fresh_cert(&mut self) -> Result<()> {
        let deadline = (Utc::now() + Duration::seconds(CERT_REFRESH_MARGIN_SECONDS)).timestamp();
        if self.cert.claims().exp <= deadline {
            self.remint().await?;
        }
        Ok(())
    }

    pub fn to_stored(&self) -> StoredIdentity {
        StoredIdentity {
            secret_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(self.keypair.secret_bytes()),
            email: self.email.clone(),
            cert: self.cert.encoded().to_string(),
        }
    }

    /// Rehydrate from a stored identity plus the credential. An expired stored
    /// cert is fine — it re-mints on the next use.
    pub fn from_stored(stored: StoredIdentity, credential: &AgentCredential) -> Result<Self> {
        let seed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&stored.secret_key)
            .map_err(|e| AgentError::InvalidStored(format!("bad secret_key: {e}")))?;
        let keypair = KeyPair::from_seed(&seed)?;
        let cert = Certificate::parse(&stored.cert)?;
        Ok(Self {
            http: reqwest::Client::new(),
            idp_domain: url_host(&credential.idp).to_string(),
            credential: credential.clone(),
            keypair,
            email: stored.email,
            cert,
        })
    }

    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(&self.to_stored())?)?;
        Ok(())
    }

    pub fn load(path: impl AsRef<std::path::Path>, credential: &AgentCredential) -> Result<Self> {
        let stored: StoredIdentity = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        Self::from_stored(stored, credential)
    }
}

/// Build `U_cert~P_cert~R` from the credential's delegation plus a request.
fn build_bundle(credential: &AgentCredential, request: ProvisioningRequest) -> Result<RequestBundle> {
    let (u, p) = credential
        .delegation
        .split_once('~')
        .ok_or_else(|| AgentError::InvalidCredential("delegation must be U_cert~P_cert".into()))?;
    Ok(RequestBundle::new(
        Certificate::parse(u)?,
        ProvisioningCert::parse(p)?,
        request,
    ))
}

/// Sign a mint request, endorse it, mint at the IdP. Returns (email, cert).
async fn mint(
    http: &reqwest::Client,
    credential: &AgentCredential,
    idp_domain: &str,
    name: &str,
    agent_key: &KeyPair,
) -> Result<(String, Certificate)> {
    let key = credential.provisioning_key()?;
    let request =
        ProvisioningRequest::mint(idp_domain, name, &agent_key.public_key(), false, &key)?;
    let bundle = build_bundle(credential, request)?;
    let endorsement = endorse(http, &credential.broker, &bundle).await?;
    let resp = idp_post(http, &credential.idp, "/provision/mint", &bundle, &endorsement).await?;
    let email = resp["email"]
        .as_str()
        .ok_or_else(|| AgentError::InvalidStored("mint response missing email".into()))?
        .to_string();
    let cert = Certificate::parse(
        resp["cert"]
            .as_str()
            .ok_or_else(|| AgentError::InvalidStored("mint response missing cert".into()))?,
    )?;
    Ok((email, cert))
}

/// POST the request bundle to the broker's endorse endpoint.
async fn endorse(
    http: &reqwest::Client,
    broker: &str,
    bundle: &RequestBundle,
) -> Result<String> {
    let response = http
        .post(format!("{}/provision/endorse", broker.trim_end_matches('/')))
        .json(&serde_json::json!({ "request_bundle": bundle.encoded() }))
        .send()
        .await?;
    let status = response.status();
    let value: serde_json::Value = response.json().await.unwrap_or_default();
    if !status.is_success() || value["success"] != serde_json::Value::Bool(true) {
        return Err(AgentError::Endorse {
            status: status.as_u16(),
            reason: value["reason"].as_str().unwrap_or("no reason given").to_string(),
        });
    }
    value["endorsement"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| AgentError::InvalidStored("endorse response missing endorsement".into()))
}

/// POST {request_bundle, endorsement} to an IdP provisioning endpoint.
async fn idp_post(
    http: &reqwest::Client,
    idp: &str,
    path: &str,
    bundle: &RequestBundle,
    endorsement: &str,
) -> Result<serde_json::Value> {
    let response = http
        .post(format!("{}{}", idp.trim_end_matches('/'), path))
        .json(&serde_json::json!({
            "request_bundle": bundle.encoded(),
            "endorsement": endorsement,
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
    Ok(value)
}

/// 8 random hex chars, for a generated subaddress suffix (`<prefix>+<hex>`).
fn random_hex() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> (AgentCredential, KeyPair) {
        // A self-consistent (but not broker-registered) credential for
        // serialization tests.
        let idp = KeyPair::generate();
        let user = KeyPair::generate();
        let prov = KeyPair::generate();
        let u_cert = Certificate::create(
            "mingo.place",
            "dan@mingo.place",
            &user.public_key(),
            Duration::hours(24),
            &idp,
        )
        .unwrap();
        let p_cert = ProvisioningCert::create(
            "dan@mingo.place",
            &prov.public_key(),
            browserid_core::Constraint::names(["bot"]),
            Duration::days(90),
            &user,
        )
        .unwrap();
        let credential = AgentCredential {
            secret_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(prov.secret_bytes()),
            delegation: format!("{}~{}", u_cert.encoded(), p_cert.encoded()),
            broker: "https://browserid.me".into(),
            idp: "https://mingo.place".into(),
        };
        (credential, prov)
    }

    #[test]
    fn credential_loads_provisioning_key() {
        let (cred, prov) = credential();
        assert_eq!(cred.provisioning_key().unwrap().public_key(), prov.public_key());
        // Debug never prints the secret.
        assert!(!format!("{cred:?}").contains(&cred.secret_key));
    }

    #[test]
    fn url_host_extraction() {
        assert_eq!(url_host("https://mingo.place"), "mingo.place");
        assert_eq!(url_host("http://127.0.0.1:7899/"), "127.0.0.1:7899");
        assert_eq!(url_host("https://mingo.place/path"), "mingo.place");
    }

    #[test]
    fn stored_identity_excludes_credential() {
        let agent_kp = KeyPair::generate();
        let issuer = KeyPair::generate();
        let cert = Certificate::create(
            "mingo.place",
            "bot@mingo.place",
            &agent_kp.public_key(),
            Duration::hours(24),
            &issuer,
        )
        .unwrap();
        let (cred, _) = credential();
        let identity = AgentIdentity {
            http: reqwest::Client::new(),
            idp_domain: "mingo.place".into(),
            credential: cred.clone(),
            keypair: agent_kp,
            email: "bot@mingo.place".into(),
            cert,
        };
        let json = serde_json::to_string(&identity.to_stored()).unwrap();
        assert!(json.contains("bot@mingo.place"));
        assert!(!json.contains(&cred.secret_key), "credential must not be persisted");

        let restored = AgentIdentity::from_stored(
            serde_json::from_str(&json).unwrap(),
            &cred,
        )
        .unwrap();
        assert_eq!(restored.email(), "bot@mingo.place");
    }

    #[test]
    fn generated_subaddress_names_are_valid() {
        for _ in 0..20 {
            let n = format!("svc+{}", random_hex());
            assert!(n.starts_with("svc+") && n.len() <= 32);
            assert!(browserid_core::Constraint {
                names: vec![],
                patterns: vec!["svc+*".into()]
            }
            .authorizes(&n));
        }
    }
}
