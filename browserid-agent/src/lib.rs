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
    TokenResponse, Warrant, WarrantGrant,
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

    #[error("no warrant for audience {audience} — ask your principal to approve one (spec §6)")]
    NoWarrant { audience: String },

    #[error("invalid warrant: {0}")]
    InvalidWarrant(String),

    #[error("warrant request denied by the principal")]
    WarrantDenied,

    #[error("warrant request expired before the principal responded")]
    WarrantExpired,

    #[error("warrant request failed ({status}): {reason}")]
    WarrantRequest { status: u16, reason: String },

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
    /// User-signed warrants, one per RP audience (spec §5.2). Required to
    /// present anywhere once the cert is an agent certificate.
    warrants: std::collections::HashMap<String, Warrant>,
}

impl std::fmt::Debug for AgentIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentIdentity")
            .field("idp", &self.credential.idp)
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

/// A pending consent request at the registrar (spec §6.2). Surface
/// `verification_uri` to the principal; poll with the `code`.
#[derive(Debug, Clone)]
pub struct WarrantRequestHandle {
    /// The audiences this request asks grants for (one warrant each)
    pub audiences: Vec<String>,
    pub code: String,
    pub verification_uri: String,
    pub expires_in: i64,
    pub interval: i64,
}

/// Serializable identity: the agent key seed, email, and last cert. Excludes
/// the credential — that is re-supplied on [`AgentIdentity::load`].
#[derive(Serialize, Deserialize)]
pub struct StoredIdentity {
    /// base64url (no pad) Ed25519 seed of the agent key
    pub secret_key: String,
    pub email: String,
    pub cert: String,
    /// Encoded warrants (one per audience); absent in pre-v0.4 files
    #[serde(default)]
    pub warrants: Vec<String>,
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

        // Every name must be authorized by the credential's constraint. When the
        // caller omits one: derive a random name under the first `<prefix>+*`
        // pattern (`<prefix>+<hex>`); else, if the credential reserves exactly one
        // fixed `name`, use it (the common single-identity credential). Only error
        // when the name is genuinely ambiguous (several fixed names, no pattern).
        let name = match name {
            Some(n) => n.to_string(),
            None => {
                let c = credential.constraint()?;
                if let Some(prefix) = c
                    .patterns
                    .first()
                    .and_then(|p| browserid_core::Constraint::pattern_prefix(p))
                {
                    format!("{}+{}", prefix, random_hex())
                } else if c.names.len() == 1 {
                    c.names[0].clone()
                } else {
                    return Err(AgentError::InvalidCredential(
                        "no name given: this credential reserves several fixed names (or none) \
                         and no `<prefix>+*` pattern — pass one of its reserved names explicitly"
                            .into(),
                    ));
                }
            }
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
            warrants: std::collections::HashMap::new(),
        })
    }

    /// Store a user-signed warrant (obtained from the principal via the
    /// registrar UI or the consent flow). Returns the audience it is for.
    /// Rejects warrants naming a different agent identity.
    pub fn add_warrant(&mut self, encoded: &str) -> Result<String> {
        let warrant = Warrant::parse(encoded)
            .map_err(|e| AgentError::InvalidWarrant(e.to_string()))?;
        if warrant.agent() != self.email {
            return Err(AgentError::InvalidWarrant(format!(
                "warrant is for '{}', this identity is '{}'",
                warrant.agent(),
                self.email
            )));
        }
        let audience = warrant.audience().to_string();
        self.warrants.insert(audience.clone(), warrant);
        Ok(audience)
    }

    /// The warrant held for `audience`, if any
    pub fn warrant_for(&self, audience: &str) -> Option<&Warrant> {
        self.warrants.get(audience)
    }

    /// Whether a held warrant satisfies a request for `audience` with `scopes`:
    /// same audience, and (when scopes are requested) the held warrant grants at
    /// least all of them. An unqualified request (no scopes) is covered by any
    /// held warrant for the audience.
    fn warrant_covers(&self, audience: &str, scopes: Option<&[String]>) -> bool {
        match self.warrants.get(audience) {
            None => false,
            Some(w) => match scopes {
                None => true,
                Some(want) if want.is_empty() => true,
                Some(want) => {
                    let held = w.claims().scopes.clone().unwrap_or_default();
                    want.iter().all(|s| held.contains(s))
                }
            },
        }
    }

    /// Audiences this agent currently holds warrants for
    pub fn warranted_audiences(&self) -> Vec<&str> {
        self.warrants.keys().map(String::as_str).collect()
    }

    /// Raise a **consent request** at the registrar (spec §6.2) for a single
    /// audience — sugar over [`Self::request_warrants`].
    pub async fn request_warrant(
        &self,
        audience: &str,
        scopes: Option<Vec<String>>,
    ) -> Result<WarrantRequestHandle> {
        self.request_warrants(vec![WarrantGrant { aud: audience.to_string(), scopes }])
            .await
    }

    /// Raise a **consent request** at the registrar for one or more grants
    /// (spec §6.2): the principal approves the whole set in one deliberate
    /// action and one single-audience warrant per grant comes back. Returns a
    /// handle whose `verification_uri` must reach the principal (print it,
    /// message it — whatever channel exists).
    pub async fn request_warrants(
        &self,
        grants: Vec<WarrantGrant>,
    ) -> Result<WarrantRequestHandle> {
        let audiences: Vec<String> = grants.iter().map(|g| g.aud.clone()).collect();
        let name = self
            .email
            .split('@')
            .next()
            .ok_or_else(|| AgentError::InvalidStored("email has no local part".into()))?;
        let registrar_domain = url_host(&self.credential.broker).to_string();
        let key = self.credential.provisioning_key()?;
        let request = ProvisioningRequest::warrant(&registrar_domain, name, grants, &key)?;
        let bundle = build_bundle(&self.credential, request)?;

        let response = self
            .http
            .post(format!(
                "{}/warrant/request",
                self.credential.broker.trim_end_matches('/')
            ))
            .json(&serde_json::json!({ "request_bundle": bundle.encoded() }))
            .send()
            .await?;
        let status = response.status();
        let value: serde_json::Value = response.json().await.unwrap_or_default();
        if !status.is_success() || value["success"] != serde_json::Value::Bool(true) {
            return Err(AgentError::WarrantRequest {
                status: status.as_u16(),
                reason: value["reason"].as_str().unwrap_or("no reason given").to_string(),
            });
        }
        Ok(WarrantRequestHandle {
            audiences,
            code: value["code"].as_str().unwrap_or_default().to_string(),
            verification_uri: value["verification_uri"].as_str().unwrap_or_default().to_string(),
            expires_in: value["expires_in"].as_i64().unwrap_or(900),
            interval: value["interval"].as_i64().unwrap_or(5).max(1),
        })
    }

    /// Poll a pending consent request once. On approval the warrant is
    /// validated and stored ([`Self::add_warrant`]) and `Ok(true)` returned;
    /// `Ok(false)` means still pending; denial/expiry are errors.
    pub async fn poll_warrant(&mut self, handle: &WarrantRequestHandle) -> Result<bool> {
        let response = self
            .http
            .post(format!(
                "{}/warrant/poll",
                self.credential.broker.trim_end_matches('/')
            ))
            .json(&serde_json::json!({ "code": handle.code }))
            .send()
            .await?;
        if response.status().as_u16() == 410 {
            return Err(AgentError::WarrantExpired);
        }
        if response.status().as_u16() == 429 {
            return Ok(false); // polled too fast; caller waits out the interval
        }
        let value: serde_json::Value = response.json().await.unwrap_or_default();
        match value["status"].as_str() {
            Some("pending") => Ok(false),
            Some("denied") => Err(AgentError::WarrantDenied),
            Some("approved") => {
                // Batch shape: `warrants` array; `warrant` kept for N==1.
                let mut stored = 0;
                if let Some(list) = value["warrants"].as_array() {
                    for w in list {
                        if let Some(jws) = w.as_str() {
                            self.add_warrant(jws)?;
                            stored += 1;
                        }
                    }
                }
                if stored == 0 {
                    let warrant = value["warrant"].as_str().ok_or_else(|| {
                        AgentError::InvalidWarrant("approved response missing warrants".into())
                    })?;
                    self.add_warrant(warrant)?;
                }
                Ok(true)
            }
            Some("expired") | None | Some(_) => Err(AgentError::WarrantExpired),
        }
    }

    /// The whole consent loop for a single audience — sugar over
    /// [`Self::obtain_warrants`].
    pub async fn obtain_warrant(
        &mut self,
        audience: &str,
        scopes: Option<Vec<String>>,
        notify: impl FnOnce(&WarrantRequestHandle),
    ) -> Result<()> {
        self.obtain_warrants(vec![WarrantGrant { aud: audience.to_string(), scopes }], notify)
            .await
    }

    /// The whole consent loop for a set of grants: request the batch,
    /// surface the verification URI via `notify`, poll until the principal
    /// responds (or the request expires). Grants already covered by held
    /// warrants are skipped; if nothing is missing, no request is raised.
    pub async fn obtain_warrants(
        &mut self,
        grants: Vec<WarrantGrant>,
        notify: impl FnOnce(&WarrantRequestHandle),
    ) -> Result<()> {
        // A grant is missing unless a held warrant COVERS it — same audience AND
        // its scopes are a superset of the requested ones. Filtering on audience
        // alone let a scope-less (or under-scoped) warrant permanently shadow a
        // scoped re-request; a freshly granted warrant replaces the old one for
        // that audience (`add_warrant` inserts by audience).
        let missing: Vec<WarrantGrant> = grants
            .into_iter()
            .filter(|g| !self.warrant_covers(&g.aud, g.scopes.as_deref()))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        let handle = self.request_warrants(missing).await?;
        notify(&handle);
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(handle.expires_in.max(0) as u64);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(handle.interval as u64)).await;
            if self.poll_warrant(&handle).await? {
                return Ok(());
            }
            if std::time::Instant::now() > deadline {
                return Err(AgentError::WarrantExpired);
            }
        }
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn certificate(&self) -> &Certificate {
        &self.cert
    }

    /// Backed assertion for `audience`, valid for
    /// [`ASSERTION_VALIDITY_MINUTES`]. Signing is local; the cert is re-minted
    /// (endorse→mint) first if stale. When the cert is an agent certificate
    /// (spec §5.1), the presentation is `agent_cert~warrant~assertion` — a
    /// user-signed warrant for `audience` must be held ([`Self::add_warrant`])
    /// or this fails with [`AgentError::NoWarrant`].
    pub async fn assertion_for(&mut self, audience: &str) -> Result<String> {
        self.ensure_fresh_cert().await?;
        let assertion = Assertion::create(
            audience,
            Duration::minutes(ASSERTION_VALIDITY_MINUTES),
            &self.keypair,
        )?;
        if self.cert.is_agent() {
            let warrant = self.warrants.get(audience).ok_or_else(|| {
                AgentError::NoWarrant { audience: audience.to_string() }
            })?;
            Ok(BackedAssertion::new_agent(self.cert.clone(), warrant.clone(), assertion).encode())
        } else {
            Ok(BackedAssertion::new(self.cert.clone(), assertion).encode())
        }
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
        let backed = self.assertion_for(&challenge.audience).await?;

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
            warrants: self.warrants.values().map(|w| w.encoded().to_string()).collect(),
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
        let mut warrants = std::collections::HashMap::new();
        for encoded in &stored.warrants {
            let warrant = Warrant::parse(encoded)
                .map_err(|e| AgentError::InvalidStored(format!("bad warrant: {e}")))?;
            warrants.insert(warrant.audience().to_string(), warrant);
        }
        Ok(Self {
            http: reqwest::Client::new(),
            idp_domain: url_host(&credential.idp).to_string(),
            credential: credential.clone(),
            keypair,
            email: stored.email,
            cert,
            warrants,
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
    fn credential_exposes_reserved_names() {
        // The `identity` CLI command reads this offline instead of decoding the
        // P_cert JWT by hand.
        let (cred, _) = credential();
        let c = cred.constraint().unwrap();
        assert_eq!(c.names, vec!["bot".to_string()]);
        assert!(c.patterns.is_empty());
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
            warrants: std::collections::HashMap::new(),
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
    fn warrants_store_and_persist() {
        let idp = KeyPair::generate();
        let user = KeyPair::generate();
        let agent_kp = KeyPair::generate();
        let parent_cert = Certificate::create(
            "mingo.place",
            "dan@mingo.place",
            &user.public_key(),
            Duration::hours(24),
            &idp,
        )
        .unwrap();
        let cert = Certificate::create_agent(
            "mingo.place",
            "bot@mingo.place",
            "dan@mingo.place",
            &agent_kp.public_key(),
            Duration::hours(24),
            &idp,
            Some("https://browserid.me".to_string()),
        )
        .unwrap();
        let (cred, _) = credential();
        let mut identity = AgentIdentity {
            http: reqwest::Client::new(),
            idp_domain: "mingo.place".into(),
            credential: cred.clone(),
            keypair: agent_kp,
            email: "bot@mingo.place".into(),
            cert,
            warrants: std::collections::HashMap::new(),
        };

        let warrant = Warrant::create(
            &parent_cert,
            "bot@mingo.place",
            "https://api.example.com",
            Some(vec!["post".into()]),
            Duration::days(30),
            &user,
        )
        .unwrap();
        let aud = identity.add_warrant(warrant.encoded()).unwrap();
        assert_eq!(aud, "https://api.example.com");
        assert!(identity.warrant_for("https://api.example.com").is_some());

        // A warrant for a different agent is refused.
        let other = Warrant::create(
            &parent_cert,
            "other@mingo.place",
            "https://api.example.com",
            None,
            Duration::days(30),
            &user,
        )
        .unwrap();
        assert!(identity.add_warrant(other.encoded()).is_err());

        // Warrants survive the store/load roundtrip.
        let restored = AgentIdentity::from_stored(
            serde_json::from_str(&serde_json::to_string(&identity.to_stored()).unwrap()).unwrap(),
            &cred,
        )
        .unwrap();
        assert!(restored.warrant_for("https://api.example.com").is_some());
        assert_eq!(restored.warranted_audiences().len(), 1);
    }

    #[test]
    fn warrant_coverage_respects_scopes() {
        let idp = KeyPair::generate();
        let user = KeyPair::generate();
        let agent_kp = KeyPair::generate();
        let parent_cert = Certificate::create(
            "mingo.place", "dan@mingo.place", &user.public_key(), Duration::hours(24), &idp,
        )
        .unwrap();
        let cert = Certificate::create_agent(
            "mingo.place", "bot@mingo.place", "dan@mingo.place",
            &agent_kp.public_key(), Duration::hours(24), &idp,
            Some("https://browserid.me".to_string()),
        )
        .unwrap();
        let (cred, _) = credential();
        let mut identity = AgentIdentity {
            http: reqwest::Client::new(), idp_domain: "mingo.place".into(),
            credential: cred, keypair: agent_kp, email: "bot@mingo.place".into(),
            cert, warrants: std::collections::HashMap::new(),
        };
        let aud = "https://api.example.com";
        // No warrant yet: nothing is covered.
        assert!(!identity.warrant_covers(aud, None));
        assert!(!identity.warrant_covers(aud, Some(&["post".into()])));

        // Hold a SCOPE-LESS warrant (the shape the old demo minted).
        let scopeless = Warrant::create(
            &parent_cert, "bot@mingo.place", aud, None, Duration::days(30), &user,
        )
        .unwrap();
        identity.add_warrant(scopeless.encoded()).unwrap();
        // It covers an unqualified request…
        assert!(identity.warrant_covers(aud, None));
        // …but NOT a scoped one — the bug was returning true here, letting the
        // scope-less warrant shadow a `post read` re-request forever.
        assert!(!identity.warrant_covers(aud, Some(&["post".into()])));

        // Replace it with a scoped warrant (add_warrant inserts by audience).
        let scoped = Warrant::create(
            &parent_cert, "bot@mingo.place", aud,
            Some(vec!["post".into(), "read".into()]), Duration::days(30), &user,
        )
        .unwrap();
        identity.add_warrant(scoped.encoded()).unwrap();
        assert!(identity.warrant_covers(aud, Some(&["post".into()])));
        assert!(identity.warrant_covers(aud, Some(&["post".into(), "read".into()])));
        // A scope it doesn't grant is still not covered.
        assert!(!identity.warrant_covers(aud, Some(&["delete".into()])));
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
