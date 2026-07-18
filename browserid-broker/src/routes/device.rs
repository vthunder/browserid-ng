//! Device-cert model endpoints (docs/design/browserid-end-to-end-flow.md).
//!
//! The broker acts as IdP (fallback) + hosted broker:
//! - `POST /device/issue`   (session) → an IdP-signed **device cert** (authn).
//! - `POST /access/mint`    (device-cert-authed) → a fresh-key **access cert**.
//! - `POST /warrant/issue`  (session) → a **warrant** + its **config cert**
//!   (the broker's server-side config cert signs it).
//! - `POST /verify-access`  → verify an `access_cert~assertion~warrant~config_cert`
//!   presentation (convenience verifier).

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use browserid_core::device::{
    AccessCert, AccessPresentation, AccessRequest, DeviceCert, Purpose, Subject, Warrant,
};
use browserid_core::{KeyPair, PublicKey};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};

fn ce(e: browserid_core::Error) -> BrokerError {
    BrokerError::InvalidProvisioningRequest(e.to_string())
}

/// Resolve the session and confirm it owns a verified `email`.
fn owned_verified_email<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    cookies: &Cookies,
    csrf: &str,
    email: &str,
) -> Result<String, BrokerError> {
    let session = super::session::get_session_from_cookies(cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, csrf)?;
    let normalized = email.to_lowercase();
    let emails = state.user_store.list_emails(session.user_id)?;
    let rec = emails
        .iter()
        .find(|e| e.email.to_lowercase() == normalized && e.verified)
        .ok_or(BrokerError::EmailNotFound)?;
    Ok(rec.email.clone())
}

// ---------------------------------------------------------------------------
// POST /device/issue  (session-authed)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DeviceIssueRequest {
    pub csrf: String,
    pub email: String,
    pub device_pubkey: String,
}

#[derive(Serialize)]
pub struct DeviceIssueResponse {
    pub success: bool,
    pub device_cert: String,
}

pub async fn device_issue<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<DeviceIssueRequest>,
) -> Result<Json<DeviceIssueResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let email = owned_verified_email(&state, &cookies, &req.csrf, &req.email)?;
    let device_pub = PublicKey::from_base64(&req.device_pubkey)
        .map_err(|e| BrokerError::ValidationError(format!("bad device pubkey: {e}")))?;
    let cert = DeviceCert::create(
        &state.domain,
        &device_pub,
        Purpose::Authentication,
        Subject::User,
        vec![email],
        Duration::days(90),
        &state.keypair,
    )
    .map_err(ce)?;
    Ok(Json(DeviceIssueResponse { success: true, device_cert: cert.encoded().to_string() }))
}

// ---------------------------------------------------------------------------
// POST /access/mint  (the device cert is the credential — no session)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AccessMintRequest {
    pub device_cert: String,
    pub access_request: String,
}

#[derive(Serialize)]
pub struct AccessMintResponse {
    pub success: bool,
    pub access_cert: String,
    pub email: String,
}

pub async fn access_mint<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<AccessMintRequest>,
) -> Result<Json<AccessMintResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let device_cert = DeviceCert::parse(&req.device_cert).map_err(ce)?;
    device_cert.verify(&state.keypair.public_key()).map_err(ce)?;
    if device_cert.iss() != state.domain {
        return Err(BrokerError::InvalidProvisioningRequest(
            "device cert not issued by this IdP".into(),
        ));
    }
    if device_cert.is_expired() {
        return Err(BrokerError::InvalidProvisioningRequest("device cert expired".into()));
    }
    if device_cert.purpose() != Purpose::Authentication {
        return Err(BrokerError::PolicyRefused(
            "device cert cannot mint access certs (not an authentication cert)".into(),
        ));
    }

    let areq = AccessRequest::parse(&req.access_request).map_err(ce)?;
    areq.verify(device_cert.public_key()).map_err(ce)?; // signed by the device key
    if areq.is_expired() {
        return Err(BrokerError::InvalidProvisioningRequest("access request expired".into()));
    }
    let c = areq.claims();
    if c.domain != state.domain {
        return Err(BrokerError::InvalidProvisioningRequest("wrong target domain".into()));
    }
    if !device_cert.authorizes_identity(&c.identity) {
        return Err(BrokerError::PolicyRefused(
            "device cert not authorized for this identity".into(),
        ));
    }
    if c.subject != device_cert.subject() {
        return Err(BrokerError::PolicyRefused("subject mismatch".into()));
    }

    // The IdP MAY refuse here (abuse/compromise). Demo: always mint.
    let access_cert = AccessCert::create(
        &state.domain,
        &c.identity,
        c.subject,
        &c.access_key,
        Duration::hours(24),
        &state.keypair,
        None,
    )
    .map_err(ce)?;
    Ok(Json(AccessMintResponse {
        success: true,
        access_cert: access_cert.encoded().to_string(),
        email: c.identity.clone(),
    }))
}

// ---------------------------------------------------------------------------
// POST /warrant/issue  (session-authed; broker signs with a config cert)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct WarrantIssueRequest {
    pub csrf: String,
    pub email: String,
    pub audience: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Serialize)]
pub struct WarrantIssueResponse {
    pub success: bool,
    pub warrant: String,
    pub config_cert: String,
}

pub async fn warrant_issue<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<WarrantIssueRequest>,
) -> Result<Json<WarrantIssueResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let email = owned_verified_email(&state, &cookies, &req.csrf, &req.email)?;
    // The broker's server-side config cert for this identity. (Demo: a fresh
    // config key per issue; a real deployment reuses/stores it — Phase 4.)
    let config_kp = KeyPair::generate();
    let config_cert = DeviceCert::create(
        &state.domain,
        &config_kp.public_key(),
        Purpose::Authorization,
        Subject::User,
        vec![email.clone()],
        Duration::days(90),
        &state.keypair,
    )
    .map_err(ce)?;
    let scopes = if req.scopes.is_empty() { vec!["login".to_string()] } else { req.scopes };
    let warrant = Warrant::create(
        &email,
        Subject::User,
        &req.audience,
        scopes,
        Duration::days(30),
        &config_kp,
        None,
    )
    .map_err(ce)?;
    Ok(Json(WarrantIssueResponse {
        success: true,
        warrant: warrant.encoded().to_string(),
        config_cert: config_cert.encoded().to_string(),
    }))
}

// ---------------------------------------------------------------------------
// POST /verify-access  (convenience verifier)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct VerifyAccessRequest {
    pub presentation: String,
    pub audience: String,
}

#[derive(Serialize)]
pub struct VerifyAccessResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn verr(reason: impl Into<String>) -> Json<VerifyAccessResponse> {
    Json(VerifyAccessResponse {
        status: "failure".into(),
        email: None,
        subject: None,
        scopes: None,
        issuer: None,
        reason: Some(reason.into()),
    })
}

pub async fn verify_access<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<VerifyAccessRequest>,
) -> Json<VerifyAccessResponse>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let pres = match AccessPresentation::parse(&req.presentation) {
        Ok(p) => p,
        Err(e) => return verr(format!("parse: {e}")),
    };
    let our_domain = state.domain.clone();
    let our_key = state.keypair.public_key();
    // Resolver: this broker's own issuance uses our key. (DNS resolution of
    // other issuers is a follow-up; the demo issues via browserid.me.)
    let res = pres.verify(&req.audience, |iss| {
        if iss == our_domain {
            Ok(our_key.clone())
        } else {
            Err(browserid_core::Error::InvalidProvisioning(format!(
                "issuer '{iss}' not resolvable by this verifier (demo)"
            )))
        }
    });
    match res {
        Ok(v) => Json(VerifyAccessResponse {
            status: "okay".into(),
            email: Some(v.email),
            subject: Some(match v.subject {
                Subject::User => "user".into(),
                Subject::Agent => "agent".into(),
            }),
            scopes: Some(v.scopes),
            issuer: Some(v.issuer),
            reason: None,
        }),
        Err(e) => verr(e.to_string()),
    }
}
