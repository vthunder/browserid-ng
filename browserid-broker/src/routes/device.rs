//! Device-cert model endpoints (DC Phases 2 + 6) — see
//! `docs/design/browserid-end-to-end-flow.md`. Built ADDITIVELY alongside the
//! legacy `/wsapi/cert_key` + `/provision/*` routes (removed only at cleanup).
//!
//! - `POST /device/issue`  (session) → a **user** device cert (authentication)
//!   + a **config** device cert (authorization), batch, both IdP-signed, each
//!   with a per-device status ref.
//! - `POST /access/mint`   (device-cert-authed) → a fresh-key **access cert**,
//!   rooted at the issuing device's status index.
//! - `POST /verify-access` → verify an `access_cert~assertion~warrant~config_cert`
//!   bundle with real primary/fallback conformance (convenience verifier).
//!
//! The warrant is signed CLIENT-side by the config cert; its registry/status
//! (revocation) lands with DC Phase 4.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use browserid_core::device::{AccessCert, AccessRequest, DeviceCert, Purpose, Subject};
use browserid_core::{PublicKey, StatusRef};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};
use crate::verifier::{verify_access_with_dns, AccessVerificationResult};

fn ce(e: browserid_core::Error) -> BrokerError {
    BrokerError::InvalidProvisioningRequest(e.to_string())
}
fn parse_pub(s: &str) -> Result<PublicKey, BrokerError> {
    PublicKey::from_base64(s).map_err(|e| BrokerError::ValidationError(format!("bad pubkey: {e}")))
}

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

fn device_status<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    device_pub: &PublicKey,
) -> Result<StatusRef, BrokerError> {
    let idx = state
        .user_store
        .get_or_allocate_status("device", &device_pub.to_base64())?;
    Ok(StatusRef {
        uri: browserid_registrar::consent::status_list_uri(&state.domain),
        idx,
    })
}

// ---------------------------------------------------------------------------
// POST /device/issue  (session) → user device cert + config cert (batch)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DeviceIssueRequest {
    pub csrf: String,
    pub email: String,
    pub device_pubkey: String,
    pub config_pubkey: String,
}

#[derive(Serialize)]
pub struct DeviceIssueResponse {
    pub success: bool,
    pub device_cert: String,
    pub config_cert: String,
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
    let device_pub = parse_pub(&req.device_pubkey)?;
    let config_pub = parse_pub(&req.config_pubkey)?;
    let device_cert = DeviceCert::create(
        &state.domain, &device_pub, Purpose::Authentication, Subject::User,
        vec![email.clone()], Duration::days(90), &state.keypair,
        Some(device_status(&state, &device_pub)?),
    ).map_err(ce)?;
    let config_cert = DeviceCert::create(
        &state.domain, &config_pub, Purpose::Authorization, Subject::User,
        vec![email], Duration::days(90), &state.keypair,
        Some(device_status(&state, &config_pub)?),
    ).map_err(ce)?;
    Ok(Json(DeviceIssueResponse {
        success: true,
        device_cert: device_cert.encoded().to_string(),
        config_cert: config_cert.encoded().to_string(),
    }))
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
        return Err(BrokerError::InvalidProvisioningRequest("device cert not issued by this IdP".into()));
    }
    if device_cert.is_expired() {
        return Err(BrokerError::InvalidProvisioningRequest("device cert expired".into()));
    }
    if device_cert.purpose() != Purpose::Authentication {
        return Err(BrokerError::PolicyRefused("device cert cannot mint access certs (not authentication)".into()));
    }
    let areq = AccessRequest::parse(&req.access_request).map_err(ce)?;
    areq.verify(device_cert.public_key()).map_err(ce)?;
    if areq.is_expired() {
        return Err(BrokerError::InvalidProvisioningRequest("access request expired".into()));
    }
    // TODO (B2): single-use jti replay cache.
    let c = areq.claims();
    if c.domain != state.domain {
        return Err(BrokerError::InvalidProvisioningRequest("wrong target domain".into()));
    }
    if !device_cert.authorizes_identity(&c.identity) {
        return Err(BrokerError::PolicyRefused("device cert not authorized for this identity".into()));
    }
    if c.subject != device_cert.subject() {
        return Err(BrokerError::PolicyRefused("subject mismatch".into()));
    }
    // Access cert inherits the DEVICE's status index (revoke a device → its
    // access certs die), per the B3 fix.
    let access_cert = AccessCert::create(
        &state.domain, &c.identity, c.subject, &c.access_key,
        Duration::hours(24), &state.keypair, device_cert.claims().status.clone(),
    ).map_err(ce)?;
    Ok(Json(AccessMintResponse {
        success: true,
        access_cert: access_cert.encoded().to_string(),
        email: c.identity.clone(),
    }))
}

// ---------------------------------------------------------------------------
// POST /verify-access  (convenience verifier, real conformance)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct VerifyAccessRequest {
    pub presentation: String,
    pub audience: String,
    #[serde(default)]
    pub accepted_fallbacks: Option<Vec<String>>,
}

pub async fn verify_access<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<VerifyAccessRequest>,
) -> Json<AccessVerificationResult>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let fetcher = match state.fallback_fetcher().await {
        Ok(f) => f,
        Err(e) => return Json(AccessVerificationResult {
            status: "failure".into(), email: None, subject: None, scopes: None, issuer: None,
            reason: Some(format!("fetcher: {e}")),
        }),
    };
    let accepted = req.accepted_fallbacks.unwrap_or_else(|| vec![state.domain.clone()]);
    Json(verify_access_with_dns(&req.presentation, &req.audience, fetcher.as_ref(), &accepted).await)
}
