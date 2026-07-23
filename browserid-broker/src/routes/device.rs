//! Device-cert model endpoints (DC Phases 2 + 6) — see
//! `docs/design/browserid-end-to-end-flow.md`.
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
use browserid_core::device::{AccessCert, AccessRequest, DeviceCert, Purpose};
use browserid_core::{PublicKey, StatusRef};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{DeviceCertRecord, SessionStore, UserStore};
use crate::verifier::{verify_access_with_dns, AccessVerificationResult};
use chrono::Utc;

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
    /// The client broker's stable per-browser holder (reused across identities),
    /// which must sit in this account's `browsers` namespace. Optional for
    /// backward-compat: absent → the broker assigns a fresh one.
    #[serde(default)]
    pub holder: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceIssueResponse {
    pub success: bool,
    pub device_cert: String,
    pub config_cert: String,
}

#[derive(Serialize)]
pub struct BrowserHolderResponse {
    pub prefix: String,
}

/// GET /wsapi/browser_holder  (session) → the account's `browsers` namespace
/// prefix, so the client broker can form this browser's stable holder
/// `<prefix>.<rand>` once and reuse it across identities.
pub async fn browser_holder<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Result<Json<BrowserHolderResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    let prefix = state
        .user_store
        .get_or_create_namespace(session.user_id, "browsers")?;
    Ok(Json(BrowserHolderResponse { prefix }))
}

pub async fn device_issue<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    headers: axum::http::HeaderMap,
    Json(req): Json<DeviceIssueRequest>,
) -> Result<Json<DeviceIssueResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // owned_verified_email re-derives the session; grab it too so we can
    // persist the issued certs under this account (DC Phase 8 — listable +
    // revocable in the account UI).
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    let email = owned_verified_email(&state, &cookies, &req.csrf, &req.email)?;
    let device_pub = parse_pub(&req.device_pubkey)?;
    let config_pub = parse_pub(&req.config_pubkey)?;
    let device_ref = device_status(&state, &device_pub)?;
    let config_ref = device_status(&state, &config_pub)?;
    let ttl = Duration::days(90);
    // One device slot → one holder in the user's `browsers` namespace, carried by
    // BOTH the authentication (device) and authorization (config) cert. The client
    // broker supplies this browser's stable holder (reused across identities); it
    // must sit in this account's `browsers` namespace (the requester can name a
    // holder only *within* its own browsers namespace, never a service's). Absent
    // → the broker assigns a fresh one (older clients / first contact).
    let ns_prefix = state.user_store.get_or_create_namespace(session.user_id, "browsers")?;
    let holder = match req.holder.as_deref() {
        Some(h) if !h.is_empty() => {
            browserid_core::device::Holder::new(h.to_string()).map_err(ce)?;
            // Account-driven namespace move: a stale client supplying its old
            // holder is silently redirected to the broker-assigned target —
            // the device heals at its next issuance without knowing the move
            // happened (its old certs were revoked at move time).
            let resolved = state
                .user_store
                .resolve_holder_move(session.user_id, h)?;
            match resolved {
                Some(target) => target,
                None => {
                    // Well-formed holder, and in THIS account's browsers
                    // namespace — OR the exact target of a recorded move
                    // (which may sit in any of the user's namespaces; the id
                    // was broker-assigned at move time, never client-chosen).
                    let prefix = h.split_once('.').map(|(p, _)| p).unwrap_or("");
                    let is_move_target = state
                        .user_store
                        .list_holder_moves(session.user_id)?
                        .iter()
                        .any(|(_, new)| new == h);
                    if prefix != ns_prefix && !is_move_target {
                        return Err(BrokerError::PolicyRefused(
                            "supplied holder is not in this account's browsers namespace".into(),
                        ));
                    }
                    h.to_string()
                }
            }
        }
        _ => crate::crypto::assign_holder_id(&ns_prefix),
    };
    let holder_id = browserid_core::device::Holder::new(holder.clone()).map_err(ce)?;
    let device_cert = DeviceCert::create(
        &state.domain, &device_pub, Purpose::Authentication, holder_id.clone(),
        vec![email.clone()], ttl, &state.keypair, Some(device_ref.clone()),
    ).map_err(ce)?;
    // The config cert also covers `+tag` sub-addresses so it can sign
    // warrants for the user's plus-named agent identities (design doc §3).
    let config_identities = match email.split_once('@') {
        Some((local, domain)) => vec![email.clone(), format!("{local}+*@{domain}")],
        None => vec![email.clone()],
    };
    let config_cert = DeviceCert::create(
        &state.domain, &config_pub, Purpose::Authorization, holder_id.clone(),
        config_identities, ttl, &state.keypair, Some(config_ref.clone()),
    ).map_err(ce)?;

    // Durable registry rows (upsert on pubkey) so the certs are enumerable and
    // revocable per account.
    let now = Utc::now();
    let expires = now + ttl;
    for (pubkey, purpose, status_idx) in [
        (&req.device_pubkey, "authentication", device_ref.idx),
        (&req.config_pubkey, "authorization", config_ref.idx),
    ] {
        state.user_store.insert_device_cert(DeviceCertRecord {
            id: 0,
            user_id: session.user_id,
            identities: vec![email.clone()],
            purpose: purpose.to_string(),
            holder: holder.clone(),
            pubkey: pubkey.clone(),
            iss: state.domain.clone(),
            issued_at: now,
            expires_at: expires,
            revoked_at: None,
            status_idx: Some(status_idx),
        })?;
    }
    // First sight of this holder → a friendly UA-derived default label
    // ("Chrome on macOS"); never clobbers a user rename, never fails issuance.
    super::holders::maybe_label_holder_from_ua(
        state.user_store.as_ref(), session.user_id, &holder, &headers,
    );
    // If this issuance completed an account-driven namespace move, drop the
    // old holder's (already-revoked) rows so the device appears exactly once.
    super::holders::finish_holder_move(state.user_store.as_ref(), session.user_id, &holder);

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
    // The mint copies the DEVICE cert's holder verbatim into the access cert —
    // the requester cannot choose a different holder (isolation guarantee). The
    // access request's holder, if present, must equal the device's.
    if c.holder != *device_cert.holder() {
        return Err(BrokerError::PolicyRefused("holder mismatch".into()));
    }
    // Access cert inherits the DEVICE's status index (revoke a device → its
    // access certs die), per the B3 fix.
    let access_cert = AccessCert::create(
        &state.domain, &c.identity, device_cert.holder().clone(), &c.access_key,
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
            status: "failure".into(), email: None, holder: None, scopes: None, issuer: None,
            reason: Some(format!("fetcher: {e}")),
        }),
    };
    let accepted = req.accepted_fallbacks.unwrap_or_else(|| vec![state.domain.clone()]);
    let is_own_revoked =
        |idx: u64| state.user_store.is_status_revoked_idx(idx).map_err(|e| e.to_string());
    let status = crate::verifier::StatusCtx {
        own_uri: browserid_registrar::consent::status_list_uri(&state.domain),
        is_own_revoked: &is_own_revoked,
        cache: &state.foreign_status_lists,
    };
    Json(
        verify_access_with_dns(&req.presentation, &req.audience, fetcher.as_ref(), &accepted, status)
            .await,
    )
}

// ---------------------------------------------------------------------------
// GET /wsapi/device_certs  (session) → this account's device + config certs
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct DeviceCertView {
    pub id: u64,
    pub identities: Vec<String>,
    /// "authentication" (device/agent login) | "authorization" (config, warrant signer)
    pub purpose: String,
    /// The opaque broker-assigned holder id (`<ns>.<id>`) this cert acts as.
    pub holder: String,
    pub pubkey: String,
    pub iss: String,
    pub issued_at: String,
    pub expires_at: String,
    pub revoked: bool,
}

#[derive(Serialize)]
pub struct DeviceCertsResponse {
    pub success: bool,
    pub certs: Vec<DeviceCertView>,
}

/// GET /wsapi/device_certs — list the session account's device certs
/// (authentication: user/agent) and config certs (authorization). Own-account
/// only, session-gated.
pub async fn device_certs<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Result<Json<DeviceCertsResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    let certs = state
        .user_store
        .list_device_certs(session.user_id)?
        .into_iter()
        .map(|r| DeviceCertView {
            id: r.id,
            identities: r.identities,
            purpose: r.purpose,
            holder: r.holder,
            pubkey: r.pubkey,
            iss: r.iss,
            issued_at: r.issued_at.to_rfc3339(),
            expires_at: r.expires_at.to_rfc3339(),
            revoked: r.revoked_at.is_some(),
        })
        .collect();
    Ok(Json(DeviceCertsResponse { success: true, certs }))
}

// ---------------------------------------------------------------------------
// POST /wsapi/revoke_device_cert  (session, CSRF) → log a device/agent out
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RevokeDeviceCertRequest {
    pub csrf: String,
    pub id: u64,
}

#[derive(Serialize)]
pub struct RevokeDeviceCertResponse {
    pub success: bool,
}

/// POST /wsapi/revoke_device_cert — owner-scoped soft-revoke. Also flips the
/// cert's status-list bit so any outstanding access certs rooted at this device
/// fail-closed at the RP verifier ("log this device/agent out"). Sticky: the
/// revoked_at / status bit are never un-set.
pub async fn revoke_device_cert<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<RevokeDeviceCertRequest>,
) -> Result<Json<RevokeDeviceCertResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;

    // Capture the status index BEFORE revoking (owner-scoped lookup).
    let status_idx = state
        .user_store
        .list_device_certs(session.user_id)?
        .into_iter()
        .find(|r| r.id == req.id)
        .and_then(|r| r.status_idx);

    // Owner-scoped: errors DeviceCertNotFound if it isn't this user's cert.
    state
        .user_store
        .revoke_device_cert(session.user_id, req.id)?;

    // Kill outstanding access certs rooted at this device (fail-closed status).
    if let Some(idx) = status_idx {
        state.user_store.set_status_revoked_idx(idx)?;
    }

    Ok(Json(RevokeDeviceCertResponse { success: true }))
}
