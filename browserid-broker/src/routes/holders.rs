//! Account holder-registry endpoints (holder-authorization model, stage 2b).
//!
//! The account page groups the user's device certs by their opaque **holder**
//! id, and holders into user-organized **namespaces** (`browsers` / `agents` /
//! `services`). Only the browser-vs-headless axis is load-bearing (it set the
//! default matcher at issuance); the namespace split is cosmetic organization.
//!
//! - `GET  /wsapi/holders`            → the grouped view (namespaces → holders)
//! - `POST /wsapi/rename_holder`      → friendly label for one holder id
//! - `POST /wsapi/rename_namespace`   → friendly label for a namespace
//! - `POST /wsapi/create_namespace`   → a new namespace (fresh random prefix)
//! - `POST /wsapi/delete_namespace`   → remove an EMPTY namespace
//!
//! The semantics live in `browserid_registrar::holders` — the SAME cores back
//! the registry API's `/api/v1/holders` family (registry-api-v1 §5.4), so the
//! cookie and token lanes' validation bars and revocation routing cannot
//! drift. This module is the legacy envelope (session + CSRF, `success: true`,
//! `PolicyRefused` refusals) around those cores, plus the broker-local holder
//! bookkeeping hooks its issuance paths call.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use browserid_registrar::holders as core;
use browserid_registrar::RegistrarError;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::registrar_glue::{BrokerRegistrarHost, BrokerRegistrarStore};
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};

/// The cookie lane's glue adapters, built per call (Arc clones only).
fn reg_store<U, S, E>(state: &AppState<U, S, E>) -> BrokerRegistrarStore<U>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    BrokerRegistrarStore { user_store: state.user_store.clone() }
}

fn reg_host<U, S, E>(state: &AppState<U, S, E>) -> BrokerRegistrarHost<U, S>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    BrokerRegistrarHost {
        user_store: state.user_store.clone(),
        session_store: state.session_store.clone(),
        domain: state.domain.clone(),
        idp_host: state.idp_host.clone(),
        max_agent_identities: state.max_agent_identities_per_user,
    }
}

/// Core errors onto the legacy envelope: owner-scoped misses and refusals all
/// render as the cookie lane's historical `PolicyRefused` (403 + message) —
/// the machine reasons are a token-lane affordance.
fn core_err(e: RegistrarError) -> BrokerError {
    match e {
        RegistrarError::HolderNotFound => BrokerError::PolicyRefused("no such holder".into()),
        RegistrarError::NamespaceNotFound => BrokerError::PolicyRefused("no such namespace".into()),
        RegistrarError::ValidationError(m) | RegistrarError::PolicyRefused(m) => {
            BrokerError::PolicyRefused(m)
        }
        RegistrarError::Conflict { message, .. } => BrokerError::PolicyRefused(message),
        other => BrokerError::Internal(other.to_string()),
    }
}

/// Cookie-lane wrapper for the shared §5.3 revoke core (`device.rs` calls
/// it): owner-scoped soft-revoke + authority-routed status flip. Returns
/// whether a bit actually flipped (the legacy envelope ignores it).
pub(crate) fn revoke_device_core_for<U, S, E>(
    state: &AppState<U, S, E>,
    user_id: u64,
    cert_id: u64,
) -> Result<bool, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    core::revoke_device_core(&reg_store(state), &reg_host(state), &state.domain, user_id, cert_id)
        .map_err(|e| match e {
            RegistrarError::DeviceCertNotFound => BrokerError::DeviceCertNotFound,
            other => core_err(other),
        })
}

// ---------------------------------------------------------------------------
// GET /wsapi/holders
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct HoldersResponse {
    pub success: bool,
    pub namespaces: Vec<core::NamespaceView>,
    /// Defensive: any holder whose prefix matches no namespace row.
    pub holders_without_namespace: Vec<core::HolderView>,
}

pub async fn holders<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Result<Json<HoldersResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    let view =
        core::holders_view_core(&reg_store(&state), session.user_id.0).map_err(core_err)?;
    Ok(Json(HoldersResponse {
        success: true,
        namespaces: view.namespaces,
        holders_without_namespace: view.holders_without_namespace,
    }))
}

// `ua_label` / `product_token_label` moved to browserid_registrar::holders
// (shared with the token lane's devices/register). Re-imported below.
use browserid_registrar::holders::ua_label;

/// Best-effort: give `holder_id` a UA-derived default label if the user hasn't
/// labeled it yet. Never clobbers an existing label; never fails the caller.
pub(crate) fn maybe_label_holder_from_ua<U: UserStore>(
    user_store: &U,
    user_id: crate::store::UserId,
    holder_id: &str,
    headers: &axum::http::HeaderMap,
) {
    let Some(ua) = headers.get("user-agent").and_then(|v| v.to_str().ok()) else {
        return;
    };
    let Some(label) = ua_label(ua) else { return };
    match user_store.get_holder_labels(user_id) {
        Ok(labels) if labels.contains_key(holder_id) => {} // user/default already set — keep
        Ok(_) => {
            if let Err(e) = user_store.set_holder_label(user_id, holder_id, &label) {
                tracing::debug!("ua holder label skipped: {e}");
            }
        }
        Err(e) => tracing::debug!("ua holder label skipped: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Mutations (session + CSRF, mirroring revoke_device_cert)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct OkResponse {
    pub success: bool,
}

#[derive(Deserialize)]
pub struct RenameHolderRequest {
    pub csrf: String,
    pub holder_id: String,
    pub label: String,
}

pub async fn rename_holder<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<RenameHolderRequest>,
) -> Result<Json<OkResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;
    core::rename_holder_core(&reg_store(&state), session.user_id.0, &req.holder_id, &req.label)
        .map_err(core_err)?;
    Ok(Json(OkResponse { success: true }))
}

#[derive(Deserialize)]
pub struct MoveHolderRequest {
    pub csrf: String,
    pub holder_id: String,
    /// Target namespace name (`browsers` / `services` / a custom one).
    pub namespace: String,
}

#[derive(Serialize)]
pub struct MoveHolderResponse {
    pub success: bool,
    /// The broker-assigned holder id the device will carry after re-issue.
    pub new_holder: String,
}

#[derive(Deserialize)]
pub struct HolderAssignmentQuery {
    pub holder: String,
}

#[derive(Serialize)]
pub struct HolderAssignmentResponse {
    pub success: bool,
    /// "current" | "moved"
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_holder: Option<String>,
}

/// Revoke + drop the warrants ISOLATED to `holder` (exact `<id>` matcher).
/// Store-level twin of `browserid_registrar::holders::cleanup_holder_warrants`
/// for issuance paths that have no registrar handle. Best-effort.
fn cleanup_holder_warrants<U: UserStore>(store: &U, user_id: crate::store::UserId, holder: &str) {
    let warrants = match store.list_warrants(user_id) {
        Ok(w) => w,
        Err(_) => return,
    };
    for w in warrants {
        if w.holder.as_deref() != Some(holder) {
            continue;
        }
        if let Some(idx) = w.status_idx {
            let _ = store.set_status_revoked_idx(idx);
        }
        if let Err(e) = store.delete_warrant(user_id, w.id) {
            tracing::warn!("dropping warrant {} for removed holder failed: {e}", w.id);
        }
    }
}

#[derive(Deserialize)]
pub struct ForgetHolderRequest {
    pub csrf: String,
    pub holder_id: String,
}

/// POST /wsapi/forget_holder — remove a device/service from the account: flip
/// every one of the holder's cert status bits at its revocation authority
/// ("log it out"), then delete the cert rows + label so it leaves the account
/// view. See `forget_holder_core`; `unrevocable` lists the issuers we could
/// not revoke at, so the UI can say so instead of silently pretending.
pub async fn forget_holder<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<ForgetHolderRequest>,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;
    let unrevocable = core::forget_holder_core(
        &reg_store(&state),
        &reg_host(&state),
        &state.domain,
        session.user_id.0,
        &req.holder_id,
    )
    .map_err(core_err)?;
    Ok(Json(serde_json::json!({
        "success": true,
        // Issuers whose certs we could NOT revoke: the device can keep signing
        // in with them until they expire — only that issuer can cut them off.
        "unrevocable": unrevocable,
    })))
}

#[derive(Deserialize)]
pub struct RenameNamespaceRequest {
    pub csrf: String,
    pub name: String,
    pub label: String,
}

pub async fn rename_namespace<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<RenameNamespaceRequest>,
) -> Result<Json<OkResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;
    core::rename_namespace_core(&reg_store(&state), session.user_id.0, &req.name, &req.label)
        .map_err(core_err)?;
    Ok(Json(OkResponse { success: true }))
}

#[derive(Deserialize)]
pub struct CreateNamespaceRequest {
    pub csrf: String,
    pub name: String,
    pub label: Option<String>,
}

pub async fn create_namespace<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<CreateNamespaceRequest>,
) -> Result<Json<OkResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;
    core::create_namespace_core(
        &reg_store(&state),
        session.user_id.0,
        &req.name,
        req.label.as_deref(),
    )
    .map_err(core_err)?;
    Ok(Json(OkResponse { success: true }))
}

#[derive(Deserialize)]
pub struct DeleteNamespaceRequest {
    pub csrf: String,
    pub name: String,
}

pub async fn delete_namespace<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<DeleteNamespaceRequest>,
) -> Result<Json<OkResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;
    core::delete_namespace_core(&reg_store(&state), session.user_id.0, &req.name)
        .map_err(core_err)?;
    Ok(Json(OkResponse { success: true }))
}

