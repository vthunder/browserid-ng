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

/// A friendly holder label derived from a User-Agent, e.g. "Chrome on macOS".
/// Order matters: Edge ships "Chrome/" too, Chrome ships "Safari/", Android
/// ships "Linux". None when nothing recognizable — callers fall back to the
/// generic default label.
pub(crate) fn ua_label(ua: &str) -> Option<String> {
    let browser = if ua.contains("Edg/") {
        Some("Edge")
    } else if ua.contains("Chrome/") {
        Some("Chrome")
    } else if ua.contains("Firefox/") {
        Some("Firefox")
    } else if ua.contains("Safari/") {
        Some("Safari")
    } else {
        None
    };
    let os = if ua.contains("Windows") {
        Some("Windows")
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        Some("iOS")
    } else if ua.contains("Mac OS X") {
        Some("macOS")
    } else if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("Linux") {
        Some("Linux")
    } else {
        None
    };
    match (browser, os) {
        (Some(b), Some(o)) => Some(format!("{b} on {o}")),
        (Some(b), None) => Some(b.to_string()),
        (None, Some(o)) => Some(format!("Browser on {o}")),
        // Not a browser UA: the product-token convention (bean lbla) — a
        // native client sending `Name/Version …` gets `Name` as its default
        // label, so wallets don't register as bare holder ids.
        (None, None) => product_token_label(ua),
    }
}

/// `Name/Version …` → `Name`, for non-browser clients (RFC 9110 product
/// tokens). `None` for anything that doesn't cleanly parse — callers keep
/// their generic default.
fn product_token_label(ua: &str) -> Option<String> {
    let first = ua.split_whitespace().next()?;
    let (name, _version) = first.split_once('/')?;
    let ok = !name.is_empty()
        && name.len() <= 64
        && name != "Mozilla"
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '+'));
    ok.then(|| name.to_string())
}

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

/// POST /wsapi/move_holder — move a device/service to another namespace,
/// FORCEFULLY: see `move_holder_core` for the full semantics (up-front
/// revocation, permanent redirect, label carry-over).
pub async fn move_holder<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<MoveHolderRequest>,
) -> Result<Json<MoveHolderResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;
    let new_holder = core::move_holder_core(
        &reg_store(&state),
        &reg_host(&state),
        &state.domain,
        session.user_id.0,
        &req.holder_id,
        &req.namespace,
    )
    .map_err(core_err)?;
    Ok(Json(MoveHolderResponse { success: true, new_holder }))
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

/// GET /wsapi/holder_assignment?holder=… — is this holder still current, or
/// has the account moved it? The dialog checks at sign-in and re-issues the
/// device's certs under the target when moved.
pub async fn holder_assignment<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    axum::extract::Query(q): axum::extract::Query<HolderAssignmentQuery>,
) -> Result<Json<HolderAssignmentResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    match state.user_store.resolve_holder_move(session.user_id, &q.holder)? {
        Some(new_holder) => Ok(Json(HolderAssignmentResponse {
            success: true,
            status: "moved".into(),
            new_holder: Some(new_holder),
        })),
        None => Ok(Json(HolderAssignmentResponse {
            success: true,
            status: "current".into(),
            new_holder: None,
        })),
    }
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

/// Backstop for a cold primary login whose IdP-assigned holder prefix could NOT
/// be adopted as this account's `browsers` namespace (another browser already
/// owns it): record a pending move `orphan → a fresh browsers holder`.
///
/// Without this the holder belongs to no namespace, and the account view — which
/// can only categorize by namespace — files the browser under agents. The client
/// re-issues under the target on its next sign-in (`/wsapi/holder_assignment`),
/// but the move alone is enough to categorize it correctly right away, because
/// the holders view buckets a moving holder under its TARGET. That matters: the
/// client repair lanes all depend on a window surviving an OAuth redirect, and
/// this one doesn't.
///
/// Deliberately NOT a revoking move (unlike `move_holder`): the user is midway
/// through a sign-in with these very certs, and the orphan namespace has no
/// warrants for the move to invalidate.
///
/// Returns the target holder when a move was recorded. Best-effort: every
/// failure is logged and swallowed — a login must never fail over bookkeeping.
pub fn register_orphan_browser_move<U: UserStore>(
    store: &U,
    user_id: crate::store::UserId,
    holder: &str,
) -> Option<String> {
    let (prefix, _) = holder.split_once('.')?;
    // Only a TRUE orphan is repaired. A holder under any namespace the user owns
    // (`agents`, `services`, a custom one) is categorized as its owner intended —
    // adoption "failing" for it is the normal case, not a defect.
    match store.list_namespaces(user_id) {
        Ok(namespaces) => {
            if namespaces.iter().any(|n| n.prefix == prefix) {
                return None;
            }
        }
        Err(e) => {
            tracing::warn!("orphan-holder repair skipped (namespaces: {e})");
            return None;
        }
    }
    // A foreign service holds its own cert (recorded with an empty pubkey) and
    // its holder is bound to a warrant, so there would be nothing to re-issue —
    // `move_holder` refuses these outright and so must an automatic move.
    match store.list_device_certs(user_id) {
        Ok(certs) => {
            if certs.iter().any(|c| c.holder == holder && c.pubkey.is_empty()) {
                return None;
            }
        }
        Err(e) => {
            tracing::warn!("orphan-holder repair skipped (device certs: {e})");
            return None;
        }
    }
    // Already scheduled by an earlier login that the device hasn't completed yet.
    match store.resolve_holder_move(user_id, holder) {
        Ok(Some(_)) => return None,
        Ok(None) => {}
        Err(e) => {
            tracing::warn!("orphan-holder repair skipped (move lookup: {e})");
            return None;
        }
    }
    let target = match store.get_or_create_namespace(user_id, "browsers") {
        Ok(prefix) => crate::crypto::assign_holder_id(&prefix),
        Err(e) => {
            tracing::warn!("orphan-holder repair skipped (browsers namespace: {e})");
            return None;
        }
    };
    if let Err(e) = store.set_holder_move(user_id, holder, &target) {
        tracing::warn!("orphan-holder repair failed: {e}");
        return None;
    }
    tracing::info!("cold-login holder '{holder}' orphaned; scheduled move to '{target}'");
    Some(target)
}

/// Completion hook, called from issuance paths when certs land under `holder`:
/// if it is the target of a pending move, the old holder's rows are deleted
/// (they were revoked at move time) so the device appears exactly once.
pub fn finish_holder_move<U: UserStore>(store: &U, user_id: crate::store::UserId, holder: &str) {
    let moved_from: Vec<String> = match store.list_holder_moves(user_id) {
        Ok(moves) => moves
            .into_iter()
            .filter(|(_, new)| new == holder)
            .map(|(old, _)| old)
            .collect(),
        Err(_) => return,
    };
    for old in moved_from {
        cleanup_holder_warrants(store, user_id, &old);
        if let Err(e) = store.forget_holder(user_id, &old) {
            tracing::warn!("holder move cleanup for '{old}' failed: {e}");
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

#[cfg(test)]
mod tests {
    use super::{register_orphan_browser_move, ua_label};
    use crate::store::{InMemoryUserStore, UserStore};

    #[test]
    fn ua_label_common_browsers() {
        let chrome_mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36";
        assert_eq!(ua_label(chrome_mac).as_deref(), Some("Chrome on macOS"));
        let ff_linux = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0";
        assert_eq!(ua_label(ff_linux).as_deref(), Some("Firefox on Linux"));
        let safari_ios = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
        assert_eq!(ua_label(safari_ios).as_deref(), Some("Safari on iOS"));
        // Edge carries Chrome/ too — Edge must win.
        let edge_win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0";
        assert_eq!(ua_label(edge_win).as_deref(), Some("Edge on Windows"));
        // Android carries Linux — Android must win.
        let chrome_android = "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Mobile Safari/537.36";
        assert_eq!(ua_label(chrome_android).as_deref(), Some("Chrome on Android"));
    }

    // Non-browser clients: the product-token convention (bean lbla) — a
    // native wallet's `Name/Version` UA yields `Name`, so its device row
    // gets a friendly default instead of a bare holder id.
    #[test]
    fn ua_label_product_tokens() {
        assert_eq!(ua_label("BrowserID-Wallet/0.1").as_deref(), Some("BrowserID-Wallet"));
        assert_eq!(ua_label("BrowserID-Wallet/0.1 (macOS)").as_deref(), Some("BrowserID-Wallet"));
        assert_eq!(ua_label("curl/8.7.1").as_deref(), Some("curl"));
        // A browser UA never falls through to the product token.
        assert_eq!(
            ua_label("Mozilla/5.0 (Windows NT 10.0) Chrome/150.0 Safari/537.36").as_deref(),
            Some("Chrome on Windows")
        );
        // Unparseable or spoof-y strings stay unlabeled.
        assert_eq!(ua_label("Mozilla/4.0"), None);
        assert_eq!(ua_label("no-slash-here"), None);
        assert_eq!(ua_label("we ird/1.0"), None);
        assert_eq!(ua_label(&format!("{}/1.0", "x".repeat(65))), None);
    }

    // The cold-login repair backstop (browserid-ng-i8a2). A browser whose
    // IdP-self-assigned prefix can't be adopted must not sit in no namespace at
    // all — that is what made browsers show up as agents.
    #[test]
    fn an_orphaned_cold_holder_is_scheduled_into_browsers() {
        let store = InMemoryUserStore::new();
        let user = store.create_user_no_password().unwrap();
        let browsers = store.get_or_create_namespace(user, "browsers").unwrap();

        let target = register_orphan_browser_move(&store, user, "brorphan.abc123")
            .expect("an orphan holder is scheduled");
        assert!(
            target.starts_with(&format!("{browsers}.")),
            "target {target} must live in the browsers namespace ({browsers})"
        );
        assert_eq!(
            store.resolve_holder_move(user, "brorphan.abc123").unwrap().as_deref(),
            Some(target.as_str()),
            "the move must be recorded so the device re-issues under it"
        );
    }

    #[test]
    fn a_holder_in_a_namespace_the_user_owns_is_left_alone() {
        let store = InMemoryUserStore::new();
        let user = store.create_user_no_password().unwrap();
        // Adoption also "fails" for agents/services — that is correct
        // categorization, not an orphan, and must never be rewritten.
        for ns in ["agents", "services", "browsers"] {
            let prefix = store.get_or_create_namespace(user, ns).unwrap();
            let holder = format!("{prefix}.abc123");
            assert_eq!(
                register_orphan_browser_move(&store, user, &holder),
                None,
                "{ns} holder must not be moved"
            );
            assert_eq!(store.resolve_holder_move(user, &holder).unwrap(), None);
        }
    }

    #[test]
    fn scheduling_is_idempotent_across_repeat_logins() {
        let store = InMemoryUserStore::new();
        let user = store.create_user_no_password().unwrap();
        store.get_or_create_namespace(user, "browsers").unwrap();

        let first = register_orphan_browser_move(&store, user, "brorphan.abc123").unwrap();
        // A second login before the device completes the move must not mint a
        // second target (which would strand the first).
        assert_eq!(register_orphan_browser_move(&store, user, "brorphan.abc123"), None);
        assert_eq!(
            store.resolve_holder_move(user, "brorphan.abc123").unwrap().as_deref(),
            Some(first.as_str())
        );
    }

    #[test]
    fn an_external_services_holder_is_never_auto_moved() {
        use crate::store::DeviceCertRecord;
        let store = InMemoryUserStore::new();
        let user = store.create_user_no_password().unwrap();
        store.get_or_create_namespace(user, "browsers").unwrap();
        // A foreign service is recorded with an EMPTY pubkey: it holds its own
        // cert at its own issuer, and its holder is bound to the warrant, so a
        // move would break the grant with nothing to re-issue.
        store
            .insert_device_cert(DeviceCertRecord {
                id: 0,
                user_id: user,
                identities: vec!["svc@partner.example".into()],
                purpose: "authorization".into(),
                holder: "extsvc.abc123".into(),
                pubkey: String::new(),
                iss: "partner.example".into(),
                issued_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now(),
                revoked_at: None,
                status_uri: None,
                status_idx: None,
                prov: "smtp".into(),
            })
            .unwrap();

        assert_eq!(register_orphan_browser_move(&store, user, "extsvc.abc123"), None);
        assert_eq!(store.resolve_holder_move(user, "extsvc.abc123").unwrap(), None);
    }

    #[test]
    fn a_holder_with_no_namespace_prefix_is_ignored() {
        let store = InMemoryUserStore::new();
        let user = store.create_user_no_password().unwrap();
        assert_eq!(register_orphan_browser_move(&store, user, "nodotshere"), None);
    }
}
