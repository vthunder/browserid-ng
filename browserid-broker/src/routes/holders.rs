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
//! Out of scope (need client-side cert re-provisioning — a later pass):
//! adopt-after-wipe and re-categorize.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use browserid_core::device::{Holder, HolderMatcher};
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};

// ---------------------------------------------------------------------------
// GET /wsapi/holders
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct HolderView {
    /// The opaque `<prefix>.<rand>` holder id.
    pub holder_id: String,
    pub label: String,
    /// "trusted" (holds a config/authorization cert → can authorize new sites)
    /// or "login-only" (authentication cert only → reuses existing warrants).
    pub trust: String,
    pub cert_count: usize,
    /// Latest issuance among this holder's certs (RFC 3339), if any.
    pub issued_at: Option<String>,
    /// Warrants whose matcher covers this holder.
    pub warrant_count: usize,
    /// True once any of this holder's certs is revoked.
    pub revoked: bool,
    /// A foreign service (holds its own cert): its holder is bound to a warrant,
    /// so it can't be re-categorized without revoking — the UI hides "move".
    pub external: bool,
    /// The identities (emails) this holder's certs act for, deduped.
    pub identities: Vec<String>,
    /// Set while an account-driven namespace move is pending: the label of
    /// the target namespace. The device's certs were revoked at move time; it
    /// re-registers under the target next time it's online.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moving_to: Option<String>,
}

#[derive(Serialize)]
pub struct NamespaceView {
    pub name: String,
    pub prefix: String,
    pub label: String,
    pub holders: Vec<HolderView>,
}

#[derive(Serialize)]
pub struct HoldersResponse {
    pub success: bool,
    pub namespaces: Vec<NamespaceView>,
    /// Defensive: any holder whose prefix matches no namespace row.
    pub holders_without_namespace: Vec<HolderView>,
}

/// Accumulates the certs sharing one holder id as we scan the device-cert list.
#[derive(Default)]
struct HolderAcc {
    cert_count: usize,
    has_config: bool,
    latest_issued: Option<chrono::DateTime<chrono::Utc>>,
    all_revoked: bool,
    any_cert: bool,
    identities: std::collections::BTreeSet<String>,
    /// A FOREIGN service: recorded with an empty pubkey (it holds its own cert at
    /// its own issuer). Its holder id is bound to a warrant, so it can't be moved
    /// without revoking — the UI hides "move" for it.
    external: bool,
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

    let certs = state.user_store.list_device_certs(session.user_id)?;
    let namespaces = state.user_store.list_namespaces(session.user_id)?;
    let labels = state.user_store.get_holder_labels(session.user_id)?;
    let warrants = state.user_store.list_warrants(session.user_id)?;

    // Fold the flat cert list into per-holder accumulators (stable order).
    let mut by_holder: BTreeMap<String, HolderAcc> = BTreeMap::new();
    for c in &certs {
        let acc = by_holder.entry(c.holder.clone()).or_default();
        acc.cert_count += 1;
        acc.identities.extend(c.identities.iter().cloned());
        if c.pubkey.is_empty() {
            acc.external = true;
        }
        if c.purpose == "authorization" {
            acc.has_config = true;
        }
        let revoked = c.revoked_at.is_some();
        if !acc.any_cert {
            acc.all_revoked = revoked;
            acc.any_cert = true;
        } else {
            acc.all_revoked = acc.all_revoked && revoked;
        }
        acc.latest_issued = Some(match acc.latest_issued {
            Some(prev) if prev >= c.issued_at => prev,
            _ => c.issued_at,
        });
    }

    // Pre-parse warrant matchers once so counting is a cheap loop per holder.
    let matchers: Vec<HolderMatcher> = warrants
        .iter()
        .filter_map(|w| w.holder.as_deref())
        .filter_map(|m| HolderMatcher::new(m).ok())
        .collect();
    let warrant_count = |holder_id: &str| -> usize {
        match Holder::new(holder_id) {
            Ok(h) => matchers.iter().filter(|m| m.matches(&h)).count(),
            Err(_) => 0,
        }
    };

    // Pending namespace moves: old holder → target-namespace label (for the
    // "moving to X" badge; rows disappear from here once the device re-issues).
    let moves = state.user_store.list_holder_moves(session.user_id)?;
    let ns_label_of_prefix = |prefix: &str| -> String {
        namespaces
            .iter()
            .find(|n| n.prefix == prefix)
            .map(|n| n.label.clone())
            .unwrap_or_else(|| prefix.to_string())
    };
    let moving_to = |holder_id: &str| -> Option<String> {
        moves
            .iter()
            .find(|(old, _)| old == holder_id)
            .map(|(_, new)| ns_label_of_prefix(holder_prefix(new)))
    };

    let make_view = |holder_id: &str, acc: &HolderAcc| HolderView {
        holder_id: holder_id.to_string(),
        label: labels
            .get(holder_id)
            .cloned()
            .unwrap_or_else(|| default_holder_label(holder_id)),
        trust: if acc.has_config { "trusted" } else { "login-only" }.to_string(),
        cert_count: acc.cert_count,
        issued_at: acc.latest_issued.map(|d| d.to_rfc3339()),
        warrant_count: warrant_count(holder_id),
        revoked: acc.any_cert && acc.all_revoked,
        external: acc.external,
        identities: acc.identities.iter().cloned().collect(),
        moving_to: moving_to(holder_id),
    };

    // Bucket each holder under the namespace whose prefix it carries — except
    // a pending-moved holder, which is shown under its TARGET namespace
    // immediately (the user already decided where it lives; the device just
    // hasn't re-registered yet — the badge says so).
    let effective_prefix = |holder_id: &str| -> String {
        let target = moves
            .iter()
            .find(|(old, _)| old == holder_id)
            .map(|(_, new)| new.as_str())
            .unwrap_or(holder_id);
        holder_prefix(target).to_string()
    };
    let mut ns_views: Vec<NamespaceView> = Vec::new();
    let mut placed: std::collections::HashSet<String> = std::collections::HashSet::new();
    for ns in &namespaces {
        let mut holders = Vec::new();
        for (holder_id, acc) in &by_holder {
            if effective_prefix(holder_id) == ns.prefix {
                holders.push(make_view(holder_id, acc));
                placed.insert(holder_id.clone());
            }
        }
        ns_views.push(NamespaceView {
            name: ns.name.clone(),
            prefix: ns.prefix.clone(),
            label: ns.label.clone(),
            holders,
        });
    }
    let orphans = by_holder
        .iter()
        .filter(|(id, _)| !placed.contains(*id))
        .map(|(id, acc)| make_view(id, acc))
        .collect();

    Ok(Json(HoldersResponse {
        success: true,
        namespaces: ns_views,
        holders_without_namespace: orphans,
    }))
}

/// The namespace prefix of a holder id (`<prefix>.<rand>` → `<prefix>`).
fn holder_prefix(holder_id: &str) -> &str {
    holder_id.split_once('.').map(|(p, _)| p).unwrap_or(holder_id)
}

/// A friendly default when the user hasn't labeled a holder: the first four
/// characters of its random suffix, e.g. `holder-q7f2`.
fn default_holder_label(holder_id: &str) -> String {
    let suffix = holder_id.split_once('.').map(|(_, s)| s).unwrap_or(holder_id);
    let short: String = suffix.chars().take(4).collect();
    format!("holder-{short}")
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
        (None, None) => None,
    }
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
    let label = validate_label(&req.label)?;
    // Owner-scoped: the holder must appear on one of this user's device certs.
    let owned = state
        .user_store
        .list_device_certs(session.user_id)?
        .iter()
        .any(|c| c.holder == req.holder_id);
    if !owned {
        return Err(BrokerError::PolicyRefused("no such holder".into()));
    }
    state
        .user_store
        .set_holder_label(session.user_id, &req.holder_id, &label)?;
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
/// FORCEFULLY: the old holder's certs are revoked up front (their status bits
/// flip, so the old namespace's warrants stop applying to this device within a
/// status-cache window — not lazily), and a PERMANENT redirect
/// `old → broker-assigned new holder` is recorded. The device completes the
/// move next time it's online: its next sign-in re-issues the same keys under
/// the target (the dialog checks `/wsapi/holder_assignment`; a stale client
/// supplying the old holder at `/device/issue` is silently redirected).
///
/// Caveat (tracked): primary-issued certs carry no status ref today, so the
/// up-front revocation only bites certs with one (broker-issued); for
/// primary-rooted devices immediacy is bounded by the primary's own
/// revocation story until primaries issue status-backed certs.
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
    let ns = req.namespace.trim().to_lowercase();
    let ok = ns.len() <= 32
        && ns.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && ns.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !ok {
        return Err(BrokerError::PolicyRefused("bad namespace name".into()));
    }
    let certs: Vec<_> = state
        .user_store
        .list_device_certs(session.user_id)?
        .into_iter()
        .filter(|c| c.holder == req.holder_id)
        .collect();
    if certs.is_empty() {
        return Err(BrokerError::PolicyRefused("no such holder".into()));
    }
    // A foreign service holds its own cert; its holder is bound to the warrant,
    // so a move would revoke the grant with nothing to re-issue. Refuse — the
    // service must be re-authorized from the app if you want to relocate it.
    if certs.iter().any(|c| c.pubkey.is_empty()) {
        return Err(BrokerError::PolicyRefused(
            "an external service can't be moved — re-authorize it from the app instead".into(),
        ));
    }
    let prefix = state.user_store.get_or_create_namespace(session.user_id, &ns)?;
    if req.holder_id.split_once('.').map(|(p, _)| p) == Some(prefix.as_str()) {
        return Err(BrokerError::PolicyRefused("holder is already in that namespace".into()));
    }
    let new_holder = crate::crypto::assign_holder_id(&prefix);

    // Revoke up front: the old namespace's warrants must stop applying to
    // this device NOW, not when it happens to come back online.
    for cert in &certs {
        state.user_store.revoke_device_cert(session.user_id, cert.id)?;
        if let Some(idx) = cert.status_idx {
            state.user_store.set_status_revoked_idx(idx)?;
        }
    }
    state
        .user_store
        .set_holder_move(session.user_id, &req.holder_id, &new_holder)?;
    // Carry the friendly label over so the device keeps its name in the UI.
    if let Some(label) = state
        .user_store
        .get_holder_labels(session.user_id)?
        .get(&req.holder_id)
        .cloned()
    {
        state.user_store.set_holder_label(session.user_id, &new_holder, &label)?;
    }
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

/// Revoke + drop the warrants ISOLATED to `holder` (exact `<id>` matcher):
/// with the holder gone they can never be presented again, and leaving them
/// makes Sites list grants for "a removed device" forever. Group (`<ns>.*`)
/// matchers cover other holders and are left alone. Best-effort.
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
/// every one of the holder's cert status bits (outstanding access certs
/// fail-closed at verifiers — "log it out"), then delete the cert rows + label
/// so it leaves the account view. A holder id is baked into its signed certs,
/// so this is the only "remove" there is; the device can always sign in again,
/// which records a fresh entry (under the canonical namespace, post-rrve).
/// Warrants matched to the holder become unusable (no cert can present) but
/// stay listed under Sites until revoked/forgotten there.
pub async fn forget_holder<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<ForgetHolderRequest>,
) -> Result<Json<OkResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;
    let certs: Vec<_> = state
        .user_store
        .list_device_certs(session.user_id)?
        .into_iter()
        .filter(|c| c.holder == req.holder_id)
        .collect();
    if certs.is_empty() {
        return Err(BrokerError::PolicyRefused("no such holder".into()));
    }
    // Revoke BEFORE deleting: deletion alone would leave live signed certs
    // verifying at RPs that don't know the rows are gone.
    for cert in &certs {
        if let Some(idx) = cert.status_idx {
            state.user_store.set_status_revoked_idx(idx)?;
        }
    }
    cleanup_holder_warrants(state.user_store.as_ref(), session.user_id, &req.holder_id);
    state.user_store.forget_holder(session.user_id, &req.holder_id)?;
    Ok(Json(OkResponse { success: true }))
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
    let label = validate_label(&req.label)?;
    state
        .user_store
        .set_namespace_label(session.user_id, &req.name, &label)?;
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
    // A namespace `name` is a short slug; the prefix is generated, never chosen.
    let name = req.name.trim().to_lowercase();
    if name.is_empty() || name.len() > 32 || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(BrokerError::PolicyRefused(
            "namespace name must be 1–32 chars, letters/digits/hyphen".into(),
        ));
    }
    let label = match req.label.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(l) => validate_label(l)?,
        None => title_case(&name),
    };
    state
        .user_store
        .create_namespace(session.user_id, &name, &label)?;
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
    // Refused (PolicyRefused) by the store if the namespace still has holders.
    state
        .user_store
        .delete_namespace(session.user_id, &req.name)?;
    Ok(Json(OkResponse { success: true }))
}

/// A friendly label: non-empty, trimmed, length-bounded, single line.
fn validate_label(label: &str) -> Result<String, BrokerError> {
    let l = label.trim();
    if l.is_empty() || l.len() > 64 || l.contains(['\n', '\r']) {
        return Err(BrokerError::PolicyRefused(
            "label must be 1–64 characters, single line".into(),
        ));
    }
    Ok(l.to_string())
}

fn title_case(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::ua_label;

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
        assert_eq!(ua_label("curl/8.7.1"), None);
    }
}
