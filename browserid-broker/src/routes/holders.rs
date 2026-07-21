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
    /// The identities (emails) this holder's certs act for, deduped.
    pub identities: Vec<String>,
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
        identities: acc.identities.iter().cloned().collect(),
    };

    // Bucket each holder under the namespace whose prefix it carries.
    let mut ns_views: Vec<NamespaceView> = Vec::new();
    let mut placed: std::collections::HashSet<String> = std::collections::HashSet::new();
    for ns in &namespaces {
        let mut holders = Vec::new();
        for (holder_id, acc) in &by_holder {
            if holder_prefix(holder_id) == ns.prefix {
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
