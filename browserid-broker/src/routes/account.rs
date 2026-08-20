//! Account management endpoints (cancel + admin seed provisioning).
//!
//! The persona-era signup lane (stage_user / complete_user_creation /
//! user_creation_status) was retired in M7 Phase 2 (browserid-ng-8gqm): its
//! exists-vs-new branching was an unauthenticated enumeration oracle, and the
//! unified sign-in code flow (routes/signin_code.rs) subsumes it.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::crypto::hash_password;
use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore, VerificationType};

/// Constant-time byte-string equality for the admin token (audit L8), so a
/// short-circuiting `==` can't leak the token prefix via response timing. The
/// length comparison is not itself constant-time, which is acceptable for a
/// high-entropy secret.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Minimum password length (same as original Persona)
const MIN_PASSWORD_LENGTH: usize = 8;
/// Maximum password length (same as original Persona)
const MAX_PASSWORD_LENGTH: usize = 80;

#[derive(Deserialize)]
pub struct AccountCancelRequest {
    pub email: String,
    pub pass: String,
    #[serde(default)]
    pub csrf: String,
}

#[derive(Serialize)]
pub struct AccountCancelResponse {
    pub success: bool,
}

/// POST /wsapi/account_cancel
/// Cancel (delete) user account
pub async fn account_cancel<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: tower_cookies::Cookies,
    Json(req): Json<AccountCancelRequest>,
) -> Result<Json<AccountCancelResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    use crate::crypto::verify_password;

    // Require authentication
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;

    // Verify the provided email belongs to this user
    let emails = state.user_store.list_emails(session.user_id)?;
    let email_matches = emails.iter().any(|e| e.email == req.email);
    if !email_matches {
        return Err(BrokerError::InvalidCredentials);
    }

    // Verify password
    let user = state
        .user_store
        .get_user(session.user_id)?
        .ok_or(BrokerError::UserNotFound)?;

    if !verify_password(&req.pass, &user.password_hash)
        .map_err(|e| BrokerError::Internal(e.to_string()))?
    {
        return Err(BrokerError::InvalidCredentials);
    }

    // Delete session first
    state.session_store.delete(&session.id)?;

    // Delete user and all associated data
    state.user_store.delete_user(session.user_id)?;

    // Forget the send-throttle for these addresses so the user can immediately
    // re-register (a cancel is an authenticated action, so no abuse vector).
    for e in &emails {
        state.clear_email_throttle(&e.email).await;
    }

    // Clear session cookie
    super::session::clear_session_cookie(&cookies);

    Ok(Json(AccountCancelResponse { success: true }))
}

// ===========================================================================
// Admin seed provisioning (SBO Mingo demo)
//
// Create a pre-verified account directly, bypassing email verification — for
// provisioning @mingo.place seed/admin accounts on a domain with no MX (demo
// decision #5). Gated by the ADMIN_TOKEN env var (X-Admin-Token header). Not a
// general signup path; only enabled when ADMIN_TOKEN is set.
// ===========================================================================

#[derive(Deserialize)]
pub struct AdminCreateRequest {
    pub email: String,
    pub pass: String,
}

#[derive(Serialize)]
pub struct AdminCreateResponse {
    pub success: bool,
    pub email: String,
}

/// POST /admin/create_account  (header: X-Admin-Token: <ADMIN_TOKEN>)
pub async fn admin_create_account<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: HeaderMap,
    Json(req): Json<AdminCreateRequest>,
) -> Result<Json<AdminCreateResponse>, (StatusCode, String)>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let expected = std::env::var("ADMIN_TOKEN").ok().filter(|t| !t.is_empty());
    let provided = headers.get("x-admin-token").and_then(|v| v.to_str().ok());
    match (expected, provided) {
        (Some(exp), Some(got)) if ct_eq(&exp, got) => {}
        _ => return Err((StatusCode::FORBIDDEN, "admin token required".into())),
    }

    if req.pass.len() < MIN_PASSWORD_LENGTH || req.pass.len() > MAX_PASSWORD_LENGTH {
        return Err((StatusCode::BAD_REQUEST, "invalid password length".into()));
    }
    let ise = |e: String| (StatusCode::INTERNAL_SERVER_ERROR, e);
    if state
        .user_store
        .get_user_by_email(&req.email)
        .map_err(|e| ise(e.to_string()))?
        .is_some()
    {
        return Err((StatusCode::CONFLICT, "email already exists".into()));
    }
    let hash = hash_password(&req.pass).map_err(|e| ise(e.to_string()))?;
    let user_id = state
        .user_store
        .create_user(&hash)
        .map_err(|e| ise(e.to_string()))?;
    state
        .user_store
        .add_email(user_id, &req.email, true)
        .map_err(|e| ise(e.to_string()))?;

    Ok(Json(AdminCreateResponse { success: true, email: req.email }))
}

#[derive(Deserialize)]
pub struct AdminPendingCodeQuery {
    pub email: String,
    /// "signin_code" (default), "add_email", or legacy "new_account" /
    /// "password_reset" for pendings staged before the M7 consolidation.
    #[serde(rename = "type")]
    pub verification_type: Option<String>,
}

/// GET /admin/pending_code?email=&type=  (header: X-Admin-Token)
///
/// Operator-only escape hatch: return the current pending verification/reset
/// code for an address. Gated by ADMIN_TOKEN — the operator already has full DB
/// access, so this is not a privilege escalation; it exists so the operator can
/// exercise the sign-up/reset flow when email delivery is flaky, WITHOUT
/// reopening the public `/wsapi/test/*` route (which was an account-takeover
/// hole). Never enable ADMIN_TOKEN-less, and keep the token secret.
pub async fn admin_pending_code<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: HeaderMap,
    Query(q): Query<AdminPendingCodeQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let expected = std::env::var("ADMIN_TOKEN").ok().filter(|t| !t.is_empty());
    let provided = headers.get("x-admin-token").and_then(|v| v.to_str().ok());
    match (expected, provided) {
        (Some(exp), Some(got)) if ct_eq(&exp, got) => {}
        _ => return Err((StatusCode::FORBIDDEN, "admin token required".into())),
    }
    let vt = match q.verification_type.as_deref() {
        Some("add_email") => VerificationType::AddEmail,
        Some("password_reset") | Some("reset") => VerificationType::PasswordReset,
        Some("new_account") => VerificationType::NewAccount,
        _ => VerificationType::SigninCode,
    };
    match state.user_store.get_pending_by_email(&q.email, vt) {
        Ok(Some(p)) => Ok(Json(serde_json::json!({ "success": true, "code": p.secret, "email": p.email }))),
        _ => Ok(Json(serde_json::json!({ "success": false, "reason": "no pending code for that address/type" }))),
    }
}
