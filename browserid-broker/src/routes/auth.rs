//! Authentication endpoints

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::crypto::{hash_password, verify_password};
use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};

/// Minimum password length (same as original Persona)
const MIN_PASSWORD_LENGTH: usize = 8;
/// Maximum password length (same as original Persona)
const MAX_PASSWORD_LENGTH: usize = 80;

#[derive(Deserialize)]
pub struct AuthenticateRequest {
    pub email: String,
    pub pass: String,
}

#[derive(Serialize)]
pub struct AuthenticateResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/authenticate_user
/// Conservative brute-force throttle for password login (bean ytjn): at most
/// this many FAILED attempts per client IP per window, then 429 until the
/// window rolls over. Keyed by IP (not account) so no one can lock out a
/// victim; auto-resets, so there is no permanent lockout.
const LOGIN_MAX_FAILURES: u32 = 10;
const LOGIN_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);

/// Best-effort client IP behind nginx/dokku (X-Forwarded-For's first hop, then
/// X-Real-IP). Falls back to a shared bucket when absent — still bounds a
/// header-less attacker, just coarsely.
fn client_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// A real bcrypt hash of an unguessable random value, computed once per
/// process. Failure paths verify against it so a caller cannot tell from
/// timing whether the account existed or had a password at all.
fn dummy_password_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| {
        hash_password(&uuid::Uuid::new_v4().to_string()).expect("bcrypt never fails on a uuid")
    })
}

pub async fn authenticate_user<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    headers: axum::http::HeaderMap,
    Json(req): Json<AuthenticateRequest>,
) -> Result<Json<AuthenticateResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let ip = client_ip(&headers);

    // Throttle check (before any password work), fail-closed to 429.
    {
        let mut attempts = state.login_attempts.write().unwrap();
        let now = std::time::Instant::now();
        attempts.retain(|_, (start, _)| now.duration_since(*start) < LOGIN_WINDOW);
        if let Some((start, count)) = attempts.get(&ip) {
            if now.duration_since(*start) < LOGIN_WINDOW && *count >= LOGIN_MAX_FAILURES {
                return Err(BrokerError::LoginRateLimited);
            }
        }
    }

    // Record a failed attempt against `ip` (a fresh window if none/expired).
    let record_failure = || {
        let mut attempts = state.login_attempts.write().unwrap();
        let now = std::time::Instant::now();
        let entry = attempts.entry(ip.clone()).or_insert((now, 0));
        if now.duration_since(entry.0) >= LOGIN_WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
    };

    // Find user by email. A missing account, a password-less account (empty
    // or unparsable hash), and a wrong password must all be indistinguishable
    // in body, status, AND timing (audit M7) — so every failure path still
    // pays for one bcrypt verification. The dummy compare uses a real hash of
    // an unguessable value, so it can never accidentally succeed.
    let user = state.user_store.get_user_by_email(&req.email)?;

    let valid = match &user {
        Some(u) => match verify_password(&req.pass, &u.password_hash) {
            Ok(v) => v,
            // Empty/unparsable stored hash (a password-less account, e.g.
            // bridge-established): burn the same bcrypt cost, then fail.
            Err(_) => {
                let _ = verify_password(&req.pass, dummy_password_hash());
                false
            }
        },
        None => {
            let _ = verify_password(&req.pass, dummy_password_hash());
            false
        }
    };

    if !valid {
        record_failure();
        return Err(BrokerError::InvalidCredentials);
    }
    // valid ⇒ user exists.
    let user = user.unwrap();

    // Success clears this IP's failure counter.
    state.login_attempts.write().unwrap().remove(&ip);

    // Create session — Full: the account password was just verified.
    let session = state
        .session_store
        .create(user.id, crate::store::SessionLevel::Full)?;
    super::session::set_session_cookie(
        &cookies,
        &session.id.0,
        super::session::cookie_secure(&state.domain),
    );

    Ok(Json(AuthenticateResponse {
        success: true,
        userid: Some(user.id.0),
        reason: None,
    }))
}

#[derive(Serialize)]
pub struct LogoutResponse {
    pub success: bool,
}

#[derive(Deserialize, Default)]
pub struct LogoutRequest {
    #[serde(default)]
    pub csrf: String,
}

/// POST /wsapi/logout
pub async fn logout<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    req: Option<Json<LogoutRequest>>,
) -> Result<Json<LogoutResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Get and delete session (CSRF-gated: forced logout is a nuisance vector)
    if let Some(session) = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref()) {
        super::session::require_csrf(&session, &req.unwrap_or_default().csrf)?;
        let _ = state.session_store.delete(&session.id);
    }

    super::session::clear_session_cookie(&cookies);

    Ok(Json(LogoutResponse { success: true }))
}

#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
    pub oldpass: String,
    pub newpass: String,
    #[serde(default)]
    pub csrf: String,
}

#[derive(Serialize)]
pub struct UpdatePasswordResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/update_password
/// Update the user's password (requires authentication)
pub async fn update_password<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<UpdatePasswordRequest>,
) -> Result<Json<UpdatePasswordResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Require authentication
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;

    // Validate new password length
    if req.newpass.len() < MIN_PASSWORD_LENGTH {
        return Err(BrokerError::PasswordTooShort);
    }
    if req.newpass.len() > MAX_PASSWORD_LENGTH {
        return Err(BrokerError::PasswordTooLong);
    }

    // Get user
    let user = state
        .user_store
        .get_user(session.user_id)?
        .ok_or(BrokerError::UserNotFound)?;

    // Verify old password
    let valid = verify_password(&req.oldpass, &user.password_hash)
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

    if !valid {
        return Err(BrokerError::InvalidCredentials);
    }

    // Hash new password
    let new_hash = hash_password(&req.newpass)
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

    // Update password
    state.user_store.update_password(session.user_id, &new_hash)?;

    // Evict every existing session for this user (audit H2), then mint a fresh
    // one for the caller so the password change also logs out any other live
    // session (e.g. a co-resident attacker) without logging *this* user out.
    state.session_store.delete_by_user(session.user_id)?;
    let fresh = state
        .session_store
        .create(session.user_id, crate::store::SessionLevel::Full)?;
    super::session::set_session_cookie(
        &cookies,
        &fresh.id.0,
        super::session::cookie_secure(&state.domain),
    );

    Ok(Json(UpdatePasswordResponse {
        success: true,
        reason: None,
    }))
}

#[derive(Deserialize)]
pub struct SetPasswordRequest {
    pub pass: String,
    #[serde(default)]
    pub csrf: String,
}

#[derive(Serialize)]
pub struct SetPasswordResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/set_password
/// First password for a signed-in passwordless account (browserid-ng-iudv).
/// The session already proves control of the account (it was established by a
/// primary presentation, bridge claim, or SMTP verification), so no mailed
/// code is needed — unlike the reset flow, which is the cold/no-session path.
/// Refused once a password exists: changing it requires the old password
/// (update_password) or the reset ceremony.
pub async fn set_password<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<SetPasswordRequest>,
) -> Result<Json<SetPasswordResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;

    if req.pass.len() < MIN_PASSWORD_LENGTH {
        return Err(BrokerError::PasswordTooShort);
    }
    if req.pass.len() > MAX_PASSWORD_LENGTH {
        return Err(BrokerError::PasswordTooLong);
    }

    if state.user_store.has_password(session.user_id)? {
        return Err(BrokerError::ValidationError(
            "account already has a password".to_string(),
        ));
    }

    let hash = hash_password(&req.pass).map_err(|e| BrokerError::Internal(e.to_string()))?;
    state.user_store.set_password(session.user_id, &hash)?;

    // The caller just chose — and therefore knows — the account password, so
    // re-mint this session as Full (ca29). Without this, the set-on-add flow
    // would demand the same password again at the very next E3 mint. Only the
    // current session upgrades; other live sessions keep their own level
    // (this is not a recovery event, so no delete_by_user).
    state.session_store.delete(&session.id)?;
    let fresh = state
        .session_store
        .create(session.user_id, crate::store::SessionLevel::Full)?;
    super::session::set_session_cookie(
        &cookies,
        &fresh.id.0,
        super::session::cookie_secure(&state.domain),
    );

    Ok(Json(SetPasswordResponse {
        success: true,
        reason: None,
    }))
}
