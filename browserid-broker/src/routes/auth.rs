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
pub async fn authenticate_user<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<AuthenticateRequest>,
) -> Result<Json<AuthenticateResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Find user by email
    let user = state
        .user_store
        .get_user_by_email(&req.email)?
        .ok_or(BrokerError::InvalidCredentials)?;

    // Verify password
    let valid = verify_password(&req.pass, &user.password_hash)
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

    if !valid {
        return Err(BrokerError::InvalidCredentials);
    }

    // Create session
    let session = state.session_store.create(user.id)?;
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
    let fresh = state.session_store.create(session.user_id)?;
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
