//! Authentication endpoints

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::crypto::verify_password;
use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};

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
    super::session::set_session_cookie(&cookies, &session.id.0);

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

/// POST /wsapi/logout
pub async fn logout<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Json<LogoutResponse>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Get and delete session
    if let Some(session) = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref()) {
        let _ = state.session_store.delete(&session.id);
    }

    super::session::clear_session_cookie(&cookies);

    Json(LogoutResponse { success: true })
}
