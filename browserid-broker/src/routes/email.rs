//! Email management endpoints

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::crypto::generate_verification_code;
use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{PendingVerification, SessionStore, UserStore};

#[derive(Serialize)]
pub struct ListEmailsResponse {
    pub success: bool,
    pub emails: Vec<EmailInfo>,
}

#[derive(Serialize)]
pub struct EmailInfo {
    pub email: String,
    pub verified: bool,
}

/// GET /wsapi/list_emails
pub async fn list_emails<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Result<Json<ListEmailsResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;

    let emails = state.user_store.list_emails(session.user_id)?;

    Ok(Json(ListEmailsResponse {
        success: true,
        emails: emails
            .into_iter()
            .map(|e| EmailInfo {
                email: e.email,
                verified: e.verified,
            })
            .collect(),
    }))
}

#[derive(Deserialize)]
pub struct StageEmailRequest {
    pub email: String,
}

#[derive(Serialize)]
pub struct StageEmailResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/stage_email
pub async fn stage_email<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<StageEmailRequest>,
) -> Result<Json<StageEmailResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;

    // Check if email already exists
    if state.user_store.get_user_by_email(&req.email)?.is_some() {
        return Err(BrokerError::EmailAlreadyExists);
    }

    // Generate verification code
    let code = generate_verification_code();

    // Store pending verification
    let pending = PendingVerification {
        secret: code.clone(),
        email: req.email.clone(),
        user_id: Some(session.user_id),
        password_hash: None,
        created_at: Utc::now(),
    };
    state.user_store.create_pending(pending)?;

    // Send verification email
    state
        .email_sender
        .send_verification(&req.email, &code)
        .map_err(|e| BrokerError::Internal(e))?;

    Ok(Json(StageEmailResponse {
        success: true,
        reason: None,
    }))
}

#[derive(Deserialize)]
pub struct CompleteEmailRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct CompleteEmailResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/complete_email_addition
pub async fn complete_email_addition<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<CompleteEmailRequest>,
) -> Result<Json<CompleteEmailResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;

    // Look up pending verification
    let pending = state
        .user_store
        .get_pending(&req.token)?
        .ok_or(BrokerError::InvalidVerificationCode)?;

    // Verify this is for the current user
    if pending.user_id != Some(session.user_id) {
        return Err(BrokerError::InvalidVerificationCode);
    }

    // Check expiry
    let age = Utc::now() - pending.created_at;
    if age.num_minutes() > 15 {
        state.user_store.delete_pending(&req.token)?;
        return Err(BrokerError::VerificationExpired);
    }

    // Add email to user
    state
        .user_store
        .add_email(session.user_id, &pending.email, true)?;

    // Clean up
    state.user_store.delete_pending(&req.token)?;

    Ok(Json(CompleteEmailResponse {
        success: true,
        reason: None,
    }))
}

#[derive(Deserialize)]
pub struct RemoveEmailRequest {
    pub email: String,
}

#[derive(Serialize)]
pub struct RemoveEmailResponse {
    pub success: bool,
}

/// POST /wsapi/remove_email
pub async fn remove_email<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<RemoveEmailRequest>,
) -> Result<Json<RemoveEmailResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;

    // Ensure user has at least one other email
    let emails = state.user_store.list_emails(session.user_id)?;
    if emails.len() <= 1 {
        return Err(BrokerError::Internal(
            "Cannot remove last email".to_string(),
        ));
    }

    state.user_store.remove_email(session.user_id, &req.email)?;

    Ok(Json(RemoveEmailResponse { success: true }))
}
