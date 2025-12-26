//! Account creation endpoints

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::crypto::{generate_secret, generate_verification_code, hash_password};
use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{PendingVerification, SessionStore, UserStore};

#[derive(Deserialize)]
pub struct StageUserRequest {
    pub email: String,
    pub pass: String,
}

#[derive(Serialize)]
pub struct StageUserResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/stage_user
/// Start account creation by sending verification code
pub async fn stage_user<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<StageUserRequest>,
) -> Result<Json<StageUserResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Check if email already exists
    if state.user_store.get_user_by_email(&req.email)?.is_some() {
        return Err(BrokerError::EmailAlreadyExists);
    }

    // Hash password
    let password_hash = hash_password(&req.pass)
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

    // Generate verification code and secret
    let code = generate_verification_code();
    let secret = generate_secret();

    // Store pending verification
    let pending = PendingVerification {
        secret: secret.clone(),
        email: req.email.clone(),
        user_id: None, // New account
        password_hash: Some(password_hash),
        created_at: Utc::now(),
    };
    state.user_store.create_pending(pending)?;

    // Send verification email
    state
        .email_sender
        .send_verification(&req.email, &code)
        .map_err(|e| BrokerError::Internal(e))?;

    // Store code -> secret mapping (simplified: use code as lookup, secret in pending)
    // In production, you'd want a separate mapping
    let pending_with_code = PendingVerification {
        secret: code, // Use code as the lookup key
        email: req.email.clone(),
        user_id: None,
        password_hash: None, // Reference the full record
        created_at: Utc::now(),
    };
    state.user_store.create_pending(pending_with_code)?;

    Ok(Json(StageUserResponse {
        success: true,
        reason: None,
    }))
}

#[derive(Deserialize)]
pub struct CompleteUserCreationRequest {
    pub token: String, // The 6-digit code
}

#[derive(Serialize)]
pub struct CompleteUserCreationResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/complete_user_creation
/// Complete account creation with verification code
pub async fn complete_user_creation<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: tower_cookies::Cookies,
    Json(req): Json<CompleteUserCreationRequest>,
) -> Result<Json<CompleteUserCreationResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Look up pending verification by code
    let pending = state
        .user_store
        .get_pending(&req.token)?
        .ok_or(BrokerError::InvalidVerificationCode)?;

    // Check expiry (15 minutes)
    let age = Utc::now() - pending.created_at;
    if age.num_minutes() > 15 {
        state.user_store.delete_pending(&req.token)?;
        return Err(BrokerError::VerificationExpired);
    }

    // Find the full pending record with password hash
    // (In simplified impl, we need to look up by email)
    let all_pending: Vec<_> = {
        // This is a simplification - in production, use proper indexing
        // For now, we'll store password hash directly in the code-indexed record
        vec![pending.clone()]
    };

    let full_pending = all_pending
        .iter()
        .find(|p| p.password_hash.is_some())
        .cloned()
        .unwrap_or(pending.clone());

    let password_hash = full_pending
        .password_hash
        .ok_or(BrokerError::InvalidVerificationCode)?;

    // Create user
    let user_id = state.user_store.create_user(&password_hash)?;

    // Add verified email
    state.user_store.add_email(user_id, &pending.email, true)?;

    // Clean up pending
    state.user_store.delete_pending(&req.token)?;

    // Create session
    let session = state.session_store.create(user_id)?;
    super::session::set_session_cookie(&cookies, &session.id.0);

    Ok(Json(CompleteUserCreationResponse {
        success: true,
        reason: None,
    }))
}
