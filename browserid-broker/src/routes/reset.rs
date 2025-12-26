//! Password reset endpoints

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::crypto::{generate_verification_code, hash_password};
use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{PendingVerification, SessionStore, UserStore, VerificationType};

/// Minimum password length (same as original Persona)
const MIN_PASSWORD_LENGTH: usize = 8;
/// Maximum password length (same as original Persona)
const MAX_PASSWORD_LENGTH: usize = 80;

#[derive(Deserialize)]
pub struct StageResetRequest {
    pub email: String,
}

#[derive(Serialize)]
pub struct StageResetResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/stage_reset
/// Initiate password reset by sending verification code
pub async fn stage_reset<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<StageResetRequest>,
) -> Result<Json<StageResetResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Find user by email
    let user = state
        .user_store
        .get_user_by_email(&req.email)?
        .ok_or(BrokerError::EmailNotFound)?;

    // Generate verification code
    let code = generate_verification_code();

    // Store pending password reset
    let pending = PendingVerification {
        secret: code.clone(),
        email: req.email.clone(),
        user_id: Some(user.id),
        password_hash: None, // Will be set at completion
        verification_type: VerificationType::PasswordReset,
        created_at: Utc::now(),
    };
    state.user_store.create_pending(pending)?;

    // Send password reset email
    state
        .email_sender
        .send_password_reset(&req.email, &code)
        .map_err(|e| BrokerError::Internal(e))?;

    Ok(Json(StageResetResponse {
        success: true,
        reason: None,
    }))
}

#[derive(Deserialize)]
pub struct CompleteResetRequest {
    pub token: String,
    pub pass: String,
}

#[derive(Serialize)]
pub struct CompleteResetResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/complete_reset
/// Complete password reset with new password
pub async fn complete_reset<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<CompleteResetRequest>,
) -> Result<Json<CompleteResetResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Validate password length
    if req.pass.len() < MIN_PASSWORD_LENGTH {
        return Err(BrokerError::PasswordTooShort);
    }
    if req.pass.len() > MAX_PASSWORD_LENGTH {
        return Err(BrokerError::PasswordTooLong);
    }

    // Look up pending verification
    let pending = state
        .user_store
        .get_pending(&req.token)?
        .ok_or(BrokerError::InvalidVerificationCode)?;

    // Verify this is a password reset
    if pending.verification_type != VerificationType::PasswordReset {
        return Err(BrokerError::InvalidVerificationCode);
    }

    // Get user ID
    let user_id = pending.user_id.ok_or(BrokerError::InvalidVerificationCode)?;

    // Check expiry (15 minutes)
    let age = Utc::now() - pending.created_at;
    if age.num_minutes() > 15 {
        state.user_store.delete_pending(&req.token)?;
        return Err(BrokerError::VerificationExpired);
    }

    // Hash new password
    let password_hash =
        hash_password(&req.pass).map_err(|e| BrokerError::Internal(e.to_string()))?;

    // Update user's password
    state.user_store.update_password(user_id, &password_hash)?;

    // Clean up pending verification
    state.user_store.delete_pending(&req.token)?;

    Ok(Json(CompleteResetResponse {
        success: true,
        reason: None,
    }))
}

#[derive(Deserialize)]
pub struct PasswordResetStatusQuery {
    pub email: String,
}

#[derive(Serialize)]
pub struct PasswordResetStatusResponse {
    pub status: String, // "complete" or "pending"
}

/// GET /wsapi/password_reset_status
/// Check if there's a pending password reset for an email
pub async fn password_reset_status<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Query(query): Query<PasswordResetStatusQuery>,
) -> Result<Json<PasswordResetStatusResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let has_pending = state.user_store.has_pending_reset(&query.email)?;

    Ok(Json(PasswordResetStatusResponse {
        status: if has_pending {
            "pending".to_string()
        } else {
            "complete".to_string()
        },
    }))
}
