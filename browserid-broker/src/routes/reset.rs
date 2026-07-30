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

    // A mailed reset code is an account-takeover primitive on a domain whose
    // authority is not the mailbox (browserid-ng-tsqk): whoever routes mail
    // for an atproto handle domain must not be able to reset the handle
    // owner's password.
    super::email::require_smtp_authority(&state, &req.email).await?;

    // One reset email per address per cooldown (anti email-bombing / code spam).
    if let Err(secs) = state.throttle_email(&req.email, "reset").await {
        return Err(BrokerError::EmailRateLimited(secs));
    }

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
    /// Target email the code was issued to — binds the guess to one pending
    /// record so the code space can't be walked globally (audit C1).
    pub email: String,
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

    // Look up the pending record by its target email and verify the code with
    // the brute-force guard (binds the guess to one record, burns after N wrong
    // tries). Expiry is enforced inside the guard.
    let pending = super::code_guard::verify_pending_code(
        state.user_store.as_ref(),
        &req.email,
        VerificationType::PasswordReset,
        &req.token,
    )?;

    // Get user ID
    let user_id = pending.user_id.ok_or(BrokerError::InvalidVerificationCode)?;

    // Hash new password
    let password_hash =
        hash_password(&req.pass).map_err(|e| BrokerError::Internal(e.to_string()))?;

    // Update user's password
    state.user_store.update_password(user_id, &password_hash)?;

    // Evict every existing session for this user: a reset is the recovery path,
    // so it must also cut off an attacker who already holds a session (audit
    // H2). The client re-authenticates immediately after, so no legitimate
    // session is lost. Device certs are intentionally left in place (revoking
    // them would silently break the user's agents) — see the audit doc.
    state.session_store.delete_by_user(user_id)?;

    // Clean up pending verification
    state.user_store.delete_pending(&pending.secret)?;

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
