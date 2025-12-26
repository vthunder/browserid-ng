//! Account creation endpoints

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

/// Minimum password length (same as original Persona)
const MIN_PASSWORD_LENGTH: usize = 8;
/// Maximum password length (same as original Persona)
const MAX_PASSWORD_LENGTH: usize = 80;

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
    // Validate password length
    if req.pass.len() < MIN_PASSWORD_LENGTH {
        return Err(BrokerError::PasswordTooShort);
    }
    if req.pass.len() > MAX_PASSWORD_LENGTH {
        return Err(BrokerError::PasswordTooLong);
    }

    // Check if email already exists
    if state.user_store.get_user_by_email(&req.email)?.is_some() {
        return Err(BrokerError::EmailAlreadyExists);
    }

    // Hash password
    let password_hash = hash_password(&req.pass)
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

    // Generate verification code (this is both the user-facing code and the lookup key)
    let code = generate_verification_code();

    // Store pending verification with code as the lookup key
    let pending = PendingVerification {
        secret: code.clone(), // Use code as the lookup key
        email: req.email.clone(),
        user_id: None, // New account
        password_hash: Some(password_hash),
        verification_type: VerificationType::NewAccount,
        created_at: Utc::now(),
    };
    state.user_store.create_pending(pending)?;

    // Send verification email
    state
        .email_sender
        .send_verification(&req.email, &code)
        .map_err(|e| BrokerError::Internal(e))?;

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

    // Get password hash from pending record
    let password_hash = pending
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

#[derive(Deserialize)]
pub struct AccountCancelRequest {
    pub email: String,
    pub pass: String,
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

    // Clear session cookie
    super::session::clear_session_cookie(&cookies);

    Ok(Json(AccountCancelResponse { success: true }))
}

#[derive(Deserialize)]
pub struct UserCreationStatusQuery {
    pub email: Option<String>,
}

#[derive(Serialize)]
pub struct UserCreationStatusResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// GET /wsapi/user_creation_status
/// Check the status of a pending user registration
pub async fn user_creation_status<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Query(query): Query<UserCreationStatusQuery>,
) -> Result<Json<UserCreationStatusResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Email is required
    let email = match &query.email {
        Some(e) => e,
        None => {
            return Err(BrokerError::ValidationError(
                "email parameter required".to_string(),
            ))
        }
    };

    // Check if user already exists (complete)
    if state.user_store.get_user_by_email(email)?.is_some() {
        return Ok(Json(UserCreationStatusResponse {
            success: true,
            status: Some("complete".to_string()),
        }));
    }

    // Check for pending new account verification
    if state
        .user_store
        .get_pending_by_email(email, VerificationType::NewAccount)?
        .is_some()
    {
        return Ok(Json(UserCreationStatusResponse {
            success: true,
            status: Some("pending".to_string()),
        }));
    }

    // No pending registration found - this is an error case
    Err(BrokerError::ValidationError(
        "no pending registration".to_string(),
    ))
}
