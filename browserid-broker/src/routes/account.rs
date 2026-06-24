//! Account creation endpoints

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
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
        (Some(exp), Some(got)) if exp == got => {}
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

// ===========================================================================
// Passwordless external login + federated @mingo.place provisioning (SBO T1)
//
// The Mingo demo's identity flow (decision #5): authenticate an EXTERNAL email
// (e.g. danmills@sandmill.org, gmail) by email round-trip — no password — then
// provision a local <handle>@mingo.place identity linked to that account. The
// existing cert_key then issues @mingo.place certs (issuer browserid.me, pinned
// + DNSSEC-anchored → SBO-attributable). See the typed-signing design note.
// ===========================================================================

#[derive(Deserialize)]
pub struct StageLoginRequest {
    pub email: String,
}

/// POST /wsapi/stage_login  — email a one-time code to `email` (no password).
/// Works whether or not an account exists (login or first-time).
pub async fn stage_login<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<StageLoginRequest>,
) -> Result<Json<StageUserResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let email = req.email.trim().to_lowercase();
    if !email.contains('@') {
        return Err(BrokerError::ValidationError("invalid email".into()));
    }
    let code = generate_verification_code();
    state.user_store.create_pending(PendingVerification {
        secret: code.clone(),
        email: email.clone(),
        user_id: None,
        password_hash: None, // passwordless
        verification_type: VerificationType::NewAccount,
        created_at: Utc::now(),
    })?;
    state
        .email_sender
        .send_verification(&email, &code)
        .map_err(BrokerError::Internal)?;
    Ok(Json(StageUserResponse { success: true, reason: None }))
}

#[derive(Deserialize)]
pub struct CompleteLoginRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct CompleteLoginResponse {
    pub success: bool,
    pub email: String,
}

/// POST /wsapi/complete_login — verify the code, open a session. Creates a
/// passwordless account on first login for this external email.
pub async fn complete_login<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: tower_cookies::Cookies,
    Json(req): Json<CompleteLoginRequest>,
) -> Result<Json<CompleteLoginResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let pending = state
        .user_store
        .get_pending(&req.token)?
        .ok_or(BrokerError::InvalidVerificationCode)?;
    if (Utc::now() - pending.created_at).num_minutes() > 15 {
        state.user_store.delete_pending(&req.token)?;
        return Err(BrokerError::VerificationExpired);
    }

    let user_id = match state.user_store.get_user_by_email(&pending.email)? {
        Some(user) => user.id,
        None => {
            let uid = state.user_store.create_user_no_password()?;
            state.user_store.add_email(uid, &pending.email, true)?;
            uid
        }
    };
    state.user_store.delete_pending(&req.token)?;

    let session = state.session_store.create(user_id)?;
    super::session::set_session_cookie(&cookies, &session.id.0);
    Ok(Json(CompleteLoginResponse { success: true, email: pending.email }))
}

#[derive(Deserialize)]
pub struct ProvisionMingoRequest {
    pub handle: String,
}

#[derive(Serialize)]
pub struct ProvisionMingoResponse {
    pub success: bool,
    pub email: String,
}

/// POST /wsapi/provision_mingo — add <handle>@<MINGO_DOMAIN> as a verified email
/// on the authenticated account (the federated IdP step). Idempotent for the
/// owner; rejects a handle owned by another account. cert_key can then issue its
/// cert. Requires a session (from complete_login).
pub async fn provision_mingo<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: tower_cookies::Cookies,
    Json(req): Json<ProvisionMingoRequest>,
) -> Result<Json<ProvisionMingoResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;

    let handle = req.handle.trim().to_lowercase();
    let valid = !handle.is_empty()
        && handle.len() <= 31
        && handle.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || (i > 0 && matches!(b, b'-' | b'_' | b'.'))
        });
    if !valid {
        return Err(BrokerError::ValidationError(
            "handle must be lowercase [a-z0-9] then [a-z0-9._-]".into(),
        ));
    }
    let domain = std::env::var("MINGO_DOMAIN").unwrap_or_else(|_| "mingo.place".to_string());
    let email = format!("{handle}@{domain}");

    if let Some(existing) = state.user_store.get_user_by_email(&email)? {
        if existing.id != session.user_id {
            return Err(BrokerError::ValidationError("handle already taken".into()));
        }
        return Ok(Json(ProvisionMingoResponse { success: true, email })); // idempotent
    }
    state.user_store.add_email(session.user_id, &email, true)?;
    Ok(Json(ProvisionMingoResponse { success: true, email }))
}
