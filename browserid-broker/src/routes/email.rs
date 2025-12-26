//! Email management endpoints

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::crypto::generate_verification_code;
use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{PendingVerification, SessionStore, UserStore, VerificationType};

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
        verification_type: VerificationType::AddEmail,
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

#[derive(Deserialize)]
pub struct AddressInfoQuery {
    pub email: String,
}

#[derive(Serialize)]
pub struct AddressInfoResponse {
    /// Type of identity provider ("secondary" for broker-managed)
    #[serde(rename = "type")]
    pub addr_type: String,
    /// State of the email ("known" or "unknown")
    pub state: String,
    /// The issuing domain
    pub issuer: String,
    /// Whether this domain is disabled
    pub disabled: bool,
    /// Normalized form of the email
    #[serde(rename = "normalizedEmail")]
    pub normalized_email: String,
}

/// GET /wsapi/address_info
/// Get information about an email address
pub async fn address_info<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Query(query): Query<AddressInfoQuery>,
) -> Json<AddressInfoResponse>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Normalize email (lowercase)
    let normalized = query.email.to_lowercase();

    // Check if email exists
    let exists = state
        .user_store
        .get_user_by_email(&normalized)
        .ok()
        .flatten()
        .is_some();

    Json(AddressInfoResponse {
        addr_type: "secondary".to_string(),
        state: if exists { "known" } else { "unknown" }.to_string(),
        issuer: state.domain.clone(),
        disabled: false,
        normalized_email: normalized,
    })
}

#[derive(Deserialize)]
pub struct EmailAdditionStatusQuery {
    pub email: String,
}

#[derive(Serialize)]
pub struct EmailAdditionStatusResponse {
    pub status: String,
}

/// GET /wsapi/email_addition_status
/// Check the status of a pending email addition
pub async fn email_addition_status<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Query(query): Query<EmailAdditionStatusQuery>,
) -> Json<EmailAdditionStatusResponse>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Check if email already exists (complete)
    if state
        .user_store
        .get_user_by_email(&query.email)
        .ok()
        .flatten()
        .is_some()
    {
        // Check if user has this email verified
        if let Ok(Some(user)) = state.user_store.get_user_by_email(&query.email) {
            if let Ok(emails) = state.user_store.list_emails(user.id) {
                if emails.iter().any(|e| e.email == query.email && e.verified) {
                    return Json(EmailAdditionStatusResponse {
                        status: "complete".to_string(),
                    });
                }
            }
        }
    }

    // Check for pending email addition
    if state
        .user_store
        .get_pending_by_email(&query.email, VerificationType::AddEmail)
        .ok()
        .flatten()
        .is_some()
    {
        return Json(EmailAdditionStatusResponse {
            status: "pending".to_string(),
        });
    }

    // No pending and not complete = failed
    Json(EmailAdditionStatusResponse {
        status: "failed".to_string(),
    })
}
