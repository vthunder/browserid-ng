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
use crate::store::{EmailType, PendingVerification, SessionStore, UserStore, VerificationType};

#[derive(Serialize)]
pub struct ListEmailsResponse {
    pub success: bool,
    /// Just the email addresses as strings (for compatibility with original BrowserID protocol)
    pub emails: Vec<String>,
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
        emails: emails.into_iter().map(|e| e.email).collect(),
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
    /// Type of identity provider ("primary" or "secondary")
    #[serde(rename = "type")]
    pub addr_type: String,
    /// State of the email ("known", "unknown", "transition_to_primary", etc.)
    pub state: String,
    /// The issuing domain
    pub issuer: String,
    /// Whether this domain is disabled
    pub disabled: bool,
    /// Normalized form of the email
    #[serde(rename = "normalizedEmail")]
    pub normalized_email: String,
    /// Authentication URL (primary IdP only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// Provisioning URL (primary IdP only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prov: Option<String>,
}

/// Determine state based on password_known, last_used_as, current_type
fn compute_state(
    password_known: bool,
    last_used_as: Option<EmailType>,
    current_type: EmailType,
) -> &'static str {
    match (password_known, last_used_as, current_type) {
        // User has password
        (true, Some(EmailType::Primary), EmailType::Primary) => "known",
        (true, Some(EmailType::Primary), EmailType::Secondary) => "transition_to_secondary",
        (true, Some(EmailType::Secondary), EmailType::Primary) => "transition_to_primary",
        (true, Some(EmailType::Secondary), EmailType::Secondary) => "known",

        // User has no password
        (false, Some(EmailType::Primary), EmailType::Primary) => "known",
        (false, Some(EmailType::Primary), EmailType::Secondary) => "transition_no_password",
        (false, Some(EmailType::Secondary), EmailType::Primary) => "transition_to_primary",
        (false, Some(EmailType::Secondary), EmailType::Secondary) => "transition_no_password",

        // Email not in database
        (_, None, _) => "unknown",
    }
}

/// GET /wsapi/address_info
/// Get information about an email address
pub async fn address_info<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Query(query): Query<AddressInfoQuery>,
) -> Result<Json<AddressInfoResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Normalize email (lowercase)
    let normalized = query.email.to_lowercase();

    // Extract domain from email
    let domain = normalized
        .split('@')
        .nth(1)
        .ok_or(BrokerError::InvalidEmail)?;

    // Try DNS discovery if fallback_fetcher is already initialized
    // We use get_fallback_fetcher() to avoid triggering initialization in contexts
    // where it might cause issues (e.g., tests without DNS support)
    let discovery = if let Some(fetcher) = state.get_fallback_fetcher() {
        Some(fetcher.discover(domain).await?)
    } else {
        None
    };

    // Determine type and URLs based on discovery
    let (addr_type, current_type, auth, prov, issuer) = if let Some(ref result) = discovery {
        if result.is_primary {
            // Primary IdP - use domain as issuer
            let auth_url = result
                .document
                .authentication
                .as_ref()
                .map(|path| format!("https://{}{}", domain, path));
            let prov_url = result
                .document
                .provisioning
                .as_ref()
                .map(|path| format!("https://{}{}", domain, path));
            (
                "primary",
                EmailType::Primary,
                auth_url,
                prov_url,
                domain.to_string(),
            )
        } else {
            // Secondary (fallback to broker)
            ("secondary", EmailType::Secondary, None, None, state.domain.clone())
        }
    } else {
        // No discovery available - treat as secondary
        ("secondary", EmailType::Secondary, None, None, state.domain.clone())
    };

    // Look up email in database
    let email_record = state.user_store.get_email(&normalized)?;

    let email_state = if let Some(ref email) = email_record {
        // Email exists - compute state based on password and type history
        let password_known = state.user_store.has_password(email.user_id)?;
        compute_state(password_known, Some(email.last_used_as), current_type)
    } else {
        // Email not in database
        "unknown"
    };

    Ok(Json(AddressInfoResponse {
        addr_type: addr_type.to_string(),
        state: email_state.to_string(),
        issuer,
        disabled: false,
        normalized_email: normalized,
        auth,
        prov,
    }))
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
