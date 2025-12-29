//! Primary IdP authentication endpoints

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{EmailType, SessionStore, UserStore};
use crate::verifier::verify_assertion_with_dns;

#[derive(Deserialize)]
pub struct AuthWithAssertionRequest {
    pub assertion: String,
    #[serde(default)]
    pub ephemeral: bool,
}

#[derive(Serialize)]
pub struct AuthWithAssertionResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/auth_with_assertion
/// Authenticate a user via a primary IdP assertion
pub async fn auth_with_assertion<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<AuthWithAssertionRequest>,
) -> Result<Json<AuthWithAssertionResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Get fallback fetcher
    let fallback_fetcher = state
        .get_fallback_fetcher()
        .ok_or_else(|| BrokerError::Internal("DNS discovery not configured".to_string()))?;

    // Verify the assertion - audience is the broker itself
    let result = verify_assertion_with_dns(
        &req.assertion,
        &format!("https://{}", state.domain),
        &fallback_fetcher,
        &state.domain,
    )
    .await;

    if result.status != "okay" {
        return Err(BrokerError::InvalidAssertion(
            result.reason.unwrap_or_else(|| "Unknown error".to_string()),
        ));
    }

    let email = result
        .email
        .ok_or_else(|| BrokerError::InvalidAssertion("No email in assertion".to_string()))?;
    let issuer = result
        .issuer
        .ok_or_else(|| BrokerError::InvalidAssertion("No issuer in assertion".to_string()))?;

    // Verify this is actually a primary IdP (issuer != broker)
    if issuer == state.domain {
        return Err(BrokerError::InvalidAssertion(
            "Cannot use auth_with_assertion for secondary emails".to_string(),
        ));
    }

    // Find or create user
    let user_id = match state.user_store.get_email(&email)? {
        Some(email_record) => {
            // Update last_used_as to primary
            state
                .user_store
                .update_email_last_used(&email, EmailType::Primary)?;
            email_record.user_id
        }
        None => {
            // Create new user without password
            let user_id = state.user_store.create_user_no_password()?;
            state
                .user_store
                .add_email_with_type(user_id, &email, true, EmailType::Primary)?;
            user_id
        }
    };

    // Create session
    let session = state.session_store.create(user_id)?;
    if !req.ephemeral {
        super::session::set_session_cookie(&cookies, &session.id.0);
    }

    Ok(Json(AuthWithAssertionResponse {
        success: true,
        reason: None,
    }))
}
