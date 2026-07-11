//! Primary IdP authentication endpoints

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::crypto::hash_password;
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

    // Verify the assertion - audience is the broker itself. Accepted fallback:
    // just this broker (a login here roots in a primary or this broker's own
    // fallback).
    let accepted = [state.domain.clone()];
    let result = verify_assertion_with_dns(
        &req.assertion,
        &format!("https://{}", state.domain),
        fallback_fetcher.as_ref(),
        &accepted,
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

    // If the caller already holds an authenticated session, prefer LINKING the
    // assertion-verified email into that existing account rather than minting a
    // separate one. Otherwise every primary-IdP email becomes its own orphan
    // account and the chooser only ever surfaces the last one authenticated
    // (mingo-1c6v). browserid treats all issuers as peer IdPs, so linking a
    // sandmill.org email and a mingo.place email into one account is expected.
    let existing_session =
        super::session::get_session_from_cookies(&cookies, state.session_store.as_ref());

    // Find or create the account this email authenticates as.
    let user_id = match state.user_store.get_email(&email)? {
        Some(email_record) => {
            state
                .user_store
                .update_email_last_used(&email, EmailType::Primary)?;
            match existing_session.as_ref() {
                // The email lives on a *different* account than the caller's
                // current session → transfer it into the current account. The
                // verified assertion IS the proof of ownership, so this is the
                // per-email transfer-on-proof merge (Persona semantics, mingo-z8im):
                // an email belongs to exactly one account, and proving it under
                // another session moves it there.
                Some(session) if session.user_id != email_record.user_id => {
                    let former = email_record.user_id;
                    state.user_store.transfer_email(&email, session.user_id)?;
                    // Clean up the former account if it has no emails left.
                    if state.user_store.list_emails(former)?.is_empty() {
                        state.user_store.delete_user(former)?;
                    }
                    session.user_id
                }
                // Same account, or no session → authenticate as the email's owner.
                _ => email_record.user_id,
            }
        }
        None => match existing_session.as_ref() {
            // Logged in + a brand-new email → attach it to the current account.
            Some(session) => {
                state.user_store.add_email_with_type(
                    session.user_id,
                    &email,
                    true,
                    EmailType::Primary,
                )?;
                session.user_id
            }
            // Not logged in → create a fresh account for this email.
            None => {
                let user_id = state.user_store.create_user_no_password()?;
                state.user_store.add_email_with_type(
                    user_id,
                    &email,
                    true,
                    EmailType::Primary,
                )?;
                user_id
            }
        },
    };

    // Reuse the current session when we linked into it; otherwise start a new one
    // (either no prior session, or the email belongs to a different account).
    let reuse = existing_session
        .as_ref()
        .is_some_and(|s| s.user_id == user_id);
    if !reuse {
        let session = state.session_store.create(user_id)?;
        if !req.ephemeral {
            super::session::set_session_cookie(
                &cookies,
                &session.id.0,
                super::session::cookie_secure(&state.domain),
            );
        }
    }

    Ok(Json(AuthWithAssertionResponse {
        success: true,
        reason: None,
    }))
}

#[derive(Deserialize)]
pub struct SetPasswordRequest {
    pub email: String,
    pub pass: String,
    #[serde(default)]
    pub csrf: String,
}

#[derive(Serialize)]
pub struct SetPasswordResponse {
    pub success: bool,
}

/// POST /wsapi/set_password
/// Set password for a user who was previously primary-only (transition_no_password state)
/// Requires authentication - user must have a valid session from auth_with_assertion
pub async fn set_password<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<SetPasswordRequest>,
) -> Result<Json<SetPasswordResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Require authentication
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;

    // Validate password length
    if req.pass.len() < 8 {
        return Err(BrokerError::PasswordTooShort);
    }
    if req.pass.len() > 80 {
        return Err(BrokerError::PasswordTooLong);
    }

    // Find the email record and verify it belongs to the authenticated user
    let email_record = state
        .user_store
        .get_email(&req.email)?
        .ok_or(BrokerError::EmailNotFound)?;
    if email_record.user_id != session.user_id {
        return Err(BrokerError::NotAuthenticated);
    }

    // Get user to check password status
    let user = state
        .user_store
        .get_user(session.user_id)?
        .ok_or(BrokerError::UserNotFound)?;

    // Ensure user doesn't already have a password
    if state.user_store.has_password(user.id)? {
        return Err(BrokerError::Internal(
            "User already has a password".to_string(),
        ));
    }

    // Hash and set password
    let password_hash =
        hash_password(&req.pass).map_err(|e| BrokerError::Internal(e.to_string()))?;
    state.user_store.set_password(user.id, &password_hash)?;

    // Update email type to secondary since they now have a password
    state
        .user_store
        .update_email_last_used(&req.email, EmailType::Secondary)?;

    Ok(Json(SetPasswordResponse { success: true }))
}
