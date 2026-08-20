//! Unified sign-in code — the dialog's SMTP escape hatch (browserid-ng-dw35).
//!
//! The cold sign-in dialog cannot know whether an address has an account
//! (that knowledge was the M7 enumeration oracle), so its "email me a code"
//! path stages ONE flow that works either way: the user picks a password and
//! receives a mailed code; completion then creates the account or resets the
//! existing password — the existence branch runs server-side, after the
//! mailbox proof, where distinguishing the two leaks nothing. Both staging
//! outcomes return byte-identical responses.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::crypto::{generate_verification_code, hash_password};
use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{
    EmailType, PendingVerification, ProofMethod, SessionStore, UserStore, VerificationType,
};

/// Minimum password length (same as original Persona)
const MIN_PASSWORD_LENGTH: usize = 8;
/// Maximum password length (same as original Persona)
const MAX_PASSWORD_LENGTH: usize = 80;

#[derive(Deserialize)]
pub struct StageSigninCodeRequest {
    pub email: String,
    pub pass: String,
}

#[derive(Serialize)]
pub struct SigninCodeResponse {
    pub success: bool,
}

/// POST /wsapi/stage_signin_code
/// Stage the unified code: hash the chosen password into the pending record
/// and mail a 6-digit code. Identical response whether or not the address has
/// an account — the only difference is the pending record's `user_id`, which
/// never leaves the server.
pub async fn stage_signin_code<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<StageSigninCodeRequest>,
) -> Result<Json<SigninCodeResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    if req.pass.len() < MIN_PASSWORD_LENGTH {
        return Err(BrokerError::PasswordTooShort);
    }
    if req.pass.len() > MAX_PASSWORD_LENGTH {
        return Err(BrokerError::PasswordTooLong);
    }

    // The SMTP loop only proves ownership where the mailbox is the authority
    // (browserid-ng-tsqk). Domain-level check — no account dependence.
    super::email::require_smtp_authority(&state, &req.email).await?;

    // One code email per address per cooldown (anti email-bombing).
    if let Err(secs) = state.throttle_email(&req.email, "signin_code").await {
        return Err(BrokerError::EmailRateLimited(secs));
    }

    let password_hash =
        hash_password(&req.pass).map_err(|e| BrokerError::Internal(e.to_string()))?;

    // Existence decides only what completion will do; every other step —
    // and the response — is the same on both branches.
    let user_id = state
        .user_store
        .get_user_by_email(&req.email)?
        .map(|u| u.id);

    let code = generate_verification_code();
    state.user_store.create_pending(PendingVerification {
        secret: code.clone(),
        email: req.email.clone(),
        user_id,
        password_hash: Some(password_hash),
        verification_type: VerificationType::SigninCode,
        created_at: Utc::now(),
    })?;

    state
        .email_sender
        .send_verification(&req.email, &code)
        .map_err(BrokerError::Internal)?;

    Ok(Json(SigninCodeResponse { success: true }))
}

#[derive(Deserialize)]
pub struct CompleteSigninCodeRequest {
    /// Target email the code was issued to — binds the guess to one pending
    /// record so the code space can't be walked globally (audit C1).
    pub email: String,
    pub token: String,
}

/// POST /wsapi/complete_signin_code
/// The mailed code proves the mailbox; now resolve existence server-side.
/// New address → create the account with the staged password. Existing
/// address → this is a password reset, with the reset path's full fences
/// (kgb9 sibling re-verification, H2 session eviction). Either way the
/// account ends up password-backed with the staged password, so the dialog
/// follows up with a normal authenticate_user — no session is minted here
/// and the response does not say which branch ran.
pub async fn complete_signin_code<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<CompleteSigninCodeRequest>,
) -> Result<Json<SigninCodeResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Code check with the brute-force guard (binds the guess to one record,
    // burns after N wrong tries; expiry enforced inside).
    let pending = super::code_guard::verify_pending_code(
        state.user_store.as_ref(),
        &req.email,
        VerificationType::SigninCode,
        &req.token,
    )?;

    let password_hash = pending
        .password_hash
        .clone()
        .ok_or(BrokerError::InvalidVerificationCode)?;

    match pending.user_id {
        None => {
            // No account at staging time. Guard against one having appeared
            // since (e.g. a parallel create flow) — that turns this into the
            // reset branch, never a duplicate account.
            match state.user_store.get_user_by_email(&pending.email)? {
                Some(user) => reset_password(&state, user.id, &pending)?,
                None => {
                    let user_id = state.user_store.create_user(&password_hash)?;
                    state.user_store.add_email(user_id, &pending.email, true)?;
                }
            }
        }
        Some(user_id) => reset_password(&state, user_id, &pending)?,
    }

    state.user_store.delete_pending(&pending.secret)?;

    Ok(Json(SigninCodeResponse { success: true }))
}

/// The existing-account branch = a password reset, so it carries the reset
/// path's security fences verbatim (see `reset::complete_reset`).
fn reset_password<U, S, E>(
    state: &AppState<U, S, E>,
    user_id: crate::store::UserId,
    pending: &PendingVerification,
) -> Result<(), BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let password_hash = pending
        .password_hash
        .clone()
        .ok_or(BrokerError::InvalidVerificationCode)?;
    state.user_store.update_password(user_id, &password_hash)?;

    // Re-verification fence (kgb9): control of ONE inbox + a reset must not
    // pivot to minting the account's OTHER SMTP addresses.
    let reset_addr = pending.email.to_lowercase();
    for e in state.user_store.list_emails(user_id)? {
        if e.email_type == EmailType::Secondary
            && e.proof == ProofMethod::Smtp
            && e.email.to_lowercase() != reset_addr
        {
            state.user_store.unverify_email(&e.email)?;
        }
    }
    // The reset address itself: freshly proven, whatever its history.
    state.user_store.verify_email(&pending.email)?;

    // Session eviction (audit H2): a reset is the recovery path, so it cuts
    // off an attacker who already holds a session. The dialog immediately
    // re-authenticates with the new password.
    state.session_store.delete_by_user(user_id)?;

    Ok(())
}
