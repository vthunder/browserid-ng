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
    EmailType, PendingVerification, ProofMethod, RecoveryAttempt, SessionStore, UserId, UserStore, VerificationType,
};

/// A recovery attempt waits this long for its remaining proofs.
const RECOVERY_SECONDS: i64 = 30 * 60;

/// Minimum password length (same as original Persona)
const MIN_PASSWORD_LENGTH: usize = 8;
/// Maximum password length (same as original Persona)
const MAX_PASSWORD_LENGTH: usize = 80;

/// Per-client-IP cap on stagings (M7 cross-cutting): the per-address cooldown
/// bounds bombing one mailbox; this bounds one client spraying many addresses.
/// Fixed window, auto-resets — same shape as the login throttle (bean ytjn).
const STAGE_MAX_PER_IP: u32 = 10;
const STAGE_WINDOW: std::time::Duration = std::time::Duration::from_secs(3600);

#[derive(Deserialize)]
pub struct StageSigninCodeRequest {
    pub email: String,
    pub pass: String,
}

#[derive(Serialize)]
pub struct SigninCodeResponse {
    pub success: bool,
    /// The reset needs more identity proofs first (bean yz4y): continue at
    /// `/wsapi/recovery_proofs` with this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryInfo>,
}

#[derive(Serialize, Clone)]
pub struct RecoveryInfo {
    pub id: String,
    /// Masked addresses still to prove.
    pub hints: Vec<String>,
    pub proven: Vec<String>,
    pub needed: u32,
}

/// POST /wsapi/stage_signin_code
/// Stage the unified code: hash the chosen password into the pending record
/// and mail a 6-digit code. Identical response whether or not the address has
/// an account — the only difference is the pending record's `user_id`, which
/// never leaves the server.
pub async fn stage_signin_code<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: axum::http::HeaderMap,
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

    // Per-IP window BEFORE any account-dependent work, counted on every
    // attempt — throttling must not itself become an existence signal.
    // Skipped in dev/test mode (the whole local test suite shares one IP);
    // the per-address cooldown below still applies there.
    if !state.test_endpoints_enabled {
        let mut attempts = state.signin_code_attempts.write().unwrap();
        let now = std::time::Instant::now();
        attempts.retain(|_, (start, _)| now.duration_since(*start) < STAGE_WINDOW);
        let ip = super::auth::client_ip(&headers);
        let entry = attempts.entry(ip).or_insert((now, 0));
        if entry.1 >= STAGE_MAX_PER_IP {
            return Err(BrokerError::EmailRateLimited(
                STAGE_WINDOW.as_secs() as i64 - now.duration_since(entry.0).as_secs() as i64,
            ));
        }
        entry.1 += 1;
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

    Ok(Json(SigninCodeResponse { success: true, recovery: None }))
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

    let mut recovery = None;
    match pending.user_id {
        None => {
            // No account at staging time. Guard against one having appeared
            // since (e.g. a parallel create flow) — that turns this into the
            // reset branch, never a duplicate account.
            match state.user_store.get_user_by_email(&pending.email)? {
                Some(user) => recovery = begin_reset(&state, user.id, &pending)?,
                None => {
                    let user_id = state.user_store.create_user(&password_hash)?;
                    state.user_store.add_email(user_id, &pending.email, true)?;
                }
            }
        }
        Some(user_id) => recovery = begin_reset(&state, user_id, &pending)?,
    }

    state.user_store.delete_pending(&pending.secret)?;

    // The code was redeemed — the anti-bombing cooldown has served its
    // purpose, so a legitimate follow-up staging (another reset moments
    // later) isn't blocked. Unredeemed codes keep the cooldown.
    state.clear_email_throttle(&pending.email).await;

    Ok(Json(SigninCodeResponse { success: true, recovery }))
}

/// The proofs a reset wants (registry-api-v1 §5.2.7 `proofs`, capped by
/// the identity count): the mailbox code is one.
fn reset_needed<U: UserStore, S: SessionStore, E: EmailSender>(state: &AppState<U, S, E>, user_id: UserId) -> Result<u32, BrokerError> {
    let policy = crate::account_auth::account_policy(state.user_store.as_ref(), user_id)?;
    let identities = crate::account_auth::identity_count(state.user_store.as_ref(), user_id)?;
    Ok(policy.proofs.unwrap_or(browserid_registrar::policy::BASELINE_PROOFS).min(identities.max(1)))
}

fn masked_hints<U: UserStore, S: SessionStore, E: EmailSender>(state: &AppState<U, S, E>, user_id: UserId, proven: &[String]) -> Result<Vec<String>, BrokerError> {
    Ok(crate::membership::roster(state.user_store.as_ref(), user_id)?
        .into_iter()
        .filter(|(i, s)| *s == "active" && !proven.iter().any(|p| p.eq_ignore_ascii_case(i)))
        .map(|(i, _)| super::registry_login::mask_address(&i))
        .collect())
}

/// The existing-account branch: a reset is one ceremony that meets the
/// account's proof bar before anything changes (bean yz4y). The mailbox
/// code is the first proof; when it is the only one wanted (a single-
/// identity account, or a policy asking for one), the reset applies now.
/// Otherwise a recovery attempt records it and the client continues with
/// presentations at `/wsapi/recovery_proofs`.
fn begin_reset<U, S, E>(
    state: &AppState<U, S, E>,
    user_id: UserId,
    pending: &PendingVerification,
) -> Result<Option<RecoveryInfo>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let password_hash = pending
        .password_hash
        .clone()
        .ok_or(BrokerError::InvalidVerificationCode)?;
    let proven = vec![pending.email.to_lowercase()];
    let needed = reset_needed(state, user_id)?;
    if proven.len() as u32 >= needed {
        apply_reset(state, user_id, &password_hash, &proven)?;
        return Ok(None);
    }
    let id = crate::crypto::generate_salt_b64() + &crate::crypto::generate_salt_b64();
    let now = Utc::now();
    state.user_store.create_recovery(RecoveryAttempt {
        id: id.clone(),
        user_id,
        email: pending.email.to_lowercase(),
        password_hash,
        proven: proven.clone(),
        created_at: now,
        expires_at: now + chrono::Duration::seconds(RECOVERY_SECONDS),
    })?;
    tracing::info!(needed, "reset: waiting for more identity proofs");
    Ok(Some(RecoveryInfo { hints: masked_hints(state, user_id, &proven)?, id, proven, needed }))
}

/// The parent identity an agent row derives from: its recorded parent,
/// else the address before the `+tag`.
fn agent_parent(e: &crate::store::Email) -> Option<String> {
    if let Some(p) = &e.parent_email {
        return Some(p.to_lowercase());
    }
    let (local, domain) = browserid_core::identity::email_parts(&e.email)?;
    let base = local.split('+').next()?;
    Some(format!("{base}@{domain}").to_lowercase())
}

/// What a completed reset does (draft, "Reset the password"): the new
/// password; every plain mailbox not proven in this ceremony unverified;
/// agent identities of unproven parents unverified until the parent is
/// re-proven; every browser session ended and every login key revoked, so
/// each device passes the add-a-device bar again.
pub(super) fn apply_reset<U, S, E>(
    state: &AppState<U, S, E>,
    user_id: UserId,
    password_hash: &str,
    proven: &[String],
) -> Result<(), BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    state.user_store.update_password(user_id, password_hash)?;
    let is_proven = |e: &str| proven.iter().any(|p| p.eq_ignore_ascii_case(e));
    for e in state.user_store.list_emails(user_id)? {
        match e.email_type {
            EmailType::Secondary if e.proof == ProofMethod::Smtp => {
                if is_proven(&e.email) { state.user_store.verify_email(&e.email)?; }
                else { state.user_store.unverify_email(&e.email)?; }
            }
            EmailType::Agent => {
                let parent_ok = agent_parent(&e).is_some_and(|p| is_proven(&p));
                if !parent_ok { state.user_store.unverify_email(&e.email)?; }
            }
            _ => {}
        }
    }
    // Session eviction (audit H2) and every login key (draft): a reset is
    // the recovery path, so it cuts off whoever already holds a device.
    state.session_store.delete_by_user(user_id)?;
    for k in state.user_store.list_login_certs(user_id)? {
        if k.revoked_at.is_none() {
            state.user_store.revoke_login_cert(user_id, k.id)?;
        }
        state.user_store.end_sessions_on_login_key(user_id, k.id).ok();
    }
    tracing::info!(proofs = proven.len(), "reset: applied");
    Ok(())
}

/// Re-verify the agent identities that derive from `parent` (it was just
/// re-proven at its issuer; they were unverified with it by a reset).
pub(super) fn reverify_agents_of<U: UserStore>(store: &U, user_id: UserId, parent: &str) -> Result<(), BrokerError> {
    for e in store.list_emails(user_id)? {
        if e.email_type == EmailType::Agent && !e.verified && agent_parent(&e).is_some_and(|p| p.eq_ignore_ascii_case(parent)) {
            store.verify_email(&e.email)?;
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct RecoveryProofsRequest {
    pub id: String,
    pub presentations: Vec<String>,
}

#[derive(Serialize)]
pub struct RecoveryProofsResponse {
    pub success: bool,
    /// The reset applied.
    pub reset: bool,
    pub hints: Vec<String>,
    pub proven: Vec<String>,
    pub needed: u32,
}

/// POST /wsapi/recovery_proofs — presentations for this origin's own
/// audience, one per identity; the reset applies when enough distinct
/// identities are proven.
pub async fn recovery_proofs<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<RecoveryProofsRequest>,
) -> Result<Json<RecoveryProofsResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let rec = state
        .user_store
        .get_recovery(&req.id)?
        .filter(|r| r.expires_at > Utc::now())
        .ok_or(BrokerError::InvalidVerificationCode)?;
    let fresh = super::registry_login::proven_identities(&state, rec.user_id, &req.presentations).await?;
    let mut proven = rec.proven.clone();
    for p in fresh {
        if !proven.iter().any(|x| x.eq_ignore_ascii_case(&p)) {
            proven.push(p);
        }
    }
    let needed = reset_needed(&state, rec.user_id)?;
    if proven.len() as u32 >= needed {
        apply_reset(&state, rec.user_id, &rec.password_hash, &proven)?;
        state.user_store.delete_recovery(&rec.id)?;
        return Ok(Json(RecoveryProofsResponse { success: true, reset: true, hints: vec![], proven, needed }));
    }
    state.user_store.set_recovery_proven(&rec.id, &proven)?;
    let hints = masked_hints(&state, rec.user_id, &proven)?;
    Ok(Json(RecoveryProofsResponse { success: true, reset: false, hints, proven, needed }))
}

