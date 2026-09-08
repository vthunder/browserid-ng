//! The registry guard (registry-api-v1 §4.2, bean 0c49 step 5): the
//! broker's guard PAGE (`/guard`) calls this to mint a guard token for
//! the certs and identity in its fragment. The check is the registry's
//! own: the account's password, or a live broker session on the account
//! that holds the identity plus the explicit click that made this call.
//! Never reveals whether an identity is in use — every refusal is the
//! same `guard_rejected`.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{EmailType, GuardToken, SessionStore, UserStore};

/// Guard tokens live this long (§4.2: RECOMMENDED 1 h).
const GUARD_TTL_SECONDS: i64 = 3600;
const GUARD_MAX_FAILURES: u32 = 10;
/// A full session younger than this is the password kind already passed.
const FRESH_SESSION_SECONDS: i64 = 600;
const GUARD_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Deserialize)]
pub struct GuardRequest {
    pub identity: String,
    /// The certs the token binds to, as the wallet passed them to the page.
    pub certs: Vec<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// The explicit user action, when the check is a live session on the
    /// account (the guard page's Approve, or the dialog's guard screen).
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Serialize)]
pub struct GuardResponse {
    pub guard: String,
}

fn rejected() -> BrokerError {
    BrokerError::PolicyRefused("guard_rejected".into())
}

pub async fn mint<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    headers: axum::http::HeaderMap,
    Json(req): Json<GuardRequest>,
) -> Result<Json<GuardResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let ip = super::auth::client_ip(&headers);
    // Per-source backoff, before any password work (§4.2).
    {
        let mut attempts = state.login_attempts.write().unwrap();
        let now = std::time::Instant::now();
        attempts.retain(|_, (start, _)| now.duration_since(*start) < GUARD_WINDOW);
        if let Some((_, count)) = attempts.get(&format!("guard|{ip}")) {
            if *count >= GUARD_MAX_FAILURES {
                return Err(BrokerError::LoginRateLimited);
            }
        }
    }
    let fail = || {
        let mut attempts = state.login_attempts.write().unwrap();
        let entry = attempts
            .entry(format!("guard|{ip}"))
            .or_insert((std::time::Instant::now(), 0));
        entry.1 += 1;
        rejected()
    };

    let identity = req.identity.trim().to_lowercase();
    if req.certs.is_empty() || req.certs.len() > 2 {
        return Err(BrokerError::ValidationError("certs must carry 1–2 entries".into()));
    }
    let mut kids: Vec<String> = Vec::new();
    for c in &req.certs {
        let cert = browserid_core::device::DeviceCert::parse(c)
            .map_err(|e| BrokerError::ValidationError(format!("bad cert: {e}")))?;
        kids.push(cert.claims().public_key.kid());
    }
    kids.sort();

    // The account that holds the identity — active, not an agent.
    let Some(rec) = state
        .user_store
        .get_email(&identity)?
        .filter(|e| e.email_type != EmailType::Agent && !e.is_suspended())
    else {
        return Err(fail());
    };
    let user_id = rec.user_id;

    // A live session on that account passes with the explicit action, or
    // by itself when it is a FULL session opened moments ago — the user
    // typed the account password in this very ceremony (the password kind,
    // fulfilled); else the account password.
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref());
    let passed = match (session, req.password.as_deref()) {
        (Some(s), _) if s.user_id == user_id
            && (req.confirm
                || (s.level == crate::store::SessionLevel::Full
                    && (Utc::now() - s.created_at).num_seconds() <= FRESH_SESSION_SECONDS)) => true,
        (_, Some(pw)) if !pw.is_empty() => {
            let user = state.user_store.get_user(user_id)?.ok_or_else(rejected)?;
            !user.password_hash.is_empty()
                && crate::crypto::verify_password(pw, &user.password_hash).unwrap_or(false)
        }
        _ => false,
    };
    if !passed {
        return Err(fail());
    }

    let token = crate::crypto::generate_salt_b64() + &crate::crypto::generate_salt_b64();
    let now = Utc::now();
    state.user_store.create_guard_token(GuardToken {
        token_hash: browserid_registrar::session::b64url_sha256_pub(token.as_bytes()),
        user_id,
        identity,
        kids,
        created_at: now,
        expires_at: now + Duration::seconds(GUARD_TTL_SECONDS),
    })?;
    Ok(Json(GuardResponse { guard: token }))
}
