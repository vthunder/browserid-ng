//! The registry login page's backend (registry-api-v1 §4.2 `login_page`):
//! the page at `/registry-login` posts the account password here and
//! gets a one-time login token, which the wallet spends at
//! `POST /api/v1/login`. This registry's check is the account password;
//! nothing else is offered yet. Never reveals whether an account exists —
//! every refusal is the same 403.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{LoginToken, SessionStore, UserStore};

/// Login tokens live this long.
const LOGIN_TOKEN_SECONDS: i64 = 300;
const LOGIN_MAX_FAILURES: u32 = 10;
const LOGIN_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Deserialize)]
pub struct LoginRequest {
    /// The account's public id (registry-api-v1 §3).
    pub account: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub login: String,
}

fn rejected() -> BrokerError {
    BrokerError::PolicyRefused("login_rejected".into())
}

pub async fn mint<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let ip = super::auth::client_ip(&headers);
    {
        let mut attempts = state.login_attempts.write().unwrap();
        let now = std::time::Instant::now();
        attempts.retain(|_, (start, _)| now.duration_since(*start) < LOGIN_WINDOW);
        if let Some((_, count)) = attempts.get(&format!("registry-login|{ip}")) {
            if *count >= LOGIN_MAX_FAILURES {
                return Err(BrokerError::LoginRateLimited);
            }
        }
    }
    let fail = || {
        let mut attempts = state.login_attempts.write().unwrap();
        let entry = attempts
            .entry(format!("registry-login|{ip}"))
            .or_insert((std::time::Instant::now(), 0));
        entry.1 += 1;
        rejected()
    };
    let Some(user_id) = state.user_store.user_for_public_id(req.account.trim())? else {
        return Err(fail());
    };
    let user = state.user_store.get_user(user_id)?.ok_or_else(rejected)?;
    if req.password.is_empty()
        || user.password_hash.is_empty()
        || !crate::crypto::verify_password(&req.password, &user.password_hash).unwrap_or(false)
    {
        return Err(fail());
    }
    let token = crate::crypto::generate_salt_b64() + &crate::crypto::generate_salt_b64();
    state.user_store.create_login_token(LoginToken {
        token_hash: browserid_registrar::session::b64url_sha256_pub(token.as_bytes()),
        user_id,
        expires_at: Utc::now() + Duration::seconds(LOGIN_TOKEN_SECONDS),
    })?;
    Ok(Json(LoginResponse { login: token }))
}
