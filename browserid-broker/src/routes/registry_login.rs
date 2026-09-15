//! The registry login page's backend (registry-api-v1 §4.2 `login_page`):
//! the page at `/registry-login` posts the account password here and
//! gets a one-time login token, which the wallet spends at
//! `POST /api/v1/login`. The password is one way through the account's
//! enrol rule (`account_auth`, bean noqd); the token it mints records that
//! so the registry enrols the key as `password`. Never reveals whether an
//! account exists — every refusal is the same 403.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::account_auth::{self, Proof};
use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};

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
    let token = account_auth::login_token_for(state.user_store.as_ref(), user_id, &[Proof::Password])
        .map_err(|_| fail())?;
    Ok(Json(LoginResponse { login: token }))
}
