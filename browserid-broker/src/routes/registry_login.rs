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
use crate::store::{SessionStore, UserId, UserStore};

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


// ---------------------------------------------------------------------------
// Identity proofs as a login method (bean d26p): the page — or the wallet
// directly — hands over presentations for this origin's own audience, one
// per identity of the account; enough of them (the account's rule, §5.2.7)
// earn the token. After one valid proof the page may ask for the account's
// other identities as masked hints, so the person knows what else to prove.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ProofsRequest {
    pub account: String,
    pub presentations: Vec<String>,
}

#[derive(Serialize)]
pub struct HintsResponse {
    /// Masked addresses of the account's other active identities.
    pub hints: Vec<String>,
    /// Identities proven by the presentations sent.
    pub proven: Vec<String>,
    /// How many distinct identities the rule wants.
    pub needed: u32,
}

/// `d***@sandmill.org`: the first character and the domain.
pub fn mask_address(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let first = local.chars().next().map(|c| c.to_string()).unwrap_or_default();
            format!("{first}***@{domain}")
        }
        None => "***".into(),
    }
}

fn rate_limited<U: UserStore, S: SessionStore, E: EmailSender>(state: &AppState<U, S, E>, ip: &str) -> Result<(), BrokerError> {
    let mut attempts = state.login_attempts.write().unwrap();
    let now = std::time::Instant::now();
    attempts.retain(|_, (start, _)| now.duration_since(*start) < LOGIN_WINDOW);
    if let Some((_, count)) = attempts.get(&format!("registry-login|{ip}")) {
        if *count >= LOGIN_MAX_FAILURES {
            return Err(BrokerError::LoginRateLimited);
        }
    }
    Ok(())
}

fn count_failure<U: UserStore, S: SessionStore, E: EmailSender>(state: &AppState<U, S, E>, ip: &str) {
    let mut attempts = state.login_attempts.write().unwrap();
    let entry = attempts.entry(format!("registry-login|{ip}")).or_insert((std::time::Instant::now(), 0));
    entry.1 += 1;
}

/// Verify presentations for this origin's own audience and keep those
/// naming an active identity of `user_id`: the distinct identities proven.
async fn proven_identities<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    user_id: UserId,
    presentations: &[String],
) -> Result<Vec<String>, BrokerError> {
    if presentations.is_empty() || presentations.len() > 8 {
        return Err(rejected());
    }
    let fetcher = state
        .fallback_fetcher()
        .await
        .map_err(|e| BrokerError::Internal(format!("DNS discovery not configured: {e}")))?;
    let audience = browserid_registrar::consent::public_origin(&state.domain);
    let accepted = vec![state.domain.clone()];
    let is_own_revoked = |idx: u64| state.user_store.is_status_revoked_idx(idx).map_err(|e| e.to_string());
    let active: Vec<String> = crate::membership::roster(state.user_store.as_ref(), user_id)?
        .into_iter()
        .filter(|(_, s)| *s == "active")
        .map(|(i, _)| i.to_lowercase())
        .collect();
    let mut proven: Vec<String> = Vec::new();
    for p in presentations {
        let status = crate::verifier::StatusCtx {
            own_uri: browserid_registrar::consent::status_list_uri(&state.domain),
            is_own_revoked: &is_own_revoked,
            cache: &state.foreign_status_lists,
            allow_private_hosts: !super::session::cookie_secure(&state.domain),
        };
        let r = crate::verifier::verify_access_with_dns(p, &audience, fetcher.as_ref(), &accepted, status).await;
        if r.status != "okay" {
            return Err(rejected());
        }
        let email = r.email.map(|e| e.to_lowercase()).ok_or_else(rejected)?;
        if !active.iter().any(|a| *a == email) {
            return Err(rejected());
        }
        if !proven.contains(&email) {
            proven.push(email);
        }
    }
    Ok(proven)
}

/// `POST /wsapi/registry_login_hints { account, presentations }` — after at
/// least one valid proof: the other identities, masked, and how many the
/// rule wants. Never reveals anything about an account no proof reaches.
pub async fn hints<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ProofsRequest>,
) -> Result<Json<HintsResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let ip = super::auth::client_ip(&headers);
    rate_limited(&state, &ip)?;
    let Some(user_id) = state.user_store.user_for_public_id(req.account.trim())? else {
        count_failure(&state, &ip);
        return Err(rejected());
    };
    let proven = match proven_identities(&state, user_id, &req.presentations).await {
        Ok(p) => p,
        Err(e) => { count_failure(&state, &ip); return Err(e); }
    };
    let policy = account_auth::account_policy(state.user_store.as_ref(), user_id)?;
    let identities = account_auth::identity_count(state.user_store.as_ref(), user_id)?;
    let needed = policy.proofs.unwrap_or(browserid_registrar::policy::BASELINE_PROOFS).min(identities.max(1));
    let hints: Vec<String> = crate::membership::roster(state.user_store.as_ref(), user_id)?
        .into_iter()
        .filter(|(i, s)| *s == "active" && !proven.iter().any(|p| p.eq_ignore_ascii_case(i)))
        .map(|(i, _)| mask_address(&i))
        .collect();
    Ok(Json(HintsResponse { hints, proven, needed }))
}

/// `POST /wsapi/registry_login_proofs { account, presentations }` — the
/// identities proven against the account's add-a-device rule; a token
/// when it is met, `login_rejected` otherwise.
pub async fn proofs<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ProofsRequest>,
) -> Result<Json<LoginResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let ip = super::auth::client_ip(&headers);
    rate_limited(&state, &ip)?;
    let Some(user_id) = state.user_store.user_for_public_id(req.account.trim())? else {
        count_failure(&state, &ip);
        return Err(rejected());
    };
    let proven = match proven_identities(&state, user_id, &req.presentations).await {
        Ok(p) => p,
        Err(e) => { count_failure(&state, &ip); return Err(e); }
    };
    let proofs: Vec<Proof> = proven.iter().map(|i| Proof::Identity(i.clone())).collect();
    let token = account_auth::login_token_for(state.user_store.as_ref(), user_id, &proofs).map_err(|_| {
        count_failure(&state, &ip);
        rejected()
    })?;
    tracing::info!(proven = proven.len(), "registry login: by identity proofs");
    Ok(Json(LoginResponse { login: token }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn masks_keep_the_first_character_and_the_domain() {
        assert_eq!(super::mask_address("dan@sandmill.org"), "d***@sandmill.org");
        assert_eq!(super::mask_address("vthunder@gmail.com"), "v***@gmail.com");
    }
}
