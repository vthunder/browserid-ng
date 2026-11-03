//! Authentication endpoints

use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use axum::Json;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::crypto::{hash_password, verify_password};
use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};

/// Minimum password length (same as original Persona)
const MIN_PASSWORD_LENGTH: usize = 8;
/// Maximum password length (same as original Persona)
const MAX_PASSWORD_LENGTH: usize = 80;

#[derive(Deserialize)]
pub struct AuthenticateRequest {
    pub email: String,
    pub pass: String,
}

#[derive(Serialize)]
pub struct AuthenticateResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/authenticate_user
/// Conservative brute-force throttle for password login (bean ytjn): at most
/// this many FAILED attempts per client IP per window, then 429 until the
/// window rolls over. Keyed by IP (not account) so no one can lock out a
/// victim; auto-resets, so there is no permanent lockout.
const LOGIN_MAX_FAILURES: u32 = 10;
const LOGIN_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);

/// How many fronting proxies append to `X-Forwarded-For` before the
/// request reaches the broker (`TRUSTED_PROXIES`, default 1: dokku's nginx).
/// The client address is the hop that many from the END of the list — a
/// client-supplied prefix is never trusted (audit 2026-11 W5-6). `0` means
/// the broker is reached directly: the header is ignored and the peer
/// address (`ConnectInfo`) is the client.
static TRUSTED_PROXIES: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// Default when `TRUSTED_PROXIES` is unset: one proxy (dokku's nginx).
pub const DEFAULT_TRUSTED_PROXIES: usize = 1;

/// Configure the trusted-proxy count once at startup (`main.rs`). Later
/// calls are ignored; tests and the default get [`DEFAULT_TRUSTED_PROXIES`].
pub fn set_trusted_proxies(n: usize) {
    let _ = TRUSTED_PROXIES.set(n);
}

pub(crate) fn trusted_proxies() -> usize {
    *TRUSTED_PROXIES.get().unwrap_or(&DEFAULT_TRUSTED_PROXIES)
}

/// The header `resolve_client_ip` stamps with the address it worked out.
/// Stripped from every incoming request, so only the middleware sets it.
pub(crate) const RESOLVED_CLIENT_IP: &str = "x-browserid-client-ip";

/// The client address according to `X-Forwarded-For` with `trusted` proxies
/// in front: the hop `trusted` from the end (the one the outermost trusted
/// proxy appended). `None` when there is nothing to trust (no proxies, or
/// no header). With fewer hops than proxies the first hop is taken — the
/// whole list was written by the proxies.
pub(crate) fn forwarded_client_ip(headers: &axum::http::HeaderMap, trusted: usize) -> Option<String> {
    if trusted == 0 {
        return None;
    }
    let hops: Vec<&str> = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())?
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if hops.is_empty() {
        return None;
    }
    Some(hops[hops.len().saturating_sub(trusted)].to_string())
}

/// The client IP every throttle keys on. Prefers the address
/// `resolve_client_ip` stamped (which knows the peer address); otherwise the
/// trusted `X-Forwarded-For` hop; otherwise a shared `unknown` bucket, which
/// still bounds a header-less attacker, just coarsely.
pub(crate) fn client_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(RESOLVED_CLIENT_IP)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| forwarded_client_ip(headers, trusted_proxies()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Outermost middleware: work the client address out once per request and
/// carry it in [`RESOLVED_CLIENT_IP`]. Any such header a client sent is
/// dropped first. Behind proxies the trusted `X-Forwarded-For` hop; reached
/// directly (`TRUSTED_PROXIES=0`) the connection's peer address.
pub(crate) async fn resolve_client_ip(mut req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    req.headers_mut().remove(RESOLVED_CLIENT_IP);
    let forwarded = forwarded_client_ip(req.headers(), trusted_proxies());
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string());
    if let Some(ip) = forwarded.or(peer) {
        if let Ok(v) = axum::http::HeaderValue::from_str(&ip) {
            req.headers_mut().insert(RESOLVED_CLIENT_IP, v);
        }
    }
    next.run(req).await
}

/// A real bcrypt hash of an unguessable random value, computed once per
/// process. Failure paths verify against it so a caller cannot tell from
/// timing whether the account existed or had a password at all.
fn dummy_password_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| {
        hash_password(&uuid::Uuid::new_v4().to_string()).expect("bcrypt never fails on a uuid")
    })
}

pub async fn authenticate_user<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    headers: axum::http::HeaderMap,
    Json(req): Json<AuthenticateRequest>,
) -> Result<Json<AuthenticateResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let ip = client_ip(&headers);

    // Throttle check (before any password work), fail-closed to 429.
    {
        let mut attempts = state.login_attempts.write().unwrap();
        let now = std::time::Instant::now();
        attempts.retain(|_, (start, _)| now.duration_since(*start) < LOGIN_WINDOW);
        if let Some((start, count)) = attempts.get(&ip) {
            if now.duration_since(*start) < LOGIN_WINDOW && *count >= LOGIN_MAX_FAILURES {
                return Err(BrokerError::LoginRateLimited);
            }
        }
    }

    // Record a failed attempt against `ip` (a fresh window if none/expired).
    let record_failure = || {
        let mut attempts = state.login_attempts.write().unwrap();
        let now = std::time::Instant::now();
        let entry = attempts.entry(ip.clone()).or_insert((now, 0));
        if now.duration_since(entry.0) >= LOGIN_WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
    };

    // Find user by email. A missing account, a password-less account (empty
    // or unparsable hash), and a wrong password must all be indistinguishable
    // in body, status, AND timing (audit M7) — so every failure path still
    // pays for one bcrypt verification. The dummy compare uses a real hash of
    // an unguessable value, so it can never accidentally succeed.
    let user = state.user_store.get_user_by_email(&req.email)?;

    let valid = match &user {
        Some(u) => match verify_password(&req.pass, &u.password_hash) {
            Ok(v) => v,
            // Empty/unparsable stored hash (a password-less account, e.g.
            // bridge-established): burn the same bcrypt cost, then fail.
            Err(_) => {
                let _ = verify_password(&req.pass, dummy_password_hash());
                false
            }
        },
        None => {
            let _ = verify_password(&req.pass, dummy_password_hash());
            false
        }
    };

    if !valid {
        record_failure();
        return Err(BrokerError::InvalidCredentials);
    }
    // valid ⇒ user exists.
    let user = user.unwrap();

    // Success clears this IP's failure counter.
    state.login_attempts.write().unwrap().remove(&ip);

    // Create session — Full: the account password was just verified. The
    // password proves every broker-vouched address on the account (bean
    // 160l): those are the identities this session may issue for — or
    // re-verify, so an address a reset unverified (kgb9) stays in reach —
    // before the registry admits the browser. Primary addresses are their
    // own IdP's to prove.
    let proved: Vec<String> = state
        .user_store
        .list_emails(user.id)?
        .into_iter()
        .filter(|e| e.email_type != crate::store::EmailType::Primary)
        .map(|e| e.email)
        .collect();
    let session = state
        .session_store
        .create(user.id, crate::store::SessionLevel::Full, proved)?;
    super::session::set_session_cookie(
        &cookies,
        &session.id.0,
        super::session::cookie_secure(&state.domain),
    );

    Ok(Json(AuthenticateResponse {
        success: true,
        userid: Some(user.id.0),
        reason: None,
    }))
}

#[derive(Serialize)]
pub struct LogoutResponse {
    pub success: bool,
}

#[derive(Deserialize, Default)]
pub struct LogoutRequest {
    #[serde(default)]
    pub csrf: String,
}

/// POST /wsapi/logout
pub async fn logout<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    req: Option<Json<LogoutRequest>>,
) -> Result<Json<LogoutResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Get and delete session (CSRF-gated: forced logout is a nuisance vector)
    if let Some(session) = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref()) {
        super::session::require_csrf(&session, &req.unwrap_or_default().csrf)?;
        let _ = state.session_store.delete(&session.id);
    }

    super::session::clear_session_cookie(&cookies);

    Ok(Json(LogoutResponse { success: true }))
}

#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
    pub oldpass: String,
    pub newpass: String,
    #[serde(default)]
    pub csrf: String,
}

#[derive(Serialize)]
pub struct UpdatePasswordResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/update_password
/// Update the user's password (requires authentication)
pub async fn update_password<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<UpdatePasswordRequest>,
) -> Result<Json<UpdatePasswordResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Require authentication
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;
    // Account-wide: admitted browsers only (bean 160l).
    super::session::require_admitted(&session)?;

    // Validate new password length
    if req.newpass.len() < MIN_PASSWORD_LENGTH {
        return Err(BrokerError::PasswordTooShort);
    }
    if req.newpass.len() > MAX_PASSWORD_LENGTH {
        return Err(BrokerError::PasswordTooLong);
    }

    // Get user
    let user = state
        .user_store
        .get_user(session.user_id)?
        .ok_or(BrokerError::UserNotFound)?;

    // Verify old password
    let valid = verify_password(&req.oldpass, &user.password_hash)
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

    if !valid {
        return Err(BrokerError::InvalidCredentials);
    }

    // Hash new password
    let new_hash = hash_password(&req.newpass)
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

    // Update password
    state.user_store.update_password(session.user_id, &new_hash)?;

    // Evict every existing session for this user (audit H2), then mint a fresh
    // one for the caller so the password change also logs out any other live
    // session (e.g. a co-resident attacker) without logging *this* user out.
    state.session_store.delete_by_user(session.user_id)?;
    // And every registry login key the OLD password let in (audit 2026-11
    // W5-4, decision Q4 (a)): a key enrolled through the login page by
    // password — except the one this very session is bound to — is revoked
    // and its bearer sessions ended, so a wallet an attacker enrolled with
    // the old password does not keep the account. Keys enrolled by identity
    // proofs or by approval stay: the password never vouched for them.
    for k in state.user_store.list_login_certs(session.user_id)? {
        if k.revoked_at.is_some()
            || k.enrolled_by != browserid_registrar::policy::ENROLLED_BY_PASSWORD
            || session.login_key_id == Some(k.id)
        {
            continue;
        }
        state.user_store.revoke_login_cert(session.user_id, k.id)?;
        state.user_store.end_sessions_on_login_key(session.user_id, k.id).ok();
        tracing::info!(kid = %k.kid, "update_password: retired a password-enrolled login key");
    }
    let fresh = super::session::recreate_session(
        state.session_store.as_ref(),
        &session,
        crate::store::SessionLevel::Full,
    )?;
    super::session::set_session_cookie(
        &cookies,
        &fresh.id.0,
        super::session::cookie_secure(&state.domain),
    );

    Ok(Json(UpdatePasswordResponse {
        success: true,
        reason: None,
    }))
}

#[derive(Deserialize)]
pub struct SetPasswordRequest {
    pub pass: String,
    #[serde(default)]
    pub csrf: String,
}

#[derive(Serialize)]
pub struct SetPasswordResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/set_password
/// First password for a signed-in passwordless account (browserid-ng-iudv).
/// The session already proves control of the account (it was established by a
/// primary presentation, bridge claim, or SMTP verification), so no mailed
/// code is needed — unlike the reset flow, which is the cold/no-session path.
/// Refused once a password exists: changing it requires the old password
/// (update_password) or the reset ceremony.
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
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;

    if req.pass.len() < MIN_PASSWORD_LENGTH {
        return Err(BrokerError::PasswordTooShort);
    }
    if req.pass.len() > MAX_PASSWORD_LENGTH {
        return Err(BrokerError::PasswordTooLong);
    }

    if state.user_store.has_password(session.user_id)? {
        return Err(BrokerError::ValidationError(
            "account already has a password".to_string(),
        ));
    }

    let hash = hash_password(&req.pass).map_err(|e| BrokerError::Internal(e.to_string()))?;
    state.user_store.set_password(session.user_id, &hash)?;

    // The caller just chose — and therefore knows — the account password, so
    // re-mint this session as Full (ca29). Without this, the set-on-add flow
    // would demand the same password again at the very next E3 mint. Only the
    // current session upgrades; other live sessions keep their own level
    // (this is not a recovery event, so no delete_by_user).
    state.session_store.delete(&session.id)?;
    let fresh = super::session::recreate_session(
        state.session_store.as_ref(),
        &session,
        crate::store::SessionLevel::Full,
    )?;
    super::session::set_session_cookie(
        &cookies,
        &fresh.id.0,
        super::session::cookie_secure(&state.domain),
    );

    Ok(Json(SetPasswordResponse {
        success: true,
        reason: None,
    }))
}

#[cfg(test)]
mod client_ip_tests {
    use super::*;
    use axum::http::HeaderMap;

    fn h(xff: Option<&str>) -> HeaderMap {
        let mut m = HeaderMap::new();
        if let Some(v) = xff {
            m.insert("x-forwarded-for", v.parse().unwrap());
        }
        m
    }

    #[test]
    fn takes_the_hop_the_trusted_proxy_appended_not_a_spoofed_prefix() {
        // The client sent `X-Forwarded-For: 1.2.3.4`; nginx appended the
        // connection address. One trusted proxy → the appended hop wins.
        assert_eq!(forwarded_client_ip(&h(Some("1.2.3.4, 203.0.113.7")), 1).as_deref(), Some("203.0.113.7"));
        assert_eq!(forwarded_client_ip(&h(Some("203.0.113.7")), 1).as_deref(), Some("203.0.113.7"));
        // Two proxies: the hop the outer one appended.
        assert_eq!(forwarded_client_ip(&h(Some("1.2.3.4, 203.0.113.7, 10.0.0.2")), 2).as_deref(), Some("203.0.113.7"));
        // Fewer hops than proxies: the whole list is the proxies' — first hop.
        assert_eq!(forwarded_client_ip(&h(Some("203.0.113.7")), 2).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn direct_exposure_ignores_the_header_entirely() {
        assert_eq!(forwarded_client_ip(&h(Some("1.2.3.4")), 0), None);
        assert_eq!(forwarded_client_ip(&h(None), 1), None);
        assert_eq!(client_ip(&h(None)), "unknown");
    }

    #[test]
    fn x_real_ip_is_not_trusted_and_the_resolved_header_wins() {
        let mut m = h(Some("1.2.3.4, 203.0.113.7"));
        m.insert("x-real-ip", "9.9.9.9".parse().unwrap());
        assert_eq!(client_ip(&m), "203.0.113.7");
        m.insert(RESOLVED_CLIENT_IP, "198.51.100.3".parse().unwrap());
        assert_eq!(client_ip(&m), "198.51.100.3");
    }
}
