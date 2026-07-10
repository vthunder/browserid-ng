//! Session context endpoint

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::Serialize;
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{SessionId, SessionStore, UserStore};

const SESSION_COOKIE: &str = "browserid_session";

/// Sessions (and their cookie) expire this long after creation. Enforced
/// server-side in [`get_session_from_cookies`] so a replayed cookie dies with
/// the session row, not just in the browser.
pub const SESSION_MAX_AGE_SECONDS: i64 = 30 * 24 * 3600;

/// Whether cookies for this deployment should carry `Secure` (everything but
/// plain-http localhost dev).
pub fn cookie_secure(domain: &str) -> bool {
    !(domain.starts_with("localhost") || domain.starts_with("127."))
}

#[derive(Serialize)]
pub struct SessionContext {
    pub csrf_token: Option<String>,
    pub authenticated: bool,
    /// auth_level is used by the frontend (UserContext) to determine authentication status
    /// Values: "password", "assertion", or null for unauthenticated
    pub auth_level: Option<String>,
    pub user_id: Option<u64>,
    /// userid is used by the frontend (UserContext) for user identification
    pub userid: Option<u64>,
    pub server_time: i64,
    /// domain_key_creation_time is used by the frontend to check if certs are still valid
    /// This should be the timestamp when the domain's signing key was created
    pub domain_key_creation_time: i64,
    /// Whether the client has cookies enabled
    /// The communication_iframe checks this to know if it can proceed
    pub cookies: bool,
}

/// GET /wsapi/session_context
pub async fn get_session_context<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Json<SessionContext>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = get_session_from_cookies(&cookies, state.session_store.as_ref());

    let server_time = chrono::Utc::now().timestamp();
    // domain_key_creation_time: when the signing key was created
    // For simplicity, we use the start of time (0) so all certs are considered valid
    let domain_key_creation_time = 0i64;

    let context = if let Some(session) = session {
        SessionContext {
            csrf_token: Some(session.csrf_token),
            authenticated: true,
            auth_level: Some("password".to_string()),
            user_id: Some(session.user_id.0),
            userid: Some(session.user_id.0),
            server_time,
            domain_key_creation_time,
            cookies: true,
        }
    } else {
        SessionContext {
            csrf_token: None,
            authenticated: false,
            auth_level: None,
            user_id: None,
            userid: None,
            server_time,
            domain_key_creation_time,
            cookies: true, // Assume cookies are enabled - the original checks for a test cookie
        }
    };

    Json(context)
}

/// Helper to get current session from cookies. Sessions past
/// [`SESSION_MAX_AGE_SECONDS`] are treated as absent and deleted.
pub fn get_session_from_cookies<S: SessionStore>(
    cookies: &Cookies,
    session_store: &S,
) -> Option<crate::store::Session> {
    let session_id = SessionId(cookies.get(SESSION_COOKIE)?.value().to_string());
    let session = session_store.get(&session_id).ok().flatten()?;
    let age = chrono::Utc::now() - session.created_at;
    if age > chrono::Duration::seconds(SESSION_MAX_AGE_SECONDS) {
        let _ = session_store.delete(&session_id);
        return None;
    }
    Some(session)
}

/// Require that the caller presented the session's CSRF token. All
/// session-authenticated state-changing endpoints go through this.
pub fn require_csrf(session: &crate::store::Session, csrf: &str) -> Result<(), BrokerError> {
    if !csrf.is_empty() && session.csrf_token == csrf {
        Ok(())
    } else {
        Err(BrokerError::InvalidCsrf)
    }
}

/// Helper to set session cookie. `SameSite=Lax` deliberately drops the
/// third-party-iframe case (communication_iframe silent session checks) —
/// modern browsers block third-party cookies there anyway; the dialog is a
/// top-level popup and unaffected.
pub fn set_session_cookie(cookies: &Cookies, session_id: &str, secure: bool) {
    use tower_cookies::cookie::SameSite;
    use tower_cookies::Cookie;
    let cookie = Cookie::build((SESSION_COOKIE, session_id.to_string()))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(tower_cookies::cookie::time::Duration::seconds(
            SESSION_MAX_AGE_SECONDS,
        ))
        .build();
    cookies.add(cookie);
}

/// Helper to clear session cookie
pub fn clear_session_cookie(cookies: &Cookies) {
    use tower_cookies::cookie::SameSite;
    use tower_cookies::Cookie;
    let cookie = Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(tower_cookies::cookie::time::Duration::ZERO)
        .build();
    cookies.add(cookie);
}
