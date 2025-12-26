//! Session context endpoint

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::Serialize;
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::state::AppState;
use crate::store::{SessionId, SessionStore, UserStore};

const SESSION_COOKIE: &str = "browserid_session";

#[derive(Serialize)]
pub struct SessionContext {
    pub csrf_token: Option<String>,
    pub authenticated: bool,
    pub user_id: Option<u64>,
    pub server_time: i64,
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
    let session = cookies
        .get(SESSION_COOKIE)
        .and_then(|c| {
            let session_id = SessionId(c.value().to_string());
            state.session_store.get(&session_id).ok().flatten()
        });

    let context = if let Some(session) = session {
        SessionContext {
            csrf_token: Some(session.csrf_token),
            authenticated: true,
            user_id: Some(session.user_id.0),
            server_time: chrono::Utc::now().timestamp(),
            cookies: true,
        }
    } else {
        SessionContext {
            csrf_token: None,
            authenticated: false,
            user_id: None,
            server_time: chrono::Utc::now().timestamp(),
            cookies: true, // Assume cookies are enabled - the original checks for a test cookie
        }
    };

    Json(context)
}

/// Helper to get current session from cookies
pub fn get_session_from_cookies<S: SessionStore>(
    cookies: &Cookies,
    session_store: &S,
) -> Option<crate::store::Session> {
    cookies
        .get(SESSION_COOKIE)
        .and_then(|c| {
            let session_id = SessionId(c.value().to_string());
            session_store.get(&session_id).ok().flatten()
        })
}

/// Helper to set session cookie
pub fn set_session_cookie(cookies: &Cookies, session_id: &str) {
    use tower_cookies::Cookie;
    let cookie = Cookie::build((SESSION_COOKIE, session_id.to_string()))
        .path("/")
        .http_only(true)
        .build();
    cookies.add(cookie);
}

/// Helper to clear session cookie
pub fn clear_session_cookie(cookies: &Cookies) {
    use tower_cookies::Cookie;
    let cookie = Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .http_only(true)
        .max_age(tower_cookies::cookie::time::Duration::ZERO)
        .build();
    cookies.add(cookie);
}
