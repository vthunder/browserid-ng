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
    /// Values: "password" (Full session), "assertion" (Lightweight session),
    /// or null for unauthenticated — no longer hard-coded (browserid-ng-ca29).
    pub auth_level: Option<String>,
    /// How the session was established: "full" (password) or "lightweight"
    /// (E1/E2 proof). The dialog branches on this — e.g. selecting an SMTP
    /// (E3) address under a lightweight session prompts for the password.
    pub session_level: Option<String>,
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
    /// This broker's own issuer domain — the fallback IdP identity it stamps
    /// on secondary certs. The dialog checks it against the RP's
    /// `acceptedFallbacks` (spec §8.1) to know whether email sign-in here is
    /// acceptable to the RP.
    pub domain: String,
    /// The registry account's public id (registry-api-v1 §3) when
    /// authenticated: what the /account page logs in to as its own
    /// device (a login key, no identity certs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Whether the registry has admitted this browser: the session is bound
    /// to a login key enrolled on the account (bean 160l). Until then the
    /// account-wide cookie endpoints answer `403 not_admitted`.
    pub admitted: bool,
    /// The identities this session proved itself — what an unadmitted
    /// session may still do issuer-role work for (issue, re-verify, set a
    /// first password). Never the account's roster; that is `list_emails`,
    /// admitted only.
    pub proved_emails: Vec<String>,
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
        // The account id stays visible to an unadmitted session: it is the
        // opaque handle the device needs to log in to the registry (§4.2)
        // — the very step that admits it — and reveals nothing else.
        let account = state.user_store.account_public_id(session.user_id).ok();
        SessionContext {
            account,
            admitted: session.admitted(),
            proved_emails: session.proved_emails.clone(),
            csrf_token: Some(session.csrf_token),
            authenticated: true,
            auth_level: Some(match session.level {
                crate::store::SessionLevel::Full => "password".to_string(),
                crate::store::SessionLevel::Lightweight => "assertion".to_string(),
            }),
            session_level: Some(session.level.as_str().to_string()),
            user_id: Some(session.user_id.0),
            userid: Some(session.user_id.0),
            server_time,
            domain_key_creation_time,
            cookies: true,
            domain: state.domain.clone(),
        }
    } else {
        SessionContext {
            csrf_token: None,
            authenticated: false,
            auth_level: None,
            session_level: None,
            user_id: None,
            userid: None,
            server_time,
            domain_key_creation_time,
            cookies: true, // Assume cookies are enabled - the original checks for a test cookie
            domain: state.domain.clone(),
            account: None,
            admitted: false,
            proved_emails: vec![],
        }
    };

    Json(context)
}

/// Refuse unless the registry has admitted this browser (bean 160l): the
/// session is bound to a login key enrolled on the account. Every
/// account-wide cookie endpoint — the roster, the browsers namespace,
/// parent links, names, removals, cancellation, the password change —
/// goes through this.
pub fn require_admitted(session: &crate::store::Session) -> Result<(), BrokerError> {
    if session.admitted() {
        Ok(())
    } else {
        Err(BrokerError::NotAdmitted)
    }
}

/// Replace `old` with a fresh session at `level` that keeps what the old
/// one had earned: the identities it proved and its admission. Used where
/// a password change re-mints the caller's session.
pub fn recreate_session<S: SessionStore>(
    store: &S,
    old: &crate::store::Session,
    level: crate::store::SessionLevel,
) -> Result<crate::store::Session, BrokerError> {
    let fresh = store.create(old.user_id, level, old.proved_emails.clone())?;
    if let Some(id) = old.login_key_id {
        store.bind_login_key(&fresh.id, id)?;
    }
    Ok(fresh)
}

#[derive(Serialize)]
pub struct SessionAdmitResponse {
    pub success: bool,
    pub admitted: bool,
}

/// POST /wsapi/session_admit — bind the cookie session to the registry
/// login key the call is made under (bean 160l; broker-private, the
/// co-located issuer + registry case). The call carries the registry's
/// `Authorization: Bearer` + `Proof` by the login key — the same §4.4 path
/// `/device/issue` accepts — so the registry, not the cookie, vouches that
/// this browser is enrolled on the account. Refused when the registry
/// session's account is not the cookie session's. Idempotent.
pub async fn session_admit<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<SessionAdmitResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    let registrar = state
        .registrar
        .get()
        .ok_or_else(|| BrokerError::Internal("registrar not wired".into()))?;
    let bh = browserid_registrar::session::b64url_sha256_pub(&body);
    let (rec, key, _proof) = browserid_registrar::session::verify_session_call(
        registrar,
        &headers,
        "POST",
        "/wsapi/session_admit",
        Some(&bh),
    )
    .await
    .map_err(|e| BrokerError::PolicyRefused(format!("registry session: {e:?}")))?;
    if rec.user_id != session.user_id.0 || key.user_id != session.user_id.0 {
        return Err(BrokerError::PolicyRefused(
            "the registry session is not on this account".into(),
        ));
    }
    if !key.is_live() {
        return Err(BrokerError::PolicyRefused("the login key is not live".into()));
    }
    if session.login_key_id != Some(key.id) {
        state.session_store.bind_login_key(&session.id, key.id)?;
    }
    Ok(Json(SessionAdmitResponse { success: true, admitted: true }))
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
    set_fedcm_cookie(cookies, session_id);
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
    clear_fedcm_cookie(cookies);
}

/// The FedCM sibling of the session cookie (browserid-ng-mhyp). FedCM fetches
/// the accounts endpoint credentialed but from the RP's (cross-site) page
/// context, so a `SameSite=Lax` cookie is NOT sent — the accounts endpoint
/// couldn't identify the user. We therefore mint a SEPARATE, minimal
/// `SameSite=None` cookie carrying the same session id, scoped to `/fedcm`, and
/// leave the CSRF-hardened `Lax` session untouched. `SameSite=None` requires
/// `Secure`; browsers make an exception for localhost, so we always set it.
const FEDCM_COOKIE: &str = "browserid_fedcm";

fn set_fedcm_cookie(cookies: &Cookies, session_id: &str) {
    use tower_cookies::cookie::SameSite;
    use tower_cookies::Cookie;
    let cookie = Cookie::build((FEDCM_COOKIE, session_id.to_string()))
        .path("/fedcm")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::None)
        .max_age(tower_cookies::cookie::time::Duration::seconds(
            SESSION_MAX_AGE_SECONDS,
        ))
        .build();
    cookies.add(cookie);
}

fn clear_fedcm_cookie(cookies: &Cookies) {
    use tower_cookies::cookie::SameSite;
    use tower_cookies::Cookie;
    let cookie = Cookie::build((FEDCM_COOKIE, ""))
        .path("/fedcm")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::None)
        .max_age(tower_cookies::cookie::time::Duration::ZERO)
        .build();
    cookies.add(cookie);
}

/// Resolve the session for a FedCM endpoint: prefer the dedicated `SameSite=None`
/// FedCM cookie (what a real browser sends cross-site), falling back to the
/// regular session cookie (same-site calls and tests).
pub fn get_fedcm_session<S: SessionStore>(
    cookies: &Cookies,
    session_store: &S,
) -> Option<crate::store::Session> {
    let raw = cookies
        .get(FEDCM_COOKIE)
        .or_else(|| cookies.get(SESSION_COOKIE))?;
    let session_id = SessionId(raw.value().to_string());
    let session = session_store.get(&session_id).ok().flatten()?;
    let age = chrono::Utc::now() - session.created_at;
    if age > chrono::Duration::seconds(SESSION_MAX_AGE_SECONDS) {
        let _ = session_store.delete(&session_id);
        return None;
    }
    Some(session)
}
