//! FedCM IdP endpoints (spike browserid-ng-mhyp).
//!
//! browserid.me acts as a FedCM Identity Provider for **fallback** identities:
//! the browser mediates a native account chooser and we mint a *standard*
//! `cert~assertion` server-side (the "silent lane" — no client keystore is
//! involved, by FedCM's design). The token is byte-identical to the popup path,
//! so `/verify` and every verifier library are unchanged.
//!
//! Fallback-only: we only surface **Secondary** emails — the ones browserid.me
//! itself verified over SMTP and is therefore authoritative for. Primary emails
//! (their own domain is the IdP) and Agent identities are never returned; they
//! keep using the popup dialog.
//!
//! Not yet wired for a real browser (see the bean): `Set-Login` status,
//! passkey-account filtering, and end-to-end Chromium validation are follow-ups.
//! The assertion CORS headers below are best-effort pending that validation.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use chrono::Duration;
use serde::Deserialize;
use serde_json::json;
use tower_cookies::Cookies;

use browserid_core::{Assertion, BackedAssertion, Certificate};

use crate::email::EmailSender;
use crate::state::AppState;
use crate::store::models::EmailType;
use crate::store::{SessionStore, UserStore};

/// FedCM assertions are short-lived, like the popup path's ephemeral certs.
const ASSERTION_VALIDITY_MINS: i64 = 5;

fn origin(domain: &str) -> String {
    if domain.starts_with("localhost") || domain.starts_with("127.") {
        format!("http://{domain}")
    } else {
        format!("https://{domain}")
    }
}

/// The browser sets `Sec-Fetch-Dest: webidentity` on genuine FedCM requests, and
/// page JS (`fetch`/XHR) cannot forge it (it's a forbidden header). Gating the
/// credentialed endpoints on it is what prevents a malicious site from
/// cross-site `fetch()`-ing them with the (cross-site-sent) FedCM cookie and
/// reading back a user's accounts or, worse, an assertion minted for the
/// attacker's own origin. Both credentialed endpoints MUST require it.
fn is_fedcm_request(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-dest")
        .and_then(|v| v.to_str().ok())
        == Some("webidentity")
}

/// `GET /.well-known/web-identity` — points the browser at our config file.
pub async fn web_identity<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
) -> Json<serde_json::Value>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    Json(json!({
        "provider_urls": [format!("{}/fedcm/config.json", origin(&state.domain))]
    }))
}

/// `GET /fedcm/config.json` — the FedCM IdP config.
pub async fn config<U, S, E>(
    State(_state): State<Arc<AppState<U, S, E>>>,
) -> Json<serde_json::Value>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    Json(json!({
        "accounts_endpoint": "/fedcm/accounts",
        "id_assertion_endpoint": "/fedcm/assertion",
        "login_url": "/account",
        "branding": {
            "name": "browserid.me"
        }
    }))
}

/// `GET /fedcm/accounts` — the fallback identities the signed-in user owns.
/// Credentialed (FedCM sends the `SameSite=None` cookie). Returns 401 with no
/// body when there's no session or no eligible account, per FedCM.
pub async fn accounts<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: HeaderMap,
    cookies: Cookies,
) -> Response
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    if !is_fedcm_request(&headers) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let Some(session) =
        super::session::get_fedcm_session(&cookies, state.session_store.as_ref())
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let emails = match state.user_store.list_emails(session.user_id) {
        Ok(e) => e,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let accounts: Vec<serde_json::Value> = emails
        .iter()
        .filter(|e| e.verified && e.email_type == EmailType::Secondary)
        .map(|e| {
            json!({
                "id": e.email,
                "email": e.email,
                "name": e.email,
                "login_hints": [e.email],
            })
        })
        .collect();

    if accounts.is_empty() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    Json(json!({ "accounts": accounts })).into_response()
}

/// Body of the id-assertion POST (FedCM sends `application/x-www-form-urlencoded`).
#[derive(Deserialize)]
pub struct AssertionForm {
    #[allow(dead_code)]
    pub client_id: Option<String>,
    pub account_id: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub disclosure_text_shown: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pub is_auto_selected: Option<String>,
    /// Serialized custom params from the RP's `get()` (may carry a nonce). The
    /// current assertion format binds audience + expiry only, so the nonce is
    /// not embedded yet — an optional future claim, no verifier change needed.
    #[allow(dead_code)]
    #[serde(default)]
    pub params: Option<String>,
}

/// `POST /fedcm/assertion` — mint a standard `cert~assertion` for the chosen
/// account, scoped to the RP origin (the `Origin` header = the audience). Uses a
/// throwaway ephemeral key generated and discarded within the request, so no new
/// persistent key custody is introduced.
pub async fn assertion<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: HeaderMap,
    cookies: Cookies,
    Form(req): Form<AssertionForm>,
) -> Response
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
    E: EmailSender + 'static,
{
    let err = |code: StatusCode, msg: &str| {
        (
            code,
            Json(json!({ "error": { "code": "access_denied", "detail": msg } })),
        )
            .into_response()
    };

    // CRITICAL: this endpoint echoes the RP origin with allow-credentials, so
    // without this gate a malicious page could cross-site fetch() it with the
    // FedCM cookie and read an assertion minted for its own origin. Sec-Fetch-Dest
    // is browser-set and unforgeable by fetch/XHR — only real FedCM passes.
    if !is_fedcm_request(&headers) {
        return err(StatusCode::BAD_REQUEST, "not a FedCM request");
    }

    // The RP origin FedCM is minting for = the audience the assertion binds to.
    let Some(rp_origin) = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    else {
        return err(StatusCode::BAD_REQUEST, "missing Origin");
    };

    let Some(session) =
        super::session::get_fedcm_session(&cookies, state.session_store.as_ref())
    else {
        return err(StatusCode::UNAUTHORIZED, "not authenticated");
    };

    // The account must be a Secondary (fallback) email this user owns — the same
    // fallback-only rule as /fedcm/accounts.
    let emails = match state.user_store.list_emails(session.user_id) {
        Ok(e) => e,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "store error"),
    };
    let Some(email_record) = emails.iter().find(|e| {
        e.email == req.account_id && e.verified && e.email_type == EmailType::Secondary
    }) else {
        return err(StatusCode::FORBIDDEN, "account not eligible");
    };

    // Mint identical cert~assertion: broker signs the cert over a throwaway
    // ephemeral key; that key signs the audience-bound assertion; discard it.
    let ephemeral = browserid_core::KeyPair::generate();
    let pubkey_json = super::cert::PublicKeyJson {
        algorithm: "Ed25519".to_string(),
        public_key: ephemeral.public_key().to_base64(),
    };

    let cert_str = match super::cert::issue_certificate(
        &state.domain,
        &state.keypair,
        state.user_store.as_ref(),
        email_record,
        &pubkey_json,
        true, // ephemeral
    ) {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("cert: {e:?}")),
    };
    let cert = match Certificate::parse(&cert_str) {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("parse cert: {e}")),
    };
    let assertion =
        match Assertion::create(&rp_origin, Duration::minutes(ASSERTION_VALIDITY_MINS), &ephemeral) {
            Ok(a) => a,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("assertion: {e}")),
        };
    let token = BackedAssertion::new(cert, assertion).encode();

    // FedCM requires the id-assertion response to allow the specific RP origin
    // with credentials (never `*`). Best-effort here pending browser validation.
    let mut resp = Json(json!({ "token": token })).into_response();
    if let Ok(v) = HeaderValue::from_str(&rp_origin) {
        resp.headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
        resp.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
    resp
}
