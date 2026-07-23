//! FedCM IdP endpoints (spike browserid-ng-mhyp, ported to the device-cert
//! model).
//!
//! browserid.me acts as a FedCM Identity Provider for **fallback** identities:
//! the browser mediates a native account chooser and we mint a *standard*
//! device-model presentation (`access_cert~assertion~warrant~config_cert`)
//! SERVER-side (the "silent lane" — no client keystore is involved, by FedCM's
//! design: the token comes from an IdP HTTP endpoint, so no client JS can
//! sign). The ephemeral access/config keys live only inside this one request
//! and are discarded — the same server-custody property the classic FedCM lane
//! had. The token is byte-compatible with the popup path, so `/verify-access`
//! and every verifier library are unchanged.
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

use browserid_core::device::{AccessCert, DeviceCert, Purpose, Warrant};
use browserid_core::Assertion;

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

/// `POST /fedcm/assertion` — mint a device-model presentation for the chosen
/// account, scoped to the RP origin (the `Origin` header = the audience). Uses
/// throwaway ephemeral keys generated and discarded within the request, so no
/// new persistent key custody is introduced.
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

    // SERVER-SIDE auto-login enforcement (browserid-ng-mhyp). FedCM reports
    // whether the token was AUTO-selected (silent auto-reauthn) vs the user
    // picking in the chooser (interactive). We refuse a *silent* token unless the
    // user opted into auto-login for THIS RP on a prior interactive selection —
    // so the client can't obtain a silent assertion just by asking. An
    // interactive selection is the opt-in and is recorded after minting below.
    let session_id = session.id.0.clone();
    let is_auto = req.is_auto_selected.as_deref() == Some("true");
    if is_auto {
        let allowed = state
            .fedcm_autologin
            .read()
            .await
            .get(&session_id)
            .map(|set| set.contains(&rp_origin))
            .unwrap_or(false);
        if !allowed {
            return err(
                StatusCode::FORBIDDEN,
                "silent auto-login not authorized for this site",
            );
        }
    }

    // Mint the standard 4-object presentation entirely server-side: the broker
    // (as this fallback identity's IdP) certifies a throwaway access key and a
    // throwaway config key, the config key signs a login warrant for the RP
    // audience, the access key signs the assertion — then both private keys are
    // discarded with the request. Short-lived across the board: FedCM tokens
    // are consumed immediately by the RP's verifier.
    let email = &email_record.email;
    let access_kp = browserid_core::KeyPair::generate();
    let config_kp = browserid_core::KeyPair::generate();
    let validity = Duration::minutes(ASSERTION_VALIDITY_MINS);
    // A browsers-namespace holder for this silent login; the warrant grants the
    // whole namespace (`<prefix>.*`) so a login reuses across the user's
    // browsers (holder-authorization model).
    let ns_prefix = match state.user_store.get_or_create_namespace(session.user_id, "browsers") {
        Ok(p) => p,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("namespace: {e}")),
    };
    let holder = match browserid_core::device::Holder::new(crate::crypto::assign_holder_id(&ns_prefix)) {
        Ok(h) => h,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("holder: {e}")),
    };
    let login_matcher = match browserid_core::device::HolderMatcher::new(format!("{ns_prefix}.*")) {
        Ok(m) => m,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("matcher: {e}")),
    };
    let access_cert = match AccessCert::create(
        &state.domain, email, holder.clone(), &access_kp.public_key(),
        validity, &state.keypair, None,
    ) {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("access cert: {e}")),
    };
    let config_cert = match DeviceCert::create(
        &state.domain, &config_kp.public_key(), Purpose::Authorization, holder.clone(),
        vec![email.clone()], validity, &state.keypair, None,
    ) {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("config cert: {e}")),
    };
    let warrant = match Warrant::create(
        email, email, login_matcher, &rp_origin, vec!["login".to_string()],
        validity, &config_kp, None,
    ) {
        Ok(w) => w,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("warrant: {e}")),
    };
    let assertion = match Assertion::create(&rp_origin, validity, &access_kp) {
        Ok(a) => a,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("assertion: {e}")),
    };
    let token = format!(
        "{}~{}~{}~{}",
        access_cert.encoded(), assertion.encoded(), warrant.encoded(), config_cert.encoded()
    );

    // Register the login warrant like the dialog path does, so FedCM logins
    // also appear (and are forgettable) under "Authorized sites". Best-effort:
    // a registry hiccup must not fail the login.
    {
        let now = chrono::Utc::now();
        let rec = crate::store::WarrantRecord {
            id: 0,
            user_id: session.user_id,
            delegator_email: email.clone(),
            agent_email: email.clone(),
            audience: rp_origin.clone(),
            scopes: vec!["login".to_string()],
            warrant: warrant.encoded().to_string(),
            status_idx: None,
            holder: Some(format!("{ns_prefix}.*")),
            config_cert: Some(config_cert.encoded().to_string()),
            signed_at: now,
            expires_at: now + Duration::seconds(validity.num_seconds()),
        };
        if let Err(e) = state.user_store.upsert_warrant(rec) {
            tracing::warn!("fedcm: warrant registration failed (non-fatal): {e}");
        }
    }

    // Interactive selection = the opt-in: remember it so future SILENT
    // auto-reauthns for this RP are allowed (see the is_auto gate above).
    if !is_auto {
        state
            .fedcm_autologin
            .write()
            .await
            .entry(session_id)
            .or_default()
            .insert(rp_origin.clone());
    }

    // FedCM requires the id-assertion response to allow the specific RP origin
    // with credentials (never `*`).
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

/// `POST /fedcm/reset` — called by include.js on RP logout to DISABLE silent
/// auto-login for that RP (clears the `(session, RP)` consent). Fail-safe: it
/// only ever *removes* consent, so no `Sec-Fetch-Dest` gate is needed.
/// Credentialed (the FedCM cookie identifies the session).
pub async fn reset<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: HeaderMap,
    cookies: Cookies,
) -> Response
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
    E: EmailSender + 'static,
{
    let rp_origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if let (Some(session), Some(origin)) = (
        super::session::get_fedcm_session(&cookies, state.session_store.as_ref()),
        rp_origin.clone(),
    ) {
        if let Some(set) = state.fedcm_autologin.write().await.get_mut(&session.id.0) {
            set.remove(&origin);
        }
    }
    let mut resp = StatusCode::OK.into_response();
    if let Some(origin) = rp_origin {
        if let Ok(v) = HeaderValue::from_str(&origin) {
            resp.headers_mut()
                .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
            resp.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
    }
    resp
}
