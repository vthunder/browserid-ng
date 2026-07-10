//! HTTP routes for the broker

mod account;
mod agent;
mod auth;
mod cert;
mod email;
mod primary;
mod reset;
mod session;
mod test;
mod verify;
pub(crate) mod warrant;
mod well_known;

use std::sync::Arc;

use axum::http::{header, HeaderValue, Method};
use axum::response::Html;
use axum::routing::{get, post};
use axum::Router;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::email::EmailSender;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};

/// Create the router with all routes
pub fn create_router<U, S, E>(state: Arc<AppState<U, S, E>>) -> Router
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
    E: EmailSender + 'static,
{
    create_router_with_static_path(state, "static")
}

/// Create the router with a custom static file path
pub fn create_router_with_static_path<U, S, E>(
    state: Arc<AppState<U, S, E>>,
    static_path: &str,
) -> Router
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
    E: EmailSender + 'static,
{
    Router::new()
        .route("/.well-known/browserid", get(well_known::get_support_document))
        .route("/wsapi/session_context", get(session::get_session_context))
        .route("/wsapi/stage_user", post(account::stage_user))
        .route("/wsapi/complete_user_creation", post(account::complete_user_creation))
        .route("/wsapi/user_creation_status", get(account::user_creation_status))
        // Admin seed provisioning (ADMIN_TOKEN-gated; for @mingo.place demo accounts)
        .route("/admin/create_account", post(account::admin_create_account))
        .route("/wsapi/authenticate_user", post(auth::authenticate_user))
        .route("/wsapi/logout", post(auth::logout))
        .route("/wsapi/update_password", post(auth::update_password))
        .route("/wsapi/list_emails", get(email::list_emails))
        .route("/wsapi/stage_email", post(email::stage_email))
        .route("/wsapi/complete_email_addition", post(email::complete_email_addition))
        .route("/wsapi/remove_email", post(email::remove_email))
        .route("/wsapi/address_info", get(email::address_info))
        .route("/wsapi/set_parent", post(email::set_parent))
        .route("/wsapi/parent_of", get(email::parent_of))
        .route("/wsapi/email_addition_status", get(email::email_addition_status))
        .route("/wsapi/cert_key", post(cert::cert_key))
        // Agent provisioning (tdxf, delegation chain) — 404 unless
        // state.agent_provisioning_enabled is set.
        // Browser-side registry management (session + CSRF):
        .route("/wsapi/provisioning_certs", get(agent::list_provisioning_certs))
        .route("/wsapi/register_provisioning_cert", post(agent::register_provisioning_cert))
        .route("/wsapi/revoke_provisioning_cert", post(agent::revoke_provisioning_cert))
        // Broker-as-endorser:
        .route("/provision/endorse", post(agent::endorse))
        // Broker-as-target-IdP (for @<broker-domain> agents):
        .route("/provision/reserve", post(agent::reserve))
        .route("/provision/mint", post(agent::mint))
        .route("/provision/list", post(agent::list))
        .route("/provision/revoke", post(agent::revoke))
        // Warrant consent flow (agent spec §6, v0.4)
        .route("/warrant/request", post(warrant::request))
        .route("/warrant/poll", post(warrant::poll))
        .route("/wsapi/warrant_requests", get(warrant::list_requests))
        .route("/wsapi/warrant_respond", post(warrant::respond))
        .route("/wsapi/warrants", get(warrant::list_warrants))
        .route("/wsapi/register_warrant", post(warrant::register_warrant))
        .route("/wsapi/forget_warrant", post(warrant::forget_warrant))
        .route("/wsapi/revoke_warrant", post(warrant::revoke_warrant))
        .route("/wsapi/allocate_warrant_status", post(warrant::allocate_warrant_status))
        // Signed revocation status list (core §6.4)
        .route("/.well-known/browserid-status", get(warrant::status_list))
        .route("/wsapi/account_cancel", post(account::account_cancel))
        .route("/wsapi/stage_reset", post(reset::stage_reset))
        .route("/wsapi/complete_reset", post(reset::complete_reset))
        .route("/wsapi/password_reset_status", get(reset::password_reset_status))
        // Primary IdP authentication
        .route("/wsapi/auth_with_assertion", post(primary::auth_with_assertion))
        .route("/wsapi/set_password", post(primary::set_password))
        // Verification endpoint
        .route("/verify", post(verify::verify))
        // Test endpoints (should only be enabled in dev/test)
        .route("/wsapi/test/pending_verification", get(test::get_pending_verification))
        .route("/wsapi/test/set_mock_primary_idp", post(test::set_mock_primary_idp))
        .route("/wsapi/test/clear_mock_primary_idps", post(test::clear_mock_primary_idps))
        .route("/wsapi/test/remove_mock_primary_idp", post(test::remove_mock_primary_idp))
        // Compatibility routes for include.js
        .route("/sign_in", get(sign_in_return))
        .nest_service("/relay", ServeDir::new(format!("{}/relay", static_path)))
        .route_service("/include.js", ServeFile::new(format!("{}/include.js", static_path)))
        .route_service("/communication_iframe", ServeFile::new(format!("{}/communication_iframe.html", static_path)))
        // API shims for primary IdP pages
        .route_service("/provisioning_api.js", ServeFile::new(format!("{}/provisioning_api.js", static_path)))
        .route_service("/authentication_api.js", ServeFile::new(format!("{}/authentication_api.js", static_path)))
        // Serve common JS files (for communication_iframe)
        .nest_service("/common/js", ServeDir::new(format!("{}/common/js", static_path)))
        // Serve communication_iframe scripts (explicit route to avoid conflict)
        .route_service("/communication_iframe/start.js", ServeFile::new(format!("{}/communication_iframe/start.js", static_path)))
        // SBO signer popup (first-party broker window for cross-site typed signing)
        .route_service("/sign", ServeFile::new(format!("{}/sign.html", static_path)))
        // Agent-key management UI (tdxf) — create/list/revoke provisioning certs
        .route_service("/agents", ServeFile::new(format!("{}/agents.html", static_path)))
        // Warrant consent surface (spec §6.3) — approve/deny agent requests.
        // The {code} deep link and the bare list are the same page.
        .route_service("/consent", ServeFile::new(format!("{}/consent.html", static_path)))
        // axum 0.7 param syntax (`:code`, not 0.8's `{code}`) — the code is
        // read client-side from the path; the route just serves the page.
        .route_service("/consent/:code", ServeFile::new(format!("{}/consent.html", static_path)))
        // Broker account utilities (sign out / clear cached certs / agent keys),
        // moved off the root when the marketing landing page took `/`.
        .route_service("/account", ServeFile::new(format!("{}/account.html", static_path)))
        // Landing page at the root.
        .route_service("/", ServeFile::new(format!("{}/index.html", static_path)))
        // Serve static files (dialog, CSS, JS)
        .nest_service("/dialog", ServeDir::new(static_path))
        // Deny framing everywhere except the surfaces RPs legitimately embed
        // (communication_iframe + winchan relay). The consent page especially
        // must never render in an iframe: its one-click Approve signs a
        // warrant, a classic clickjacking target.
        .layer(axum::middleware::from_fn(deny_framing))
        .layer(CookieManagerLayer::new())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::ACCEPT]),
        )
        // Always revalidate served assets (HTML/JS/wasm). The broker ships
        // security-critical agent code (login + typed signing); stale cached
        // JS must never silently run. `no-cache` still permits 304s via
        // etag/last-modified, so it's cheap — just never blindly fresh.
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
        .with_state(state)
}

/// Anti-clickjacking: `X-Frame-Options: DENY` + `frame-ancestors 'none'` on
/// every response except the RP-embeddable surfaces.
async fn deny_framing(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path();
    let embeddable =
        path.starts_with("/communication_iframe") || path.starts_with("/relay");
    let mut resp = next.run(req).await;
    if !embeddable {
        let headers = resp.headers_mut();
        headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("frame-ancestors 'none'"),
        );
    }
    resp
}

/// `GET /sign_in` — the primary-IdP auth-return handler. After the IdP
/// authenticates the user it redirects this popup to `/sign_in#AUTH_RETURN`
/// (or `#AUTH_RETURN_CANCEL`). This page signals the opening dialog via
/// postMessage and closes, completing the primary provisioning flow. (Was a
/// blind redirect to the dialog, which dropped the completion signal.)
async fn sign_in_return() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Signing in…</title></head>
<body style="font:14px/1.5 system-ui,sans-serif;text-align:center;margin-top:40px;color:#555">
<p id="m">Completing sign-in…</p>
<script>
(function () {
  var hash = window.location.hash;
  var cancel = hash === '#AUTH_RETURN_CANCEL';
  var ok = hash === '#AUTH_RETURN';
  if ((ok || cancel) && window.opener) {
    try {
      window.opener.postMessage(
        { type: 'browserid_auth_complete', success: ok },
        window.location.origin
      );
    } catch (e) { /* opener gone */ }
    window.close();
  } else if (!ok && !cancel) {
    // Direct hit with no auth-return state — go to the dialog.
    window.location.replace('/dialog/dialog.html');
  } else {
    document.getElementById('m').textContent = 'You can close this window.';
  }
})();
</script>
</body></html>"#,
    )
}
