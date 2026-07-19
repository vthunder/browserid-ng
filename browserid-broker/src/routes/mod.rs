//! HTTP routes for the broker

mod account;
mod auth;
mod cert;
mod device;
mod email;
mod fallback_idp;
mod fedcm;
mod guestbook;
mod primary;
mod reset;
pub(crate) mod session;
mod test;
mod verify;
mod well_known;

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::Router;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::CorsLayer;
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
    // The registrar component (1pnf): provisioning-cert registry,
    // endorsement signing, warrant consent flow + registry, status list.
    // The broker is IdP + registrar in one process; a federated IdP
    // self-hosts this same component (or points at a managed one).
    // Foreign-IdP key discovery for external warrant requests (§6.6):
    // DNSSEC-rooted, unless a test injected its own resolver. If the DNS
    // stack can't initialize, external requests are refused (None) but
    // everything else runs.
    let issuer_resolver = state.issuer_resolver_override.clone().or_else(|| {
        match crate::fallback_fetcher::FallbackFetcher::new(state.domain.clone()) {
            Ok(f) => Some(Arc::new(crate::registrar_glue::BrokerIssuerResolver {
                fetcher: Arc::new(f),
            }) as Arc<dyn browserid_registrar::IssuerKeyResolver>),
            Err(e) => {
                tracing::warn!("issuer resolver unavailable (external warrant requests off): {e}");
                None
            }
        }
    });
    let registrar = browserid_registrar::router(Arc::new(
        browserid_registrar::RegistrarState {
            domain: state.domain.clone(),
            keypair: state.keypair.clone(),
            enabled: state.agent_provisioning_enabled,
            store: Arc::new(crate::registrar_glue::BrokerRegistrarStore {
                user_store: state.user_store.clone(),
            }),
            host: Arc::new(crate::registrar_glue::BrokerRegistrarHost {
                user_store: state.user_store.clone(),
                session_store: state.session_store.clone(),
                domain: state.domain.clone(),
                max_agent_identities: state.max_agent_identities_per_user,
            }),
            issuer_resolver,
        },
    ));

    let mut app = Router::new()
        .route("/.well-known/browserid", get(well_known::get_support_document))
        .route("/wsapi/session_context", get(session::get_session_context))
        .route("/wsapi/stage_user", post(account::stage_user))
        .route("/wsapi/complete_user_creation", post(account::complete_user_creation))
        .route("/wsapi/user_creation_status", get(account::user_creation_status))
        // Admin seed provisioning (ADMIN_TOKEN-gated; for @mingo.place demo accounts)
        .route("/admin/create_account", post(account::admin_create_account))
        // Operator-only code peek (X-Admin-Token) — testing escape hatch when
        // email delivery is flaky; not the public /wsapi/test route.
        .route("/admin/pending_code", get(account::admin_pending_code))
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
        // Device-cert model (DC Phases 2/6) — additive alongside the legacy routes.
        .route("/device/issue", post(device::device_issue))
        .route("/access/mint", post(device::access_mint))
        .route("/verify-access", post(device::verify_access))
        .route("/wsapi/device_certs", get(device::device_certs))
        .route("/wsapi/revoke_device_cert", post(device::revoke_device_cert))
        .route("/wsapi/account_cancel", post(account::account_cancel))
        .route("/wsapi/stage_reset", post(reset::stage_reset))
        .route("/wsapi/complete_reset", post(reset::complete_reset))
        .route("/wsapi/password_reset_status", get(reset::password_reset_status))
        // Primary IdP authentication
        .route("/wsapi/auth_with_assertion", post(primary::auth_with_assertion))
        .route("/wsapi/set_password", post(primary::set_password))
        // Verification endpoint
        .route("/verify", post(verify::verify))
        // FedCM IdP surface (browserid-ng-mhyp spike): browserid.me as a FedCM
        // Identity Provider for fallback identities. Silent lane — mints a
        // standard cert~assertion server-side; /verify unchanged.
        .route("/.well-known/web-identity", get(fedcm::web_identity))
        .route("/fedcm/config.json", get(fedcm::config))
        .route("/fedcm/accounts", get(fedcm::accounts))
        .route("/fedcm/assertion", post(fedcm::assertion))
        .route("/fedcm/reset", post(fedcm::reset))
        // The agent guestbook demo (a public RP only agents can sign).
        .route("/guestbook", get(guestbook::page).post(guestbook::sign))
        .route("/guestbook/feed", get(guestbook::feed))
        // Fallback-IdP surface (apgv): the broker implements the primary-IdP
        // interface (auth+provision pages driven by the dialog) with SMTP auth,
        // so it can vouch for emails whose domain it doesn't own for any RP
        // that lists it in acceptedFallbacks.
        .route("/auth/send", post(fallback_idp::auth_send))
        .route("/auth/verify", post(fallback_idp::auth_verify))
        .route("/whoami", get(fallback_idp::whoami))
        .route("/cert_key", post(fallback_idp::cert_key))
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
        // Fallback-IdP primary interface pages (apgv)
        .route_service("/auth", ServeFile::new(format!("{}/auth.html", static_path)))
        .route_service("/auth.js", ServeFile::new(format!("{}/auth.js", static_path)))
        .route_service("/provision", ServeFile::new(format!("{}/provision.html", static_path)))
        .route_service("/provision.js", ServeFile::new(format!("{}/provision.js", static_path)))
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
        // Demo RPs (apgv): one trusts only an external fallback, one trusts browserid.me.
        .route_service("/fallback-demo", ServeFile::new(format!("{}/fallback-demo.html", static_path)))
        .route_service("/broker-demo", ServeFile::new(format!("{}/broker-demo.html", static_path)))
        // Landing page at the root. When the origin split is deployed
        // (MARKETING_URL set), redirect to the static marketing site instead;
        // otherwise serve index.html locally.
        .route("/", get({
            let index_path = format!("{}/index.html", static_path);
            move |State(state): State<Arc<AppState<U, S, E>>>| {
                let index_path = index_path.clone();
                async move {
                    if let Some(url) = &state.marketing_url {
                        return axum::response::Redirect::permanent(url).into_response();
                    }
                    match tokio::fs::read_to_string(&index_path).await {
                        Ok(body) => Html(body).into_response(),
                        Err(_) => axum::http::StatusCode::NOT_FOUND.into_response(),
                    }
                }
            }
        }))
        // Serve static files (dialog, CSS, JS)
        .nest_service("/dialog", ServeDir::new(static_path));

    // Test-only helper routes (raw verification codes, mock-IdP controls). They
    // are an account-takeover primitive — anyone could read a victim's reset
    // code — so they mount ONLY when explicitly enabled for dev/test, NEVER in
    // production (guarded by AppState::test_endpoints_enabled).
    if state.test_endpoints_enabled {
        app = app
            .route("/wsapi/test/pending_verification", get(test::get_pending_verification))
            .route("/wsapi/test/set_mock_primary_idp", post(test::set_mock_primary_idp))
            .route("/wsapi/test/clear_mock_primary_idps", post(test::clear_mock_primary_idps))
            .route("/wsapi/test/remove_mock_primary_idp", post(test::remove_mock_primary_idp));
    }

    // Admin cert-mint for demo seeding (mingo-b2yz): impersonation-grade, so
    // it mounts ONLY when BROKER_ADMIN_TOKEN is configured, and the handler
    // additionally enforces the hard principal allowlist (fails closed).
    if state.admin_mint_token.is_some() {
        app = app.route("/wsapi/admin/cert_key", post(cert::admin_cert_key));
    }

    app.with_state(state)
        // Registrar routes join here (already stateful); the shared layers
        // below — frame denial, cookies, CORS, cache-control — cover both.
        .merge(registrar)
        .layer(CookieManagerLayer::new())
        .layer(
            // Mirror the request Origin rather than emitting `*`. For the
            // non-credentialed endpoints this is equivalent to `*` (any origin
            // may read the response), but it lets `/fedcm/assertion` return a
            // VALID credentialed CORS response — `Access-Control-Allow-Origin: *`
            // combined with `Allow-Credentials: true` is rejected by browsers,
            // which is the "did not send the correct CORS headers" error.
            CorsLayer::new()
                .allow_origin(tower_http::cors::AllowOrigin::mirror_request())
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
        // Security headers (CSP, anti-clickjacking) + the FedCM Set-Login status.
        // Applied LAST so it's the OUTERMOST layer: on the response it runs after
        // CookieManagerLayer has written Set-Cookie, so it can read whether the
        // session cookie was just set/cleared to derive the login status. It also
        // denies framing everywhere except the surfaces RPs legitimately embed
        // (communication_iframe + winchan relay); the consent page especially
        // must never render in an iframe (its one-click Approve signs a warrant).
        .layer(axum::middleware::from_fn(security_headers))
}

/// sha256 hashes of the *inline* `<script>` blocks on the auth-origin pages, so
/// the strict policy can keep `script-src 'self'` (no `'unsafe-inline'`). All
/// other auth-cluster pages load only external same-origin scripts. These are
/// verified against the real files by `csp_tests::inline_script_hashes_match` —
/// if you edit one of those inline scripts, that test fails and prints the new
/// hash to paste here.
const INLINE_SCRIPT_HASHES: &[&str] = &[
    "'sha256-Lqu77yLdsnzOKedRdfXM9jR8RXq2ezoL1c6qSX9yZP8='", // account.html
    "'sha256-b1iFaqLAekTKdTAr89Bm4ToBdO7tJYCPKo4ZNxiClG8='", // consent.html
    "'sha256-+XqUYbHj+ZXqocYeM/oRYCX1zljIPfY94AJwWAtU2Do='", // agents.html
    "'sha256-BsrrX7K7ju9+1BRkiBPUrOiGM3NRGzylCP/gwg5h22Y='", // /sign_in (SIGN_IN_HTML)
];

/// Build the strict CSP. `wasm-unsafe-eval` is required by the WASM signer
/// (`common/js/sbo-wasm`); there is no `eval`/`new Function` anywhere, so plain
/// `unsafe-eval` is not needed. `frame-src http(s):` lets the dialog embed a
/// primary IdP's provisioning page at *any* web origin (https in production,
/// http for localhost/dev IdPs) — the mediator can't enumerate IdP origins
/// ahead of time; it still blocks non-web schemes (data:/blob:) an injected
/// script might abuse. `frame-ancestors 'none'` is added for non-embeddable
/// pages (everything but the surfaces RPs/mediator legitimately iframe).
fn build_strict_csp(frame_ancestors_none: bool) -> String {
    let mut csp = format!(
        "default-src 'self'; base-uri 'self'; object-src 'none'; \
         script-src 'self' 'wasm-unsafe-eval' {}; \
         style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; \
         connect-src 'self'; frame-src 'self' https: http:; form-action 'self'",
        INLINE_SCRIPT_HASHES.join(" ")
    );
    if frame_ancestors_none {
        csp.push_str("; frame-ancestors 'none'");
    }
    csp
}

static CSP_STRICT: std::sync::LazyLock<HeaderValue> = std::sync::LazyLock::new(|| {
    HeaderValue::from_str(&build_strict_csp(true)).expect("valid CSP header")
});
static CSP_STRICT_EMBEDDABLE: std::sync::LazyLock<HeaderValue> = std::sync::LazyLock::new(|| {
    HeaderValue::from_str(&build_strict_csp(false)).expect("valid CSP header")
});

enum CspTier {
    /// Demo / marketing / dev pages: unhashed inline scripts, but no keystore,
    /// session, or wsapi — not security-critical. Keep the old permissive policy.
    Loose,
    /// The auth cluster (dialog, account, consent, agents, auth, sign, wsapi, …):
    /// strict CSP + framing denied.
    Strict,
    /// Surfaces RPs / the mediator dialog legitimately embed cross-origin: strict
    /// CSP, but framing must be *allowed*, so no frame-ancestors/X-Frame-Options.
    StrictEmbeddable,
}

fn csp_tier(path: &str) -> CspTier {
    if path.starts_with("/communication_iframe")
        || path.starts_with("/relay")
        // The fallback-IdP provisioning page is framed cross-origin by the
        // mediator's dialog (apgv), exactly like a primary IdP's provision page.
        || path == "/provision"
        || path == "/provision.js"
    {
        return CspTier::StrictEmbeddable;
    }
    // Demo / marketing / dev pages carry unhashed inline scripts (and demo.html
    // uses inline handlers). They hold nothing sensitive, so keep them loose
    // rather than hash every one. `/` 308-redirects to the marketing site in
    // production; served locally it is index.html.
    let loose = path == "/"
        || path == "/broker-demo"
        || path == "/fallback-demo"
        || path.ends_with("/index.html")
        || path.ends_with("/broker-demo.html")
        || path.ends_with("/fallback-demo.html")
        || path.ends_with("/demo.html")
        || path.ends_with("/sbo-smoke-test.html");
    if loose {
        CspTier::Loose
    } else {
        CspTier::Strict
    }
}

/// Security headers: a Content-Security-Policy (script/style/connect/frame/…)
/// plus anti-clickjacking. The auth cluster gets a strict `script-src 'self'`
/// (+ inline-script hashes + wasm) so an injected script can neither run nor
/// exfiltrate; embeddable iframes get the same policy minus framing denial;
/// demo/marketing pages keep the permissive frame-ancestors-only policy.
async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let tier = csp_tier(req.uri().path());
    // Whether the *request* already carried a browserid.me session (for the
    // FedCM Login Status header below — see after the handler runs).
    let req_has_session = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|c| cookie_present(c, "browserid_session"))
        .unwrap_or(false);

    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    match tier {
        CspTier::Loose => {
            headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("frame-ancestors 'none'"),
            );
        }
        CspTier::Strict => {
            headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
            headers.insert(header::CONTENT_SECURITY_POLICY, CSP_STRICT.clone());
        }
        CspTier::StrictEmbeddable => {
            headers.insert(header::CONTENT_SECURITY_POLICY, CSP_STRICT_EMBEDDABLE.clone());
        }
    }

    // FedCM Login Status API (browserid-ng-mhyp). FedCM caches the IdP's
    // login status; once it records "logged-out" (e.g. from an early
    // /fedcm/accounts 401), it rejects future calls with "not signed in"
    // WITHOUT re-querying — only Set-Login un-sticks it. We derive the status
    // from what just happened: this response setting the session cookie =
    // logged-in, clearing it = logged-out, otherwise fall back to whether the
    // request was already authenticated. So any authenticated page load (e.g.
    // /account) re-asserts logged-in, and logout asserts logged-out.
    let status = login_status(resp.headers(), req_has_session);
    if let Some(v) = status {
        resp.headers_mut()
            .insert(HeaderName::from_static("set-login"), HeaderValue::from_static(v));
    }
    resp
}

/// True if `cookie_header` sets `name` to a non-empty value.
fn cookie_present(cookie_header: &str, name: &str) -> bool {
    cookie_header.split(';').any(|kv| {
        kv.trim()
            .strip_prefix(name)
            .and_then(|r| r.strip_prefix('='))
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    })
}

/// Derive the FedCM Login Status from the response's Set-Cookie(s) — setting
/// `browserid_session` to a real value = "logged-in", clearing it (empty /
/// Max-Age=0) = "logged-out" — else fall back to whether the request was
/// authenticated.
fn login_status(resp_headers: &axum::http::HeaderMap, req_has_session: bool) -> Option<&'static str> {
    for sc in resp_headers.get_all(header::SET_COOKIE) {
        if let Ok(s) = sc.to_str() {
            if let Some(rest) = s.strip_prefix("browserid_session=") {
                let clearing = rest.starts_with(';') || s.contains("Max-Age=0");
                return Some(if clearing { "logged-out" } else { "logged-in" });
            }
        }
    }
    if req_has_session {
        Some("logged-in")
    } else {
        None
    }
}

/// `GET /sign_in` — the primary-IdP auth-return handler. After the IdP
/// authenticates the user it redirects this popup to `/sign_in#AUTH_RETURN`
/// (or `#AUTH_RETURN_CANCEL`). This page signals the opening dialog via
/// postMessage and closes, completing the primary provisioning flow. (Was a
/// blind redirect to the dialog, which dropped the completion signal.)
async fn sign_in_return() -> Html<&'static str> {
    Html(SIGN_IN_HTML)
}

/// The `/sign_in` page body. A const (not an inline literal) so the CSP
/// inline-script-hash test can read the exact bytes it hashes.
const SIGN_IN_HTML: &str = r#"<!DOCTYPE html>
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
</body></html>"#;

#[cfg(test)]
mod csp_tests {
    use super::{csp_tier, CspTier, INLINE_SCRIPT_HASHES, SIGN_IN_HTML};
    use base64::Engine;
    use sha2::{Digest, Sha256};

    /// Extract the first inline (non-`src`) `<script>` body from an HTML string.
    fn first_inline_script(html: &str) -> Option<&str> {
        let mut cursor = 0;
        loop {
            let start = html[cursor..].find("<script")? + cursor;
            let gt = html[start..].find('>')? + start;
            let open_tag = &html[start..=gt];
            if !open_tag.contains("src=") {
                let content_start = gt + 1;
                let end = html[content_start..].find("</script>")? + content_start;
                return Some(&html[content_start..end]);
            }
            cursor = gt + 1;
        }
    }

    fn hash_of(script: &str) -> String {
        let digest = Sha256::digest(script.as_bytes());
        format!(
            "'sha256-{}'",
            base64::engine::general_purpose::STANDARD.encode(digest)
        )
    }

    /// The CSP inline-script hashes must match the bytes actually served. If an
    /// inline script is edited, this fails and prints the hash to paste into
    /// INLINE_SCRIPT_HASHES — so the strict CSP can never silently break a page.
    #[test]
    fn inline_script_hashes_match() {
        let mut checked = 0;
        for file in ["static/account.html", "static/consent.html", "static/agents.html"] {
            let html = std::fs::read_to_string(file)
                .unwrap_or_else(|e| panic!("read {file}: {e}"));
            let script = first_inline_script(&html)
                .unwrap_or_else(|| panic!("no inline script in {file}"));
            let h = hash_of(script);
            assert!(
                INLINE_SCRIPT_HASHES.contains(&h.as_str()),
                "{file}: inline-script hash {h} not in INLINE_SCRIPT_HASHES — update the CSP"
            );
            checked += 1;
        }
        // The /sign_in page (served from a Rust const).
        let script = first_inline_script(SIGN_IN_HTML).expect("sign_in inline script");
        let h = hash_of(script);
        assert!(
            INLINE_SCRIPT_HASHES.contains(&h.as_str()),
            "/sign_in: inline-script hash {h} not in INLINE_SCRIPT_HASHES — update the CSP"
        );
        checked += 1;
        assert_eq!(checked, INLINE_SCRIPT_HASHES.len(), "unexpected number of inline scripts");
    }

    #[test]
    fn cookie_present_detects_nonempty() {
        assert!(super::cookie_present("browserid_session=abc; Path=/", "browserid_session"));
        assert!(super::cookie_present("a=1; browserid_session=abc", "browserid_session"));
        assert!(!super::cookie_present("browserid_session=; Path=/", "browserid_session"));
        assert!(!super::cookie_present("other=abc", "browserid_session"));
    }

    #[test]
    fn login_status_from_response() {
        use axum::http::{header::SET_COOKIE, HeaderMap, HeaderValue};
        // Setting the session cookie → logged-in.
        let mut h = HeaderMap::new();
        h.insert(SET_COOKIE, HeaderValue::from_static("browserid_session=xyz; Path=/; Max-Age=2592000"));
        assert_eq!(super::login_status(&h, false), Some("logged-in"));
        // Clearing it → logged-out.
        let mut h = HeaderMap::new();
        h.insert(SET_COOKIE, HeaderValue::from_static("browserid_session=; Path=/; Max-Age=0"));
        assert_eq!(super::login_status(&h, true), Some("logged-out"));
        // No session cookie change, but request was authenticated → logged-in.
        assert_eq!(super::login_status(&HeaderMap::new(), true), Some("logged-in"));
        // Anonymous → nothing.
        assert_eq!(super::login_status(&HeaderMap::new(), false), None);
    }

    #[test]
    fn csp_tiers_route_correctly() {
        assert!(matches!(csp_tier("/account"), CspTier::Strict));
        assert!(matches!(csp_tier("/consent"), CspTier::Strict));
        assert!(matches!(csp_tier("/dialog/dialog.html"), CspTier::Strict));
        assert!(matches!(csp_tier("/wsapi/session_context"), CspTier::Strict));
        assert!(matches!(csp_tier("/sign_in"), CspTier::Strict));
        assert!(matches!(csp_tier("/communication_iframe"), CspTier::StrictEmbeddable));
        assert!(matches!(csp_tier("/provision"), CspTier::StrictEmbeddable));
        assert!(matches!(csp_tier("/relay/index.html"), CspTier::StrictEmbeddable));
        assert!(matches!(csp_tier("/"), CspTier::Loose));
        assert!(matches!(csp_tier("/broker-demo"), CspTier::Loose));
        assert!(matches!(csp_tier("/dialog/demo.html"), CspTier::Loose));
    }
}
