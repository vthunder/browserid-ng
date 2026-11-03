//! Status-list distribution for RPs (watch() v2, bean 6u70).
//!
//! - `GET /status/proxy?uri=…` — serve a VERIFIED status list token to RP
//!   pages. include.js polls this (never the issuer directly) so an open tab
//!   can flip to logged-out when the issuing device is revoked, without
//!   leaking the RP↔user association to a primary IdP: the page always talks
//!   to the broker (which already learned the pairing at login), and primary
//!   IdPs see only the broker's aggregate cache-refresh fetches.
//! - `POST /status/check` — fail-closed revocation re-check for RP backends,
//!   taking the `status_refs` returned by `/verify`. This is the
//!   enforcement path; the page-side poll is UX only.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use browserid_core::StatusRef;
use serde::{Deserialize, Serialize};

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};
use crate::verifier::fetch_foreign_status_list;

/// Bound on refs per `/status/check` call: a presentation carries at most
/// three (access cert, config cert, warrant), so a handful covers any RP
/// batching a few sessions while keeping the fan-out attacker-bounded.
const MAX_CHECK_REFS: usize = 16;

fn allow_private<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
) -> bool {
    // Enforce the SSRF guard in production; relax only on localhost dev —
    // same policy as /verify.
    !super::session::cookie_secure(&state.domain)
}

#[derive(Deserialize)]
pub struct StatusProxyQuery {
    pub uri: String,
}

/// The one error `/status/proxy` ever shows a page. The guard's and the
/// fetcher's reasons ("resolves to non-global address 10.…", connection
/// errors) would make the unauthenticated endpoint an internal-network
/// oracle (audit 2026-11 W5-5); they go to the debug log instead.
const PROXY_UNAVAILABLE: &str = "status list unavailable";

/// Is `uri` shaped like an issuer's status-list URI? Only the two forms
/// issuers publish are proxied: `/.well-known/browserid-status` (core §6.4)
/// and the hosted lane's `/status/<tenant>`; https (http only on localhost
/// dev), no userinfo, query or fragment. Narrows the unauthenticated GET
/// from "any URL" to a status-list path (W5-5).
pub fn status_list_uri_shape_ok(uri: &str, allow_private: bool) -> bool {
    let Ok(url) = reqwest::Url::parse(uri) else { return false };
    let scheme_ok = url.scheme() == "https" || (allow_private && url.scheme() == "http");
    if !scheme_ok || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    if url.query().is_some() || url.fragment().is_some() {
        return false;
    }
    let path = url.path();
    path == "/.well-known/browserid-status"
        || (path.starts_with("/status/") && path.len() > "/status/".len() && !path["/status/".len()..].contains('/'))
}

// GET /status/proxy?uri=<status-list-uri>
pub async fn status_proxy<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Query(q): Query<StatusProxyQuery>,
) -> Result<Response, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let own = browserid_registrar::consent::status_list_uri(&state.domain);
    if q.uri == own {
        // Our own list is published in-process; hand the client to it rather
        // than duplicating the registrar's signing path here.
        return Ok(Redirect::temporary("/.well-known/browserid-status").into_response());
    }
    let allow_private = allow_private(&state);
    if !status_list_uri_shape_ok(&q.uri, allow_private) {
        return Err(BrokerError::ValidationError("not a status list uri".into()));
    }

    let fetcher = state.fallback_fetcher().await.map_err(|e| {
        tracing::debug!(error = %e, "status proxy: fetcher unavailable");
        BrokerError::ValidationError(PROXY_UNAVAILABLE.into())
    })?;
    let token = fetch_foreign_status_list(&q.uri, fetcher.as_ref(), &state.foreign_status_lists, allow_private)
        .await
        .map_err(|e| {
            tracing::debug!(error = %e, "status proxy: fetch refused or failed");
            BrokerError::ValidationError(PROXY_UNAVAILABLE.into())
        })?;

    Ok(token.encoded().to_string().into_response())
}

#[cfg(test)]
mod shape_tests {
    use super::status_list_uri_shape_ok as ok;

    #[test]
    fn only_status_list_paths_pass() {
        assert!(ok("https://idp.example/.well-known/browserid-status", false));
        assert!(ok("https://idp.browserid.me/status/tenant.example", false));
        assert!(ok("http://127.0.0.1:3000/.well-known/browserid-status", true));
        assert!(!ok("http://idp.example/.well-known/browserid-status", false));
        assert!(!ok("https://idp.example/", false));
        assert!(!ok("https://idp.example/admin", false));
        assert!(!ok("https://idp.example/status/", false));
        assert!(!ok("https://idp.example/status/a/b", false));
        assert!(!ok("https://idp.example/.well-known/browserid-status?x=1", false));
        assert!(!ok("https://u:p@idp.example/.well-known/browserid-status", false));
        assert!(!ok("file:///etc/passwd", true));
    }
}

#[derive(Deserialize)]
pub struct StatusCheckRequest {
    pub refs: Vec<StatusRef>,
}

#[derive(Serialize)]
pub struct StatusCheckResponse {
    /// Every ref was checked successfully. Fail-closed: a `false` here MUST be
    /// treated as revoked by the caller (spec §6.4).
    pub ok: bool,
    /// Any checked ref is revoked.
    pub revoked: bool,
    pub results: Vec<StatusCheckResult>,
}

#[derive(Serialize)]
pub struct StatusCheckResult {
    pub uri: String,
    pub idx: u64,
    /// "valid" | "revoked" | "unavailable"
    pub state: String,
}

// POST /status/check
pub async fn status_check<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    req: Result<Json<StatusCheckRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Malformed bodies get the structured-JSON rejection contract shared by
    // the public API endpoints (/verify, /validate-record).
    let Json(req) = match req {
        Ok(json) => json,
        Err(rej) => return Ok(crate::error::bad_request_json(rej.body_text())),
    };
    if req.refs.is_empty() || req.refs.len() > MAX_CHECK_REFS {
        return Err(BrokerError::ValidationError(format!(
            "refs must contain 1..={MAX_CHECK_REFS} entries"
        )));
    }

    let own = browserid_registrar::consent::status_list_uri(&state.domain);
    let fetcher = state.fallback_fetcher().await;
    let mut results = Vec::with_capacity(req.refs.len());
    let mut any_revoked = false;
    let mut all_ok = true;

    for r in &req.refs {
        let checked: Result<bool, String> = if r.uri == own {
            state.user_store.is_status_revoked_idx(r.idx).map_err(|e| e.to_string())
        } else {
            match &fetcher {
                Ok(f) => fetch_foreign_status_list(
                    &r.uri,
                    f.as_ref(),
                    &state.foreign_status_lists,
                    allow_private(&state),
                )
                .await
                .map(|tok| tok.is_revoked(r.idx)),
                Err(e) => Err(format!("fetcher: {e}")),
            }
        };
        let state_str = match checked {
            Ok(true) => {
                any_revoked = true;
                "revoked"
            }
            Ok(false) => "valid",
            Err(_) => {
                all_ok = false;
                "unavailable"
            }
        };
        results.push(StatusCheckResult { uri: r.uri.clone(), idx: r.idx, state: state_str.into() });
    }

    Ok(Json(StatusCheckResponse { ok: all_ok, revoked: any_revoked, results }).into_response())
}
