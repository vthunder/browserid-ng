//! HTTP routes for the broker

mod account;
mod auth;
mod cert;
mod email;
mod primary;
mod reset;
mod session;
mod test;
mod verify;
mod well_known;

use std::sync::Arc;

use axum::http::{header, Method};
use axum::response::Redirect;
use axum::routing::{get, post};
use axum::Router;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

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
        .route("/wsapi/authenticate_user", post(auth::authenticate_user))
        .route("/wsapi/logout", post(auth::logout))
        .route("/wsapi/update_password", post(auth::update_password))
        .route("/wsapi/list_emails", get(email::list_emails))
        .route("/wsapi/stage_email", post(email::stage_email))
        .route("/wsapi/complete_email_addition", post(email::complete_email_addition))
        .route("/wsapi/remove_email", post(email::remove_email))
        .route("/wsapi/address_info", get(email::address_info))
        .route("/wsapi/email_addition_status", get(email::email_addition_status))
        .route("/wsapi/cert_key", post(cert::cert_key))
        .route("/wsapi/account_cancel", post(account::account_cancel))
        .route("/wsapi/stage_reset", post(reset::stage_reset))
        .route("/wsapi/complete_reset", post(reset::complete_reset))
        .route("/wsapi/password_reset_status", get(reset::password_reset_status))
        // Primary IdP authentication
        .route("/wsapi/auth_with_assertion", post(primary::auth_with_assertion))
        // Verification endpoint
        .route("/verify", post(verify::verify))
        // Test endpoints (should only be enabled in dev/test)
        .route("/wsapi/test/pending_verification", get(test::get_pending_verification))
        // Compatibility routes for include.js
        .route("/sign_in", get(|| async { Redirect::to("/dialog/dialog.html") }))
        .nest_service("/relay", ServeDir::new(format!("{}/relay", static_path)))
        .route_service("/include.js", ServeFile::new(format!("{}/include.js", static_path)))
        .route_service("/communication_iframe", ServeFile::new(format!("{}/communication_iframe.html", static_path)))
        // Serve common JS files (for communication_iframe)
        .nest_service("/common/js", ServeDir::new(format!("{}/common/js", static_path)))
        // Serve communication_iframe scripts (explicit route to avoid conflict)
        .route_service("/communication_iframe/start.js", ServeFile::new(format!("{}/communication_iframe/start.js", static_path)))
        // Serve static files (dialog, CSS, JS)
        .nest_service("/dialog", ServeDir::new(static_path))
        .layer(CookieManagerLayer::new())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::ACCEPT]),
        )
        .with_state(state)
}
