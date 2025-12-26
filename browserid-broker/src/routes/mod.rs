//! HTTP routes for the broker

mod account;
mod auth;
mod session;
mod well_known;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tower_cookies::CookieManagerLayer;

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
    Router::new()
        .route("/.well-known/browserid", get(well_known::get_support_document))
        .route("/wsapi/session_context", get(session::get_session_context))
        .route("/wsapi/stage_user", post(account::stage_user))
        .route("/wsapi/complete_user_creation", post(account::complete_user_creation))
        .route("/wsapi/authenticate_user", post(auth::authenticate_user))
        .route("/wsapi/logout", post(auth::logout))
        .layer(CookieManagerLayer::new())
        .with_state(state)
}
