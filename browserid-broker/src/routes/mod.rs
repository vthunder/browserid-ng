//! HTTP routes for the broker

mod session;
mod well_known;

use std::sync::Arc;

use axum::routing::get;
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
        .layer(CookieManagerLayer::new())
        .with_state(state)
}
