//! # browserid-registrar
//!
//! The **registrar** role of the agent-identity protocol, unbundled from the
//! broker (bean 1pnf): the provisioning-cert registry, endorsement signing,
//! the warrant consent flow + per-delegator warrant registry, and the signed
//! revocation status list.
//!
//! v2 conflated three roles under "broker": fallback IdP, mediator/UX, and
//! the registrar. This crate is only the third — packaged so any IdP can
//! self-host it (default: your registrar is the IdP that roots your
//! identity), while browserid.me offers the same component as the managed
//! product. **You manage your agents where your identity lives.**
//!
//! ## Embedding
//!
//! The host keeps accounts and sessions; the registrar asks for them through
//! [`RegistrarHost`] and persists its own records through [`RegistrarStore`]:
//!
//! ```ignore
//! let registrar = Arc::new(RegistrarState {
//!     domain: "id.example.com".into(),
//!     keypair,                       // signs endorsements + the status list
//!     enabled: true,
//!     store,                         // Arc<dyn RegistrarStore>
//!     host,                          // Arc<dyn RegistrarHost>
//! });
//! let app = my_idp_router.merge(browserid_registrar::router(registrar));
//! ```
//!
//! The router serves the wire-stable paths (`/provision/endorse`,
//! `/warrant/request`, `/warrant/poll`, the `/wsapi/*` browser API, and
//! `/.well-known/browserid-status`). The consent/key-management UI remains
//! host-served for now (the broker's `/consent` + `/account` pages are the
//! reference implementation).

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use browserid_core::KeyPair;

pub mod agent_provision;
pub mod consent;
pub mod error;
pub mod host;
pub mod models;
pub mod registry;
mod store;

pub use error::RegistrarError;
pub use host::{AgentIdentity, AuthedUser, RegistrarHost};
pub use consent::scope_fingerprint;
pub use registry::valid_agent_name;
pub use store::{RegistrarStore, StoreResult};

/// Everything the registrar needs from its deployment.
pub struct RegistrarState {
    /// The registrar's own domain (endorsement issuer, status-list subject,
    /// consent-page origin).
    pub domain: String,
    /// Signs endorsements and the status list. For a self-hosting IdP this
    /// is the IdP key — endorser and issuer collapse.
    pub keypair: KeyPair,
    /// Master switch (the broker gates this on `agent_provisioning_enabled`).
    pub enabled: bool,
    pub store: Arc<dyn RegistrarStore>,
    pub host: Arc<dyn RegistrarHost>,
}

/// The registrar's routes, ready to merge into a host router.
pub fn router(state: Arc<RegistrarState>) -> Router {
    Router::new()
        // Browser-side registry management (session + CSRF):
        .route("/wsapi/provisioning_certs", get(registry::list_provisioning_certs))
        .route("/wsapi/register_provisioning_cert", post(registry::register_provisioning_cert))
        .route("/wsapi/revoke_provisioning_cert", post(registry::revoke_provisioning_cert))
        // Endorsement signing:
        .route("/provision/endorse", post(registry::endorse))
        // Warrant consent flow (agent spec §6, v0.4):
        .route("/warrant/request", post(consent::request))
        .route("/warrant/poll", post(consent::poll))
        // Paired agent provisioning (device-grant bootstrap, 74u1):
        .route("/agent-provision/request", post(agent_provision::request))
        .route("/agent-provision/poll", post(agent_provision::poll))
        .route("/agent-provision/info", post(agent_provision::info))
        .route("/agent-provision/resolve", post(agent_provision::resolve))
        .route("/agent-provision/complete", post(agent_provision::complete))
        .route("/wsapi/warrant_requests", get(consent::list_requests))
        .route("/wsapi/warrant_respond", post(consent::respond))
        // Warrant registry (jipx):
        .route("/wsapi/warrants", get(consent::list_warrants))
        .route("/wsapi/register_warrant", post(consent::register_warrant))
        .route("/wsapi/forget_warrant", post(consent::forget_warrant))
        .route("/wsapi/revoke_warrant", post(consent::revoke_warrant))
        .route("/wsapi/allocate_warrant_status", post(consent::allocate_warrant_status))
        // Signed revocation status list (core §6.4):
        .route("/.well-known/browserid-status", get(consent::status_list))
        .with_state(state)
}
