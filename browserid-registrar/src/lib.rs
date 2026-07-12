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

/// Construct an agent identity's email from its owner (the delegating human) and
/// the IdP domain that roots them. This is the single source of truth for the
/// agent-namespace shape — every mint/reserve/warrant site must agree, or the
/// warrant's agent-email comparison fails at verify time.
///
/// - **Primary IdP** — the owner's email domain *is* the IdP domain: a bare
///   handle, `<name>@<idp_domain>`. A global-unique namespace at that domain,
///   kept deliberately as an incentive to use a primary-IdP email.
/// - **Fallback** — the owner is broker-rooted (their email domain differs from
///   the IdP/broker domain): sub-address the handle under the owner's own
///   verified email, `<local>+<name>@<owner_domain>` (RFC 5233). Handles are
///   then scoped per-owner by construction — cross-user squatting is impossible,
///   because only the party who proved `<local>@<owner_domain>` can mint under
///   it. The cert issuer stays the broker; verification uses the same fallback
///   path as the human (the email domain need not equal the issuer).
pub fn agent_identity_email(delegator_email: &str, idp_domain: &str, name: &str) -> String {
    match delegator_email.rsplit_once('@') {
        Some((local, domain)) if !domain.eq_ignore_ascii_case(idp_domain) => {
            format!("{local}+{name}@{domain}")
        }
        _ => format!("{name}@{idp_domain}"),
    }
}

/// Guardrail: is `agent` a canonical agent-identity email for owner
/// `delegator_email` under `idp_domain` — i.e. one that [`agent_identity_email`]
/// could have produced for *some* handle? This is the inverse of that rule and
/// the last line of defense before a cert is stamped: it rejects any address
/// that isn't derived from the owner's proven email.
///
/// - Fallback owner (email domain ≠ IdP domain): the agent MUST be a sub-address
///   of the owner's own email — `<owner-local>+<name>@<owner-domain>`. This is
///   what makes it impossible for the fallback IdP to stamp e.g. a bare
///   `victim@gmail.com` the owner never proved.
/// - Primary / native-domain owner (email domain == IdP domain): a bare
///   `<name>@<idp_domain>` at that domain.
pub fn is_canonical_agent_email(agent: &str, delegator_email: &str, idp_domain: &str) -> bool {
    let (a_local, a_domain) = match agent.rsplit_once('@') {
        Some(x) => x,
        None => return false,
    };
    let (d_local, d_domain) = match delegator_email.rsplit_once('@') {
        Some(x) => x,
        None => return false,
    };
    if d_domain.eq_ignore_ascii_case(idp_domain) {
        // Primary / native-domain owner: bare `<name>@<idp_domain>`.
        !a_local.is_empty() && a_domain.eq_ignore_ascii_case(idp_domain)
    } else {
        // Fallback owner: sub-address `<owner-local>+<name>@<owner-domain>`.
        let prefix = format!("{d_local}+");
        a_domain.eq_ignore_ascii_case(d_domain)
            && a_local.len() > prefix.len()
            && a_local
                .get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(&prefix))
    }
}

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

#[cfg(test)]
mod email_rule_tests {
    use super::{agent_identity_email, is_canonical_agent_email};

    #[test]
    fn subaddress_for_fallback_bare_for_primary() {
        // Fallback: owner's email domain != IdP domain -> sub-address.
        assert_eq!(agent_identity_email("vthunder@gmail.com", "browserid.me", "researcher"),
                   "vthunder+researcher@gmail.com");
        // Primary/native: owner's email domain == IdP domain -> bare.
        assert_eq!(agent_identity_email("bob@browserid.me", "browserid.me", "researcher"),
                   "researcher@browserid.me");
    }

    #[test]
    fn canonical_accepts_only_derived_addresses() {
        // Fallback owner: only their own sub-address is canonical.
        assert!(is_canonical_agent_email("vthunder+researcher@gmail.com", "vthunder@gmail.com", "browserid.me"));
        assert!(is_canonical_agent_email("vthunder+svc+abc@gmail.com", "vthunder@gmail.com", "browserid.me")); // handle may contain '+'
        // The whole point: a bare, unproven address is REJECTED.
        assert!(!is_canonical_agent_email("researcher@gmail.com", "vthunder@gmail.com", "browserid.me"));
        assert!(!is_canonical_agent_email("victim@gmail.com", "vthunder@gmail.com", "browserid.me"));
        // Someone else's sub-address (different local) is rejected.
        assert!(!is_canonical_agent_email("mallory+x@gmail.com", "vthunder@gmail.com", "browserid.me"));
        // Wrong domain rejected.
        assert!(!is_canonical_agent_email("vthunder+x@evil.com", "vthunder@gmail.com", "browserid.me"));
        // Primary/native owner: bare at the IdP domain is canonical.
        assert!(is_canonical_agent_email("researcher@browserid.me", "bob@browserid.me", "browserid.me"));
        assert!(!is_canonical_agent_email("researcher@gmail.com", "bob@browserid.me", "browserid.me"));
    }
}
