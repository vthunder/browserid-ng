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

/// An agent identity's email is simply `<name>@<domain-of the owner's email>`.
/// The `name` is the FULL local-part carried verbatim in the provisioning-cert
/// constraint (no translation): `vthunder+claude@gmail.com`, `claude@sandmill.org`,
/// or `danmills+claude@sandmill.org`. What names are *permitted* is enforced by
/// [`agent_name_allowed`], not by rewriting here.
pub fn agent_identity_email(delegator_email: &str, name: &str) -> String {
    let domain = delegator_email.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
    format!("{name}@{domain}")
}

/// Which agent-identity local-parts a delegator may mint — the anti-squatting
/// rule, enforced when a provisioning cert is registered and again before any
/// cert is stamped:
///
/// - **Fallback IdP** — the owner's email domain differs from the IdP that
///   rooted them (e.g. a gmail address vouched by the broker): the name MUST
///   sub-address the owner's own verified email, i.e. start with `<owner-local>+`
///   and carry something after it. So you can only ever mint under an address you
///   proved you control; `victim@gmail.com` or someone else's `alice+x` is
///   impossible.
/// - **Primary / native-domain IdP** — the owner owns the domain: any non-empty
///   local-part is allowed (bare `claude` or `owner+claude`); that domain runs
///   its own namespace.
pub fn agent_name_allowed(name: &str, delegator_email: &str, idp_domain: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let (local, domain) = match delegator_email.rsplit_once('@') {
        Some(x) => x,
        None => return false,
    };
    if domain.eq_ignore_ascii_case(idp_domain) {
        true // primary / native-domain owner: their own domain's namespace
    } else {
        // Fallback owner: must be `<owner-local>+<something>`.
        let prefix = format!("{local}+");
        name.len() > prefix.len()
            && name
                .get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(&prefix))
    }
}

/// Resolves a foreign IdP's identity key (DNSSEC-rooted discovery) so the
/// registrar can verify the agent certificate on an **external** warrant
/// request — a service agent certified by its own IdP asking a delegator
/// rooted here to warrant it (`agent_cert~R`, spec §6.6). The host wires in
/// its discovery stack; a `None` resolver on [`RegistrarState`] means
/// external requests are refused.
pub trait IssuerKeyResolver: Send + Sync {
    fn resolve_issuer_key<'a>(
        &'a self,
        domain: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<browserid_core::PublicKey, RegistrarError>>
                + Send
                + 'a,
        >,
    >;

    /// The key plus the domain's DNSSEC-published serving host (`host=`),
    /// when its §7 surface is delegated elsewhere (hosted primaries, g5qt).
    /// The host comes from the SAME validated record as the key, so origins
    /// derived from it carry the same trust. Default: key only — simple
    /// test resolvers need not implement it.
    fn resolve_issuer<'a>(
        &'a self,
        domain: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ResolvedIssuer, RegistrarError>> + Send + 'a>,
    > {
        Box::pin(async move {
            Ok(ResolvedIssuer {
                key: self.resolve_issuer_key(domain).await?,
                serving_host: None,
            })
        })
    }
}

/// A resolved issuer: identity key + optional DNSSEC-published serving host.
pub struct ResolvedIssuer {
    pub key: browserid_core::PublicKey,
    pub serving_host: Option<String>,
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
    /// Foreign-IdP key discovery for external warrant requests (§6.6);
    /// `None` refuses them.
    pub issuer_resolver: Option<Arc<dyn IssuerKeyResolver>>,
}

/// The registrar's routes, ready to merge into a host router.
pub fn router(state: Arc<RegistrarState>) -> Router {
    Router::new()
        // Paired agent provisioning (device-grant bootstrap, 74u1):
        .route("/agent-provision/request", post(agent_provision::request))
        .route("/agent-provision/poll", post(agent_provision::poll))
        .route("/agent-provision/info", post(agent_provision::info))
        .route("/agent-provision/resolve", post(agent_provision::resolve))
        .route("/agent-provision/prepare", post(agent_provision::prepare))
        .route("/agent-provision/complete", post(agent_provision::complete))
        // Agent-facing consent flow (device-cert model): raise + poll.
        .route("/warrant/request", post(consent::warrant_request))
        .route("/warrant/poll", post(consent::warrant_poll))
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
    use super::{agent_identity_email, agent_name_allowed};

    #[test]
    fn email_is_name_at_owner_domain() {
        // No translation: the name is the full local-part, appended to the
        // owner's own email domain — same rule on any IdP.
        assert_eq!(agent_identity_email("vthunder@gmail.com", "vthunder+claude"),
                   "vthunder+claude@gmail.com");
        assert_eq!(agent_identity_email("dan@sandmill.org", "claude"), "claude@sandmill.org");
        assert_eq!(agent_identity_email("dan@sandmill.org", "dan+claude"), "dan+claude@sandmill.org");
    }

    #[test]
    fn fallback_names_must_subaddress_the_owner() {
        // Fallback (email domain != IdP): must be `<owner-local>+<something>`.
        assert!(agent_name_allowed("vthunder+claude", "vthunder@gmail.com", "browserid.me"));
        assert!(agent_name_allowed("vthunder+svc+abc", "vthunder@gmail.com", "browserid.me")); // may contain more '+'
        assert!(!agent_name_allowed("claude", "vthunder@gmail.com", "browserid.me")); // bare -> rejected
        assert!(!agent_name_allowed("victim", "vthunder@gmail.com", "browserid.me"));
        assert!(!agent_name_allowed("mallory+x", "vthunder@gmail.com", "browserid.me")); // someone else's prefix
        assert!(!agent_name_allowed("vthunder+", "vthunder@gmail.com", "browserid.me")); // empty after '+'
        // Primary / native-domain owner (email domain == IdP): bare OR sub-addressed both allowed.
        assert!(agent_name_allowed("claude", "dan@sandmill.org", "sandmill.org"));
        assert!(agent_name_allowed("dan+claude", "dan@sandmill.org", "sandmill.org"));
        assert!(!agent_name_allowed("", "dan@sandmill.org", "sandmill.org"));
    }
}
