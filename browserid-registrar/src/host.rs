//! What the registrar needs from its host (the broker, or a self-hosting
//! IdP): who is signed in, and which identities an account owns. Keeping
//! accounts/sessions host-side is what makes the component embeddable —
//! "you manage your agents where your identity lives" (1pnf).

use tower_cookies::Cookies;

use crate::error::RegistrarError;

/// The signed-in user behind a browser request, as the host resolves it.
#[derive(Debug, Clone)]
pub struct AuthedUser {
    pub user_id: u64,
    /// The session's CSRF token; state-changing registrar endpoints require
    /// the caller to echo it.
    pub csrf_token: String,
}

/// An agent identity the host has minted for an account (used to flip
/// status bits when the provisioning key that covers it is revoked).
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub email: String,
    /// The delegating (parent) identity, when recorded
    pub parent_email: Option<String>,
}

pub trait RegistrarHost: Send + Sync {
    /// Resolve the browser session from cookies. `None` = not signed in.
    fn resolve_session(&self, cookies: &Cookies) -> Option<AuthedUser>;

    /// Whether `email` is a verified address on `user_id`'s account — the
    /// human-authorization gate for registering delegations and warrants.
    fn owns_verified_email(&self, user_id: u64, email: &str) -> Result<bool, RegistrarError>;

    /// The account's agent identities (for key-revocation status flips).
    fn agent_identities(&self, user_id: u64) -> Result<Vec<AgentIdentity>, RegistrarError>;

    /// Reserve agent handles `<name>@<domain>` for `user_id`, parented to
    /// `delegator` — the session-authenticated counterpart of the
    /// provisioning-key `/provision/reserve`, used by paired provisioning to
    /// lock handles at approval time (closing the approve→mint race). Errors
    /// with `NamesTaken` if any handle belongs to another account, or
    /// `PolicyRefused` on quota.
    fn reserve_agent_names(
        &self,
        user_id: u64,
        delegator: &str,
        names: &[String],
    ) -> Result<(), RegistrarError>;
}

/// Require that the caller presented the session's CSRF token.
pub(crate) fn require_csrf(user: &AuthedUser, csrf: &str) -> Result<(), RegistrarError> {
    if !csrf.is_empty() && user.csrf_token == csrf {
        Ok(())
    } else {
        Err(RegistrarError::InvalidCsrf)
    }
}
