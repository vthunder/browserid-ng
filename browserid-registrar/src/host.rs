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

/// What the host knows about an agent an account has already met — the
/// trustworthy "who" a permission card opens with (Flow P, bean eywc):
/// the user-chosen display name and when the agent was first authorized.
#[derive(Debug, Clone)]
pub struct KnownAgent {
    pub display_name: Option<String>,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub trait RegistrarHost: Send + Sync {
    /// Resolve the browser session from cookies. `None` = not signed in.
    fn resolve_session(&self, cookies: &Cookies) -> Option<AuthedUser>;

    /// Whether `email` is a verified address on `user_id`'s account — the
    /// human-authorization gate for registering delegations and warrants.
    fn owns_verified_email(&self, user_id: u64, email: &str) -> Result<bool, RegistrarError>;

    /// The account that owns `email` as a verified address, if any — how an
    /// external warrant request's delegator hint (§6.6) is routed to the
    /// local user whose consent it needs.
    fn user_for_verified_email(&self, email: &str) -> Result<Option<u64>, RegistrarError>;

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

    /// Record a provisioned agent/service device cert in the host's holder
    /// registry (what the account "Devices & services" view lists), with an
    /// optional friendly label for its holder. Best-effort — a recording
    /// failure must not fail the approval — and a default no-op for hosts
    /// without a registry.
    #[allow(clippy::too_many_arguments)]
    fn record_agent_device_cert(
        &self,
        _user_id: u64,
        _identity: &str,
        _holder: &str,
        _pubkey: &str,
        _iss: &str,
        _issued_at: i64,
        _expires_at: i64,
        _status_idx: Option<u64>,
        _label: Option<&str>,
    ) {
    }

    /// Store the USER-CHOSEN display name for an agent identity (Flow I step
    /// 2, bean eywc) — the name every later permission card opens with.
    /// Best-effort; a default no-op for hosts without a registry.
    fn set_agent_display_name(&self, _user_id: u64, _agent_email: &str, _name: &str) {}

    /// Whether this account has already met `agent_email` — an agent identity
    /// on the account, or a recorded device cert / service entry covering it —
    /// and what it knows about it. `None` = an unknown agent: the consent page
    /// renders deny-only (P4) and the requester's poll learns why. The default
    /// treats every agent as unknown; hosts with a registry override.
    fn known_agent(&self, _user_id: u64, _agent_email: &str) -> Result<Option<KnownAgent>, RegistrarError> {
        Ok(None)
    }
}

/// Require that the caller presented the session's CSRF token.
pub(crate) fn require_csrf(user: &AuthedUser, csrf: &str) -> Result<(), RegistrarError> {
    if !csrf.is_empty() && user.csrf_token == csrf {
        Ok(())
    } else {
        Err(RegistrarError::InvalidCsrf)
    }
}
