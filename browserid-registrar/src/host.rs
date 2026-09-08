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

    /// Token-lane account resolution (registry-api-v1 §3.1): the caller has
    /// PROVEN control of `email` with a fully verified presentation. If an
    /// account owns the identity, that account authenticates; otherwise a new
    /// account containing exactly that identity is created. No linking,
    /// transfer, or merge — those are cookie-lane / fallback-IdP ceremonies.
    /// Default errors, so hosts without the token lane keep compiling.
    fn account_for_presented_identity(&self, _email: &str) -> Result<u64, RegistrarError> {
        Err(RegistrarError::Internal(
            "token-lane account resolution not supported by this host".into(),
        ))
    }

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
    /// INTERNAL: shown only to the owning account, never published.
    /// Best-effort; a default no-op for hosts without a registry.
    fn set_agent_display_name(&self, _user_id: u64, _agent_email: &str, _name: &str) {}

    /// Store the PUBLIC byline for an agent identity (bean tmk8) — what
    /// services display next to the identity's actions. Only set when the
    /// human filled the explicitly-public field on the approval page.
    /// Best-effort; a default no-op for hosts without a registry.
    fn set_agent_public_name(&self, _user_id: u64, _agent_email: &str, _name: &str) {}

    /// Flip the revocation bit behind a status ref that is NOT on the
    /// registrar's own list but may still be hosted by this deployment (the
    /// broker also hosts its tenants' lists under the idp host's
    /// `/status/<domain>`). `Ok(true)` = this deployment is the ref's
    /// authority and the bit is now revoked; `Ok(false)` = a genuinely
    /// foreign ref — nobody here can revoke it, and callers surface that
    /// (registry-api-v1 §5.3/§5.4) instead of silently pretending. The
    /// default hosts no foreign lists.
    fn revoke_hosted_status(&self, _uri: &str, _idx: u64) -> Result<bool, RegistrarError> {
        Ok(false)
    }

    /// Whether this account has already met `agent_email` — an agent identity
    /// on the account, or a recorded device cert / service entry covering it —
    /// and what it knows about it. `None` = an unknown agent: the consent page
    /// renders deny-only (P4) and the requester's poll learns why. The default
    /// treats every agent as unknown; hosts with a registry override.
    fn known_agent(&self, _user_id: u64, _agent_email: &str) -> Result<Option<KnownAgent>, RegistrarError> {
        Ok(None)
    }

    // --- Account membership (registry-api-v1 §4.1; bean 0c49) ---
    // Identities are host-owned, so the leave/return cascade is the host's;
    // the registry calls it from attach/detach/delete. Defaults error so
    // hosts without membership keep compiling.

    /// `identity` leaves `user_id`'s account (§4.1 rule 3): suspended there
    /// for the hold, records frozen, agents with it, notice filed. `reason`
    /// is `transferred` | `taken_over` | `detached` | `deleted`.
    fn identity_leaves(&self, _user_id: u64, _identity: &str, _reason: &str) -> Result<(), RegistrarError> {
        Err(RegistrarError::Internal("membership not supported by this host".into()))
    }

    /// `identity` returns to `user_id`'s account within the hold.
    fn identity_returns(&self, _user_id: u64, _identity: &str) -> Result<(), RegistrarError> {
        Err(RegistrarError::Internal("membership not supported by this host".into()))
    }

    /// The account's roster (§4.5): `(identity, "active" | "suspended")`.
    fn roster(&self, _user_id: u64) -> Result<Vec<(String, &'static str)>, RegistrarError> {
        Err(RegistrarError::Internal("membership not supported by this host".into()))
    }

    /// Drop what expired holds kept; opportunistic, safe to call often.
    fn sweep_holds(&self) -> Result<(), RegistrarError> {
        Ok(())
    }

    /// The account's public id (registry-api-v1 §3: opaque, ≥128 bits,
    /// never the row id), minted on first use.
    fn account_public_id(&self, _user_id: u64) -> Result<String, RegistrarError> {
        Err(RegistrarError::Internal("account ids not supported by this host".into()))
    }

    /// The account behind a public id, if any.
    fn account_for_public_id(&self, _public_id: &str) -> Result<Option<u64>, RegistrarError> {
        Err(RegistrarError::Internal("account ids not supported by this host".into()))
    }

    // --- Attach (registry-api-v1 §5.2.1) ---

    /// The account on which `identity` is ACTIVE, if any (a suspended copy
    /// elsewhere does not count).
    fn identity_holder(&self, _identity: &str) -> Result<Option<u64>, RegistrarError> {
        Err(RegistrarError::Internal("membership not supported by this host".into()))
    }

    /// Whether `identity` is on hold on `user_id`'s account.
    fn identity_suspended_on(&self, _user_id: u64, _identity: &str) -> Result<bool, RegistrarError> {
        Err(RegistrarError::Internal("membership not supported by this host".into()))
    }

    /// A new, empty account (a takeover's destination; the identity moves
    /// in right after).
    fn create_empty_account(&self) -> Result<u64, RegistrarError> {
        Err(RegistrarError::Internal("membership not supported by this host".into()))
    }

    /// A new account holding exactly `identity` (issued by `iss`).
    fn create_account_with_identity(&self, _identity: &str, _iss: &str) -> Result<u64, RegistrarError> {
        Err(RegistrarError::Internal("membership not supported by this host".into()))
    }

    /// `identity`, held by no account, joins `user_id`'s.
    fn add_identity(&self, _user_id: u64, _identity: &str, _iss: &str) -> Result<(), RegistrarError> {
        Err(RegistrarError::Internal("membership not supported by this host".into()))
    }

    /// `identity` leaves `from` (§4.1 rule 3) and joins `to`; a hold on
    /// `to` becomes a return.
    fn transfer_identity(&self, _from: u64, _to: u64, _identity: &str, _reason: &str) -> Result<(), RegistrarError> {
        Err(RegistrarError::Internal("membership not supported by this host".into()))
    }

    /// `identity`, on hold on `user_id`'s account and active nowhere,
    /// returns there.
    fn restore_identity(&self, _user_id: u64, _identity: &str, _iss: &str) -> Result<(), RegistrarError> {
        Err(RegistrarError::Internal("membership not supported by this host".into()))
    }

    /// Detach (§5.2.2): `identity` leaves and nobody holds it.
    fn detach_identity(&self, _user_id: u64, _identity: &str) -> Result<(), RegistrarError> {
        Err(RegistrarError::Internal("membership not supported by this host".into()))
    }

    /// Delete (§5.2.3): every identity leaves; the account is dropped after
    /// the hold.
    fn delete_account(&self, _user_id: u64) -> Result<(), RegistrarError> {
        Err(RegistrarError::Internal("membership not supported by this host".into()))
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
