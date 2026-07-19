//! Shared registrar request guards + agent-name validation.
//!
//! The legacy provisioning-cert registry and `/provision/endorse` endorser
//! (the delegation-chain model) have been retired; the device-cert model
//! replaces them. What remains here are the small guards reused across the
//! registrar's handlers and the agent-name rule.

use tower_cookies::Cookies;

use crate::error::RegistrarError;
use crate::RegistrarState;

pub(crate) fn require_enabled(state: &RegistrarState) -> Result<(), RegistrarError> {
    if state.enabled {
        Ok(())
    } else {
        Err(RegistrarError::AgentProvisioningDisabled)
    }
}

pub(crate) fn require_session(
    state: &RegistrarState,
    cookies: &Cookies,
) -> Result<crate::host::AuthedUser, RegistrarError> {
    state
        .host
        .resolve_session(cookies)
        .ok_or(RegistrarError::NotAuthenticated)
}

/// Agent identity local-part: 1–64 chars of [a-z0-9._+-] (the `+` enables
/// `<handle>+<suffix>` subaddressing), starting alphanumeric.
pub fn valid_agent_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'+' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_name_validation() {
        assert!(valid_agent_name("checkpoint-attestor"));
        assert!(valid_agent_name("a"));
        assert!(valid_agent_name("dan+ci"), "subaddressing allowed");
        assert!(valid_agent_name("svc+1a2b"));
        assert!(!valid_agent_name(""));
        assert!(!valid_agent_name("-x"), "must start alphanumeric");
        assert!(!valid_agent_name("+x"));
        assert!(!valid_agent_name("Ab"), "no uppercase");
        assert!(!valid_agent_name("a b"), "no spaces");
        assert!(!valid_agent_name(&"x".repeat(65)));
    }
}
