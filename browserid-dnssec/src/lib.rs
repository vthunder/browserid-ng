//! DNSSEC-authenticated BrowserID discovery.
//!
//! The authenticated `_browserid.<domain>` DNSSEC record is the **sole root
//! of trust** for an IdP's identity key (spec §3). A conformant verifier
//! resolves the key here and NEVER from `.well-known` — a `.well-known`
//! document carries endpoints, never a key, and a hosted primary
//! (`host=<provider>`) serves no key at its own origin at all.
//!
//! This crate is the shared resolver so every verifier — the broker, the RP
//! library, downstream consumers — roots trust the same way.

pub mod dns;

pub use dns::DnsFetcher;

use browserid_core::{DnssecStatus, PublicKey};

/// Why an issuer key could not be DNSSEC-resolved.
#[derive(Debug, Clone)]
pub enum ResolveError {
    /// No DNSSEC-validated `_browserid` record — the domain is not a primary
    /// IdP (AD-unset / NXDOMAIN). A verifier MUST NOT trust it as an issuer.
    NotPrimary,
    /// The DNSSEC chain is broken (SERVFAIL / Bogus) — an attack signal, hard
    /// reject rather than fall through.
    Bogus,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::NotPrimary => {
                write!(f, "no DNSSEC-validated _browserid record (not a primary IdP)")
            }
            ResolveError::Bogus => write!(f, "DNSSEC validation failed (bogus chain)"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Resolve an issuer's identity key from its authenticated `_browserid`
/// DNSSEC record — the only value a verifier needs to check a signature.
///
/// The key comes from the DNS record itself; `.well-known` is never consulted
/// (so a hosted primary's `host=` is honored implicitly — the verifier never
/// tries to fetch a key from the tenant domain, which serves none). Endpoint
/// discovery (the `host=` target's support document) is a separate concern
/// that only issuance/mediation needs, not verification.
pub async fn resolve_idp_key(
    fetcher: &DnsFetcher,
    domain: &str,
) -> Result<PublicKey, ResolveError> {
    let result = fetcher.lookup(domain).await;
    match result.dnssec_status {
        DnssecStatus::Secure => result.record.map(|r| r.public_key).ok_or(ResolveError::NotPrimary),
        DnssecStatus::Insecure => Err(ResolveError::NotPrimary),
        DnssecStatus::Bogus => Err(ResolveError::Bogus),
    }
}
