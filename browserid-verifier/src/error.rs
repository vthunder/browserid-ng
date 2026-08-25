//! Discovery/verification errors.

/// Errors surfaced by DNSSEC-rooted discovery ([`crate::Discoverer`]).
/// Verification itself reports failures as data (`status: "failure"` with a
/// `reason`), never as an `Err` — a presentation that doesn't verify is a
/// normal outcome, not an error.
#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("DNSSEC validation failed for domain: {domain}")]
    DnssecValidationFailed { domain: String },

    #[error("Discovery failed: {0}")]
    Discovery(String),
}
