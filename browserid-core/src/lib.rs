//! BrowserID-NG Core Library
//!
//! Implements the BrowserID protocol for email-based identity:
//! - Domains publish keys and sign certificates for their users
//! - Users create assertions proving identity to relying parties
//! - Verifiers check certificate chains back to domain keys

pub mod keys;
pub mod certificate;
pub mod assertion;
pub mod device;
pub mod discovery;
pub mod dns;
pub mod error;
pub mod jws;
pub mod rp_auth;
pub mod status;
pub mod warrant;

pub use keys::{KeyPair, PublicKey};
pub use certificate::{AgentClaims, Certificate, TYP_AGENT_CERT};
pub use assertion::{AgentAttribution, Assertion, BackedAssertion, VerifiedPresentation};
// Device-cert model (device.rs). `device::Warrant` is intentionally NOT re-exported
// at the crate root to avoid clashing with the legacy `warrant::Warrant`.
pub use device::{
    AccessCert, AccessPresentation, AccessRequest, DeviceCert, Purpose, Subject, VerifiedAccess,
};
pub use dns::{DnsRecord, DnssecStatus, DnsLookupResult};
pub use error::Error;
pub use rp_auth::{RpChallenge, TokenRequest, TokenResponse};
pub use status::{StatusList, StatusListToken, StatusRef, TYP_STATUS_LIST};
pub use warrant::{Warrant, TYP_AGENT_WARRANT, WARRANT_VALIDITY_DAYS};

/// Result type for browserid-core operations
pub type Result<T> = std::result::Result<T, Error>;
