//! BrowserID-NG Core Library
//!
//! Implements the BrowserID protocol for email-based identity:
//! - Domains publish keys and sign certificates for their users
//! - Users create assertions proving identity to relying parties
//! - Verifiers check certificate chains back to domain keys

pub mod keys;
pub mod certificate;
pub mod assertion;
pub mod discovery;
pub mod dns;
pub mod error;
pub mod provisioning;
pub mod rp_auth;

pub use keys::{KeyPair, PublicKey};
pub use certificate::Certificate;
pub use assertion::{Assertion, BackedAssertion};
pub use dns::{DnsRecord, DnssecStatus, DnsLookupResult};
pub use error::Error;
pub use provisioning::{
    Action, Endorsement, ProvisioningCert, ProvisioningRequest, RequestBundle, VerifiedRequest,
};
pub use rp_auth::{RpChallenge, TokenRequest, TokenResponse};

/// Result type for browserid-core operations
pub type Result<T> = std::result::Result<T, Error>;
