//! BrowserID-NG Core Library
//!
//! Implements the BrowserID device-cert model for email-based identity:
//! - IdPs (DNSSEC-discovered) issue device certs — authentication (mints
//!   access certs) x authorization (signs warrants) — and run the headless
//!   access-cert mint
//! - Holders present `access_cert~assertion~warrant~config_cert` to RPs
//! - Verifiers join the bundle by (identity, holder∈matcher, audience), rooted
//!   at the identity's own IdP key

pub mod keys;
pub mod assertion;
pub mod attestation;
pub mod device;
pub mod discovery;
pub mod dns;
pub mod error;
pub mod jws;
pub mod rp_auth;
pub mod status;

pub use keys::{KeyPair, PublicKey};
pub use assertion::Assertion;
// `device::Warrant` is not re-exported at the crate root: call it
// `device::Warrant` at use sites, mirroring the wire object's home.
pub use device::{
    AccessCert, AccessPresentation, AccessRequest, DeviceCert, Holder, HolderMatcher, Purpose,
    VerifiedAccess,
};
pub use dns::{DnsRecord, DnssecStatus, DnsLookupResult};
pub use error::Error;
pub use rp_auth::{RpChallenge, TokenRequest, TokenResponse};
pub use status::{StatusList, StatusListToken, StatusRef, TYP_STATUS_LIST};
pub use attestation::{HandleAttestation, HandleAttestationClaims, TYP_HANDLE_ATTESTATION};

/// Result type for browserid-core operations
pub type Result<T> = std::result::Result<T, Error>;
