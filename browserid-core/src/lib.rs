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
pub mod error;

pub use keys::{KeyPair, PublicKey};
pub use certificate::Certificate;
pub use assertion::{Assertion, BackedAssertion};
pub use error::Error;

/// Result type for browserid-core operations
pub type Result<T> = std::result::Result<T, Error>;
