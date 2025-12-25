//! Error types for BrowserID-NG

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("Invalid assertion: {0}")]
    InvalidAssertion(String),

    #[error("Certificate expired")]
    CertificateExpired,

    #[error("Assertion expired")]
    AssertionExpired,

    #[error("Audience mismatch: expected {expected}, got {actual}")]
    AudienceMismatch { expected: String, actual: String },

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Certificate chain invalid: {0}")]
    InvalidCertificateChain(String),

    #[error("Issuer mismatch: certificate issuer {cert_issuer} does not match email domain {email_domain}")]
    IssuerMismatch {
        cert_issuer: String,
        email_domain: String,
    },

    #[error("Discovery failed for domain {domain}: {reason}")]
    DiscoveryFailed { domain: String, reason: String },

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}
