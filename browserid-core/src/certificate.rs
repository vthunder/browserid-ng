//! Identity certificates for BrowserID-NG
//!
//! A certificate binds a user's public key to their email address,
//! signed by the email domain's key.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, KeyPair, PublicKey, Result};

/// Principal identifier in a certificate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Principal {
    /// Email address principal
    Email {
        email: String,
    },
}

impl Principal {
    /// Create an email principal
    pub fn email(email: impl Into<String>) -> Self {
        Principal::Email { email: email.into() }
    }

    /// Get the email address if this is an email principal
    pub fn as_email(&self) -> Option<&str> {
        match self {
            Principal::Email { email } => Some(email),
        }
    }

    /// Extract the domain from an email principal
    pub fn domain(&self) -> Option<&str> {
        self.as_email().and_then(|e| e.split('@').nth(1))
    }
}

/// Claims in an identity certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateClaims {
    /// Issuer (the domain that signed this certificate)
    pub iss: String,

    /// Expiration time (Unix timestamp)
    pub exp: i64,

    /// Issued at time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// The user's public key
    #[serde(rename = "public-key")]
    pub public_key: PublicKey,

    /// The principal (email address)
    pub principal: Principal,
}

/// An identity certificate binding a public key to an email address
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The encoded JWT
    encoded: String,
    /// The decoded claims
    claims: CertificateClaims,
}

impl Certificate {
    /// Create and sign a new certificate
    ///
    /// # Arguments
    /// * `issuer` - The domain issuing this certificate
    /// * `email` - The user's email address
    /// * `user_public_key` - The user's public key to certify
    /// * `validity` - How long the certificate should be valid
    /// * `issuer_key` - The domain's signing key
    pub fn create(
        issuer: &str,
        email: &str,
        user_public_key: &PublicKey,
        validity: Duration,
        issuer_key: &KeyPair,
    ) -> Result<Self> {
        let now = Utc::now();
        let exp = now + validity;

        let claims = CertificateClaims {
            iss: issuer.to_string(),
            exp: exp.timestamp(),
            iat: Some(now.timestamp()),
            public_key: user_public_key.clone(),
            principal: Principal::email(email),
        };

        let encoded = Self::encode_and_sign(&claims, issuer_key)?;

        Ok(Self { encoded, claims })
    }

    /// Parse a certificate from its encoded form (does not verify signature)
    pub fn parse(encoded: &str) -> Result<Self> {
        let claims = Self::decode_claims(encoded)?;
        Ok(Self {
            encoded: encoded.to_string(),
            claims,
        })
    }

    /// Verify the certificate signature against a public key
    pub fn verify(&self, issuer_public_key: &PublicKey) -> Result<()> {
        Self::verify_signature(&self.encoded, issuer_public_key)
    }

    /// Check if the certificate has expired
    pub fn is_expired(&self) -> bool {
        let exp = DateTime::from_timestamp(self.claims.exp, 0)
            .unwrap_or(DateTime::UNIX_EPOCH);
        Utc::now() > exp
    }

    /// Get the certificate claims
    pub fn claims(&self) -> &CertificateClaims {
        &self.claims
    }

    /// Get the certified public key
    pub fn public_key(&self) -> &PublicKey {
        &self.claims.public_key
    }

    /// Get the email address
    pub fn email(&self) -> Option<&str> {
        self.claims.principal.as_email()
    }

    /// Get the issuer domain
    pub fn issuer(&self) -> &str {
        &self.claims.iss
    }

    /// Get the encoded JWT
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    // Internal: encode claims and sign with Ed25519
    fn encode_and_sign(claims: &CertificateClaims, key: &KeyPair) -> Result<String> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        // Header for Ed25519
        let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header);

        // Claims
        let claims_json = serde_json::to_string(claims)?;
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

        // Sign header.claims
        let message = format!("{}.{}", header_b64, claims_b64);
        let signature = key.sign(message.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}", message, sig_b64))
    }

    // Internal: decode claims without verifying signature
    fn decode_claims(encoded: &str) -> Result<CertificateClaims> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let parts: Vec<&str> = encoded.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidCertificate("expected 3 JWT parts".into()));
        }

        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
        let claims: CertificateClaims = serde_json::from_slice(&claims_bytes)?;

        Ok(claims)
    }

    // Internal: verify signature
    fn verify_signature(encoded: &str, public_key: &PublicKey) -> Result<()> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let parts: Vec<&str> = encoded.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidCertificate("expected 3 JWT parts".into()));
        }

        let message = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD.decode(parts[2])?;

        public_key.verify(message.as_bytes(), &signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_create_and_verify() {
        // Domain keypair
        let domain_key = KeyPair::generate();

        // User keypair
        let user_key = KeyPair::generate();

        // Create certificate
        let cert = Certificate::create(
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();

        // Verify with domain's public key
        cert.verify(&domain_key.public_key()).unwrap();

        // Check claims
        assert_eq!(cert.issuer(), "example.com");
        assert_eq!(cert.email(), Some("alice@example.com"));
        assert_eq!(cert.public_key(), &user_key.public_key());
        assert!(!cert.is_expired());
    }

    #[test]
    fn test_certificate_parse_and_verify() {
        let domain_key = KeyPair::generate();
        let user_key = KeyPair::generate();

        let cert = Certificate::create(
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();

        // Parse from encoded form
        let parsed = Certificate::parse(cert.encoded()).unwrap();
        parsed.verify(&domain_key.public_key()).unwrap();

        assert_eq!(parsed.email(), Some("alice@example.com"));
    }

    #[test]
    fn test_certificate_wrong_key_rejected() {
        let domain_key = KeyPair::generate();
        let wrong_key = KeyPair::generate();
        let user_key = KeyPair::generate();

        let cert = Certificate::create(
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();

        // Should fail with wrong key
        assert!(cert.verify(&wrong_key.public_key()).is_err());
    }
}
