//! Identity assertions for BrowserID-NG
//!
//! An assertion proves a user's identity to a relying party.
//! A backed assertion includes the certificate chain for verification.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{Certificate, Error, KeyPair, PublicKey, Result};

/// Claims in an identity assertion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionClaims {
    /// Expiration time (Unix timestamp)
    pub exp: i64,

    /// Audience (the relying party origin this assertion is for)
    pub aud: String,
}

/// An identity assertion claiming an email for a specific audience
#[derive(Debug, Clone)]
pub struct Assertion {
    /// The encoded JWT
    encoded: String,
    /// The decoded claims
    claims: AssertionClaims,
}

impl Assertion {
    /// Create and sign a new assertion
    ///
    /// # Arguments
    /// * `audience` - The origin of the relying party (e.g., "https://example.com")
    /// * `validity` - How long the assertion should be valid (typically 2-5 minutes)
    /// * `user_key` - The user's signing key
    pub fn create(audience: &str, validity: Duration, user_key: &KeyPair) -> Result<Self> {
        let now = Utc::now();
        let exp = now + validity;

        let claims = AssertionClaims {
            exp: exp.timestamp(),
            aud: audience.to_string(),
        };

        let encoded = Self::encode_and_sign(&claims, user_key)?;

        Ok(Self { encoded, claims })
    }

    /// Parse an assertion from its encoded form (does not verify signature)
    pub fn parse(encoded: &str) -> Result<Self> {
        let claims = Self::decode_claims(encoded)?;
        Ok(Self {
            encoded: encoded.to_string(),
            claims,
        })
    }

    /// Verify the assertion signature against a public key
    pub fn verify(&self, public_key: &PublicKey) -> Result<()> {
        Self::verify_signature(&self.encoded, public_key)
    }

    /// Check if the assertion has expired
    pub fn is_expired(&self) -> bool {
        let exp = chrono::DateTime::from_timestamp(self.claims.exp, 0)
            .unwrap_or(chrono::DateTime::UNIX_EPOCH);
        Utc::now() > exp
    }

    /// Get the assertion claims
    pub fn claims(&self) -> &AssertionClaims {
        &self.claims
    }

    /// Get the audience
    pub fn audience(&self) -> &str {
        &self.claims.aud
    }

    /// Get the encoded JWT
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    // Internal: encode claims and sign
    fn encode_and_sign(claims: &AssertionClaims, key: &KeyPair) -> Result<String> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header);

        let claims_json = serde_json::to_string(claims)?;
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

        let message = format!("{}.{}", header_b64, claims_b64);
        let signature = key.sign(message.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}", message, sig_b64))
    }

    // Internal: decode claims
    fn decode_claims(encoded: &str) -> Result<AssertionClaims> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let parts: Vec<&str> = encoded.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidAssertion("expected 3 JWT parts".into()));
        }

        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
        let claims: AssertionClaims = serde_json::from_slice(&claims_bytes)?;

        Ok(claims)
    }

    // Internal: verify signature
    fn verify_signature(encoded: &str, public_key: &PublicKey) -> Result<()> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let parts: Vec<&str> = encoded.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidAssertion("expected 3 JWT parts".into()));
        }

        let message = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD.decode(parts[2])?;

        public_key.verify(message.as_bytes(), &signature)
    }
}

/// A backed identity assertion: certificate chain + assertion
///
/// Format: `<cert-1>~<cert-2>~...~<cert-n>~<assertion>`
///
/// The certificate chain goes from user cert (signed by domain) to assertion.
/// In the simple case, there's just one certificate.
#[derive(Debug, Clone)]
pub struct BackedAssertion {
    /// The certificate chain (typically just one certificate)
    certificates: Vec<Certificate>,
    /// The assertion
    assertion: Assertion,
}

impl BackedAssertion {
    /// Create a backed assertion with a single certificate
    pub fn new(certificate: Certificate, assertion: Assertion) -> Self {
        Self {
            certificates: vec![certificate],
            assertion,
        }
    }

    /// Create a backed assertion with a certificate chain
    pub fn with_chain(certificates: Vec<Certificate>, assertion: Assertion) -> Self {
        Self {
            certificates,
            assertion,
        }
    }

    /// Parse a backed assertion from the `cert~cert~...~assertion` format
    pub fn parse(encoded: &str) -> Result<Self> {
        let parts: Vec<&str> = encoded.split('~').collect();
        if parts.len() < 2 {
            return Err(Error::InvalidAssertion(
                "backed assertion must have at least one certificate and one assertion".into(),
            ));
        }

        let assertion_str = parts.last().unwrap();
        let cert_strs = &parts[..parts.len() - 1];

        let certificates: Result<Vec<Certificate>> =
            cert_strs.iter().map(|s| Certificate::parse(s)).collect();
        let certificates = certificates?;

        let assertion = Assertion::parse(assertion_str)?;

        Ok(Self {
            certificates,
            assertion,
        })
    }

    /// Encode to the `cert~cert~...~assertion` format
    pub fn encode(&self) -> String {
        let mut parts: Vec<&str> = self.certificates.iter().map(|c| c.encoded()).collect();
        parts.push(self.assertion.encoded());
        parts.join("~")
    }

    /// Verify the entire chain and assertion
    ///
    /// # Arguments
    /// * `expected_audience` - The audience the assertion should be for
    /// * `get_domain_key` - Function to retrieve a domain's public key
    ///
    /// Returns the verified email address on success.
    pub fn verify<F>(&self, expected_audience: &str, get_domain_key: F) -> Result<String>
    where
        F: Fn(&str) -> Result<PublicKey>,
    {
        if self.certificates.is_empty() {
            return Err(Error::InvalidCertificateChain(
                "no certificates in chain".into(),
            ));
        }

        // Check assertion audience
        if self.assertion.audience() != expected_audience {
            return Err(Error::AudienceMismatch {
                expected: expected_audience.to_string(),
                actual: self.assertion.audience().to_string(),
            });
        }

        // Check assertion expiration
        if self.assertion.is_expired() {
            return Err(Error::AssertionExpired);
        }

        // Verify assertion signature with the certificate's public key
        let user_cert = self.certificates.last().unwrap();
        self.assertion.verify(user_cert.public_key())?;

        // Check certificate expiration
        if user_cert.is_expired() {
            return Err(Error::CertificateExpired);
        }

        // Get the email and domain from the certificate
        let email = user_cert
            .email()
            .ok_or_else(|| Error::InvalidCertificate("certificate has no email".into()))?;

        let domain = user_cert
            .claims()
            .principal
            .domain()
            .ok_or_else(|| Error::InvalidCertificate("cannot extract domain from email".into()))?;

        // Check that the issuer matches the email domain
        if user_cert.issuer() != domain {
            return Err(Error::IssuerMismatch {
                cert_issuer: user_cert.issuer().to_string(),
                email_domain: domain.to_string(),
            });
        }

        // Verify certificate chain (for now, just single certificate)
        // TODO: Support longer chains with intermediate certificates
        if self.certificates.len() == 1 {
            let domain_key = get_domain_key(domain)?;
            user_cert.verify(&domain_key)?;
        } else {
            // For longer chains, verify each cert with the previous cert's public key
            // The root cert is verified with the domain key
            let domain = self.certificates[0]
                .claims()
                .principal
                .domain()
                .ok_or_else(|| {
                    Error::InvalidCertificate("cannot extract domain from root cert".into())
                })?;
            let domain_key = get_domain_key(domain)?;
            self.certificates[0].verify(&domain_key)?;

            for i in 1..self.certificates.len() {
                let prev_cert = &self.certificates[i - 1];
                self.certificates[i].verify(prev_cert.public_key())?;

                if self.certificates[i].is_expired() {
                    return Err(Error::CertificateExpired);
                }
            }
        }

        Ok(email.to_string())
    }

    /// Get the certificates in the chain
    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }

    /// Get the assertion
    pub fn assertion(&self) -> &Assertion {
        &self.assertion
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assertion_create_and_verify() {
        let user_key = KeyPair::generate();

        let assertion =
            Assertion::create("https://example.com", Duration::minutes(5), &user_key).unwrap();

        assertion.verify(&user_key.public_key()).unwrap();
        assert_eq!(assertion.audience(), "https://example.com");
        assert!(!assertion.is_expired());
    }

    #[test]
    fn test_backed_assertion_verify() {
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

        // Create assertion
        let assertion =
            Assertion::create("https://relying-party.com", Duration::minutes(5), &user_key)
                .unwrap();

        // Bundle into backed assertion
        let backed = BackedAssertion::new(cert, assertion);

        // Verify
        let email = backed
            .verify("https://relying-party.com", |domain| {
                assert_eq!(domain, "example.com");
                Ok(domain_key.public_key())
            })
            .unwrap();

        assert_eq!(email, "alice@example.com");
    }

    #[test]
    fn test_backed_assertion_encode_parse() {
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

        let assertion =
            Assertion::create("https://relying-party.com", Duration::minutes(5), &user_key)
                .unwrap();

        let backed = BackedAssertion::new(cert, assertion);
        let encoded = backed.encode();

        // Should contain a ~ separator
        assert!(encoded.contains('~'));

        // Parse it back
        let parsed = BackedAssertion::parse(&encoded).unwrap();

        // Verify
        let email = parsed
            .verify("https://relying-party.com", |_| Ok(domain_key.public_key()))
            .unwrap();

        assert_eq!(email, "alice@example.com");
    }

    #[test]
    fn test_audience_mismatch_rejected() {
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

        let assertion =
            Assertion::create("https://relying-party.com", Duration::minutes(5), &user_key)
                .unwrap();

        let backed = BackedAssertion::new(cert, assertion);

        // Verify with wrong audience should fail
        let result = backed.verify("https://wrong-audience.com", |_| Ok(domain_key.public_key()));
        assert!(matches!(result, Err(Error::AudienceMismatch { .. })));
    }
}
