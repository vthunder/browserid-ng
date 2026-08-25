//! Identity assertions for BrowserID-NG
//!
//! The minimal 2-claim `{aud, exp}` JWS, signed by a certified key. In the
//! device-cert model it is signed by the fresh ACCESS key and presented
//! inside an `AccessPresentation` (`device.rs`).

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, KeyPair, PublicKey, Result};

/// Claims in an identity assertion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionClaims {
    /// Expiration time (Unix timestamp)
    pub exp: i64,

    /// Audience (the relying party origin this assertion is for)
    pub aud: String,

    /// The requesting channel: the authenticated origin the signing request
    /// arrived from, stamped by the wallet at dispatch (spec §5). Present iff
    /// the presented warrant carries a `requester` binding entry — matched by
    /// verifiers fail-closed (§6.6 invariant 13).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_origin: Option<String>,
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
        Self::create_with_req_origin(audience, None, validity, user_key)
    }

    /// Create and sign an assertion carrying the wallet's `req_origin` stamp
    /// (spec §5): the authenticated origin the signing request arrived from.
    /// Only for presentations under a record with a `requester` entry.
    pub fn create_with_req_origin(
        audience: &str,
        req_origin: Option<&str>,
        validity: Duration,
        user_key: &KeyPair,
    ) -> Result<Self> {
        let now = Utc::now();
        let exp = now + validity;

        let claims = AssertionClaims {
            exp: exp.timestamp(),
            aud: audience.to_string(),
            req_origin: req_origin.map(str::to_string),
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
