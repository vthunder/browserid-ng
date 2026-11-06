//! Identity assertions for BrowserID-NG
//!
//! The minimal `{iat, aud, exp}` JWS, signed by a certified key. In the
//! device-cert model it is signed by the fresh ACCESS key and presented
//! inside an `AccessPresentation` (`device.rs`).
//!
//! Time bounds (spec §5, §6.1; audit 2026-11 W4-40 / Q19): the assertion
//! carries `iat` like every other signed object and is judged by the one
//! clock rule in [`crate::time::check_window`]. **Transition:** signers
//! that predate the audit emit no `iat`; such an assertion is still accepted
//! (expiry-only) until the sunset date [`IAT_SUNSET`], after which the claim
//! becomes required. New signers MUST set it.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::jws::invalid;
use crate::time::{check_window, CLOCK_SKEW_SECONDS};
use crate::{Error, KeyPair, PublicKey, Result};

/// Sunset for assertions without `iat` (2027-02-01T00:00:00Z): a verifier
/// judging an `iat`-less assertion at or after this instant rejects it.
/// Before it, the assertion is accepted on its `exp` alone (the pre-audit
/// wire shape; W4-40 transition window).
pub const IAT_SUNSET: i64 = 1_801_526_400;

/// Claims in an identity assertion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionClaims {
    /// Issuance time (Unix timestamp). Required of new signers (spec §5);
    /// absent only on pre-audit assertions, tolerated until [`IAT_SUNSET`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

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
        Self::create_at(audience, req_origin, now.timestamp(), exp.timestamp(), user_key)
    }

    /// Create and sign an assertion with an explicit `iat`/`exp` window —
    /// for deterministic signers and fixtures that must not consult the wall
    /// clock (the counterpart of [`AccessPresentation::verify_at`]).
    ///
    /// [`AccessPresentation::verify_at`]: crate::device::AccessPresentation::verify_at
    pub fn create_at(
        audience: &str,
        req_origin: Option<&str>,
        iat: i64,
        exp: i64,
        user_key: &KeyPair,
    ) -> Result<Self> {
        let claims = AssertionClaims {
            iat: Some(iat),
            exp,
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

    /// Verify the assertion signature against a public key. Signature only:
    /// the time bounds are a separate, clock-dependent question —
    /// [`Self::check_window_at`] — that `AccessPresentation::verify_at` asks
    /// right after this.
    pub fn verify(&self, public_key: &PublicKey) -> Result<()> {
        Self::verify_signature(&self.encoded, public_key)
    }

    /// The §6.1 time bounds at the instant `at` (the one clock rule,
    /// [`check_window`]): `iat ≤ exp`, `iat ≤ at + skew`, unexpired. An
    /// assertion without `iat` (pre-audit signer) is accepted on `exp`
    /// alone while `at < IAT_SUNSET`, rejected from the sunset on.
    pub fn check_window_at(&self, at: i64) -> Result<()> {
        match self.claims.iat {
            Some(iat) => check_window("assertion", iat, self.claims.exp, at, CLOCK_SKEW_SECONDS),
            None if at >= IAT_SUNSET => Err(invalid("assertion", "no iat (required since 2027-02-01)")),
            None => {
                if self.is_expired_at(at) {
                    return Err(invalid("assertion", "expired"));
                }
                Ok(())
            }
        }
    }

    /// Check if the assertion has expired
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Utc::now().timestamp())
    }

    /// Expiry at an explicit instant — for deterministic verifiers that must
    /// not consult the wall clock (`AccessPresentation::verify_at`).
    pub fn is_expired_at(&self, at: i64) -> bool {
        at > self.claims.exp
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

    // Internal: verify signature. The JOSE header is checked like every other
    // typed object's (audit 2026-11 W6-2): `alg` MUST be exactly `EdDSA`
    // — the protocol is Ed25519-only, so `alg: none`, `HS256`, or a missing
    // header field is refused up front rather than relying on the signature
    // check alone.
    fn verify_signature(encoded: &str, public_key: &PublicKey) -> Result<()> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let parts: Vec<&str> = encoded.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidAssertion("expected 3 JWT parts".into()));
        }

        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| Error::InvalidAssertion(format!("bad header b64: {e}")))?;
        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| Error::InvalidAssertion(format!("bad header: {e}")))?;
        if header.get("alg").and_then(|a| a.as_str()) != Some("EdDSA") {
            return Err(Error::InvalidAssertion(
                "unexpected JWS alg (only EdDSA is accepted)".into(),
            ));
        }

        let message = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD.decode(parts[2])?;

        public_key.verify(message.as_bytes(), &signature)
    }
}
