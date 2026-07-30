//! Handle attestations (browserid-ng-tsqk): the signed claim a proof
//! specialist hands the broker after verifying non-SMTP ownership of a
//! domain.
//!
//! In the handle-identity design the bsky bridge runs the atproto OAuth hop
//! and the bidirectional handle↔DID resolution, then attests the outcome —
//! "DID X holds handle H, verified at time T" — signed with its own IdP key
//! (a DNSSEC-published `_browserid` key, so the broker verifies it with the
//! discovery machinery it already has). The broker, as the issuer, consumes
//! the attestation exactly once and attaches `<label>@<handle>` to the
//! account as a verified identity.
//!
//! The attestation is a short-lived, audience-bound bearer token: whoever
//! holds it within its validity window can attach the handle to *their*
//! broker account, which is why it expires in minutes, names the one broker
//! that may consume it, and carries a `jti` for replay rejection. The
//! attestor is a trusted internal component of the fallback, not a third
//! party — the broker decides *which* issuer domains it accepts by
//! configuration, and trust in the signature is rooted in DNSSEC like every
//! other issuer key.

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::jws::{jws_decode, jws_sign, jws_verify};
use crate::{Error, KeyPair, PublicKey, Result};

/// Claim-level `typ` of a handle attestation
pub const TYP_HANDLE_ATTESTATION: &str = "browserid-handle-attestation-v1";

/// How long an attestation is redeemable. Long enough for one browser
/// round trip from the bridge back to the dialog and one broker call;
/// short enough that a leaked token goes stale before it travels far.
pub const ATTESTATION_VALIDITY_SECONDS: i64 = 300;

fn invalid(msg: impl std::fmt::Display) -> Error {
    Error::InvalidAttestation(msg.to_string())
}

/// 128 bits of OS randomness, base64url — collision-free within any
/// realistic replay window.
fn random_jti() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleAttestationClaims {
    pub typ: String,
    /// The attesting IdP domain (e.g. `bsky.browserid.me`) — the domain
    /// whose DNSSEC-published key signed this.
    pub iss: String,
    /// The broker domain this attestation is addressed to. A consumer MUST
    /// refuse an attestation addressed elsewhere.
    pub aud: String,
    /// The proven handle — the domain position of the identity.
    pub handle: String,
    /// The DID that held the handle when it was verified.
    pub did: String,
    pub iat: i64,
    pub exp: i64,
    /// Unique id for replay rejection within the validity window.
    pub jti: String,
}

/// A signed handle attestation (EdDSA JWS, same idiom as certs and status
/// lists).
#[derive(Debug, Clone)]
pub struct HandleAttestation {
    encoded: String,
    claims: HandleAttestationClaims,
}

impl HandleAttestation {
    /// Sign a fresh attestation: `handle` is held by `did`, verified now,
    /// redeemable at `aud` for [`ATTESTATION_VALIDITY_SECONDS`].
    pub fn create(
        issuer: &str,
        audience: &str,
        handle: &str,
        did: &str,
        issuer_key: &KeyPair,
    ) -> Result<Self> {
        let now = Utc::now().timestamp();
        let claims = HandleAttestationClaims {
            typ: TYP_HANDLE_ATTESTATION.to_string(),
            iss: issuer.to_string(),
            aud: audience.to_string(),
            handle: handle.to_ascii_lowercase(),
            did: did.to_string(),
            iat: now,
            exp: now + ATTESTATION_VALIDITY_SECONDS,
            jti: random_jti(),
        };
        let encoded = jws_sign(&claims, issuer_key)?;
        Ok(Self { encoded, claims })
    }

    /// Parse without verifying the signature; rejects a wrong `typ`.
    pub fn parse(encoded: &str) -> Result<Self> {
        let claims: HandleAttestationClaims = jws_decode(encoded, "handle attestation")?;
        if claims.typ != TYP_HANDLE_ATTESTATION {
            return Err(invalid(format!("typ '{}'", claims.typ)));
        }
        Ok(Self { encoded: encoded.to_string(), claims })
    }

    /// Full check: signature under the issuer's key, addressed to
    /// `expected_audience`, and not expired. The caller still owns the
    /// trust decision about *which issuer* — resolve `claims().iss` to a
    /// key it trusts (DNSSEC discovery) before calling this — and replay
    /// rejection via `claims().jti`.
    pub fn verify(&self, issuer_key: &PublicKey, expected_audience: &str) -> Result<()> {
        jws_verify(&self.encoded, issuer_key, "handle attestation")?;
        if self.claims.aud != expected_audience {
            return Err(Error::AudienceMismatch {
                expected: expected_audience.to_string(),
                actual: self.claims.aud.clone(),
            });
        }
        let now = Utc::now().timestamp();
        if now >= self.claims.exp {
            return Err(invalid("attestation expired"));
        }
        // An iat in the future is a clock lie, not skew we should absorb.
        if self.claims.iat > now + 60 {
            return Err(invalid("attestation issued in the future"));
        }
        Ok(())
    }

    pub fn claims(&self) -> &HandleAttestationClaims {
        &self.claims
    }

    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attest(key: &KeyPair) -> HandleAttestation {
        HandleAttestation::create(
            "bsky.browserid.test",
            "broker.test",
            "Dan.BSky.Social",
            "did:plc:abc",
            key,
        )
        .unwrap()
    }

    #[test]
    fn round_trips_and_verifies() {
        let key = KeyPair::generate();
        let a = attest(&key);
        let parsed = HandleAttestation::parse(a.encoded()).unwrap();
        parsed.verify(&key.public_key(), "broker.test").unwrap();
        // The handle lands lowercased — it is the domain half of an
        // identity string and the stores lowercase identities globally.
        assert_eq!(parsed.claims().handle, "dan.bsky.social");
        assert_eq!(parsed.claims().did, "did:plc:abc");
        assert_eq!(parsed.claims().iss, "bsky.browserid.test");
        assert!(!parsed.claims().jti.is_empty());
    }

    #[test]
    fn the_wrong_key_is_rejected() {
        let a = attest(&KeyPair::generate());
        assert!(a.verify(&KeyPair::generate().public_key(), "broker.test").is_err());
    }

    /// An attestation addressed to broker A must not be redeemable at
    /// broker B — that is the whole point of `aud` on a bearer claim.
    #[test]
    fn the_wrong_audience_is_rejected() {
        let key = KeyPair::generate();
        let a = attest(&key);
        assert!(matches!(
            a.verify(&key.public_key(), "other.test"),
            Err(Error::AudienceMismatch { .. })
        ));
    }

    #[test]
    fn tampered_claims_are_rejected() {
        let key = KeyPair::generate();
        let a = attest(&key);
        // Re-encode with a different handle but the original signature.
        let parts: Vec<&str> = a.encoded().split('.').collect();
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let mut claims: HandleAttestationClaims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        claims.handle = "evil.example".into();
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap()),
            parts[2]
        );
        let forged = HandleAttestation::parse(&forged).unwrap();
        assert!(forged.verify(&key.public_key(), "broker.test").is_err());
    }

    #[test]
    fn a_wrong_typ_does_not_parse() {
        let key = KeyPair::generate();
        // A status-list token is also a JWS — it must not parse as an
        // attestation.
        let list = crate::StatusList::from_revoked(vec![], 8);
        let token =
            crate::StatusListToken::create("iss.test", "https://iss.test/s", &list, &key).unwrap();
        assert!(HandleAttestation::parse(token.encoded()).is_err());
    }

    #[test]
    fn expiry_is_enforced() {
        let key = KeyPair::generate();
        let a = attest(&key);
        let mut claims = a.claims().clone();
        claims.iat -= 1000;
        claims.exp = Utc::now().timestamp() - 1;
        let expired = HandleAttestation {
            encoded: crate::jws::jws_sign(&claims, &key).unwrap(),
            claims,
        };
        assert!(expired.verify(&key.public_key(), "broker.test").is_err());
    }
}
