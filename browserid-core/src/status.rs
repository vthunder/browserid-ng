//! Certificate/warrant status lists (core §6.4) — sub-TTL revocation.
//!
//! Credentials are offline and self-contained, so absent anything else they
//! are valid until `exp`. For faster revocation a credential MAY carry a
//! [`StatusRef`] — `{uri, idx}` — pointing into a compact, issuer-signed
//! bitmap (the **status list**) published at `uri`. Verifiers fetch the
//! list, cache it briefly (reference: 5 minutes, the token's `ttl`), and
//! treat a set bit as revoked → reject.
//!
//! The list format follows the IETF OAuth Token Status List mechanism in
//! shape — 1 bit per entry, LSB-first within each byte, zlib-compressed,
//! base64url — carried in this protocol's usual claim-level-`typ` JWS
//! rather than a JOSE-header-typed JWT.
//!
//! Properties worth noting:
//! - Fetching the whole list reveals nothing about *which* credential the
//!   verifier is checking (no OCSP-style privacy leak).
//! - The dependency is soft: an unreachable list degrades to TTL-only
//!   semantics; fail-open vs fail-closed is verifier policy.
//! - A list token is a portable artifact — a detached snapshot can travel
//!   with detached DNSSEC proofs (§6.3) for offline "valid as of T"
//!   verification.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

use crate::provisioning::{jws_decode, jws_sign, jws_verify};
use crate::{Error, KeyPair, PublicKey, Result};

/// Claim-level `typ` of a status list token
pub const TYP_STATUS_LIST: &str = "browserid-status-list-v1";

/// Reference cache lifetime a publisher advertises (seconds)
pub const STATUS_LIST_TTL_SECONDS: i64 = 300;

fn invalid(msg: impl std::fmt::Display) -> Error {
    Error::InvalidStatusList(msg.to_string())
}

/// The `status` claim a certificate or warrant carries: where its
/// revocation bit lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusRef {
    /// The status list URI (issuer-published)
    pub uri: String,
    /// This credential's bit index in the list
    pub idx: u64,
}

/// A revocation bitmap: 1 bit per index, LSB-first within each byte.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatusList {
    bytes: Vec<u8>,
}

impl StatusList {
    /// Build from the set of revoked indices (everything else is valid).
    pub fn from_revoked(revoked: impl IntoIterator<Item = u64>, capacity: u64) -> Self {
        let mut list = Self { bytes: vec![0u8; (capacity as usize + 8) / 8 + 1] };
        for idx in revoked {
            list.set(idx);
        }
        list
    }

    pub fn set(&mut self, idx: u64) {
        let byte = (idx / 8) as usize;
        if byte >= self.bytes.len() {
            self.bytes.resize(byte + 1, 0);
        }
        self.bytes[byte] |= 1 << (idx % 8);
    }

    pub fn is_revoked(&self, idx: u64) -> bool {
        let byte = (idx / 8) as usize;
        self.bytes
            .get(byte)
            .is_some_and(|b| b & (1 << (idx % 8)) != 0)
    }

    /// zlib-compress + base64url — the `lst` encoding
    pub fn encode(&self) -> Result<String> {
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&self.bytes)
            .and_then(|_| enc.finish())
            .map(|out| URL_SAFE_NO_PAD.encode(out))
            .map_err(|e| invalid(format!("compress: {e}")))
    }

    pub fn decode(lst: &str) -> Result<Self> {
        let compressed = URL_SAFE_NO_PAD
            .decode(lst)
            .map_err(|e| invalid(format!("base64: {e}")))?;
        let mut bytes = Vec::new();
        flate2::read::ZlibDecoder::new(&compressed[..])
            .read_to_end(&mut bytes)
            .map_err(|e| invalid(format!("decompress: {e}")))?;
        // A decompression bomb has no leverage here, but cap it anyway.
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(invalid("status list too large"));
        }
        Ok(Self { bytes })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusListClaims {
    /// MUST be [`TYP_STATUS_LIST`]
    pub typ: String,
    /// Publishing issuer (domain)
    pub iss: String,
    /// The list's own URI — must match where the verifier fetched it
    pub sub: String,
    pub iat: i64,
    /// Suggested max cache age, seconds
    pub ttl: i64,
    pub status_list: StatusListPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusListPayload {
    /// Bits per entry — always 1 here (revoked / not)
    pub bits: u8,
    /// zlib+base64url bitmap
    pub lst: String,
}

/// A signed status list: the issuer's current revocation bitmap as a
/// portable JWS artifact.
#[derive(Debug, Clone)]
pub struct StatusListToken {
    encoded: String,
    claims: StatusListClaims,
    list: StatusList,
}

impl StatusListToken {
    pub fn create(
        issuer: &str,
        uri: &str,
        list: &StatusList,
        issuer_key: &KeyPair,
    ) -> Result<Self> {
        let claims = StatusListClaims {
            typ: TYP_STATUS_LIST.to_string(),
            iss: issuer.to_string(),
            sub: uri.to_string(),
            iat: Utc::now().timestamp(),
            ttl: STATUS_LIST_TTL_SECONDS,
            status_list: StatusListPayload { bits: 1, lst: list.encode()? },
        };
        let encoded = jws_sign(&claims, issuer_key)?;
        Ok(Self { encoded, claims, list: list.clone() })
    }

    /// Parse (no signature check); rejects wrong `typ`/`bits`
    pub fn parse(encoded: &str) -> Result<Self> {
        let claims: StatusListClaims = jws_decode(encoded, "status list")?;
        if claims.typ != TYP_STATUS_LIST {
            return Err(invalid(format!("typ '{}'", claims.typ)));
        }
        if claims.status_list.bits != 1 {
            return Err(invalid(format!("unsupported bits {}", claims.status_list.bits)));
        }
        let list = StatusList::decode(&claims.status_list.lst)?;
        Ok(Self { encoded: encoded.to_string(), claims, list })
    }

    /// Verify the issuer signature and that the token is for `expected_uri`.
    pub fn verify(&self, issuer_key: &PublicKey, expected_uri: &str) -> Result<()> {
        jws_verify(&self.encoded, issuer_key, "status list")?;
        if self.claims.sub != expected_uri {
            return Err(invalid(format!(
                "list is for '{}', not '{}'",
                self.claims.sub, expected_uri
            )));
        }
        Ok(())
    }

    /// Whether the token is within its advertised cache lifetime (plus
    /// `grace` seconds of slack).
    pub fn is_fresh(&self, grace: i64) -> bool {
        Utc::now().timestamp() <= self.claims.iat + self.claims.ttl + grace
    }

    pub fn is_revoked(&self, idx: u64) -> bool {
        self.list.is_revoked(idx)
    }

    pub fn claims(&self) -> &StatusListClaims {
        &self.claims
    }

    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    #[test]
    fn bitmap_roundtrip_and_bounds() {
        let list = StatusList::from_revoked([0, 7, 8, 300], 1000);
        assert!(list.is_revoked(0) && list.is_revoked(7) && list.is_revoked(8) && list.is_revoked(300));
        assert!(!list.is_revoked(1) && !list.is_revoked(299) && !list.is_revoked(301));
        // Out of range reads as valid, never panics.
        assert!(!list.is_revoked(1_000_000));

        let decoded = StatusList::decode(&list.encode().unwrap()).unwrap();
        assert_eq!(decoded, list);
    }

    #[test]
    fn token_roundtrip_verify_and_freshness() {
        let key = KeyPair::generate();
        let uri = "https://broker.example/.well-known/browserid-status";
        let list = StatusList::from_revoked([42], 100);
        let token = StatusListToken::create("broker.example", uri, &list, &key).unwrap();

        let parsed = StatusListToken::parse(token.encoded()).unwrap();
        parsed.verify(&key.public_key(), uri).unwrap();
        assert!(parsed.is_revoked(42));
        assert!(!parsed.is_revoked(41));
        assert!(parsed.is_fresh(0));

        // Wrong key / wrong uri rejected.
        assert!(parsed.verify(&KeyPair::generate().public_key(), uri).is_err());
        assert!(parsed.verify(&key.public_key(), "https://other.example/list").is_err());

        // Domain separation: a certificate is not a status list.
        let cert = crate::Certificate::create(
            "broker.example",
            "a@broker.example",
            &KeyPair::generate().public_key(),
            chrono::Duration::hours(1),
            &key,
        )
        .unwrap();
        assert!(StatusListToken::parse(cert.encoded()).is_err());
    }
}
