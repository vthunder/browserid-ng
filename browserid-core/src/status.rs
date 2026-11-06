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
//! - Verifiers MUST treat the checks as **fail-closed** (spec §6.4): an
//!   unreachable or stale list is "cannot prove unrevoked" → reject.
//!   Degrading to TTL-only semantics (fail-open) is a non-conformant,
//!   explicit opt-out for consumers that choose availability over
//!   revocation latency.
//! - A list token is a portable artifact — a detached snapshot can travel
//!   with detached DNSSEC proofs (§6.3) for offline "valid as of T"
//!   verification.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

use crate::jws::{jws_decode, jws_sign, jws_verify};
use crate::{Error, KeyPair, PublicKey, Result};

/// Claim-level `typ` of a status list token
pub const TYP_STATUS_LIST: &str = "browserid-status-list-v1";

/// Reference cache lifetime a publisher advertises (seconds)
pub const STATUS_LIST_TTL_SECONDS: i64 = 300;

/// Hard ceiling on a status list's INFLATED bitmap (bytes): 4 MiB, i.e.
/// 32 Mi entries. [`StatusList::decode`] bounds the inflate at this size
/// before it allocates (audit 2026-11 W6-3 / W5-8: zlib inflates ~1000:1,
/// so a transport body cap alone does not bound memory), and the encoder
/// side ([`StatusList::from_revoked`], [`StatusList::set`]) never grows a
/// bitmap past it either (W3-4).
pub const STATUS_LIST_MAX_BYTES: usize = 4 * 1024 * 1024;

/// The highest index a status list can carry (`STATUS_LIST_MAX_BYTES * 8 - 1`).
pub const STATUS_LIST_MAX_INDEX: u64 = STATUS_LIST_MAX_BYTES as u64 * 8 - 1;

/// Upper bound on zlib's inflation ratio (the format's ceiling is ≈1032:1),
/// used only to pre-size the inflate buffer so a small list does not pay
/// for a 4 MiB allocation.
const ZLIB_MAX_RATIO: usize = 1100;

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
    ///
    /// `capacity` is the highest index the list is sized for; it is clamped
    /// to [`STATUS_LIST_MAX_INDEX`] and the arithmetic is checked, so a
    /// publisher-side bug (a runaway allocator counter) cannot allocate
    /// gigabytes (W3-4). An index beyond the ceiling cannot be represented
    /// and is skipped — use [`StatusList::try_set`] to surface that.
    pub fn from_revoked(revoked: impl IntoIterator<Item = u64>, capacity: u64) -> Self {
        let capacity = capacity.min(STATUS_LIST_MAX_INDEX) as usize;
        // Same sizing as before the audit (golden vectors depend on the
        // encoded length): `(capacity + 8) / 8 + 1` bytes, clamped.
        let len = ((capacity + 8) / 8 + 1).min(STATUS_LIST_MAX_BYTES);
        let mut list = Self { bytes: vec![0u8; len] };
        for idx in revoked {
            let _ = list.try_set(idx);
        }
        list
    }

    /// Mark `idx` revoked. An index beyond [`STATUS_LIST_MAX_INDEX`] cannot
    /// be represented in a conforming list and is ignored; see
    /// [`StatusList::try_set`] for the fallible form.
    pub fn set(&mut self, idx: u64) {
        let _ = self.try_set(idx);
    }

    /// Mark `idx` revoked, or fail if it lies beyond [`STATUS_LIST_MAX_INDEX`].
    pub fn try_set(&mut self, idx: u64) -> Result<()> {
        if idx > STATUS_LIST_MAX_INDEX {
            return Err(invalid(format!("index {idx} exceeds the status list ceiling")));
        }
        let byte = (idx / 8) as usize;
        if byte >= self.bytes.len() {
            self.bytes.resize(byte + 1, 0);
        }
        self.bytes[byte] |= 1 << (idx % 8);
        Ok(())
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

    /// Decode a `lst` value. The inflate is bounded at
    /// [`STATUS_LIST_MAX_BYTES`] BEFORE it happens: the decoder reads at most
    /// cap + 1 bytes into a buffer pre-sized from the compressed length, so a
    /// zlib bomb (a few KiB inflating to gigabytes) is rejected without ever
    /// inflating past the cap (audit 2026-11 W6-3 / W5-8).
    pub fn decode(lst: &str) -> Result<Self> {
        let compressed = URL_SAFE_NO_PAD
            .decode(lst)
            .map_err(|e| invalid(format!("base64: {e}")))?;
        let limit = STATUS_LIST_MAX_BYTES + 1;
        // Pre-size so `read_to_end` never has to double past the cap; a
        // small list stays a small allocation.
        let hint = compressed
            .len()
            .saturating_mul(ZLIB_MAX_RATIO)
            .saturating_add(64)
            .min(limit);
        let mut bytes = Vec::with_capacity(hint);
        flate2::read::ZlibDecoder::new(&compressed[..])
            .take(limit as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| invalid(format!("decompress: {e}")))?;
        if bytes.len() > STATUS_LIST_MAX_BYTES {
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
    /// `grace` seconds of slack) at wall-clock now. See
    /// [`StatusListToken::is_fresh_at`] for the rule.
    pub fn is_fresh(&self, grace: i64) -> bool {
        self.is_fresh_at(Utc::now().timestamp(), grace)
    }

    /// Freshness with a consumer-imposed ceiling on the issuer-declared `ttl`.
    /// A relying verifier caps how long it will honor a *foreign* issuer's list
    /// so a malicious/compromised issuer cannot set `ttl` arbitrarily large and
    /// pin a cached all-clear list past a real revocation (audit M3).
    pub fn is_fresh_capped(&self, grace: i64, max_ttl: i64) -> bool {
        self.is_fresh_capped_at(Utc::now().timestamp(), grace, max_ttl)
    }

    /// [`StatusListToken::is_fresh`] at an explicit instant. The §6.1 clock
    /// rule (spec §6.3 "the list's own time bounds"): a list is fresh iff
    /// `ttl ≥ 0`, `iat ≤ at + skew` (a post-dated list is not fresh — it
    /// would otherwise stay "fresh" past any cap, D16), and
    /// `at ≤ iat + ttl + grace`. Checked arithmetic: an overflow is stale
    /// (W3-2), never a wrap that reads fresh forever.
    pub fn is_fresh_at(&self, at: i64, grace: i64) -> bool {
        Self::fresh(self.claims.iat, self.claims.ttl, at, grace)
    }

    /// [`StatusListToken::is_fresh_capped`] at an explicit instant.
    pub fn is_fresh_capped_at(&self, at: i64, grace: i64, max_ttl: i64) -> bool {
        Self::fresh(self.claims.iat, self.claims.ttl.min(max_ttl), at, grace)
    }

    fn fresh(iat: i64, ttl: i64, at: i64, grace: i64) -> bool {
        if ttl < 0 || grace < 0 {
            return false;
        }
        if iat > at.saturating_add(crate::time::CLOCK_SKEW_SECONDS) {
            return false;
        }
        match iat.checked_add(ttl).and_then(|d| d.checked_add(grace)) {
            Some(deadline) => at <= deadline,
            None => false,
        }
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
    fn encoder_is_bounded_by_the_list_ceiling() {
        // A runaway capacity allocates at most the 4 MiB ceiling (W3-4).
        let list = StatusList::from_revoked([STATUS_LIST_MAX_INDEX], u64::MAX);
        assert_eq!(list.bytes.len(), STATUS_LIST_MAX_BYTES);
        assert!(list.is_revoked(STATUS_LIST_MAX_INDEX));
        // An index past the ceiling cannot be represented: `set` ignores it,
        // `try_set` says so, and neither grows the bitmap.
        let mut small = StatusList::from_revoked([], 8);
        let before = small.bytes.len();
        small.set(STATUS_LIST_MAX_INDEX + 1);
        assert!(small.try_set(u64::MAX).is_err());
        assert_eq!(small.bytes.len(), before);
        assert!(!small.is_revoked(u64::MAX));
        // Capacity arithmetic is checked across the whole u64 range.
        let _ = StatusList::from_revoked([u64::MAX], u64::MAX - 1);
    }

    #[test]
    fn freshness_follows_the_clock_rule() {
        let key = KeyPair::generate();
        let uri = "https://broker.example/.well-known/browserid-status";
        let tok = |iat: i64, ttl: i64| {
            let claims = StatusListClaims {
                typ: TYP_STATUS_LIST.into(),
                iss: "broker.example".into(),
                sub: uri.into(),
                iat,
                ttl,
                status_list: StatusListPayload { bits: 1, lst: StatusList::from_revoked([], 8).encode().unwrap() },
            };
            StatusListToken::parse(&jws_sign(&claims, &key).unwrap()).unwrap()
        };
        let at = 1_000_000;
        // Within ttl (+ grace): fresh; past it: stale.
        assert!(tok(at - 100, 300).is_fresh_at(at, 0));
        assert!(!tok(at - 400, 300).is_fresh_at(at, 0));
        assert!(tok(at - 400, 300).is_fresh_at(at, 100));
        // A post-dated list is not fresh, however long its ttl (D16).
        assert!(!tok(at + 301, 3600).is_fresh_at(at, 0));
        assert!(!tok(at + 10 * 365 * 86_400, 300).is_fresh_capped_at(at, 0, 300));
        assert!(tok(at + 300, 3600).is_fresh_at(at, 0)); // within skew: drift
        // A negative ttl is stale; overflow is stale (W3-2), never fresh.
        assert!(!tok(at, -1).is_fresh_at(at, 0));
        assert!(!tok(i64::MAX - 10, i64::MAX).is_fresh_at(i64::MAX - 20, 0));
        assert!(!tok(at, 300).is_fresh_at(at, -1));
        // The cap still bounds an honest-but-long ttl.
        assert!(!tok(at - 400, 3600).is_fresh_capped_at(at, 0, 300));
    }

    #[test]
    fn decode_caps_the_inflate_at_the_ceiling() {
        // Exactly the ceiling decodes; one byte more rejects.
        let at_cap = StatusList { bytes: vec![0u8; STATUS_LIST_MAX_BYTES] };
        assert!(StatusList::decode(&at_cap.encode().unwrap()).is_ok());
        let over = StatusList { bytes: vec![0u8; STATUS_LIST_MAX_BYTES + 1] };
        assert!(StatusList::decode(&over.encode().unwrap()).is_err());
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

        // Domain separation: a device cert is not a status list.
        let cert = crate::DeviceCert::create(
            "broker.example",
            &KeyPair::generate().public_key(),
            crate::Purpose::Authentication,
            crate::Holder::new("br.main").unwrap(),
            vec!["a@broker.example".to_string()],
            chrono::Duration::hours(1),
            &key,
            None,
        )
        .unwrap();
        assert!(StatusListToken::parse(cert.encoded()).is_err());
    }
}
