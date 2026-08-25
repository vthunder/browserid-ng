//! The device-cert model — see `docs/design/browserid-end-to-end-flow.md`.
//!
//! Two IdP-signed device-cert *purposes* (`authentication` mints access certs;
//! `authorization` signs warrants) each carrying an opaque, broker-assigned
//! [`Holder`] (which of the user's things acts). An authentication device cert
//! signs an [`AccessRequest`] that the IdP exchanges for a short-lived,
//! fresh-key [`AccessCert`] carrying the same holder. A config cert
//! (`authorization`, device-resident) signs a [`Warrant`] delegating from a
//! `grantor` (the attributed identity) to a `grantee` (the actor) over
//! `(holder-matcher) → audience[+scopes]`. The RP receives an
//! [`AccessPresentation`] — `access_cert ~ assertion ~ warrant ~ config_cert` —
//! and joins them by `(identity, holder∈matcher, audience)`.
//!
//! Hardening (from the 2026-07-18 adversarial review):
//! - **Cross-issuer conformance is the caller's obligation.** The config cert
//!   and the access cert may be issued by *different* IdPs (an on-behalf-of
//!   warrant attributes to the grantor, whose IdP need not be the grantee's), so
//!   [`AccessPresentation::verify`] no longer requires `config_cert.iss ==
//!   access_cert.iss`. Instead the caller's `get_idp_key` resolver MUST verify
//!   that `access_cert.iss` is authoritative for the access-cert identity AND
//!   that `config_cert.iss` is authoritative for the warrant's grantor (each
//!   under its own domain, DNSSEC-rooted). If a caller resolves keys without
//!   that per-issuer conformance check, a rogue IdP's authorization cert can
//!   vouch for another IdP's identity — so this precondition is load-bearing
//!   (`browserid-broker`'s `resolve_conformant_key` and `browserid-rp`'s
//!   `issuer_conformant` both enforce it);
//! - three revocation authorities — access cert, config cert, warrant — each
//!   carry a status ref; [`VerifiedAccess`] surfaces all three for the caller to
//!   check **fail-closed** (revocation needs network, so it lives in the RP-side
//!   verifier, not here);
//! - the holder is part of the join (matcher-covers-holder); unknown `purpose`
//!   values fail closed (serde rejects unknown variants), and an over-long or
//!   empty holder/matcher is rejected at parse;
//! - access requests carry a `jti` for single-use replay protection at the mint.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::jws::{invalid, jws_decode, jws_sign, jws_verify};
use crate::status::StatusRef;
use crate::{Assertion, KeyPair, PublicKey, Result};

pub const TYP_DEVICE_CERT: &str = "browserid-device-cert-v1";
pub const TYP_ACCESS_REQUEST: &str = "browserid-access-request-v1";
pub const TYP_ACCESS_CERT: &str = "browserid-access-cert-v1";
pub const TYP_WARRANT: &str = "browserid-warrant-v1";
pub const TYP_WARRANT_V2: &str = "browserid-warrant-v2";

pub const DEVICE_CERT_VALIDITY_DAYS: i64 = 90;
pub const ACCESS_CERT_VALIDITY_HOURS: i64 = 24;
pub const ACCESS_REQUEST_VALIDITY_MINUTES: i64 = 10;
pub const WARRANT_VALIDITY_DAYS: i64 = 90;

fn expired(exp: i64) -> bool {
    Utc::now().timestamp() > exp
}

/// Match an identity `email` against a device-cert `identities` entry: an exact
/// email or a single-`*` glob (e.g. `danmills+*@sandmill.org`, `*`).
fn identity_matches(pattern: &str, email: &str) -> bool {
    if pattern == email || pattern == "*" {
        return true;
    }
    if let Some((pre, post)) = pattern.split_once('*') {
        return email.len() >= pre.len() + post.len()
            && email.starts_with(pre)
            && email.ends_with(post);
    }
    // RFC-style subaddressing is a PROTOCOL rule, not per-cert data: owning
    // `user@domain` implies owning `user+anything@domain` (agent identities
    // are `+tags` by definition — the same convention `delegator_of` inverts).
    // A cert naming the base identity therefore authorizes its sub-addresses;
    // no `user+*@domain` glob is needed. The identity an agent may PRESENT as
    // stays pinned elsewhere: the warrant's grantee must exactly equal the
    // access-cert identity, so a base-identity cert without a matching warrant
    // authorizes nothing at any verifier.
    if let Some((p_local, p_domain)) = pattern.split_once('@') {
        if let Some((e_local, e_domain)) = email.split_once('@') {
            return p_domain == e_domain
                && e_local.len() > p_local.len()
                && e_local.starts_with(p_local)
                && e_local.as_bytes()[p_local.len()] == b'+';
        }
    }
    false
}

/// `authentication` mints access certs; `authorization` signs warrants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Purpose {
    #[serde(rename = "authentication")]
    Authentication,
    #[serde(rename = "authorization")]
    Authorization,
}

/// Maximum wire length of a [`Holder`] id (bytes). Generous, to leave room for
/// other broker implementations; the reference broker uses ≈16.
pub const HOLDER_MAX_BYTES: usize = 128;

/// An opaque, broker-assigned **holder** id carried by device + access certs.
///
/// The wire form is a single opaque string (spec cap [`HOLDER_MAX_BYTES`]). The
/// reference broker structures it as `<ns>.<holder>` so a warrant can wildcard a
/// namespace, but that is a *broker convention* — this type treats the whole
/// value as opaque. The requesting device never chooses it: the user's broker
/// assigns it and the IdP copies it verbatim device→access at mint. It replaces
/// the old `subject: user|agent` axis (a self-asserted, unenforceable hint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Holder(String);

impl Holder {
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if s.is_empty() {
            return Err(invalid("holder", "empty"));
        }
        if s.len() > HOLDER_MAX_BYTES {
            return Err(invalid("holder", format!("exceeds {HOLDER_MAX_BYTES} bytes")));
        }
        Ok(Self(s))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Holder {
    type Error = crate::Error;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}
impl From<Holder> for String {
    fn from(h: Holder) -> String {
        h.0
    }
}

/// A warrant's holder matcher, spanning the reuse↔isolation axis:
/// - `*` — any of the user's holders (spec-legal; the reference broker refuses
///   to *issue* it, but the type accepts it so a future use isn't blocked);
/// - `<ns>.*` — any holder in a namespace (the dot-prefix before `.*`);
/// - `<id>` — one specific holder (exact match).
///
/// The RP checks the presented access cert's [`Holder`] against this matcher —
/// a trivial string test, no new crypto. Wire form is a plain opaque string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HolderMatcher(String);

impl HolderMatcher {
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if s.is_empty() {
            return Err(invalid("holder matcher", "empty"));
        }
        if s.len() > HOLDER_MAX_BYTES {
            return Err(invalid("holder matcher", format!("exceeds {HOLDER_MAX_BYTES} bytes")));
        }
        Ok(Self(s))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Does this matcher cover `holder`?
    pub fn matches(&self, holder: &Holder) -> bool {
        let m = self.0.as_str();
        let h = holder.as_str();
        if m == "*" {
            return true;
        }
        if let Some(ns) = m.strip_suffix(".*") {
            // `<ns>.*` matches a holder whose namespace prefix is exactly `ns`,
            // i.e. the holder is `<ns>.<rest>`. Require the dot so `k3n9.*` does
            // not match a different namespace `k3n9x.…`.
            return h
                .strip_prefix(ns)
                .is_some_and(|rest| rest.starts_with('.'));
        }
        m == h
    }
}

impl TryFrom<String> for HolderMatcher {
    type Error = crate::Error;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}
impl From<HolderMatcher> for String {
    fn from(m: HolderMatcher) -> String {
        m.0
    }
}

// ===========================================================================
// Constraints & managed identities (spec §4.7).
// ===========================================================================

/// Hashed-audience allowlist: an audience satisfies it iff
/// `b64url(SHA-256(salt ‖ audience))` ∈ `hashes` (audience normalized exactly
/// as assertion `aud`). Hashed because certs are presented to every RP the
/// holder visits — a cleartext list would enumerate the issuing domain's
/// application roster ecosystem-wide.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudConstraint {
    /// base64url (no pad), decoded and prepended to the audience bytes.
    pub salt: String,
    /// base64url (no pad) SHA-256 digests.
    pub hashes: Vec<String>,
}

impl AudConstraint {
    pub fn hash_audience(salt_b64: &str, audience: &str) -> Result<String> {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let salt = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(salt_b64)
            .map_err(|_| invalid("constraints", "aud salt is not base64url"))?;
        let mut h = Sha256::new();
        h.update(&salt);
        h.update(audience.as_bytes());
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize()))
    }

    pub fn permits(&self, audience: &str) -> bool {
        match Self::hash_audience(&self.salt, audience) {
            Ok(digest) => self.hashes.iter().any(|x| x == &digest),
            Err(_) => false, // malformed salt can never permit — fail-closed
        }
    }
}

/// Managed-identity restrictions (spec §4.7), carried by the PRESENTED certs
/// (access cert, config cert) and enforced at verification against the
/// presentation as presented (§6.1 step 7). Unknown keys are captured — not
/// dropped — so verification can reject them fail-closed: constraints are
/// restrictions, and ignoring one is escaping it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<AudConstraint>,
    /// The presented warrant must not carry a scope outside this set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// The presented warrant's `exp − iat` must not exceed this (seconds).
    #[serde(rename = "max-ttl", skip_serializing_if = "Option::is_none")]
    pub max_ttl: Option<i64>,
    /// Constraint keys this implementation does not know. MUST reject at
    /// verification (spec §4.7 fail-closed rule).
    #[serde(flatten)]
    pub unknown: std::collections::BTreeMap<String, serde_json::Value>,
}

impl Constraints {
    /// Enforce this cert's constraints against the presentation (spec §6.1
    /// step 7). `object` names the carrying cert for error messages.
    pub fn check(&self, object: &str, audience: &str, warrant: &WarrantClaims) -> Result<()> {
        if !self.unknown.is_empty() {
            let keys: Vec<&str> = self.unknown.keys().map(String::as_str).collect();
            return Err(invalid(
                object,
                format!("unrecognized constraint key(s): {}", keys.join(", ")),
            ));
        }
        if let Some(aud) = &self.aud {
            if !aud.permits(audience) {
                return Err(invalid(object, "audience not permitted by constraints"));
            }
        }
        if let Some(allowed) = &self.scopes {
            // Scope identity is the scope STRING (§5); parameters ride along
            // and only ever tighten, so the allowlist checks identities.
            if let Some(s) = warrant
                .scopes
                .iter()
                .find(|s| !allowed.iter().any(|a| a == s.scope()))
            {
                return Err(invalid(
                    object,
                    format!("warrant scope '{}' not permitted by constraints", s.scope()),
                ));
            }
        }
        if let Some(max) = self.max_ttl {
            if warrant.exp - warrant.iat > max {
                return Err(invalid(object, "warrant validity exceeds constraints max-ttl"));
            }
        }
        Ok(())
    }
}

// ===========================================================================
// Device certificate (IdP-signed): a device key + purpose + subject + identities.
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCertClaims {
    pub typ: String,
    /// The issuing IdP domain (the identity's primary, or `browserid.me` fallback).
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    pub purpose: Purpose,
    /// The broker-assigned opaque holder this device acts as.
    pub holder: Holder,
    /// Emails (or single-`*` globs) this device may act for.
    pub identities: Vec<String>,
    #[serde(rename = "public-key")]
    pub public_key: PublicKey,
    /// Revocation ref: revoking this device cert logs the device (or agent) out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusRef>,
    /// Managed-identity marker (spec §4.7): set on every device cert of a
    /// managed identity, BEFORE the IdP ever stamps constraints or requires a
    /// mint audience — the durable, issuance-time signal driving UA disclosure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed: Option<bool>,
    /// Restrictions (spec §4.7). Meaningful only on a CONFIG cert (presented;
    /// binds warrants at verification). An auth cert MUST NOT carry it —
    /// issuance-side rule; the parser is lenient, the verifier only reads
    /// presented certs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    /// The proof class ("smtp" / "oidc" / "atproto") the identity was
    /// verified under WHEN THIS CERT WAS ISSUED (browserid-ng-kts0). The
    /// broker's /access/mint refuses (and revokes) a cert whose class no
    /// longer matches the identity's current record, so certs are swapped at
    /// their next use after a provenance upgrade instead of outliving it.
    /// Absent on certs that predate the claim, which read as "smtp".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prov: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeviceCert {
    encoded: String,
    claims: DeviceCertClaims,
}

impl DeviceCert {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        idp_domain: &str,
        device_pub: &PublicKey,
        purpose: Purpose,
        holder: Holder,
        identities: Vec<String>,
        validity: Duration,
        idp_key: &KeyPair,
        status: Option<StatusRef>,
    ) -> Result<Self> {
        Self::create_with_provenance(
            idp_domain, device_pub, purpose, holder, identities, validity, idp_key, status, None,
        )
    }

    /// Like [`Self::create`], stamping the proof class the identity was
    /// verified under at issuance — see [`DeviceCertClaims::prov`].
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_provenance(
        idp_domain: &str,
        device_pub: &PublicKey,
        purpose: Purpose,
        holder: Holder,
        identities: Vec<String>,
        validity: Duration,
        idp_key: &KeyPair,
        status: Option<StatusRef>,
        prov: Option<String>,
    ) -> Result<Self> {
        if identities.is_empty() {
            return Err(invalid("device cert", "must authorize at least one identity"));
        }
        let now = Utc::now();
        Self::from_claims(DeviceCertClaims {
            typ: TYP_DEVICE_CERT.to_string(),
            iss: idp_domain.to_string(),
            iat: now.timestamp(),
            exp: (now + validity).timestamp(),
            purpose,
            holder,
            identities,
            public_key: device_pub.clone(),
            status,
            managed: None,
            constraints: None,
            prov,
        }, idp_key)
    }

    /// Sign explicit claims (used by golden-vector generation with fixed times).
    pub fn from_claims(claims: DeviceCertClaims, idp_key: &KeyPair) -> Result<Self> {
        Ok(Self { encoded: jws_sign(&claims, idp_key)?, claims })
    }

    pub fn parse(encoded: &str) -> Result<Self> {
        let claims: DeviceCertClaims = jws_decode(encoded, "device cert")?;
        if claims.typ != TYP_DEVICE_CERT {
            return Err(invalid("device cert", format!("typ '{}'", claims.typ)));
        }
        Ok(Self { encoded: encoded.to_string(), claims })
    }

    pub fn verify(&self, idp_key: &PublicKey) -> Result<()> {
        jws_verify(&self.encoded, idp_key, "device cert")
    }
    pub fn is_expired(&self) -> bool {
        expired(self.claims.exp)
    }
    pub fn authorizes_identity(&self, email: &str) -> bool {
        self.claims.identities.iter().any(|p| identity_matches(p, email))
    }
    pub fn iss(&self) -> &str {
        &self.claims.iss
    }
    pub fn purpose(&self) -> Purpose {
        self.claims.purpose
    }
    pub fn holder(&self) -> &Holder {
        &self.claims.holder
    }
    pub fn public_key(&self) -> &PublicKey {
        &self.claims.public_key
    }
    pub fn claims(&self) -> &DeviceCertClaims {
        &self.claims
    }
    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

// ===========================================================================
// Access request (device-signed): "mint an access cert for this fresh key."
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequestClaims {
    pub typ: String,
    pub iat: i64,
    pub exp: i64,
    /// Single-use nonce (replay protection at the mint).
    pub jti: String,
    /// Target IdP domain (audience pinning).
    pub domain: String,
    /// Which identity to mint an access cert for (∈ the device cert's list).
    pub identity: String,
    /// The holder the minted access cert must carry (copied from the device
    /// cert — the mint MUST NOT let the requester choose a different value).
    pub holder: Holder,
    /// The fresh key to certify (never the device key).
    #[serde(rename = "access-key")]
    pub access_key: PublicKey,
    /// OPTIONAL — managed identities only (spec §4.2/§4.7). The RP audience
    /// this access cert is requested for. A client MUST NOT send it unless its
    /// device cert carries `managed: true`; an IdP MUST NOT require or honor
    /// it otherwise (the mint stays RP-blind for unmanaged identities).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AccessRequest {
    encoded: String,
    claims: AccessRequestClaims,
}

impl AccessRequest {
    pub fn create(
        domain: &str,
        identity: &str,
        holder: Holder,
        access_pub: &PublicKey,
        jti: &str,
        device_key: &KeyPair,
    ) -> Result<Self> {
        let now = Utc::now();
        Self::from_claims(AccessRequestClaims {
            typ: TYP_ACCESS_REQUEST.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::minutes(ACCESS_REQUEST_VALIDITY_MINUTES)).timestamp(),
            jti: jti.to_string(),
            domain: domain.to_string(),
            identity: identity.to_string(),
            holder,
            access_key: access_pub.clone(),
            audience: None,
        }, device_key)
    }

    /// Create an access request naming the RP audience it is for — **managed
    /// identities only** (spec §4.2): callers MUST hold a `managed: true`
    /// device cert. The IdP MAY scope the minted cert to this audience.
    #[allow(clippy::too_many_arguments)]
    pub fn create_for_audience(
        domain: &str,
        identity: &str,
        holder: Holder,
        access_pub: &PublicKey,
        jti: &str,
        audience: &str,
        device_key: &KeyPair,
    ) -> Result<Self> {
        let now = Utc::now();
        Self::from_claims(AccessRequestClaims {
            typ: TYP_ACCESS_REQUEST.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::minutes(ACCESS_REQUEST_VALIDITY_MINUTES)).timestamp(),
            jti: jti.to_string(),
            domain: domain.to_string(),
            identity: identity.to_string(),
            holder,
            access_key: access_pub.clone(),
            audience: Some(audience.to_string()),
        }, device_key)
    }

    pub fn from_claims(claims: AccessRequestClaims, device_key: &KeyPair) -> Result<Self> {
        Ok(Self { encoded: jws_sign(&claims, device_key)?, claims })
    }

    pub fn parse(encoded: &str) -> Result<Self> {
        let claims: AccessRequestClaims = jws_decode(encoded, "access request")?;
        if claims.typ != TYP_ACCESS_REQUEST {
            return Err(invalid("access request", format!("typ '{}'", claims.typ)));
        }
        Ok(Self { encoded: encoded.to_string(), claims })
    }

    pub fn verify(&self, device_pub: &PublicKey) -> Result<()> {
        jws_verify(&self.encoded, device_pub, "access request")
    }
    pub fn is_expired(&self) -> bool {
        expired(self.claims.exp)
    }
    pub fn claims(&self) -> &AccessRequestClaims {
        &self.claims
    }
    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

// ===========================================================================
// Access certificate (IdP-signed, RP-facing): the assertion chains from it.
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessCertClaims {
    pub typ: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    pub identity: String,
    /// Copied verbatim from the issuing device cert at mint (the isolation
    /// guarantee: the requester cannot choose or forge it).
    pub holder: Holder,
    #[serde(rename = "public-key")]
    pub access_key: PublicKey,
    /// Revocation ref, rooted at the ISSUING DEVICE's status index (so revoking
    /// one device kills its access certs, not the whole identity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusRef>,
    /// Managed-identity restrictions (spec §4.7), stamped at the mint — the
    /// managing domain's per-~24 h policy decision point — and enforced at
    /// verification (§6.1 step 7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
}

#[derive(Debug, Clone)]
pub struct AccessCert {
    encoded: String,
    claims: AccessCertClaims,
}

impl AccessCert {
    pub fn create(
        idp_domain: &str,
        identity: &str,
        holder: Holder,
        access_pub: &PublicKey,
        validity: Duration,
        idp_key: &KeyPair,
        status: Option<StatusRef>,
    ) -> Result<Self> {
        let now = Utc::now();
        Self::from_claims(AccessCertClaims {
            typ: TYP_ACCESS_CERT.to_string(),
            iss: idp_domain.to_string(),
            iat: now.timestamp(),
            exp: (now + validity).timestamp(),
            identity: identity.to_string(),
            holder,
            access_key: access_pub.clone(),
            status,
            constraints: None,
        }, idp_key)
    }

    pub fn from_claims(claims: AccessCertClaims, idp_key: &KeyPair) -> Result<Self> {
        Ok(Self { encoded: jws_sign(&claims, idp_key)?, claims })
    }

    pub fn parse(encoded: &str) -> Result<Self> {
        let claims: AccessCertClaims = jws_decode(encoded, "access cert")?;
        if claims.typ != TYP_ACCESS_CERT {
            return Err(invalid("access cert", format!("typ '{}'", claims.typ)));
        }
        Ok(Self { encoded: encoded.to_string(), claims })
    }

    pub fn verify(&self, idp_key: &PublicKey) -> Result<()> {
        jws_verify(&self.encoded, idp_key, "access cert")
    }
    pub fn is_expired(&self) -> bool {
        expired(self.claims.exp)
    }
    pub fn claims(&self) -> &AccessCertClaims {
        &self.claims
    }
    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

// ===========================================================================
// Warrant (config-cert-signed): grantor delegates to grantee → audience[+scopes].
// ===========================================================================

/// One **channel entry** in a warrant's binding set (spec §5): a rule from the
/// grantor about the circumstances under which the grant operates — which
/// device signs, who may ask. Entries are conjunctive; each kind defines how
/// it evaluates per operation (§5's kind × operation table), and an
/// unsatisfiable cell fails that operation. Fail-closed by construction: an
/// unknown `kind`, an unknown field within a known kind, or (within
/// `connection`) an unknown `protocol` fails deserialization, so the record
/// rejects at parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind")]
pub enum Binding {
    /// Pins which **device holders** of the grantee (v1 semantics verbatim):
    /// `*`, `<ns>.*`, or `<id>`, checked against the grantee's access-cert
    /// holder (operation P) or login holder (operation A). Serves P and A.
    #[serde(rename = "holder")]
    Holder { matcher: HolderMatcher },
    /// Pins which **custody channel** of the grantee. Admission-only (operation
    /// A); a connection-bound record never verifies in a bundle.
    #[serde(rename = "connection")]
    Connection {
        protocol: ConnectionProtocol,
        /// Broker-minted at consent (§7.5), opaque and exact — no wildcard —
        /// and 1:1 with its record (§6.6 invariant 5).
        id: String,
        /// The enforceable client datum: the registered redirect-URI host.
        client_host: String,
        /// Display-only; MUST be marked unverified everywhere it appears.
        client_name: String,
    },
    /// Pins which **requesting channel** may ask the grantor's wallet to sign
    /// under this grant (§5). Evaluated by the wallet at dispatch and
    /// re-checked by verifiers against the assertion's `req_origin` stamp
    /// (§6.6 invariant 13); unsatisfiable in admission.
    #[serde(rename = "requester")]
    Requester {
        /// The authenticated request source: one web origin, exact.
        origin: String,
    },
}

// Hand-written so each kind rejects unknown fields (§6.6 invariant 14 at the
// entry level) — serde's internally-tagged derive cannot express
// `deny_unknown_fields`.
impl<'de> Deserialize<'de> for Binding {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        let v = serde_json::Value::deserialize(deserializer)?;
        let kind = v
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| D::Error::custom("binding entry missing kind"))?
            .to_string();
        match kind.as_str() {
            "holder" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct W {
                    #[serde(rename = "kind")]
                    _kind: String,
                    matcher: HolderMatcher,
                }
                let w: W = serde_json::from_value(v).map_err(D::Error::custom)?;
                Ok(Binding::Holder { matcher: w.matcher })
            }
            "connection" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct W {
                    #[serde(rename = "kind")]
                    _kind: String,
                    protocol: ConnectionProtocol,
                    id: String,
                    client_host: String,
                    client_name: String,
                }
                let w: W = serde_json::from_value(v).map_err(D::Error::custom)?;
                Ok(Binding::Connection {
                    protocol: w.protocol,
                    id: w.id,
                    client_host: w.client_host,
                    client_name: w.client_name,
                })
            }
            "requester" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct W {
                    #[serde(rename = "kind")]
                    _kind: String,
                    origin: String,
                }
                let w: W = serde_json::from_value(v).map_err(D::Error::custom)?;
                Ok(Binding::Requester { origin: w.origin })
            }
            other => Err(D::Error::custom(format!(
                "unimplemented binding kind '{other}'"
            ))),
        }
    }
}

/// The warrant's `binding` claim: a **set** of channel entries, all
/// conjunctive (spec §5, amended 2026-08-25). The wire form is either a
/// single object — shorthand for a one-entry set, the only form pre-amendment
/// records use — or an array; pre-amendment verifiers reject the array shape,
/// the intended fail-closed versioning behavior (§6.6 invariant 14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BindingSet {
    One(Binding),
    Many(Vec<Binding>),
}

impl From<Binding> for BindingSet {
    fn from(b: Binding) -> Self {
        BindingSet::One(b)
    }
}
impl From<Vec<Binding>> for BindingSet {
    fn from(v: Vec<Binding>) -> Self {
        BindingSet::Many(v)
    }
}

impl BindingSet {
    pub fn entries(&self) -> &[Binding] {
        match self {
            BindingSet::One(b) => std::slice::from_ref(b),
            BindingSet::Many(v) => v,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.entries().is_empty()
    }
    /// Whether the wire shape is the array form (pre-amendment verifiers
    /// reject it — the versioning gate invariant 14 hangs unknown-claim
    /// rejection on).
    pub fn is_set_form(&self) -> bool {
        matches!(self, BindingSet::Many(_))
    }
    pub fn has_holder(&self) -> bool {
        self.entries().iter().any(|e| matches!(e, Binding::Holder { .. }))
    }
    pub fn has_connection(&self) -> bool {
        self.entries().iter().any(|e| matches!(e, Binding::Connection { .. }))
    }
    pub fn has_requester(&self) -> bool {
        self.entries().iter().any(|e| matches!(e, Binding::Requester { .. }))
    }
    /// The first holder entry's matcher (delegated records carry exactly one;
    /// evaluation paths check every entry, not just this accessor).
    pub fn holder_matcher(&self) -> Option<&HolderMatcher> {
        self.entries().iter().find_map(|e| match e {
            Binding::Holder { matcher } => Some(matcher),
            _ => None,
        })
    }
    pub fn requester_origin(&self) -> Option<&str> {
        self.entries().iter().find_map(|e| match e {
            Binding::Requester { origin } => Some(origin.as_str()),
            _ => None,
        })
    }
    pub fn connection(&self) -> Option<&Binding> {
        self.entries().iter().find(|e| matches!(e, Binding::Connection { .. }))
    }
}

/// One entry in a warrant's `scopes` array (spec §5): a bare string — the
/// entry's identity — or an object carrying the scope string plus
/// **parameters** (attenuations, stricter-wins; wire-compatible with the
/// bare form for parameterless scopes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScopeEntry {
    /// `"s"` — shorthand for `{"scope": "s"}`.
    Bare(String),
    /// Object form. An unknown parameter key fails deserialization —
    /// invariant 14: a parameter is a restriction, and ignoring one is
    /// escaping it.
    Parameterized(ScopeParams),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeParams {
    pub scope: String,
    /// The `mode` parameter, defined on `sign:` scopes (§5): `prompt` makes
    /// the wallet render the object and wait for approval per use; absent ⇒
    /// `auto` (standing silent authority — prompt is the tightening).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<ScopeMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeMode {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "prompt")]
    Prompt,
}

impl ScopeEntry {
    /// The entry's identity — its scope string (§5: everywhere the system
    /// treats scopes as identifiers, parameters ride along).
    pub fn scope(&self) -> &str {
        match self {
            ScopeEntry::Bare(s) => s,
            ScopeEntry::Parameterized(p) => &p.scope,
        }
    }
    pub fn mode(&self) -> ScopeMode {
        match self {
            ScopeEntry::Bare(_) => ScopeMode::Auto,
            ScopeEntry::Parameterized(p) => p.mode.unwrap_or(ScopeMode::Auto),
        }
    }
}

impl From<&str> for ScopeEntry {
    fn from(s: &str) -> Self {
        ScopeEntry::Bare(s.to_string())
    }
}
impl From<String> for ScopeEntry {
    fn from(s: String) -> Self {
        ScopeEntry::Bare(s)
    }
}

/// Custody protocols a `connection` binding can name. An unimplemented
/// protocol fails deserialization — fail-closed (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionProtocol {
    /// OAuth custody mechanics (§5): exactly one exact-match registered
    /// redirect URI per connection, PKCE S256, and redirect-URI host ==
    /// `client_host` checked at every code release and token exchange.
    #[serde(rename = "oauth")]
    Oauth,
}

/// Warrant claims, serving both wire versions (spec §5):
/// - `browserid-warrant-v1` — top-level `holder` matcher, `status` OPTIONAL;
/// - `browserid-warrant-v2` — a mandatory `binding` slot in place of `holder`,
///   `status` REQUIRED.
///
/// `Warrant::parse` enforces the per-version shape; use [`WarrantClaims::binding`]
/// for the normalized view (v1 reads as a v2 record with a holder binding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarrantClaims {
    pub typ: String,
    pub iat: i64,
    pub exp: i64,
    /// Who authorizes the grant AND who the write is attributed to (the effective
    /// author). Always an exact email — never a matcher. The signing config cert
    /// must be authoritative for this identity.
    pub grantor: String,
    /// Who wields the grant. An exact email — or, on admission-consumed records
    /// only, a grantee matcher (`*` / `*@<domain>`): permission, never
    /// attribution (§5). When it equals `grantor` this is an "as-you" grant;
    /// when it differs it is delegated on-behalf, and the write attributes to
    /// `grantor` while `grantee` is the actor of record.
    pub grantee: String,
    /// v1 only: which holder(s) this warrant grants to (`*`, `<ns>.*`, `<id>`),
    /// checked against the GRANTEE's access cert holder (anti-fungibility).
    /// v2 carries this inside `binding` instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<HolderMatcher>,
    /// v2 only: exactly one `binding` claim holding a set of channel entries
    /// (§5; a singular object is the one-entry shorthand). A missing/empty
    /// binding, or an unimplemented kind/protocol, rejects at parse —
    /// fail-closed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<BindingSet>,
    pub audience: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<ScopeEntry>,
    /// Revocation ref rooted at the hosted broker's warrant registry.
    /// REQUIRED on v2 (enforced at parse); optional on v1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusRef>,
    /// Claims this implementation does not know. Captured — not dropped — so
    /// set-form records (§6.6 invariant 14) can reject them fail-closed;
    /// pre-amendment records keep the ignore-unknown-claims behavior.
    #[serde(flatten, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub unknown: std::collections::BTreeMap<String, serde_json::Value>,
}

impl WarrantClaims {
    /// The normalized binding set: v2's own, or v1 interpreted as its
    /// holder-binding sugar (§5). Only call on claims that passed
    /// `Warrant::parse` (or are otherwise known well-formed).
    pub fn binding_set(&self) -> BindingSet {
        match (&self.binding, &self.holder) {
            (Some(b), _) => b.clone(),
            (None, Some(m)) => BindingSet::One(Binding::Holder { matcher: m.clone() }),
            // Unreachable for parsed warrants; fail-closed for hand-built
            // claims: an empty set satisfies no operation.
            (None, None) => BindingSet::Many(Vec::new()),
        }
    }

    /// The first holder entry's matcher (v1 always; v2 when the set carries
    /// one). `None` for connection-bound records. Evaluation paths check
    /// every entry — this accessor is for callers that render or store the
    /// matcher.
    pub fn holder_matcher(&self) -> Option<&HolderMatcher> {
        match (&self.binding, &self.holder) {
            (Some(bs), _) => bs.holder_matcher(),
            (None, m) => m.as_ref(),
        }
    }

    /// The scopes projected to their identity strings (§5: an entry's
    /// identity is its scope string; parameters ride along).
    pub fn scope_strings(&self) -> Vec<String> {
        self.scopes.iter().map(|e| e.scope().to_string()).collect()
    }
}

#[derive(Debug, Clone)]
pub struct Warrant {
    encoded: String,
    claims: WarrantClaims,
}

impl Warrant {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        grantor: &str,
        grantee: &str,
        holder: HolderMatcher,
        audience: &str,
        scopes: Vec<String>,
        validity: Duration,
        config_key: &KeyPair,
        status: Option<StatusRef>,
    ) -> Result<Self> {
        let now = Utc::now();
        Self::from_claims(WarrantClaims {
            typ: TYP_WARRANT.to_string(),
            iat: now.timestamp(),
            exp: (now + validity).timestamp(),
            grantor: grantor.to_string(),
            grantee: grantee.to_string(),
            holder: Some(holder),
            binding: None,
            audience: audience.to_string(),
            scopes: scopes.into_iter().map(ScopeEntry::from).collect(),
            status,
            unknown: Default::default(),
        }, config_key)
    }

    /// Sign a v2 record. `status` is non-optional (REQUIRED on v2, §5), and the
    /// signing-surface rules of §6.6 invariant 3/4 are enforced here: a surface
    /// MUST refuse to mint a malformed record or a non-self-grant connection.
    #[allow(clippy::too_many_arguments)]
    pub fn create_v2(
        grantor: &str,
        grantee: &str,
        binding: impl Into<BindingSet>,
        audience: &str,
        scopes: Vec<ScopeEntry>,
        validity: Duration,
        config_key: &KeyPair,
        status: StatusRef,
    ) -> Result<Self> {
        let now = Utc::now();
        let claims = WarrantClaims {
            typ: TYP_WARRANT_V2.to_string(),
            iat: now.timestamp(),
            exp: (now + validity).timestamp(),
            grantor: grantor.to_string(),
            grantee: grantee.to_string(),
            holder: None,
            binding: Some(binding.into()),
            audience: audience.to_string(),
            scopes,
            status: Some(status),
            unknown: Default::default(),
        };
        Self::validate_claims(&claims)?;
        Self::from_claims(claims, config_key)
    }

    pub fn from_claims(claims: WarrantClaims, config_key: &KeyPair) -> Result<Self> {
        Ok(Self { encoded: jws_sign(&claims, config_key)?, claims })
    }

    pub fn parse(encoded: &str) -> Result<Self> {
        let claims: WarrantClaims = jws_decode(encoded, "warrant")?;
        Self::validate_claims(&claims)?;
        Ok(Self { encoded: encoded.to_string(), claims })
    }

    /// The per-version shape rules of spec §5, fail-closed. (An unknown binding
    /// `kind` or connection `protocol` already failed in `jws_decode` — serde
    /// rejects unknown variants.)
    fn validate_claims(claims: &WarrantClaims) -> Result<()> {
        match claims.typ.as_str() {
            TYP_WARRANT => {
                if claims.holder.is_none() {
                    return Err(invalid("warrant", "v1 requires a holder matcher"));
                }
                if claims.binding.is_some() {
                    return Err(invalid("warrant", "v1 must not carry a binding"));
                }
            }
            TYP_WARRANT_V2 => {
                if claims.holder.is_some() {
                    return Err(invalid("warrant", "v2 carries its holder matcher inside binding"));
                }
                if claims.status.is_none() {
                    return Err(invalid("warrant", "v2 requires status"));
                }
                let Some(bs) = &claims.binding else {
                    return Err(invalid("warrant", "v2 requires a binding"));
                };
                let entries = bs.entries();
                if entries.is_empty() {
                    return Err(invalid("warrant", "binding set must be non-empty"));
                }
                let self_grant =
                    crate::identity::identity_eq(&claims.grantor, &claims.grantee);
                let (mut has_holder, mut has_connection, mut has_requester) =
                    (false, false, false);
                for e in entries {
                    match e {
                        Binding::Holder { .. } => has_holder = true,
                        Binding::Connection { id, client_host, .. } => {
                            has_connection = true;
                            if id.is_empty() {
                                return Err(invalid("warrant", "connection binding requires an id"));
                            }
                            if client_host.is_empty() {
                                return Err(invalid("warrant", "connection binding requires a client_host"));
                            }
                            // §5: `connection` implies a self-grant — the actor
                            // of a custody channel is its establisher.
                            if !self_grant {
                                return Err(invalid(
                                    "warrant",
                                    "connection-bound record must be a self-grant (grantor == grantee)",
                                ));
                            }
                        }
                        Binding::Requester { origin } => {
                            has_requester = true;
                            if !valid_web_origin(origin) {
                                return Err(invalid(
                                    "warrant",
                                    "requester binding requires a web origin (scheme://host, no path)",
                                ));
                            }
                        }
                    }
                }
                // §5: multi-entry sets are self-grant-only; a delegated record
                // carries exactly one holder entry (§6.6 invariant 10).
                if !self_grant
                    && (entries.len() != 1 || !matches!(entries[0], Binding::Holder { .. }))
                {
                    return Err(invalid(
                        "warrant",
                        "delegated record must carry exactly one holder entry (multi-entry sets are self-grant-only)",
                    ));
                }
                // §5 dead paper: a set satisfiable in no operation — op P needs
                // a holder entry and no connection entry; op A admits no
                // requester entry. Signing surfaces must refuse to mint one
                // (§6.6 invariant 3); consumers reject it the same way.
                let p_ok = has_holder && !has_connection;
                let a_ok = !has_requester;
                if !p_ok && !a_ok {
                    return Err(invalid(
                        "warrant",
                        "channel set satisfies no operation (dead paper)",
                    ));
                }
            }
            other => return Err(invalid("warrant", format!("typ '{other}'"))),
        }
        // §6.6 invariant 14, scoped to set-form records (array binding or
        // parameterized scopes): unknown top-level claims reject. Pre-amendment
        // records keep the ignore-unknown-claims working assumption.
        let set_form = claims.binding.as_ref().is_some_and(BindingSet::is_set_form)
            || claims.scopes.iter().any(|s| matches!(s, ScopeEntry::Parameterized(_)));
        if set_form && !claims.unknown.is_empty() {
            let keys: Vec<&str> = claims.unknown.keys().map(String::as_str).collect();
            return Err(invalid(
                "warrant",
                format!("unrecognized claim(s) on a set-form record: {}", keys.join(", ")),
            ));
        }
        // Identities are always email strings; the grantor is attribution —
        // exact and signed-for, never a matcher (§6.6 invariant 6).
        if crate::identity::is_grantee_matcher(&claims.grantor) || !claims.grantor.contains('@') {
            return Err(invalid("warrant", "grantor must be an exact email"));
        }
        if !crate::identity::is_grantee_matcher(&claims.grantee) && !claims.grantee.contains('@') {
            return Err(invalid("warrant", "grantee must be an email or a grantee matcher"));
        }
        Ok(())
    }

    pub fn verify(&self, config_pub: &PublicKey) -> Result<()> {
        jws_verify(&self.encoded, config_pub, "warrant")
    }
    pub fn is_expired(&self) -> bool {
        expired(self.claims.exp)
    }
    pub fn claims(&self) -> &WarrantClaims {
        &self.claims
    }
    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

/// A `requester` entry's `origin`: `scheme://host[:port]`, no path/query —
/// the exact form of a browser-reported origin (spec §5; http admitted for
/// local development).
fn valid_web_origin(origin: &str) -> bool {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"));
    match rest {
        Some(host) => !host.is_empty() && !host.contains('/'),
        None => false,
    }
}

// ===========================================================================
// RP-facing presentation: access_cert ~ assertion ~ warrant ~ config_cert.
// ===========================================================================

/// The verified result. `*_status` are the three revocation refs the RP-side
/// verifier MUST check **fail-closed** (access→IdP, config→IdP, warrant→broker).
#[derive(Debug, Clone)]
pub struct VerifiedAccess {
    /// The EFFECTIVE author: the warrant grantor (whom the write attributes to).
    /// For an as-you grant this equals the actor; for a delegated grant it is the
    /// user the grantee acted for.
    pub email: String,
    /// The ACTOR of record: the identity that minted the access cert and signed
    /// (the warrant grantee == access cert identity). Equals `email` for as-you
    /// grants; differs for delegated on-behalf grants (provenance).
    pub grantee: String,
    /// The IdP domain that vouches for the ATTRIBUTED identity (`email`) — the
    /// grantor's issuer (the config cert's `iss`). Used for domain-binding of the
    /// attributed identity.
    pub issuer: String,
    /// The grantee/actor's issuer (the access cert's `iss`). Equals `issuer` for
    /// as-you grants; may differ for a cross-issuer delegated grant.
    pub grantee_issuer: String,
    /// The opaque holder the access cert carried (which of the grantee's things
    /// acted). Advisory to the RP; the human/agent axis is gone.
    pub holder: Holder,
    /// The warrant scopes projected to identity strings (§5). Parameters are
    /// enforced by the wallet and rejected-if-unknown at parse; callers
    /// needing them read `scope_entries`.
    pub scopes: Vec<String>,
    pub scope_entries: Vec<ScopeEntry>,
    /// The requesting channel the wallet stamped into the assertion, verified
    /// against the record's requester entry (present iff the record carries
    /// one — §6.6 invariant 13).
    pub req_origin: Option<String>,
    pub access_status: Option<StatusRef>,
    pub config_status: Option<StatusRef>,
    pub warrant_status: Option<StatusRef>,
}

pub struct AccessPresentation {
    pub access_cert: AccessCert,
    pub assertion: Assertion,
    pub warrant: Warrant,
    pub config_cert: DeviceCert,
}

impl AccessPresentation {
    pub fn encode(&self) -> String {
        format!(
            "{}~{}~{}~{}",
            self.access_cert.encoded(),
            self.assertion.encoded(),
            self.warrant.encoded(),
            self.config_cert.encoded()
        )
    }

    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('~').collect();
        if parts.len() != 4 {
            return Err(invalid(
                "presentation",
                "expected access_cert~assertion~warrant~config_cert",
            ));
        }
        Ok(Self {
            access_cert: AccessCert::parse(parts[0])?,
            assertion: Assertion::parse(parts[1])?,
            warrant: Warrant::parse(parts[2])?,
            config_cert: DeviceCert::parse(parts[3])?,
        })
    }

    /// Verify the CRYPTO + STRUCTURAL join for `expected_audience`, resolving IdP
    /// keys via `get_idp_key(issuer_domain)`. Returns the three status refs for
    /// the caller to check fail-closed. The caller's resolver decides which
    /// issuers it trusts (DNSSEC primary, or accepted fallback for no-primary).
    pub fn verify<F>(&self, expected_audience: &str, get_idp_key: F) -> Result<VerifiedAccess>
    where
        F: Fn(&str) -> Result<PublicKey>,
    {
        let ac = self.access_cert.claims();
        let cc = self.config_cert.claims();
        let wc = self.warrant.claims();

        // §6.1 step 1: presentation requires a channel set satisfiable in
        // op P — a holder entry, no connection entry (unsatisfiable in P,
        // §5's kind × operation table) — and an exact grantee (a matcher
        // grantee would transfer attribution to unknown actors). All reject
        // explicitly here (§6.6 invariant 1), before any crypto.
        let bset = wc.binding_set();
        if bset.has_connection() {
            return Err(invalid("warrant", "connection-bound record cannot verify in a bundle (admission-only)"));
        }
        if !bset.has_holder() {
            return Err(invalid("warrant", "presentation requires a holder entry in the channel set"));
        }
        if crate::identity::is_grantee_matcher(&wc.grantee) {
            return Err(invalid("warrant", "a matcher-grantee record cannot verify in a bundle"));
        }

        // Two independent issuer roots, each DNSSEC-proven via the caller's
        // resolver: the ACCESS cert (the actor/grantee) under its own issuer, the
        // CONFIG cert (which authorizes the grantor and signs the warrant) under
        // ITS issuer. They coincide for an as-you grant and may differ for a
        // cross-issuer delegated grant. This is safe WITHOUT the old
        // `config.iss == access.iss` rule because the write attributes to the
        // GRANTOR (the config cert's identity): a warrant signed by issuer X's
        // authorization cert can only ever attribute to an identity X vouches for,
        // so no cross-IdP privilege escalation is possible.
        let access_idp_key = get_idp_key(&ac.iss)?;
        self.access_cert.verify(&access_idp_key)?;
        let config_idp_key = if cc.iss == ac.iss {
            access_idp_key.clone()
        } else {
            get_idp_key(&cc.iss)?
        };
        self.config_cert.verify(&config_idp_key)?;
        if self.access_cert.is_expired() {
            return Err(invalid("access cert", "expired"));
        }
        if self.config_cert.is_expired() {
            return Err(invalid("config cert", "expired"));
        }

        // Assertion signed by the access cert's fresh key, for this audience.
        self.assertion.verify(&ac.access_key)?;
        if self.assertion.is_expired() {
            return Err(invalid("assertion", "expired"));
        }
        if self.assertion.audience() != expected_audience {
            return Err(invalid("assertion", "audience mismatch"));
        }

        // Config cert must be an authorization cert authoritative for the GRANTOR
        // (the attributed identity) — this is what makes the cross-issuer split
        // safe: the config cert's IdP vouches for the identity the write lands on.
        if cc.purpose != Purpose::Authorization {
            return Err(invalid("config cert", "not an authorization cert"));
        }
        if !self.config_cert.authorizes_identity(&wc.grantor) {
            return Err(invalid("config cert", "not authorized for the warrant grantor"));
        }

        // Warrant signed by the config cert (so the grantor authorized it).
        self.warrant.verify(&cc.public_key)?;
        if self.warrant.is_expired() {
            return Err(invalid("warrant", "expired"));
        }
        // The grantee is the actor: it must be the identity the access cert
        // certifies (and whose fresh key signed the assertion above). Exact,
        // per §5's identity comparison — matcher grantees were rejected above.
        if !crate::identity::identity_eq(&wc.grantee, &ac.identity) {
            return Err(invalid("warrant", "grantee != access identity"));
        }
        // §6.1 step 6: EVERY channel entry must evaluate satisfied per §5's
        // kind × operation table. Holder: the matcher covers the access
        // cert's holder — anti-fungibility: the grant binds to the grantee's
        // specific credential, not merely its identity. Requester: the
        // assertion must carry the wallet's `req_origin` stamp, equal to the
        // entry's origin (§6.6 invariant 13). Connection was rejected above.
        let req_origin = self.assertion.claims().req_origin.as_deref();
        for entry in bset.entries() {
            match entry {
                Binding::Holder { matcher } => {
                    if !matcher.matches(&ac.holder) {
                        return Err(invalid("warrant", "holder does not match warrant matcher"));
                    }
                }
                Binding::Requester { origin } => match req_origin {
                    Some(stamp) if stamp == origin => {}
                    Some(_) => {
                        return Err(invalid("assertion", "req_origin does not match the record's requester entry"));
                    }
                    None => {
                        return Err(invalid("assertion", "record carries a requester entry but the assertion has no req_origin stamp"));
                    }
                },
                Binding::Connection { .. } => {
                    return Err(invalid("warrant", "connection-bound record cannot verify in a bundle (admission-only)"));
                }
            }
        }
        // The stamp is present iff a requester entry demands it (§5): an
        // unmatched stamp on a requester-less record rejects fail-closed.
        if req_origin.is_some() && !bset.has_requester() {
            return Err(invalid("assertion", "req_origin stamped but the record has no requester entry"));
        }
        if wc.audience != expected_audience {
            return Err(invalid("warrant", "audience mismatch"));
        }

        // Constraints (spec §4.7, §6.1 step 7): each PRESENTED cert carrying a
        // `constraints` claim must be satisfied by the presentation as
        // presented — the RP audience against the salted-hash allowlist, the
        // warrant against scopes/max-ttl. Unknown constraint keys reject
        // (fail-closed): a restriction ignored is a restriction escaped.
        if let Some(c) = &ac.constraints {
            c.check("access cert", expected_audience, wc)?;
        }
        if let Some(c) = &cc.constraints {
            c.check("config cert", expected_audience, wc)?;
        }

        Ok(VerifiedAccess {
            email: wc.grantor.clone(),
            grantee: ac.identity.clone(),
            issuer: cc.iss.clone(),
            grantee_issuer: ac.iss.clone(),
            holder: ac.holder.clone(),
            scopes: wc.scope_strings(),
            scope_entries: wc.scopes.clone(),
            req_origin: req_origin.map(str::to_string),
            access_status: ac.status.clone(),
            config_status: cc.status.clone(),
            warrant_status: wc.status.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
