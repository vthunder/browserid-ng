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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarrantClaims {
    pub typ: String,
    pub iat: i64,
    pub exp: i64,
    /// Who authorizes the grant AND who the write is attributed to (the effective
    /// author). The signing config cert must be authoritative for this identity.
    pub grantor: String,
    /// Who wields the grant — the identity that mints the access cert and signs
    /// on-chain (must equal the presented access cert's identity). When it equals
    /// `grantor` this is an "as-you" grant (the service acts as the user); when it
    /// differs it is delegated on-behalf (e.g. `mingo-poster@…` acting for a user),
    /// and the write attributes to `grantor` while `grantee` is the actor of record.
    pub grantee: String,
    /// Which holder(s) this warrant grants to: `*`, `<ns>.*`, or `<id>` — checked
    /// against the GRANTEE's access cert holder (anti-fungibility).
    pub holder: HolderMatcher,
    pub audience: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Revocation ref rooted at the hosted broker's warrant registry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusRef>,
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
            holder,
            audience: audience.to_string(),
            scopes,
            status,
        }, config_key)
    }

    pub fn from_claims(claims: WarrantClaims, config_key: &KeyPair) -> Result<Self> {
        Ok(Self { encoded: jws_sign(&claims, config_key)?, claims })
    }

    pub fn parse(encoded: &str) -> Result<Self> {
        let claims: WarrantClaims = jws_decode(encoded, "warrant")?;
        if claims.typ != TYP_WARRANT {
            return Err(invalid("warrant", format!("typ '{}'", claims.typ)));
        }
        Ok(Self { encoded: encoded.to_string(), claims })
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
    pub scopes: Vec<String>,
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
        // certifies (and whose fresh key signed the assertion above).
        if wc.grantee != ac.identity {
            return Err(invalid("warrant", "grantee != access identity"));
        }
        // The warrant's holder matcher (`*` / `<ns>.*` / `<id>`) must cover the
        // access cert's holder — anti-fungibility: the grant binds to the
        // grantee's specific credential, not merely its identity.
        if !wc.holder.matches(&ac.holder) {
            return Err(invalid("warrant", "holder does not match warrant matcher"));
        }
        if wc.audience != expected_audience {
            return Err(invalid("warrant", "audience mismatch"));
        }

        Ok(VerifiedAccess {
            email: wc.grantor.clone(),
            grantee: ac.identity.clone(),
            issuer: cc.iss.clone(),
            grantee_issuer: ac.iss.clone(),
            holder: ac.holder.clone(),
            scopes: wc.scopes.clone(),
            access_status: ac.status.clone(),
            config_status: cc.status.clone(),
            warrant_status: wc.status.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
