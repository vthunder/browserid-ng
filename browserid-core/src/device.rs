//! The device-cert model — see `docs/design/browserid-end-to-end-flow.md`.
//!
//! Two IdP-signed device-cert *purposes* (`authentication` mints access certs;
//! `authorization` signs warrants) crossed with a *subject* (`user` | `agent`).
//! An authentication device cert signs an [`AccessRequest`] that the IdP
//! exchanges for a short-lived, fresh-key [`AccessCert`]. A config cert
//! (`authorization`, device-resident) signs a [`Warrant`] over `(identifier,
//! subject) → audience[+scopes]`. The RP receives an [`AccessPresentation`] —
//! `access_cert ~ assertion ~ warrant ~ config_cert` — and joins them by
//! `(identity, subject, audience)`.
//!
//! Hardening (from the 2026-07-18 adversarial review):
//! - the config cert MUST be issued by the identity's own IdP
//!   (`config_cert.iss == access_cert.iss`), so an RP never trusts a warrant
//!   signed by a rogue-IdP authorization cert (privilege-escalation fix);
//! - three revocation authorities — access cert, config cert, warrant — each
//!   carry a status ref; [`VerifiedAccess`] surfaces all three for the caller to
//!   check **fail-closed** (revocation needs network, so it lives in the RP-side
//!   verifier, not here);
//! - `subject` is part of the join; unknown `purpose`/`subject` values fail
//!   closed (serde rejects unknown variants);
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

/// Which kind of identity a cert/warrant acts for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Subject {
    #[serde(rename = "user")]
    User,
    #[serde(rename = "agent")]
    Agent,
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
    pub subject: Subject,
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
        subject: Subject,
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
            subject,
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
    pub fn subject(&self) -> Subject {
        self.claims.subject
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
    pub subject: Subject,
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
        subject: Subject,
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
            subject,
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
    pub subject: Subject,
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
        subject: Subject,
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
            subject,
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
// Warrant (config-cert-signed): (identifier, subject) → audience[+scopes].
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarrantClaims {
    pub typ: String,
    pub iat: i64,
    pub exp: i64,
    pub identifier: String,
    pub subject: Subject,
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
    pub fn create(
        identifier: &str,
        subject: Subject,
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
            identifier: identifier.to_string(),
            subject,
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
    pub email: String,
    pub subject: Subject,
    pub scopes: Vec<String>,
    pub issuer: String,
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

        // Config cert MUST be issued by the SAME IdP as the access cert — i.e.
        // the identity's own IdP. Without this an RP would trust a warrant signed
        // by any authorization cert from any IdP (privilege escalation).
        if cc.iss != ac.iss {
            return Err(invalid(
                "presentation",
                "config cert issuer must equal the access cert issuer (identity's IdP)",
            ));
        }
        let idp_key = get_idp_key(&ac.iss)?;
        self.access_cert.verify(&idp_key)?;
        self.config_cert.verify(&idp_key)?;
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

        // Config cert must be an authorization cert authoritative for the identity.
        if cc.purpose != Purpose::Authorization {
            return Err(invalid("config cert", "not an authorization cert"));
        }
        if !self.config_cert.authorizes_identity(&ac.identity) {
            return Err(invalid("config cert", "not authorized for this identity"));
        }

        // Warrant signed by the config cert, over this (identity, subject, audience).
        self.warrant.verify(&cc.public_key)?;
        if self.warrant.is_expired() {
            return Err(invalid("warrant", "expired"));
        }
        if wc.identifier != ac.identity {
            return Err(invalid("warrant", "identifier != access identity"));
        }
        if wc.subject != ac.subject {
            return Err(invalid("warrant", "subject != access subject"));
        }
        if wc.audience != expected_audience {
            return Err(invalid("warrant", "audience mismatch"));
        }

        Ok(VerifiedAccess {
            email: ac.identity.clone(),
            subject: ac.subject,
            scopes: wc.scopes.clone(),
            issuer: ac.iss.clone(),
            access_status: ac.status.clone(),
            config_status: cc.status.clone(),
            warrant_status: wc.status.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
