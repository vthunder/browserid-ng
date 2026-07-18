//! The device-cert model — see `docs/design/browserid-end-to-end-flow.md`.
//!
//! Two IdP-signed device-cert *purposes* (`authentication` mints access certs;
//! `authorization` signs warrants) crossed with a *subject* (`user` | `agent`).
//! An authentication device cert signs an [`AccessRequest`] that the IdP
//! exchanges for a short-lived, fresh-key [`AccessCert`]. A config cert
//! (`authorization`) signs a [`Warrant`] over `(identifier, subject) →
//! audience[+scopes]`. The RP receives an [`AccessPresentation`] —
//! `access_cert ~ assertion ~ warrant ~ config_cert` — and joins them by
//! `(identity, subject, audience)`.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::provisioning::{invalid, jws_decode, jws_sign, jws_verify};
use crate::status::StatusRef;
use crate::{Assertion, KeyPair, PublicKey, Result};

pub const TYP_DEVICE_CERT: &str = "browserid-device-cert-v1";
pub const TYP_ACCESS_REQUEST: &str = "browserid-access-request-v1";
pub const TYP_ACCESS_CERT: &str = "browserid-access-cert-v1";
pub const TYP_WARRANT: &str = "browserid-warrant-v1";

pub const DEVICE_CERT_VALIDITY_DAYS: i64 = 90;
pub const ACCESS_CERT_VALIDITY_HOURS: i64 = 24;
pub const ACCESS_REQUEST_VALIDITY_MINUTES: i64 = 10;
pub const WARRANT_VALIDITY_DAYS: i64 = 30;

fn expired(exp: i64) -> bool {
    Utc::now().timestamp() > exp
}

/// Match an identity `email` against a device-cert `identities` entry, which is
/// an exact email or a single-`*` glob (e.g. `danmills+*@sandmill.org`, `*`).
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
// Device certificate (IdP-signed): authorizes a device key for a purpose,
// a subject, and a set of identities.
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCertClaims {
    pub typ: String,
    /// The issuing IdP domain (primary domain, or `browserid.me` fallback).
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    pub purpose: Purpose,
    pub subject: Subject,
    /// Emails (or single-`*` globs) this device may act for.
    pub identities: Vec<String>,
    #[serde(rename = "public-key")]
    pub public_key: PublicKey,
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
    ) -> Result<Self> {
        if identities.is_empty() {
            return Err(invalid("device cert", "must authorize at least one identity"));
        }
        let now = Utc::now();
        let claims = DeviceCertClaims {
            typ: TYP_DEVICE_CERT.to_string(),
            iss: idp_domain.to_string(),
            iat: now.timestamp(),
            exp: (now + validity).timestamp(),
            purpose,
            subject,
            identities,
            public_key: device_pub.clone(),
        };
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
// Access request (device-signed): asks the IdP to mint an access cert for a
// fresh access key, for one of the device cert's identities.
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequestClaims {
    pub typ: String,
    pub iat: i64,
    pub exp: i64,
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
        device_key: &KeyPair,
    ) -> Result<Self> {
        let now = Utc::now();
        let claims = AccessRequestClaims {
            typ: TYP_ACCESS_REQUEST.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::minutes(ACCESS_REQUEST_VALIDITY_MINUTES)).timestamp(),
            domain: domain.to_string(),
            identity: identity.to_string(),
            subject,
            access_key: access_pub.clone(),
        };
        Ok(Self { encoded: jws_sign(&claims, device_key)?, claims })
    }

    pub fn parse(encoded: &str) -> Result<Self> {
        let claims: AccessRequestClaims = jws_decode(encoded, "access request")?;
        if claims.typ != TYP_ACCESS_REQUEST {
            return Err(invalid("access request", format!("typ '{}'", claims.typ)));
        }
        Ok(Self { encoded: encoded.to_string(), claims })
    }

    /// Verify the request signature against the device key that signed it.
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
        let claims = AccessCertClaims {
            typ: TYP_ACCESS_CERT.to_string(),
            iss: idp_domain.to_string(),
            iat: now.timestamp(),
            exp: (now + validity).timestamp(),
            identity: identity.to_string(),
            subject,
            access_key: access_pub.clone(),
            status,
        };
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
// Not bound to any access key; reusable across devices.
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
        let claims = WarrantClaims {
            typ: TYP_WARRANT.to_string(),
            iat: now.timestamp(),
            exp: (now + validity).timestamp(),
            identifier: identifier.to_string(),
            subject,
            audience: audience.to_string(),
            scopes,
            status,
        };
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAccess {
    pub email: String,
    pub subject: Subject,
    pub scopes: Vec<String>,
    /// The issuing IdP domain of the access cert.
    pub issuer: String,
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

    /// Verify the whole bundle for `expected_audience`, resolving IdP keys via
    /// `get_idp_key(issuer_domain)`. The caller's resolver decides which issuers
    /// it trusts (a primary for its own domain, or an accepted fallback).
    pub fn verify<F>(&self, expected_audience: &str, get_idp_key: F) -> Result<VerifiedAccess>
    where
        F: Fn(&str) -> Result<PublicKey>,
    {
        let ac = self.access_cert.claims();
        let cc = self.config_cert.claims();
        let wc = self.warrant.claims();

        // Access cert + config cert are IdP-signed by the same issuer.
        if ac.iss != cc.iss {
            return Err(invalid("presentation", "access/config cert issuer mismatch"));
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

        // Assertion is signed by the access cert's fresh key, for this audience.
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

        // Warrant is signed by the config cert, over this (identity, subject,
        // audience) — the join.
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> KeyPair {
        KeyPair::generate()
    }

    #[test]
    fn full_user_login_roundtrip() {
        let idp = key();
        let device = key();
        let access = key();
        let config = key();
        let email = "danmills@sandmill.org";
        let audience = "https://mingo.place";

        // IdP issues a user device cert + a config cert.
        let device_cert = DeviceCert::create(
            "sandmill.org", &device.public_key(), Purpose::Authentication, Subject::User,
            vec![email.into()], Duration::days(90), &idp,
        ).unwrap();
        let config_cert = DeviceCert::create(
            "sandmill.org", &config.public_key(), Purpose::Authorization, Subject::User,
            vec![email.into()], Duration::days(90), &idp,
        ).unwrap();

        // Device signs an access request; IdP verifies + mints a fresh-key access cert.
        let req = AccessRequest::create("sandmill.org", email, Subject::User, &access.public_key(), &device).unwrap();
        assert!(device_cert.authorizes_identity(email));
        req.verify(device_cert.public_key()).unwrap();
        let access_cert = AccessCert::create(
            "sandmill.org", email, Subject::User, &req.claims().access_key,
            Duration::hours(24), &idp, None,
        ).unwrap();

        // Config cert signs a warrant over (identity, subject) → audience.
        let warrant = Warrant::create(email, Subject::User, audience, vec!["login".into()], Duration::days(30), &config, None).unwrap();

        // Access key signs the assertion; bundle up + verify at the RP.
        let assertion = Assertion::create(audience, Duration::minutes(5), &access).unwrap();
        let pres = AccessPresentation { access_cert, assertion, warrant, config_cert };
        let encoded = pres.encode();

        let parsed = AccessPresentation::parse(&encoded).unwrap();
        let idp_pub = idp.public_key();
        let verified = parsed.verify(audience, |_iss| Ok(idp_pub.clone())).unwrap();
        assert_eq!(verified.email, email);
        assert_eq!(verified.subject, Subject::User);
        assert_eq!(verified.scopes, vec!["login".to_string()]);
    }

    #[test]
    fn wrong_audience_rejected() {
        let idp = key();
        let device = key();
        let access = key();
        let config = key();
        let email = "a@example.com";
        let device_cert = DeviceCert::create("example.com", &device.public_key(), Purpose::Authentication, Subject::User, vec![email.into()], Duration::days(90), &idp).unwrap();
        let config_cert = DeviceCert::create("example.com", &config.public_key(), Purpose::Authorization, Subject::User, vec![email.into()], Duration::days(90), &idp).unwrap();
        let access_cert = AccessCert::create("example.com", email, Subject::User, &access.public_key(), Duration::hours(24), &idp, None).unwrap();
        let warrant = Warrant::create(email, Subject::User, "https://good.example", vec![], Duration::days(30), &config, None).unwrap();
        let assertion = Assertion::create("https://good.example", Duration::minutes(5), &access).unwrap();
        let pres = AccessPresentation { access_cert, assertion, warrant, config_cert };
        let idp_pub = idp.public_key();
        // Verify for a DIFFERENT audience → reject.
        assert!(pres.verify("https://evil.example", |_| Ok(idp_pub.clone())).is_err());
    }

    #[test]
    fn config_not_authorized_for_identity_rejected() {
        let idp = key();
        let access = key();
        let config = key();
        let email = "a@example.com";
        // Config cert authorizes a DIFFERENT identity.
        let config_cert = DeviceCert::create("example.com", &config.public_key(), Purpose::Authorization, Subject::User, vec!["other@example.com".into()], Duration::days(90), &idp).unwrap();
        let access_cert = AccessCert::create("example.com", email, Subject::User, &access.public_key(), Duration::hours(24), &idp, None).unwrap();
        let warrant = Warrant::create(email, Subject::User, "https://rp.example", vec![], Duration::days(30), &config, None).unwrap();
        let assertion = Assertion::create("https://rp.example", Duration::minutes(5), &access).unwrap();
        let pres = AccessPresentation { access_cert, assertion, warrant, config_cert };
        let idp_pub = idp.public_key();
        assert!(pres.verify("https://rp.example", |_| Ok(idp_pub.clone())).is_err());
    }
}
