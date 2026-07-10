//! Delegation-chain agent provisioning (spec §4, v0.2).
//!
//! Three typed, domain-separated JWS shapes on top of the ordinary identity
//! certificate:
//!
//! ```text
//! IdP key                  signs  identity cert       U_cert:  U_pub ↔ a@b.c
//! identity key U_priv      signs  provisioning cert   P_cert:  P_pub delegated by a@b.c
//! provisioning key P_priv  signs  provisioning request R:      action/name/agent-key
//! broker key               signs  endorsement          E:      approves exactly one R
//! ```
//!
//! A **request bundle** is `U_cert~P_cert~R`. [`RequestBundle::verify`] checks
//! the whole user-side chain — including the *signing-time* rule: `U_cert` is
//! short-lived while `P_cert` is long-lived, so what matters is that `P_cert`
//! was signed while `U_cert` was valid (`P_cert.iat` inside `U_cert`'s
//! window), not that `U_cert` is currently fresh. The caller supplies the
//! `U_cert` issuer key (the target IdP verifies its own issuance; the broker
//! resolves it via discovery) and applies its own domain/audience checks.
//!
//! Every shape carries a required `typ` claim and is structurally distinct
//! from identity certificates (no `principal`) and assertions, so no key here
//! can be tricked into signing something replayable elsewhere.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Certificate, Error, KeyPair, PublicKey, Result};

pub const TYP_PROVISIONING_CERT: &str = "browserid-provisioning-cert-v1";
pub const TYP_PROVISIONING_REQUEST: &str = "browserid-provisioning-request-v1";
pub const TYP_ENDORSEMENT: &str = "browserid-provisioning-endorsement-v1";

/// Recommended validity for provisioning certificates (spec: 90 days)
pub const PROVISIONING_CERT_VALIDITY_DAYS: i64 = 90;
/// Recommended validity for requests and endorsements (spec: ≤ 10 min)
pub const REQUEST_VALIDITY_MINUTES: i64 = 10;

pub(crate) fn invalid(what: &str, msg: impl std::fmt::Display) -> Error {
    Error::InvalidProvisioning(format!("{what}: {msg}"))
}

// --------------------------------------------------------------------------
// Shared minimal JWS (same idiom as certificate.rs: EdDSA, three b64url parts)
// — pub(crate): warrant.rs signs/verifies the same shape.
// --------------------------------------------------------------------------

pub(crate) fn jws_sign<C: Serialize>(claims: &C, key: &KeyPair) -> Result<String> {
    let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(claims)?);
    let message = format!("{}.{}", header_b64, claims_b64);
    let sig_b64 = URL_SAFE_NO_PAD.encode(key.sign(message.as_bytes()));
    Ok(format!("{}.{}", message, sig_b64))
}

pub(crate) fn jws_decode<C: DeserializeOwned>(encoded: &str, what: &str) -> Result<C> {
    let parts: Vec<&str> = encoded.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid(what, "expected 3 JWT parts"));
    }
    let bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn jws_verify(encoded: &str, key: &PublicKey, what: &str) -> Result<()> {
    let parts: Vec<&str> = encoded.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid(what, "expected 3 JWT parts"));
    }
    let message = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD.decode(parts[2])?;
    key.verify(message.as_bytes(), &signature)
}

pub(crate) fn expired(exp: i64) -> bool {
    Utc::now().timestamp() > exp
}

// --------------------------------------------------------------------------
// Provisioning certificate (P_cert)
// --------------------------------------------------------------------------

/// What a provisioning cert authorizes minting (spec v0.3). At least one of
/// `names`/`patterns` must be non-empty — an empty constraint (and a naked `*`
/// pattern) authorizes nothing, on purpose: every agent identity is either an
/// explicitly reserved handle or a subaddress under a handle the user already
/// controls, never an arbitrary name.
///
/// - `names`: exact handles the key may mint (and which are reserved at
///   key-creation so the mint can't later be refused).
/// - `patterns`: `<prefix>+*` subaddress grants — the key may mint any
///   `<prefix>+<suffix>`. These are not reserved (unbounded); the count is
///   still bounded by the per-delegator quota.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<String>,
}

impl Constraint {
    pub fn names(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self { names: names.into_iter().map(Into::into).collect(), patterns: Vec::new() }
    }

    /// A pattern's required shape: `<prefix>+*`, where `<prefix>` is a
    /// non-empty run of `[a-z0-9._-]` (a valid handle). No naked `*`.
    pub fn pattern_prefix(pattern: &str) -> Option<&str> {
        let prefix = pattern.strip_suffix("+*")?;
        let ok = !prefix.is_empty()
            && prefix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'));
        ok.then_some(prefix)
    }

    /// Validate the constraint: at least one entry, and every pattern is a
    /// well-formed `<prefix>+*` (naked `*` rejected).
    pub fn validate(&self) -> Result<()> {
        if self.names.is_empty() && self.patterns.is_empty() {
            return Err(invalid("constraint", "must grant at least one name or pattern"));
        }
        for p in &self.patterns {
            if Self::pattern_prefix(p).is_none() {
                return Err(invalid(
                    "constraint",
                    format!("pattern '{p}' must be '<prefix>+*'"),
                ));
            }
        }
        Ok(())
    }

    /// Whether this constraint authorizes minting the agent name `name`:
    /// either an exact `names` entry, or a `<prefix>+*` pattern where
    /// `name == "<prefix>+<non-empty suffix>"`.
    pub fn authorizes(&self, name: &str) -> bool {
        if self.names.iter().any(|n| n == name) {
            return true;
        }
        self.patterns.iter().any(|p| {
            Self::pattern_prefix(p)
                .map(|prefix| {
                    name.strip_prefix(prefix)
                        .and_then(|rest| rest.strip_prefix('+'))
                        .is_some_and(|suffix| !suffix.is_empty())
                })
                .unwrap_or(false)
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningCertClaims {
    /// MUST be [`TYP_PROVISIONING_CERT`]
    pub typ: String,
    /// The delegating identity (email form)
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    /// The provisioning public key (P_pub)
    #[serde(rename = "public-key")]
    pub public_key: PublicKey,
    /// What this key may mint (v0.3). Defaults empty for backward-compatible
    /// decoding, but `create` requires a valid (non-empty) constraint.
    #[serde(default)]
    pub constraint: Constraint,
}

/// The delegation: `U_priv` certifies that `P_pub` may provision agent
/// identities on behalf of `iss`.
#[derive(Debug, Clone)]
pub struct ProvisioningCert {
    encoded: String,
    claims: ProvisioningCertClaims,
}

impl ProvisioningCert {
    /// Sign a new provisioning cert with the delegator's identity key. The
    /// `constraint` must be valid (at least one name/pattern, well-formed
    /// patterns) — an unconstrained key is rejected.
    pub fn create(
        delegator_email: &str,
        provisioning_pub: &PublicKey,
        constraint: Constraint,
        validity: Duration,
        identity_key: &KeyPair,
    ) -> Result<Self> {
        constraint.validate()?;
        let now = Utc::now();
        let claims = ProvisioningCertClaims {
            typ: TYP_PROVISIONING_CERT.to_string(),
            iss: delegator_email.to_string(),
            iat: now.timestamp(),
            exp: (now + validity).timestamp(),
            public_key: provisioning_pub.clone(),
            constraint,
        };
        let encoded = jws_sign(&claims, identity_key)?;
        Ok(Self { encoded, claims })
    }

    /// Parse (no signature check); rejects a wrong or missing `typ`
    pub fn parse(encoded: &str) -> Result<Self> {
        let claims: ProvisioningCertClaims = jws_decode(encoded, "provisioning cert")?;
        if claims.typ != TYP_PROVISIONING_CERT {
            return Err(invalid("provisioning cert", format!("typ '{}'", claims.typ)));
        }
        Ok(Self { encoded: encoded.to_string(), claims })
    }

    /// Verify the delegator's signature (the key certified by `U_cert`)
    pub fn verify(&self, delegator_identity_key: &PublicKey) -> Result<()> {
        jws_verify(&self.encoded, delegator_identity_key, "provisioning cert")
    }

    pub fn is_expired(&self) -> bool {
        expired(self.claims.exp)
    }

    pub fn claims(&self) -> &ProvisioningCertClaims {
        &self.claims
    }

    pub fn delegator(&self) -> &str {
        &self.claims.iss
    }

    /// P_pub — the key that signs provisioning requests
    pub fn public_key(&self) -> &PublicKey {
        &self.claims.public_key
    }

    /// What this key may mint
    pub fn constraint(&self) -> &Constraint {
        &self.claims.constraint
    }

    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

// --------------------------------------------------------------------------
// Provisioning request (R)
// --------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Mint,
    List,
    Revoke,
    /// Pre-allocate the cert's bound `names` at key-creation so a later mint
    /// can't be refused (spec v0.3). Acts on the P_cert's `constraint.names`;
    /// carries no `name` of its own.
    Reserve,
    /// Raise a consent request for a warrant at the registrar (spec §6,
    /// v0.4). Carries `name` plus `warrant-aud`/`warrant-scopes`; the user
    /// approves (and signs the warrant) at the registrar's consent surface.
    Warrant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningRequestClaims {
    /// MUST be [`TYP_PROVISIONING_REQUEST`]
    pub typ: String,
    pub iat: i64,
    pub exp: i64,
    pub action: Action,
    /// Target IdP domain (audience pinning)
    pub domain: String,
    /// Local part to mint/revoke
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The agent key to certify (mint only; may rotate freely)
    #[serde(rename = "agent-key", skip_serializing_if = "Option::is_none")]
    pub agent_key: Option<PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<bool>,
    /// The grants a warrant consent request asks for (action=warrant only):
    /// one entry per RP audience, each with its own scopes — audiences are
    /// copied verbatim from RP challenges, never typed by anyone. Approval
    /// yields one single-audience warrant per entry.
    #[serde(rename = "warrant-grants", skip_serializing_if = "Option::is_none")]
    pub warrant_grants: Option<Vec<WarrantGrant>>,
}

/// One requested grant in a warrant consent request (spec §6.2): a single
/// audience plus the scopes the RP asked for there. The signed warrant that
/// comes back is the same shape — one audience each; batching exists only at
/// the request/consent layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarrantGrant {
    /// Exact-match audience (https origin, or a scheme-specific URI like
    /// `sbo://…`); no wildcards
    pub aud: String,
    /// Scopes requested at this audience (RP vocabulary)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

/// Maximum grants in one consent request — a consent screen must be able to
/// show every audience with equal prominence
pub const MAX_WARRANT_GRANTS: usize = 8;

/// A single provisioning operation, signed by `P_priv`. Short-lived.
#[derive(Debug, Clone)]
pub struct ProvisioningRequest {
    encoded: String,
    claims: ProvisioningRequestClaims,
}

impl ProvisioningRequest {
    fn create(claims: ProvisioningRequestClaims, provisioning_key: &KeyPair) -> Result<Self> {
        let encoded = jws_sign(&claims, provisioning_key)?;
        Ok(Self { encoded, claims })
    }

    fn base_claims(action: Action, domain: &str) -> ProvisioningRequestClaims {
        let now = Utc::now();
        ProvisioningRequestClaims {
            typ: TYP_PROVISIONING_REQUEST.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::minutes(REQUEST_VALIDITY_MINUTES)).timestamp(),
            action,
            domain: domain.to_string(),
            name: None,
            agent_key: None,
            ephemeral: None,
            warrant_grants: None,
        }
    }

    pub fn mint(
        domain: &str,
        name: &str,
        agent_pub: &PublicKey,
        ephemeral: bool,
        provisioning_key: &KeyPair,
    ) -> Result<Self> {
        let mut claims = Self::base_claims(Action::Mint, domain);
        claims.name = Some(name.to_string());
        claims.agent_key = Some(agent_pub.clone());
        claims.ephemeral = if ephemeral { Some(true) } else { None };
        Self::create(claims, provisioning_key)
    }

    pub fn list(domain: &str, provisioning_key: &KeyPair) -> Result<Self> {
        Self::create(Self::base_claims(Action::List, domain), provisioning_key)
    }

    /// Reserve the cert's bound `names` (no per-request name — the target
    /// reads them from the verified `constraint.names`).
    pub fn reserve(domain: &str, provisioning_key: &KeyPair) -> Result<Self> {
        Self::create(Self::base_claims(Action::Reserve, domain), provisioning_key)
    }

    pub fn revoke(domain: &str, name: &str, provisioning_key: &KeyPair) -> Result<Self> {
        let mut claims = Self::base_claims(Action::Revoke, domain);
        claims.name = Some(name.to_string());
        Self::create(claims, provisioning_key)
    }

    /// A consent request for one or more warrants at the registrar (spec
    /// §6.2): `domain` is the **registrar's** domain; each grant's
    /// audience/scopes come from the RPs' challenges. One approval signs one
    /// single-audience warrant per grant.
    pub fn warrant(
        domain: &str,
        name: &str,
        grants: Vec<WarrantGrant>,
        provisioning_key: &KeyPair,
    ) -> Result<Self> {
        if grants.is_empty() || grants.len() > MAX_WARRANT_GRANTS {
            return Err(invalid(
                "provisioning request",
                format!("must request 1..={MAX_WARRANT_GRANTS} grants"),
            ));
        }
        for g in &grants {
            if g.aud.is_empty() || g.aud.contains('*') {
                return Err(invalid(
                    "provisioning request",
                    "each grant audience must be one exact identifier (no wildcards)",
                ));
            }
        }
        let mut auds: Vec<&str> = grants.iter().map(|g| g.aud.as_str()).collect();
        auds.sort_unstable();
        auds.dedup();
        if auds.len() != grants.len() {
            return Err(invalid("provisioning request", "duplicate grant audiences"));
        }
        let mut claims = Self::base_claims(Action::Warrant, domain);
        claims.name = Some(name.to_string());
        claims.warrant_grants = Some(grants);
        Self::create(claims, provisioning_key)
    }

    /// Parse (no signature check); rejects a wrong or missing `typ`
    pub fn parse(encoded: &str) -> Result<Self> {
        let claims: ProvisioningRequestClaims = jws_decode(encoded, "provisioning request")?;
        if claims.typ != TYP_PROVISIONING_REQUEST {
            return Err(invalid("provisioning request", format!("typ '{}'", claims.typ)));
        }
        Ok(Self { encoded: encoded.to_string(), claims })
    }

    pub fn verify(&self, provisioning_pub: &PublicKey) -> Result<()> {
        jws_verify(&self.encoded, provisioning_pub, "provisioning request")
    }

    pub fn is_expired(&self) -> bool {
        expired(self.claims.exp)
    }

    pub fn claims(&self) -> &ProvisioningRequestClaims {
        &self.claims
    }

    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

// --------------------------------------------------------------------------
// Request bundle (U_cert ~ P_cert ~ R)
// --------------------------------------------------------------------------

/// The outcome of verifying a request bundle's user-side chain. Callers still
/// apply their own context checks: the target IdP requires `request.domain`
/// == its domain and the `U_cert` issuer == itself; the broker checks its
/// registry + policy.
#[derive(Debug, Clone)]
pub struct VerifiedRequest {
    /// The delegating identity (`P_cert.iss` == `U_cert.principal.email`)
    pub delegator: String,
    /// The `U_cert` issuer domain (== the IdP rooting the delegator)
    pub issuer: String,
    /// P_pub, for registry lookups / audit
    pub provisioning_pub: PublicKey,
    /// What the delegation authorizes minting — callers enforce
    /// `constraint.authorizes(request.name)` for mints.
    pub constraint: Constraint,
    pub request: ProvisioningRequestClaims,
}

/// `U_cert~P_cert~R` — everything a verifier needs, in one string.
#[derive(Debug, Clone)]
pub struct RequestBundle {
    encoded: String,
    user_cert: Certificate,
    provisioning_cert: ProvisioningCert,
    request: ProvisioningRequest,
}

impl RequestBundle {
    pub fn new(
        user_cert: Certificate,
        provisioning_cert: ProvisioningCert,
        request: ProvisioningRequest,
    ) -> Self {
        let encoded = format!(
            "{}~{}~{}",
            user_cert.encoded(),
            provisioning_cert.encoded(),
            request.encoded()
        );
        Self { encoded, user_cert, provisioning_cert, request }
    }

    pub fn parse(encoded: &str) -> Result<Self> {
        let parts: Vec<&str> = encoded.split('~').collect();
        if parts.len() != 3 {
            return Err(invalid(
                "request bundle",
                "expected U_cert~P_cert~request (3 parts)",
            ));
        }
        Ok(Self {
            encoded: encoded.to_string(),
            user_cert: Certificate::parse(parts[0])?,
            provisioning_cert: ProvisioningCert::parse(parts[1])?,
            request: ProvisioningRequest::parse(parts[2])?,
        })
    }

    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// `sha256:<hex>` of the exact encoded bundle — what an endorsement's
    /// `sub` binds to
    pub fn hash(&self) -> String {
        let digest = Sha256::digest(self.encoded.as_bytes());
        format!("sha256:{}", digest.iter().map(|b| format!("{:02x}", b)).collect::<String>())
    }

    pub fn user_cert(&self) -> &Certificate {
        &self.user_cert
    }

    pub fn provisioning_cert(&self) -> &ProvisioningCert {
        &self.provisioning_cert
    }

    pub fn request(&self) -> &ProvisioningRequest {
        &self.request
    }

    /// Verify the full user-side chain against the `U_cert` issuer's key:
    ///
    /// 1. `R` signed by `P_cert`'s key and unexpired;
    /// 2. `P_cert` signed by `U_cert`'s key, unexpired, correct `typ`,
    ///    `iss` == `U_cert.principal.email`;
    /// 3. `U_cert` signed by `issuer_key` — with **signing-time semantics**:
    ///    `U_cert` may be expired now; `P_cert.iat` must fall within its
    ///    validity window (spec §3).
    pub fn verify(&self, issuer_key: &PublicKey) -> Result<VerifiedRequest> {
        // 1. Request under P_pub
        self.request.verify(self.provisioning_cert.public_key())?;
        if self.request.is_expired() {
            return Err(invalid("provisioning request", "expired"));
        }

        // 2. P_cert under U_pub
        self.provisioning_cert.verify(self.user_cert.public_key())?;
        if self.provisioning_cert.is_expired() {
            return Err(invalid("provisioning cert", "expired"));
        }
        let delegator = self
            .user_cert
            .email()
            .ok_or_else(|| invalid("user cert", "no email principal"))?;
        if self.provisioning_cert.delegator() != delegator {
            return Err(invalid(
                "provisioning cert",
                format!(
                    "iss '{}' does not match user cert principal '{}'",
                    self.provisioning_cert.delegator(),
                    delegator
                ),
            ));
        }

        // 3. U_cert under the issuer key, valid *at P_cert signing time*
        self.user_cert.verify(issuer_key)?;
        let p_iat = self.provisioning_cert.claims().iat;
        let u = self.user_cert.claims();
        if let Some(u_iat) = u.iat {
            if p_iat < u_iat {
                return Err(invalid(
                    "provisioning cert",
                    "signed before the user cert was issued",
                ));
            }
        }
        if p_iat > u.exp {
            return Err(invalid(
                "provisioning cert",
                "signed after the user cert expired",
            ));
        }

        Ok(VerifiedRequest {
            delegator: delegator.to_string(),
            issuer: self.user_cert.issuer().to_string(),
            provisioning_pub: self.provisioning_cert.public_key().clone(),
            constraint: self.provisioning_cert.constraint().clone(),
            request: self.request.claims().clone(),
        })
    }
}

// --------------------------------------------------------------------------
// Endorsement (E)
// --------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndorsementClaims {
    /// MUST be [`TYP_ENDORSEMENT`]
    pub typ: String,
    /// The endorsing broker's domain
    pub iss: String,
    /// The target IdP domain
    pub aud: String,
    /// `sha256:<hex>` of the exact request bundle being approved
    pub sub: String,
    /// The delegator the broker verified from the chain
    pub delegator: String,
    pub iat: i64,
    pub exp: i64,
}

/// The broker's policy claim: this specific request is within allowable
/// parameters for this user. Short-lived; approves exactly one bundle.
#[derive(Debug, Clone)]
pub struct Endorsement {
    encoded: String,
    claims: EndorsementClaims,
}

impl Endorsement {
    pub fn create(
        broker_domain: &str,
        target_domain: &str,
        bundle: &RequestBundle,
        delegator: &str,
        validity: Duration,
        broker_key: &KeyPair,
    ) -> Result<Self> {
        let now = Utc::now();
        let claims = EndorsementClaims {
            typ: TYP_ENDORSEMENT.to_string(),
            iss: broker_domain.to_string(),
            aud: target_domain.to_string(),
            sub: bundle.hash(),
            delegator: delegator.to_string(),
            iat: now.timestamp(),
            exp: (now + validity).timestamp(),
        };
        let encoded = jws_sign(&claims, broker_key)?;
        Ok(Self { encoded, claims })
    }

    /// Parse (no signature check); rejects a wrong or missing `typ`
    pub fn parse(encoded: &str) -> Result<Self> {
        let claims: EndorsementClaims = jws_decode(encoded, "endorsement")?;
        if claims.typ != TYP_ENDORSEMENT {
            return Err(invalid("endorsement", format!("typ '{}'", claims.typ)));
        }
        Ok(Self { encoded: encoded.to_string(), claims })
    }

    /// Verify the broker signature, freshness, audience, and the hash binding
    /// to `bundle` — everything an IdP checks besides "is this broker one I
    /// accept" (which is the caller's trust decision).
    pub fn verify_for(
        &self,
        broker_key: &PublicKey,
        target_domain: &str,
        bundle: &RequestBundle,
    ) -> Result<()> {
        jws_verify(&self.encoded, broker_key, "endorsement")?;
        if expired(self.claims.exp) {
            return Err(invalid("endorsement", "expired"));
        }
        if self.claims.aud != target_domain {
            return Err(invalid(
                "endorsement",
                format!("aud '{}' is not '{}'", self.claims.aud, target_domain),
            ));
        }
        if self.claims.sub != bundle.hash() {
            return Err(invalid("endorsement", "does not match this request bundle"));
        }
        Ok(())
    }

    pub fn claims(&self) -> &EndorsementClaims {
        &self.claims
    }

    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Chain {
        idp: KeyPair,
        user: KeyPair,
        provisioning: KeyPair,
        bundle: RequestBundle,
    }

    fn chain(u_validity: Duration) -> Chain {
        let idp = KeyPair::generate();
        let user = KeyPair::generate();
        let provisioning = KeyPair::generate();
        let agent = KeyPair::generate();

        let u_cert = Certificate::create(
            "mingo.place",
            "dan@mingo.place",
            &user.public_key(),
            u_validity,
            &idp,
        )
        .unwrap();
        let p_cert = ProvisioningCert::create(
            "dan@mingo.place",
            &provisioning.public_key(),
            Constraint::names(["attestor2"]),
            Duration::days(PROVISIONING_CERT_VALIDITY_DAYS),
            &user,
        )
        .unwrap();
        let request = ProvisioningRequest::mint(
            "mingo.place",
            "attestor2",
            &agent.public_key(),
            false,
            &provisioning,
        )
        .unwrap();

        let bundle = RequestBundle::new(u_cert, p_cert, request);
        Chain { idp, user, provisioning, bundle }
    }

    #[test]
    fn constraint_validation_and_matching() {
        // Empty → invalid.
        assert!(Constraint::default().validate().is_err());
        // Names only.
        let c = Constraint::names(["attestor2", "worker"]);
        c.validate().unwrap();
        assert!(c.authorizes("attestor2"));
        assert!(c.authorizes("worker"));
        assert!(!c.authorizes("other"));

        // Patterns: <prefix>+* only; naked * rejected.
        let c = Constraint { names: vec![], patterns: vec!["dan+*".into(), "foo+*".into()] };
        c.validate().unwrap();
        assert!(c.authorizes("dan+ci"));
        assert!(c.authorizes("foo+worker"));
        assert!(!c.authorizes("dan"), "bare prefix is not authorized by the +* pattern");
        assert!(!c.authorizes("dan+"), "empty suffix is not authorized");
        assert!(!c.authorizes("other+x"));
        assert!(Constraint { names: vec![], patterns: vec!["*".into()] }.validate().is_err());
        assert!(Constraint { names: vec![], patterns: vec!["dan*".into()] }.validate().is_err());

        // Combined names + patterns (the user's example).
        let c = Constraint {
            names: vec!["foo".into(), "bar".into()],
            patterns: vec!["user+*".into(), "foo+*".into()],
        };
        c.validate().unwrap();
        assert!(c.authorizes("foo") && c.authorizes("bar"));
        assert!(c.authorizes("user+ci") && c.authorizes("foo+ci"));
        assert!(!c.authorizes("baz"));
    }

    #[test]
    fn create_rejects_empty_constraint() {
        let user = KeyPair::generate();
        let p = KeyPair::generate();
        assert!(ProvisioningCert::create(
            "dan@mingo.place",
            &p.public_key(),
            Constraint::default(),
            Duration::days(90),
            &user,
        )
        .is_err());
    }

    #[test]
    fn constraint_survives_the_chain() {
        let c = chain(Duration::hours(24));
        let verified = c.bundle.verify(&c.idp.public_key()).unwrap();
        assert!(verified.constraint.authorizes("attestor2"));
        assert!(!verified.constraint.authorizes("nope"));
        // Reserve request carries no name.
        let r = ProvisioningRequest::reserve("mingo.place", &c.provisioning).unwrap();
        assert_eq!(r.claims().action, Action::Reserve);
        assert!(r.claims().name.is_none());
    }

    #[test]
    fn full_chain_roundtrip_and_verify() {
        let c = chain(Duration::hours(24));
        let parsed = RequestBundle::parse(c.bundle.encoded()).unwrap();
        let verified = parsed.verify(&c.idp.public_key()).unwrap();
        assert_eq!(verified.delegator, "dan@mingo.place");
        assert_eq!(verified.issuer, "mingo.place");
        assert_eq!(verified.request.action, Action::Mint);
        assert_eq!(verified.request.name.as_deref(), Some("attestor2"));
        assert_eq!(verified.request.domain, "mingo.place");
        assert_eq!(&verified.provisioning_pub, c.bundle.provisioning_cert().public_key());
    }

    #[test]
    fn wrong_issuer_key_rejected() {
        let c = chain(Duration::hours(24));
        assert!(c.bundle.verify(&KeyPair::generate().public_key()).is_err());
    }

    #[test]
    fn request_signed_by_wrong_key_rejected() {
        let c = chain(Duration::hours(24));
        // Re-sign the request with a rogue key and rebuild the bundle.
        let rogue = KeyPair::generate();
        let request = ProvisioningRequest::mint(
            "mingo.place",
            "attestor2",
            &KeyPair::generate().public_key(),
            false,
            &rogue,
        )
        .unwrap();
        let bundle = RequestBundle::new(
            c.bundle.user_cert().clone(),
            c.bundle.provisioning_cert().clone(),
            request,
        );
        assert!(bundle.verify(&c.idp.public_key()).is_err());
    }

    #[test]
    fn delegator_mismatch_rejected() {
        let c = chain(Duration::hours(24));
        // P_cert claiming a different identity than the U_cert certifies.
        let p_cert = ProvisioningCert::create(
            "mallory@mingo.place",
            &c.provisioning.public_key(),
            Constraint::names(["attestor2"]),
            Duration::days(90),
            &c.user,
        )
        .unwrap();
        let bundle = RequestBundle::new(
            c.bundle.user_cert().clone(),
            p_cert,
            c.bundle.request().clone(),
        );
        let err = bundle.verify(&c.idp.public_key()).unwrap_err().to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn signing_time_semantics() {
        // U_cert already expired NOW, but P_cert was signed inside its window
        // (both created "now" with a validity ending in the past — iat is now,
        // exp in the past, so p_iat > u.exp → rejected; then the good case).
        let c = chain(Duration::seconds(-10)); // exp in the past, iat now
        let err = c.bundle.verify(&c.idp.public_key()).unwrap_err().to_string();
        assert!(err.contains("after the user cert expired"), "{err}");

        // Healthy: U_cert window covers the P_cert signing moment. Even once
        // U_cert expires later, the chain stays valid — that is the point of
        // signing-time semantics. (Simulated by a short-but-future window.)
        let c = chain(Duration::seconds(2));
        c.bundle.verify(&c.idp.public_key()).unwrap();
    }

    #[test]
    fn typ_domain_separation() {
        let c = chain(Duration::hours(24));
        // An identity certificate is not a provisioning cert…
        assert!(ProvisioningCert::parse(c.bundle.user_cert().encoded()).is_err());
        // …and a provisioning cert is not an identity certificate (no principal)…
        assert!(Certificate::parse(c.bundle.provisioning_cert().encoded()).is_err());
        // …and neither is a request, nor is a request an endorsement.
        assert!(ProvisioningRequest::parse(c.bundle.provisioning_cert().encoded()).is_err());
        assert!(Endorsement::parse(c.bundle.request().encoded()).is_err());
    }

    #[test]
    fn endorsement_binds_one_bundle() {
        let c = chain(Duration::hours(24));
        let broker = KeyPair::generate();
        let endorsement = Endorsement::create(
            "browserid.me",
            "mingo.place",
            &c.bundle,
            "dan@mingo.place",
            Duration::minutes(REQUEST_VALIDITY_MINUTES),
            &broker,
        )
        .unwrap();

        // Round-trip + full verification against the right bundle.
        let parsed = Endorsement::parse(endorsement.encoded()).unwrap();
        parsed.verify_for(&broker.public_key(), "mingo.place", &c.bundle).unwrap();

        // Wrong broker key, wrong audience, or a different bundle → rejected.
        assert!(parsed
            .verify_for(&KeyPair::generate().public_key(), "mingo.place", &c.bundle)
            .is_err());
        assert!(parsed
            .verify_for(&broker.public_key(), "other.example", &c.bundle)
            .is_err());
        let other = chain(Duration::hours(24));
        assert!(parsed
            .verify_for(&broker.public_key(), "mingo.place", &other.bundle)
            .is_err());
    }

    #[test]
    fn expired_request_rejected() {
        let c = chain(Duration::hours(24));
        // Hand-build a request whose exp is already past.
        let mut claims = ProvisioningRequest::base_claims(Action::List, "mingo.place");
        claims.exp = Utc::now().timestamp() - 5;
        let request = ProvisioningRequest::create(claims, &c.provisioning).unwrap();
        let bundle = RequestBundle::new(
            c.bundle.user_cert().clone(),
            c.bundle.provisioning_cert().clone(),
            request,
        );
        let err = bundle.verify(&c.idp.public_key()).unwrap_err().to_string();
        assert!(err.contains("expired"), "{err}");
    }
}
