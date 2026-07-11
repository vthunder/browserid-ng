//! Identity certificates for BrowserID-NG
//!
//! A certificate binds a user's public key to their email address,
//! signed by the email domain's key.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::status::StatusRef;
use crate::{Error, KeyPair, PublicKey, Result};

/// Claim-level `typ` of an agent certificate (spec §5.1). A plain user
/// certificate carries no claim-level `typ`; a verifier MUST reject any
/// certificate whose `typ` it does not recognize (core §4.1/§6.2), which is
/// what makes agent credentials fail-closed at verifiers that predate them.
pub const TYP_AGENT_CERT: &str = "browserid-agent-cert-v1";

/// The `agent` claims block on an agent certificate: issuer-set attribution.
/// Presence of this block (with [`TYP_AGENT_CERT`]) is what makes an identity
/// protocol-visible as an agent. The agent's handle is the local part of the
/// certificate's `principal.email`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentClaims {
    /// The delegator this agent acts for — set by the IdP from the verified
    /// provisioning chain, never by the agent.
    pub parent: String,
}

/// Principal identifier in a certificate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Principal {
    /// Email address principal
    Email {
        email: String,
    },
}

impl Principal {
    /// Create an email principal
    pub fn email(email: impl Into<String>) -> Self {
        Principal::Email { email: email.into() }
    }

    /// Get the email address if this is an email principal
    pub fn as_email(&self) -> Option<&str> {
        match self {
            Principal::Email { email } => Some(email),
        }
    }

    /// Extract the domain from an email principal
    pub fn domain(&self) -> Option<&str> {
        self.as_email().and_then(|e| e.split('@').nth(1))
    }
}

/// Claims in an identity certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateClaims {
    /// Claim-level type. Absent on a plain user certificate; [`TYP_AGENT_CERT`]
    /// on an agent certificate. Any other value is rejected at parse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Issuer (the domain that signed this certificate)
    pub iss: String,

    /// Expiration time (Unix timestamp)
    pub exp: i64,

    /// Issued at time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// The user's public key
    #[serde(rename = "public-key")]
    pub public_key: PublicKey,

    /// The principal (email address)
    pub principal: Principal,

    /// Agent attribution block — present iff `typ` is [`TYP_AGENT_CERT`]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentClaims>,

    /// Agent spec §5.1: the origin of the registrar the delegator's broker
    /// chose — where the agent raises consent requests and where its warrant
    /// status list is published. Set by the IdP from the endorsement, never
    /// by the agent. An RP pins each warrant's revocation authority to this
    /// value (§5.3), which rejects any agent warrant whose cert lacks it.
    /// Present only on agent certificates; `None` on plain user certs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar: Option<String>,

    /// Fast-revocation hook (core §6.4): where this credential's status bit
    /// lives. Issuers allocate one index per *identity*, so revoking an
    /// identity kills every outstanding cert for it at once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusRef>,
}

/// An identity certificate binding a public key to an email address
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The encoded JWT
    encoded: String,
    /// The decoded claims
    claims: CertificateClaims,
}

impl Certificate {
    /// Create and sign a new certificate
    ///
    /// # Arguments
    /// * `issuer` - The domain issuing this certificate
    /// * `email` - The user's email address
    /// * `user_public_key` - The user's public key to certify
    /// * `validity` - How long the certificate should be valid
    /// * `issuer_key` - The domain's signing key
    pub fn create(
        issuer: &str,
        email: &str,
        user_public_key: &PublicKey,
        validity: Duration,
        issuer_key: &KeyPair,
    ) -> Result<Self> {
        Self::create_with_status(issuer, email, user_public_key, validity, issuer_key, None)
    }

    /// [`Certificate::create`] with a status-list reference (core §6.4)
    pub fn create_with_status(
        issuer: &str,
        email: &str,
        user_public_key: &PublicKey,
        validity: Duration,
        issuer_key: &KeyPair,
        status: Option<StatusRef>,
    ) -> Result<Self> {
        let now = Utc::now();
        let exp = now + validity;

        let claims = CertificateClaims {
            typ: None,
            iss: issuer.to_string(),
            exp: exp.timestamp(),
            iat: Some(now.timestamp()),
            public_key: user_public_key.clone(),
            principal: Principal::email(email),
            agent: None,
            registrar: None,
            status,
        };

        let encoded = Self::encode_and_sign(&claims, issuer_key)?;

        Ok(Self { encoded, claims })
    }

    /// Create and sign an **agent certificate** (spec §5.1): a user
    /// certificate carrying `typ` [`TYP_AGENT_CERT`] and an `agent` block
    /// attributing it to `parent` (the delegator, from the verified
    /// provisioning chain).
    pub fn create_agent(
        issuer: &str,
        agent_email: &str,
        parent: &str,
        agent_public_key: &PublicKey,
        validity: Duration,
        issuer_key: &KeyPair,
        registrar: Option<String>,
    ) -> Result<Self> {
        Self::create_agent_with_status(
            issuer, agent_email, parent, agent_public_key, validity, issuer_key, registrar, None,
        )
    }

    /// [`Certificate::create_agent`] with a status-list reference (core §6.4)
    pub fn create_agent_with_status(
        issuer: &str,
        agent_email: &str,
        parent: &str,
        agent_public_key: &PublicKey,
        validity: Duration,
        issuer_key: &KeyPair,
        registrar: Option<String>,
        status: Option<StatusRef>,
    ) -> Result<Self> {
        let now = Utc::now();
        let claims = CertificateClaims {
            typ: Some(TYP_AGENT_CERT.to_string()),
            iss: issuer.to_string(),
            exp: (now + validity).timestamp(),
            iat: Some(now.timestamp()),
            public_key: agent_public_key.clone(),
            principal: Principal::email(agent_email),
            agent: Some(AgentClaims {
                parent: parent.to_string(),
            }),
            registrar,
            status,
        };

        let encoded = Self::encode_and_sign(&claims, issuer_key)?;

        Ok(Self { encoded, claims })
    }

    /// The status-list reference, if this credential carries one
    pub fn status(&self) -> Option<&StatusRef> {
        self.claims.status.as_ref()
    }

    /// Parse a certificate from its encoded form (does not verify signature).
    ///
    /// Fail-closed on type (core §4.1): a plain certificate carries no
    /// claim-level `typ` and no `agent` block; an agent certificate carries
    /// both. Any other combination — an unrecognized `typ`, a `typ` without
    /// its block, or an `agent` block on an untyped certificate — is
    /// rejected.
    pub fn parse(encoded: &str) -> Result<Self> {
        let claims = Self::decode_claims(encoded)?;
        match (claims.typ.as_deref(), claims.agent.is_some()) {
            (None, false) => {}
            (Some(TYP_AGENT_CERT), true) => {}
            (Some(TYP_AGENT_CERT), false) => {
                return Err(Error::InvalidCertificate(
                    "agent certificate missing its agent block".into(),
                ));
            }
            (Some(typ), _) => {
                return Err(Error::InvalidCertificate(format!(
                    "unrecognized certificate typ '{typ}'"
                )));
            }
            (None, true) => {
                return Err(Error::InvalidCertificate(
                    "agent block on a certificate without the agent typ".into(),
                ));
            }
        }
        Ok(Self {
            encoded: encoded.to_string(),
            claims,
        })
    }

    /// Whether this is an agent certificate (`typ` == [`TYP_AGENT_CERT`])
    pub fn is_agent(&self) -> bool {
        self.claims.typ.as_deref() == Some(TYP_AGENT_CERT)
    }

    /// The delegator this agent certificate is attributed to, if any
    pub fn registrar(&self) -> Option<&str> {
        self.claims.registrar.as_deref()
    }

    pub fn agent_parent(&self) -> Option<&str> {
        self.claims.agent.as_ref().map(|a| a.parent.as_str())
    }

    /// Verify the certificate signature against a public key
    pub fn verify(&self, issuer_public_key: &PublicKey) -> Result<()> {
        Self::verify_signature(&self.encoded, issuer_public_key)
    }

    /// Check if the certificate has expired
    pub fn is_expired(&self) -> bool {
        let exp = DateTime::from_timestamp(self.claims.exp, 0)
            .unwrap_or(DateTime::UNIX_EPOCH);
        Utc::now() > exp
    }

    /// Get the certificate claims
    pub fn claims(&self) -> &CertificateClaims {
        &self.claims
    }

    /// Get the certified public key
    pub fn public_key(&self) -> &PublicKey {
        &self.claims.public_key
    }

    /// Get the email address
    pub fn email(&self) -> Option<&str> {
        self.claims.principal.as_email()
    }

    /// Get the issuer domain
    pub fn issuer(&self) -> &str {
        &self.claims.iss
    }

    /// Get the encoded JWT
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    // Internal: encode claims and sign with Ed25519
    fn encode_and_sign(claims: &CertificateClaims, key: &KeyPair) -> Result<String> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        // Header for Ed25519
        let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header);

        // Claims
        let claims_json = serde_json::to_string(claims)?;
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

        // Sign header.claims
        let message = format!("{}.{}", header_b64, claims_b64);
        let signature = key.sign(message.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}", message, sig_b64))
    }

    // Internal: decode claims without verifying signature
    fn decode_claims(encoded: &str) -> Result<CertificateClaims> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let parts: Vec<&str> = encoded.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidCertificate("expected 3 JWT parts".into()));
        }

        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
        let claims: CertificateClaims = serde_json::from_slice(&claims_bytes)?;

        Ok(claims)
    }

    // Internal: verify signature
    fn verify_signature(encoded: &str, public_key: &PublicKey) -> Result<()> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let parts: Vec<&str> = encoded.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidCertificate("expected 3 JWT parts".into()));
        }

        let message = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD.decode(parts[2])?;

        public_key.verify(message.as_bytes(), &signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_create_and_verify() {
        // Domain keypair
        let domain_key = KeyPair::generate();

        // User keypair
        let user_key = KeyPair::generate();

        // Create certificate
        let cert = Certificate::create(
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();

        // Verify with domain's public key
        cert.verify(&domain_key.public_key()).unwrap();

        // Check claims
        assert_eq!(cert.issuer(), "example.com");
        assert_eq!(cert.email(), Some("alice@example.com"));
        assert_eq!(cert.public_key(), &user_key.public_key());
        assert!(!cert.is_expired());
    }

    #[test]
    fn test_certificate_parse_and_verify() {
        let domain_key = KeyPair::generate();
        let user_key = KeyPair::generate();

        let cert = Certificate::create(
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();

        // Parse from encoded form
        let parsed = Certificate::parse(cert.encoded()).unwrap();
        parsed.verify(&domain_key.public_key()).unwrap();

        assert_eq!(parsed.email(), Some("alice@example.com"));
    }

    #[test]
    fn agent_certificate_create_parse_and_accessors() {
        let domain_key = KeyPair::generate();
        let agent_key = KeyPair::generate();

        let cert = Certificate::create_agent(
            "example.com",
            "researcher@example.com",
            "alice@example.com",
            &agent_key.public_key(),
            Duration::hours(24),
            &domain_key,
            Some("https://registrar.example".to_string()),
        )
        .unwrap();

        assert!(cert.is_agent());
        assert_eq!(cert.agent_parent(), Some("alice@example.com"));
        assert_eq!(cert.registrar(), Some("https://registrar.example"));
        assert_eq!(cert.email(), Some("researcher@example.com"));

        let parsed = Certificate::parse(cert.encoded()).unwrap();
        parsed.verify(&domain_key.public_key()).unwrap();
        assert!(parsed.is_agent());
        assert_eq!(parsed.agent_parent(), Some("alice@example.com"));

        // A plain cert is not an agent.
        let user_key = KeyPair::generate();
        let plain = Certificate::create(
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();
        assert!(!plain.is_agent());
        assert_eq!(plain.agent_parent(), None);
    }

    #[test]
    fn malformed_typ_combinations_rejected() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let domain_key = KeyPair::generate();
        let user_key = KeyPair::generate();
        let cert = Certificate::create(
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();

        let requal = |mutate: &dyn Fn(&mut serde_json::Value)| {
            let mut claims: serde_json::Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(cert.encoded().split('.').nth(1).unwrap())
                    .unwrap(),
            )
            .unwrap();
            mutate(&mut claims);
            format!(
                "{}.{}.{}",
                cert.encoded().split('.').next().unwrap(),
                URL_SAFE_NO_PAD.encode(claims.to_string()),
                cert.encoded().split('.').nth(2).unwrap()
            )
        };

        // Unrecognized typ → rejected (fail-closed for future modules).
        let e = Certificate::parse(&requal(&|c| c["typ"] = "browserid-host-cert-v1".into()))
            .unwrap_err()
            .to_string();
        assert!(e.contains("unrecognized certificate typ"), "{e}");

        // Agent typ without the agent block → rejected.
        let e = Certificate::parse(&requal(&|c| c["typ"] = TYP_AGENT_CERT.into()))
            .unwrap_err()
            .to_string();
        assert!(e.contains("missing its agent block"), "{e}");

        // Agent block without the typ → rejected.
        let e = Certificate::parse(&requal(&|c| {
            c["agent"] = serde_json::json!({"parent": "alice@example.com"})
        }))
        .unwrap_err()
        .to_string();
        assert!(e.contains("without the agent typ"), "{e}");
    }

    #[test]
    fn test_certificate_wrong_key_rejected() {
        let domain_key = KeyPair::generate();
        let wrong_key = KeyPair::generate();
        let user_key = KeyPair::generate();

        let cert = Certificate::create(
            "example.com",
            "alice@example.com",
            &user_key.public_key(),
            Duration::hours(1),
            &domain_key,
        )
        .unwrap();

        // Should fail with wrong key
        assert!(cert.verify(&wrong_key.public_key()).is_err());
    }
}
