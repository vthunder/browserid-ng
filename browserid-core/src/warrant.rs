//! Agent warrants (spec §5.2, v0.4).
//!
//! A warrant is the user-signed, per-audience authorization that makes an
//! agent certificate usable: `U_priv` — the delegator's identity key, the
//! same key that signs `P_cert`s — signs a small claim binding **one agent
//! identity** to **one RP audience**, optionally with opaque scopes. The
//! delegator's `U_cert` is embedded (`parent-cert`) so the presentation is
//! self-contained; **signing-time semantics** apply, exactly as for
//! `P_cert`: the warrant must have been signed while the embedded `U_cert`
//! was valid, and stays valid until its own `exp` even after the `U_cert`
//! expires.
//!
//! Privacy is structural: one warrant names one audience, so no artifact
//! anywhere carries the delegator's full audience list, and warrants never
//! transit the IdP or registrar — an RP sees only warrants addressed to it.
//!
//! Presentation puts the warrant *inside* the backed-assertion chain
//! (`agent_cert~warrant~assertion`, spec §5.3) — see
//! [`crate::BackedAssertion`] — so a verifier cannot skip it.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::provisioning::{expired, jws_decode, jws_sign, jws_verify};
use crate::{Certificate, Error, KeyPair, Result};

/// Claim-level `typ` of a warrant
pub const TYP_AGENT_WARRANT: &str = "browserid-agent-warrant-v1";

/// Recommended warrant validity (spec: 90 days, matching `P_cert`)
pub const WARRANT_VALIDITY_DAYS: i64 = 90;

fn invalid(msg: impl std::fmt::Display) -> Error {
    Error::InvalidWarrant(msg.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarrantClaims {
    /// MUST be [`TYP_AGENT_WARRANT`]
    pub typ: String,
    /// The delegator (== `parent-cert.principal.email` == the agent
    /// certificate's `agent.parent`)
    pub iss: String,
    /// The agent's full identity email this warrant authorizes
    pub agent: String,
    /// Exactly one RP audience (exact origin — no wildcards), same
    /// normalization as assertion `aud`
    pub aud: String,
    /// Opaque scope strings, meaningful only to the RP. Absent means
    /// audience-authorized but scope-unqualified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// The delegator's `U_cert`, embedded so verification is self-contained
    #[serde(rename = "parent-cert")]
    pub parent_cert: String,
    pub iat: i64,
    pub exp: i64,
}

/// A user-signed, per-audience agent authorization (spec §5.2)
#[derive(Debug, Clone)]
pub struct Warrant {
    encoded: String,
    claims: WarrantClaims,
}

impl Warrant {
    /// Sign a warrant with the delegator's identity key. The delegator is
    /// derived from `parent_cert` (which must be a plain, email-principal
    /// certificate — an agent identity cannot be a delegator). `audience`
    /// must be an exact origin; wildcards are rejected.
    pub fn create(
        parent_cert: &Certificate,
        agent_email: &str,
        audience: &str,
        scopes: Option<Vec<String>>,
        validity: Duration,
        identity_key: &KeyPair,
    ) -> Result<Self> {
        if parent_cert.is_agent() {
            return Err(invalid("an agent identity cannot be a delegator"));
        }
        let delegator = parent_cert
            .email()
            .ok_or_else(|| invalid("parent cert has no email principal"))?;
        if audience.is_empty() || audience.contains('*') {
            return Err(invalid("audience must be one exact origin (no wildcards)"));
        }

        let now = Utc::now();
        let claims = WarrantClaims {
            typ: TYP_AGENT_WARRANT.to_string(),
            iss: delegator.to_string(),
            agent: agent_email.to_string(),
            aud: audience.to_string(),
            scopes,
            parent_cert: parent_cert.encoded().to_string(),
            iat: now.timestamp(),
            exp: (now + validity).timestamp(),
        };
        let encoded = jws_sign(&claims, identity_key)?;
        Ok(Self { encoded, claims })
    }

    /// Parse (no signature check); rejects a wrong or missing `typ` and a
    /// wildcard audience
    pub fn parse(encoded: &str) -> Result<Self> {
        let claims: WarrantClaims = jws_decode(encoded, "warrant")?;
        if claims.typ != TYP_AGENT_WARRANT {
            return Err(invalid(format!("typ '{}'", claims.typ)));
        }
        if claims.aud.is_empty() || claims.aud.contains('*') {
            return Err(invalid("audience must be one exact origin (no wildcards)"));
        }
        Ok(Self { encoded: encoded.to_string(), claims })
    }

    /// Cheap check for chain parsing: does this segment's claim-level `typ`
    /// say "warrant"? (Full validation happens in [`Warrant::parse`].)
    pub(crate) fn segment_is_warrant(encoded: &str) -> bool {
        jws_decode::<serde_json::Value>(encoded, "segment")
            .ok()
            .and_then(|v| v.get("typ").and_then(|t| t.as_str()).map(String::from))
            .is_some_and(|t| t == TYP_AGENT_WARRANT)
    }

    /// Verify this warrant against the agent certificate it accompanies and
    /// the verifying RP's audience (spec §5.3 step 3):
    ///
    /// 1. the embedded `parent-cert` is a plain certificate from the **same
    ///    issuer domain** as the agent cert (identity-domain rule), verified
    ///    under `issuer_key`;
    /// 2. the warrant is signed by the parent cert's subject key, with
    ///    signing-time semantics (`iat` within the parent cert's window; the
    ///    parent cert need not be currently unexpired) and is itself
    ///    unexpired;
    /// 3. `iss` == parent cert's email == the agent cert's `agent.parent`;
    /// 4. `agent` == the agent cert's `principal.email`;
    /// 5. `aud` == `audience` (the same value checked against the
    ///    assertion's `aud`).
    ///
    /// Returns the granted scopes (empty when unqualified).
    pub fn verify_for(
        &self,
        agent_cert: &Certificate,
        audience: &str,
        issuer_key: &crate::PublicKey,
    ) -> Result<Vec<String>> {
        // 1. Embedded parent cert: plain, same domain, issuer-signed.
        let parent = Certificate::parse(&self.claims.parent_cert)?;
        if parent.is_agent() {
            return Err(invalid("an agent identity cannot be a delegator"));
        }
        if parent.issuer() != agent_cert.issuer() {
            return Err(invalid(format!(
                "parent cert issuer '{}' does not match agent cert issuer '{}'",
                parent.issuer(),
                agent_cert.issuer()
            )));
        }
        parent.verify(issuer_key)?;

        // 2. Warrant under U_pub, signed while the parent cert was valid,
        //    and not itself expired.
        jws_verify(&self.encoded, parent.public_key(), "warrant")?;
        let p = parent.claims();
        if let Some(p_iat) = p.iat {
            if self.claims.iat < p_iat {
                return Err(invalid("signed before the parent cert was issued"));
            }
        }
        if self.claims.iat > p.exp {
            return Err(invalid("signed after the parent cert expired"));
        }
        if expired(self.claims.exp) {
            return Err(invalid("expired"));
        }

        // 3. Delegator consistency across all three artifacts.
        let parent_email = parent
            .email()
            .ok_or_else(|| invalid("parent cert has no email principal"))?;
        if self.claims.iss != parent_email {
            return Err(invalid(format!(
                "iss '{}' does not match parent cert principal '{}'",
                self.claims.iss, parent_email
            )));
        }
        match agent_cert.agent_parent() {
            Some(cert_parent) if cert_parent == self.claims.iss => {}
            Some(cert_parent) => {
                return Err(invalid(format!(
                    "agent cert parent '{}' does not match warrant iss '{}'",
                    cert_parent, self.claims.iss
                )));
            }
            None => return Err(invalid("accompanying certificate is not an agent cert")),
        }

        // 4. Agent identity binding.
        match agent_cert.email() {
            Some(cert_email) if cert_email == self.claims.agent => {}
            _ => {
                return Err(invalid(format!(
                    "warrant is for '{}', not this certificate's identity",
                    self.claims.agent
                )));
            }
        }

        // 5. Audience pinning — the RP's own audience, exactly.
        if self.claims.aud != audience {
            return Err(Error::AudienceMismatch {
                expected: audience.to_string(),
                actual: self.claims.aud.clone(),
            });
        }

        Ok(self.claims.scopes.clone().unwrap_or_default())
    }

    pub fn claims(&self) -> &WarrantClaims {
        &self.claims
    }

    /// The delegator who signed this warrant
    pub fn delegator(&self) -> &str {
        &self.claims.iss
    }

    /// The agent identity this warrant authorizes
    pub fn agent(&self) -> &str {
        &self.claims.agent
    }

    /// The one RP audience this warrant is valid at
    pub fn audience(&self) -> &str {
        &self.claims.aud
    }

    pub fn is_expired(&self) -> bool {
        expired(self.claims.exp)
    }

    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    struct Setup {
        idp: KeyPair,
        user: KeyPair,
        parent_cert: Certificate,
        agent_cert: Certificate,
    }

    fn setup(parent_validity: Duration) -> Setup {
        let idp = KeyPair::generate();
        let user = KeyPair::generate();
        let agent = KeyPair::generate();
        let parent_cert = Certificate::create(
            "mingo.place",
            "dan@mingo.place",
            &user.public_key(),
            parent_validity,
            &idp,
        )
        .unwrap();
        let agent_cert = Certificate::create_agent(
            "mingo.place",
            "attestor2@mingo.place",
            "dan@mingo.place",
            &agent.public_key(),
            Duration::hours(24),
            &idp,
        )
        .unwrap();
        Setup { idp, user, parent_cert, agent_cert }
    }

    const AUD: &str = "https://api.example.com";

    fn warrant(s: &Setup) -> Warrant {
        Warrant::create(
            &s.parent_cert,
            "attestor2@mingo.place",
            AUD,
            Some(vec!["post".into(), "read".into()]),
            Duration::days(WARRANT_VALIDITY_DAYS),
            &s.user,
        )
        .unwrap()
    }

    #[test]
    fn roundtrip_and_verify() {
        let s = setup(Duration::hours(24));
        let w = warrant(&s);
        let parsed = Warrant::parse(w.encoded()).unwrap();
        let scopes = parsed
            .verify_for(&s.agent_cert, AUD, &s.idp.public_key())
            .unwrap();
        assert_eq!(scopes, vec!["post", "read"]);
        assert_eq!(parsed.delegator(), "dan@mingo.place");
        assert_eq!(parsed.agent(), "attestor2@mingo.place");
    }

    #[test]
    fn scopeless_warrant_grants_empty() {
        let s = setup(Duration::hours(24));
        let w = Warrant::create(
            &s.parent_cert,
            "attestor2@mingo.place",
            AUD,
            None,
            Duration::days(1),
            &s.user,
        )
        .unwrap();
        let scopes = w.verify_for(&s.agent_cert, AUD, &s.idp.public_key()).unwrap();
        assert!(scopes.is_empty());
    }

    #[test]
    fn wrong_audience_rejected() {
        let s = setup(Duration::hours(24));
        let w = warrant(&s);
        let err = w
            .verify_for(&s.agent_cert, "https://other.example.com", &s.idp.public_key())
            .unwrap_err();
        assert!(matches!(err, Error::AudienceMismatch { .. }));
    }

    #[test]
    fn wildcard_audience_rejected_at_create_and_parse() {
        let s = setup(Duration::hours(24));
        assert!(Warrant::create(
            &s.parent_cert,
            "attestor2@mingo.place",
            "https://*.example.com",
            None,
            Duration::days(1),
            &s.user,
        )
        .is_err());
    }

    #[test]
    fn wrong_agent_identity_rejected() {
        let s = setup(Duration::hours(24));
        let w = Warrant::create(
            &s.parent_cert,
            "other-agent@mingo.place",
            AUD,
            None,
            Duration::days(1),
            &s.user,
        )
        .unwrap();
        let err = w
            .verify_for(&s.agent_cert, AUD, &s.idp.public_key())
            .unwrap_err()
            .to_string();
        assert!(err.contains("not this certificate's identity"), "{err}");
    }

    #[test]
    fn warrant_signed_by_wrong_key_rejected() {
        let s = setup(Duration::hours(24));
        let rogue = KeyPair::generate();
        let w = Warrant::create(
            &s.parent_cert,
            "attestor2@mingo.place",
            AUD,
            None,
            Duration::days(1),
            &rogue, // not the key the parent cert certifies
        )
        .unwrap();
        assert!(w.verify_for(&s.agent_cert, AUD, &s.idp.public_key()).is_err());
    }

    #[test]
    fn parent_cert_from_wrong_issuer_rejected() {
        let s = setup(Duration::hours(24));
        // Parent cert signed by a different (untrusted) key: fails under the
        // real issuer key.
        let rogue_idp = KeyPair::generate();
        let forged_parent = Certificate::create(
            "mingo.place",
            "dan@mingo.place",
            &s.user.public_key(),
            Duration::hours(24),
            &rogue_idp,
        )
        .unwrap();
        let w = Warrant::create(
            &forged_parent,
            "attestor2@mingo.place",
            AUD,
            None,
            Duration::days(1),
            &s.user,
        )
        .unwrap();
        assert!(w.verify_for(&s.agent_cert, AUD, &s.idp.public_key()).is_err());
    }

    #[test]
    fn delegator_mismatch_with_agent_cert_rejected() {
        let s = setup(Duration::hours(24));
        // Agent cert attributes a different parent.
        let agent = KeyPair::generate();
        let other_parent_cert = Certificate::create_agent(
            "mingo.place",
            "attestor2@mingo.place",
            "mallory@mingo.place",
            &agent.public_key(),
            Duration::hours(24),
            &s.idp,
        )
        .unwrap();
        let w = warrant(&s);
        let err = w
            .verify_for(&other_parent_cert, AUD, &s.idp.public_key())
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match warrant iss"), "{err}");
    }

    #[test]
    fn signing_time_semantics() {
        // Parent cert already expired when the warrant is signed → rejected.
        let s = setup(Duration::seconds(-10));
        let w = warrant(&s);
        let err = w
            .verify_for(&s.agent_cert, AUD, &s.idp.public_key())
            .unwrap_err()
            .to_string();
        assert!(err.contains("after the parent cert expired"), "{err}");

        // Signed inside the window → valid, even though the parent cert will
        // expire long before the warrant does.
        let s = setup(Duration::seconds(2));
        let w = warrant(&s);
        w.verify_for(&s.agent_cert, AUD, &s.idp.public_key()).unwrap();
    }

    #[test]
    fn agent_cannot_be_a_delegator() {
        let s = setup(Duration::hours(24));
        // Try to use the agent cert itself as the parent.
        let err = Warrant::create(
            &s.agent_cert,
            "sub-agent@mingo.place",
            AUD,
            None,
            Duration::days(1),
            &s.user,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("cannot be a delegator"), "{err}");
    }

    #[test]
    fn typ_domain_separation() {
        let s = setup(Duration::hours(24));
        // A certificate is not a warrant; a warrant is not a certificate.
        assert!(Warrant::parse(s.parent_cert.encoded()).is_err());
        assert!(Warrant::parse(s.agent_cert.encoded()).is_err());
        let w = warrant(&s);
        assert!(Certificate::parse(w.encoded()).is_err());
        assert!(Warrant::segment_is_warrant(w.encoded()));
        assert!(!Warrant::segment_is_warrant(s.agent_cert.encoded()));
    }
}
