//! Operation A — admission: record validation + subject matching (spec §6.4).
//!
//! The resource *holds* the record (a `warrant ~ config_cert` two-object
//! bundle, obtained per §7.5); nothing presents it. Record validation
//! establishes only that the record is authentic and unrevoked — it
//! authenticates no one (§6.6 invariant 8). Redemption authority is custody
//! plus subject matching, both at the resource.
//!
//! Network is the caller's: issuer-key resolution MUST come from the
//! authenticated DNSSEC record with the issuer authoritative for the grantor's
//! domain (§6.4 step 1b — `browserid-broker`'s `resolve_conformant_key`
//! enforces this for the hosted endpoint), and the fail-closed status checks
//! (step 1e) run against the refs in [`ValidatedRecord::status_refs`].
//!
//! Validation MAY be split (§6.4): the signature/resolution/constraint checks
//! here are immutable and may run once at acquisition; per use, the caller
//! MUST re-check fail-closed both the status refs and the validity windows
//! ([`RecordBundle::recheck_live`]) — expiry is a live bound, not an
//! acquisition-time fact.

use crate::device::{Binding, DeviceCert, Holder, Purpose, Warrant};
use crate::identity;
use crate::jws::invalid;
use crate::status::StatusRef;
use crate::{PublicKey, Result};

/// The two-object record bundle: `warrant ~ config_cert`.
pub struct RecordBundle {
    pub warrant: Warrant,
    pub config_cert: DeviceCert,
}

/// The outcome of record validation (§6.4 steps 1a–1d): the record's claims,
/// plus what the caller needs for step 1e and the per-use live checks. Not an
/// authenticated party — see [`ValidatedRecord::matches_login`] / the custody
/// protocol's mechanics for subject matching.
#[derive(Debug, Clone)]
pub struct ValidatedRecord {
    /// The attributed identity (exact email; the config cert vouches for it).
    pub grantor: String,
    /// The identity that acts: an exact email or, on admission-consumed
    /// records, a grantee matcher (`*` / `*@<domain>`) — permission, never
    /// attribution.
    pub grantee: String,
    /// The record's binding, normalized (v1 reads as a holder binding).
    pub binding: Binding,
    pub scopes: Vec<String>,
    /// The grantor's IdP (the config cert's `iss`).
    pub grantor_issuer: String,
    /// Status refs for the caller's fail-closed step 1e: config cert → its
    /// IdP; warrant → hosted broker registry (always present on v2, optional
    /// on v1).
    pub config_status: Option<StatusRef>,
    pub warrant_status: Option<StatusRef>,
}

impl RecordBundle {
    /// Parse exactly `warrant ~ config_cert` (§6.4 step 1a — the warrant parse
    /// enforces the §5 shape matrix: implemented binding kind/protocol, v2
    /// status REQUIRED). Any other shape rejects, fail-closed.
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('~').collect();
        if parts.len() != 2 {
            return Err(invalid("record", "expected warrant~config_cert"));
        }
        Ok(Self {
            warrant: Warrant::parse(parts[0])?,
            config_cert: DeviceCert::parse(parts[1])?,
        })
    }

    pub fn encode(&self) -> String {
        format!("{}~{}", self.warrant.encoded(), self.config_cert.encoded())
    }

    /// §6.4 steps 1b–1d, minus network: verify the config cert under its
    /// resolved IdP key, the warrant under the config cert, the audience join,
    /// the connection self-grant rule, and the full §4.7 constraints.
    ///
    /// `get_idp_key(iss)` MUST resolve via the authenticated DNSSEC record and
    /// MUST require the issuer authoritative for the grantor's domain (or an
    /// accepted §8.1 fallback) — the same load-bearing caller obligation as
    /// [`crate::AccessPresentation::verify`]. Status (step 1e) is the caller's,
    /// against [`ValidatedRecord::status_refs`], fail-closed.
    pub fn validate<F>(&self, audience: &str, get_idp_key: F) -> Result<ValidatedRecord>
    where
        F: Fn(&str) -> Result<PublicKey>,
    {
        let cc = self.config_cert.claims();
        let wc = self.warrant.claims();

        // 1b: config cert under its IdP key; unexpired; an authorization cert
        // whose identities cover the grantor.
        let idp_key = get_idp_key(&cc.iss)?;
        self.config_cert.verify(&idp_key)?;
        if self.config_cert.is_expired() {
            return Err(invalid("config cert", "expired"));
        }
        if cc.purpose != Purpose::Authorization {
            return Err(invalid("config cert", "not an authorization cert"));
        }
        if !self.config_cert.authorizes_identity(&wc.grantor) {
            return Err(invalid("config cert", "not authorized for the warrant grantor"));
        }

        // 1c: warrant under the config cert's key; unexpired; audience exact
        // (same normalization as assertion `aud`). The connection self-grant
        // rule (§5) is enforced structurally at `Warrant::parse`.
        self.warrant.verify(&cc.public_key)?;
        if self.warrant.is_expired() {
            return Err(invalid("warrant", "expired"));
        }
        if wc.audience != audience {
            return Err(invalid("warrant", "audience mismatch"));
        }

        // 1d: full §4.7 constraints, exactly as §6.1 step 7 — this resource's
        // audience against `aud` (salted hash), the warrant against
        // scopes/max-ttl; an unimplemented constraint key rejects fail-closed.
        if let Some(c) = &cc.constraints {
            c.check("config cert", audience, wc)?;
        }

        Ok(ValidatedRecord {
            grantor: wc.grantor.clone(),
            grantee: wc.grantee.clone(),
            binding: wc.binding(),
            scopes: wc.scopes.clone(),
            grantor_issuer: cc.iss.clone(),
            config_status: cc.status.clone(),
            warrant_status: wc.status.clone(),
        })
    }

    /// The per-use validity-window re-check (§6.4 split rule): a held record
    /// authorizes until its `exp` or its revocation, whichever comes first.
    /// Callers run this fail-closed alongside the status re-check on every use
    /// (or, for a minting resource, at every bearer mint/refresh — §6.4
    /// freshness-backed minting).
    pub fn recheck_live(&self) -> Result<()> {
        if self.warrant.is_expired() {
            return Err(invalid("warrant", "expired"));
        }
        if self.config_cert.is_expired() {
            return Err(invalid("config cert", "expired"));
        }
        Ok(())
    }
}

impl ValidatedRecord {
    /// The record's status refs, for the caller's fail-closed checks (§6.4
    /// step 1e at acquisition; re-checked per use within the §6.3 window).
    pub fn status_refs(&self) -> Vec<StatusRef> {
        [&self.config_status, &self.warrant_status]
            .into_iter()
            .filter_map(|r| r.clone())
            .collect()
    }

    /// §6.4 step 3, holder path: match an independently authenticated
    /// browserid login against grantee + binding. `identity` is the login's
    /// authenticated email (never taken from this record — a grantee matcher
    /// grants permission, never attribution); `holder` is the login's holder,
    /// when the authentication carried one.
    ///
    /// Fail-closed: a connection-bound record does not match logins (its
    /// subject authentication is the custody protocol's mechanics, at the
    /// resource), and a non-`*` matcher cannot be evaluated against a
    /// holder-less authentication; `*` imposes nothing.
    pub fn matches_login(&self, identity: &str, holder: Option<&Holder>) -> Result<()> {
        let Binding::Holder { matcher } = &self.binding else {
            return Err(invalid(
                "record",
                "connection-bound record: subjects authenticate via the custody protocol, not a login",
            ));
        };
        if !identity::grantee_covers(&self.grantee, identity) {
            return Err(invalid("record", "login identity does not match grantee"));
        }
        match holder {
            Some(h) => {
                if !matcher.matches(h) {
                    return Err(invalid("record", "login holder not covered by matcher"));
                }
            }
            None => {
                if matcher.as_str() != "*" {
                    return Err(invalid(
                        "record",
                        "holder matcher cannot be evaluated against a holder-less login",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{
        AudConstraint, Constraints, ConnectionProtocol, DeviceCertClaims, HolderMatcher,
        WarrantClaims, TYP_DEVICE_CERT, TYP_WARRANT, TYP_WARRANT_V2,
    };
    use crate::KeyPair;

    const IAT: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn seed_key(byte: u8) -> KeyPair {
        KeyPair::from_seed(&[byte; 32]).unwrap()
    }
    fn sref(idx: u64) -> Option<StatusRef> {
        Some(StatusRef { uri: "https://browserid.me/.well-known/browserid-status".into(), idx })
    }

    struct Fx {
        idp: KeyPair,
        config_key: KeyPair,
    }
    impl Fx {
        fn new() -> Self {
            Self { idp: seed_key(1), config_key: seed_key(4) }
        }
        fn email(&self) -> &'static str {
            "friend@example.com"
        }
        fn audience(&self) -> &'static str {
            "https://gate.dan.dev/notes"
        }
        fn config_cert(&self, constraints: Option<Constraints>) -> DeviceCert {
            self.config_cert_claims(|c| c.constraints = constraints)
        }
        fn config_cert_claims(&self, edit: impl FnOnce(&mut DeviceCertClaims)) -> DeviceCert {
            let mut claims = DeviceCertClaims {
                typ: TYP_DEVICE_CERT.into(),
                iss: "example.com".into(),
                iat: IAT,
                exp: IAT + 90 * DAY,
                purpose: Purpose::Authorization,
                holder: Holder::new("br.main").unwrap(),
                identities: vec![self.email().into()],
                public_key: self.config_key.public_key(),
                status: sref(2),
                managed: None,
                constraints: None,
            };
            edit(&mut claims);
            DeviceCert::from_claims(claims, &self.idp).unwrap()
        }
        fn connection_warrant(&self) -> Warrant {
            self.warrant(|_| {})
        }
        fn warrant(&self, edit: impl FnOnce(&mut WarrantClaims)) -> Warrant {
            let mut claims = WarrantClaims {
                typ: TYP_WARRANT_V2.into(),
                iat: IAT,
                exp: IAT + 90 * DAY,
                grantor: self.email().into(),
                grantee: self.email().into(),
                holder: None,
                binding: Some(Binding::Connection {
                    protocol: ConnectionProtocol::Oauth,
                    id: "cn_8f3a".into(),
                    client_host: "claude.ai".into(),
                    client_name: "Claude".into(),
                }),
                audience: self.audience().into(),
                scopes: vec!["tool:read_file".into(), "tool:search_files".into()],
                status: sref(168),
            };
            edit(&mut claims);
            Warrant::from_claims(claims, &self.config_key).unwrap()
        }
        fn bundle(&self) -> RecordBundle {
            RecordBundle {
                warrant: self.connection_warrant(),
                config_cert: self.config_cert(None),
            }
        }
        fn idp_pub(&self) -> crate::PublicKey {
            self.idp.public_key()
        }
    }

    #[test]
    fn parse_round_trip_and_shape() {
        let f = Fx::new();
        let encoded = f.bundle().encode();
        let b = RecordBundle::parse(&encoded).unwrap();
        assert_eq!(b.encode(), encoded);
        // Anything but exactly two objects rejects.
        assert!(RecordBundle::parse(&f.connection_warrant().encoded().to_string()).is_err());
        assert!(RecordBundle::parse(&format!("{encoded}~extra")).is_err());
    }

    #[test]
    fn validate_happy_path() {
        let f = Fx::new();
        let v = f.bundle().validate(f.audience(), |iss| {
            assert_eq!(iss, "example.com");
            Ok(f.idp_pub())
        }).unwrap();
        assert_eq!(v.grantor, f.email());
        assert_eq!(v.grantee, f.email());
        assert_eq!(v.grantor_issuer, "example.com");
        assert_eq!(v.scopes.len(), 2);
        match &v.binding {
            Binding::Connection { id, client_host, .. } => {
                assert_eq!(id, "cn_8f3a");
                assert_eq!(client_host, "claude.ai");
            }
            other => panic!("expected connection binding, got {other:?}"),
        }
        // Both refs surfaced for the caller's fail-closed step 1e.
        assert_eq!(v.status_refs().len(), 2);
    }

    #[test]
    fn validate_rejects_wrong_audience() {
        let f = Fx::new();
        assert!(f.bundle().validate("https://other.example", |_| Ok(f.idp_pub())).is_err());
    }

    #[test]
    fn validate_rejects_wrong_signer_and_wrong_idp_key() {
        let f = Fx::new();
        // Warrant signed by a key that is NOT the config cert's.
        let rogue = seed_key(9);
        let b = RecordBundle {
            warrant: {
                let mut w = f.connection_warrant().claims().clone();
                w.scopes = vec!["tool:read_file".into()];
                Warrant::from_claims(w, &rogue).unwrap()
            },
            config_cert: f.config_cert(None),
        };
        assert!(b.validate(f.audience(), |_| Ok(f.idp_pub())).is_err());
        // Config cert that doesn't verify under the resolved IdP key.
        assert!(f.bundle().validate(f.audience(), |_| Ok(rogue.public_key())).is_err());
    }

    #[test]
    fn validate_rejects_wrong_purpose_and_uncovered_grantor() {
        let f = Fx::new();
        let b = RecordBundle {
            warrant: f.connection_warrant(),
            config_cert: f.config_cert_claims(|c| c.purpose = Purpose::Authentication),
        };
        assert!(b.validate(f.audience(), |_| Ok(f.idp_pub())).is_err());
        let b = RecordBundle {
            warrant: f.connection_warrant(),
            config_cert: f.config_cert_claims(|c| c.identities = vec!["someone-else@example.com".into()]),
        };
        assert!(b.validate(f.audience(), |_| Ok(f.idp_pub())).is_err());
    }

    #[test]
    fn validate_enforces_constraints_in_full() {
        let f = Fx::new();
        // Scope allowlist that excludes a warrant scope → reject.
        let c = Constraints {
            aud: None,
            scopes: Some(vec!["tool:read_file".into()]),
            max_ttl: None,
            unknown: Default::default(),
        };
        let b = RecordBundle { warrant: f.connection_warrant(), config_cert: f.config_cert(Some(c)) };
        assert!(b.validate(f.audience(), |_| Ok(f.idp_pub())).is_err());
        // Unknown constraint key → reject fail-closed.
        let mut unknown = std::collections::BTreeMap::new();
        unknown.insert("cosign".to_string(), serde_json::json!("x"));
        let c = Constraints { aud: None, scopes: None, max_ttl: None, unknown };
        let b = RecordBundle { warrant: f.connection_warrant(), config_cert: f.config_cert(Some(c)) };
        assert!(b.validate(f.audience(), |_| Ok(f.idp_pub())).is_err());
        // max-ttl below the record's validity → reject.
        let c = Constraints { aud: None, scopes: None, max_ttl: Some(DAY), unknown: Default::default() };
        let b = RecordBundle { warrant: f.connection_warrant(), config_cert: f.config_cert(Some(c)) };
        assert!(b.validate(f.audience(), |_| Ok(f.idp_pub())).is_err());
        // aud allowlist that permits this audience → pass.
        let salt = "c2FsdHktc2FsdA";
        let c = Constraints {
            aud: Some(AudConstraint {
                salt: salt.into(),
                hashes: vec![AudConstraint::hash_audience(salt, f.audience()).unwrap()],
            }),
            scopes: None,
            max_ttl: None,
            unknown: Default::default(),
        };
        let b = RecordBundle { warrant: f.connection_warrant(), config_cert: f.config_cert(Some(c)) };
        assert!(b.validate(f.audience(), |_| Ok(f.idp_pub())).is_ok());
    }

    #[test]
    fn expiry_is_a_live_bound() {
        let f = Fx::new();
        // Expiry compares against wall-clock now (a live bound), so an expired
        // record needs a genuinely past exp — the fixture IAT is a fixed
        // FUTURE epoch (2027) shared with the golden vectors.
        const PAST_EXP: i64 = 1_600_000_000; // 2020-09-13
        // An expired warrant fails validate AND the per-use re-check.
        let b = RecordBundle {
            warrant: f.warrant(|w| { w.iat = PAST_EXP - DAY; w.exp = PAST_EXP; }),
            config_cert: f.config_cert(None),
        };
        assert!(b.validate(f.audience(), |_| Ok(f.idp_pub())).is_err());
        assert!(b.recheck_live().is_err());
        // An expired config cert likewise.
        let b = RecordBundle {
            warrant: f.connection_warrant(),
            config_cert: f.config_cert_claims(|c| { c.iat = PAST_EXP - DAY; c.exp = PAST_EXP; }),
        };
        assert!(b.validate(f.audience(), |_| Ok(f.idp_pub())).is_err());
        assert!(b.recheck_live().is_err());
        // A live record passes the re-check.
        assert!(f.bundle().recheck_live().is_ok());
    }

    #[test]
    fn v1_record_admits_as_holder_binding() {
        // §6.4 step 1a: v1 is a holder-binding record; its status ref is
        // optional (the ref list just omits it).
        let f = Fx::new();
        let b = RecordBundle {
            warrant: f.warrant(|w| {
                w.typ = TYP_WARRANT.into();
                w.binding = None;
                w.holder = Some(HolderMatcher::new("*").unwrap());
                w.status = None;
            }),
            config_cert: f.config_cert(None),
        };
        let v = b.validate(f.audience(), |_| Ok(f.idp_pub())).unwrap();
        assert!(matches!(v.binding, Binding::Holder { .. }));
        assert_eq!(v.status_refs().len(), 1); // config cert's only
    }

    #[test]
    fn matches_login_holder_path() {
        let f = Fx::new();
        let record = |grantee: &str, matcher: &str| ValidatedRecord {
            grantor: f.email().into(),
            grantee: grantee.into(),
            binding: Binding::Holder { matcher: HolderMatcher::new(matcher).unwrap() },
            scopes: vec![],
            grantor_issuer: "example.com".into(),
            config_status: None,
            warrant_status: None,
        };
        let h = Holder::new("br.main").unwrap();
        // Exact grantee + covering matcher.
        assert!(record(f.email(), "*").matches_login(f.email(), Some(&h)).is_ok());
        assert!(record(f.email(), "br.*").matches_login(f.email(), Some(&h)).is_ok());
        // Identity comparison per §5 (domain case-insensitive, local byte-exact).
        assert!(record(f.email(), "*").matches_login("friend@EXAMPLE.COM", Some(&h)).is_ok());
        assert!(record(f.email(), "*").matches_login("FRIEND@example.com", Some(&h)).is_err());
        // Grantee matchers: permission for anyone matching, never anonymous.
        assert!(record("*@example.com", "*").matches_login("anyone+tag@example.com", Some(&h)).is_ok());
        assert!(record("*@example.com", "*").matches_login("anyone@sub.example.com", Some(&h)).is_err());
        assert!(record("*", "*").matches_login("x@anywhere.example", None).is_ok());
        // Wrong subject, wrong holder.
        assert!(record(f.email(), "*").matches_login("other@example.com", Some(&h)).is_err());
        assert!(record(f.email(), "svc.*").matches_login(f.email(), Some(&h)).is_err());
        // Non-`*` matcher against a holder-less login fails closed; `*` imposes nothing.
        assert!(record(f.email(), "br.*").matches_login(f.email(), None).is_err());
        assert!(record(f.email(), "*").matches_login(f.email(), None).is_ok());
    }

    #[test]
    fn matches_login_rejects_connection_bound_records() {
        let f = Fx::new();
        let v = f.bundle().validate(f.audience(), |_| Ok(f.idp_pub())).unwrap();
        assert!(v.matches_login(f.email(), None).is_err());
    }
}
