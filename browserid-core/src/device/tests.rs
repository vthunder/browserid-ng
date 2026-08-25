//! Unit tests + golden cross-language wire vectors for the device-cert model.
//!
//! The golden vectors (`test-vectors/device-cert-v1.json`) are the FROZEN wire
//! contract that Rust, JS, and PHP (sandmill) must all agree on byte-for-byte.
//! They are generated deterministically here (fixed seeds + fixed timestamps →
//! deterministic Ed25519 JWS). Run `REGEN_VECTORS=1 cargo test -p browserid-core
//! device::tests::golden_vectors` to (re)write the file; the plain test asserts
//! the committed file still verifies + re-generates identically (no drift).

use super::*;
use crate::status::StatusRef;
use serde_json::json;

// Fixed epoch so vectors are reproducible.
const IAT: i64 = 1_800_000_000; // 2027-01-15T08:00:00Z
const DAY: i64 = 86_400;
const HOUR: i64 = 3_600;

fn seed_key(byte: u8) -> KeyPair {
    KeyPair::from_seed(&[byte; 32]).unwrap()
}

fn status(uri: &str, idx: u64) -> Option<StatusRef> {
    Some(StatusRef { uri: uri.to_string(), idx })
}

/// Build a fully valid `access~assertion~warrant~config` presentation with fixed
/// keys/times. `idp` signs the access + config certs; `device` holds the
/// authentication device cert; `access` is the fresh assertion key; `config`
/// signs the warrant.
struct Fixture {
    idp: KeyPair,
    access_key: KeyPair,
    config_key: KeyPair,
    access_constraints: Option<Constraints>,
    config_constraints: Option<Constraints>,
}
impl Fixture {
    fn new() -> Self {
        Self { idp: seed_key(1), access_key: seed_key(3), config_key: seed_key(4), access_constraints: None, config_constraints: None }
    }
    fn idp_domain(&self) -> &'static str {
        "sandmill.org"
    }
    fn email(&self) -> &'static str {
        "danmills@sandmill.org"
    }
    fn audience(&self) -> &'static str {
        "https://mingo.place"
    }

    fn access_cert(&self) -> AccessCert {
        AccessCert::from_claims(
            AccessCertClaims {
                typ: TYP_ACCESS_CERT.into(),
                iss: self.idp_domain().into(),
                iat: IAT,
                exp: IAT + 24 * HOUR,
                identity: self.email().into(),
                holder: Holder::new("br.main").unwrap(),
                access_key: self.access_key.public_key(),
                status: status("https://sandmill.org/.well-known/browserid-status", 7),
                constraints: self.access_constraints.clone(),
            },
            &self.idp,
        )
        .unwrap()
    }
    fn config_cert_signed_by(&self, idp: &KeyPair, iss: &str) -> DeviceCert {
        DeviceCert::from_claims(
            DeviceCertClaims {
                typ: TYP_DEVICE_CERT.into(),
                iss: iss.into(),
                iat: IAT,
                exp: IAT + 90 * DAY,
                purpose: Purpose::Authorization,
                holder: Holder::new("br.main").unwrap(),
                identities: vec![self.email().into()],
                public_key: self.config_key.public_key(),
                status: status("https://sandmill.org/.well-known/browserid-status", 2),
                managed: None,
                constraints: self.config_constraints.clone(),
                prov: None,
            },
            idp,
        )
        .unwrap()
    }
    fn warrant(&self) -> Warrant {
        Warrant::from_claims(
            WarrantClaims {
                typ: TYP_WARRANT.into(),
                iat: IAT,
                exp: IAT + 90 * DAY,
                grantor: self.email().into(),
                grantee: self.email().into(),
                holder: Some(HolderMatcher::new("br.*").unwrap()),
                binding: None,
                audience: self.audience().into(),
                scopes: vec!["login".into()],
                status: status("https://browserid.me/.well-known/browserid-status", 42),
                unknown: Default::default(),
            },
            &self.config_key,
        )
        .unwrap()
    }
    fn assertion(&self) -> Assertion {
        // Assertion::create uses Utc::now; build via the fresh access key with a
        // far-future expiry so the vector doesn't age out.
        use crate::assertion::AssertionClaims;
        // Assertion has no from_claims; sign the 2-claim JWS directly is internal,
        // so create() then override is not possible — use create() with a long
        // validity from a fixed "now" is also not possible. Instead, the assertion
        // is the one non-deterministic-time object; vectors pin the OTHER three and
        // the assertion is regenerated live (its exp is checked, not byte-frozen).
        let _ = AssertionClaims { exp: 0, aud: String::new(), req_origin: None }; // keep import honest
        Assertion::create(self.audience(), chrono::Duration::days(3650), &self.access_key).unwrap()
    }
    fn presentation(&self) -> AccessPresentation {
        AccessPresentation {
            access_cert: self.access_cert(),
            assertion: self.assertion(),
            warrant: self.warrant(),
            config_cert: self.config_cert_signed_by(&self.idp, self.idp_domain()),
        }
    }
}

// --- unit tests -----------------------------------------------------------

#[test]
fn full_user_login_roundtrip() {
    let f = Fixture::new();
    let pres = AccessPresentation::parse(&f.presentation().encode()).unwrap();
    let idp_pub = f.idp.public_key();
    let v = pres.verify(f.audience(), |iss| {
        assert_eq!(iss, f.idp_domain());
        Ok(idp_pub.clone())
    }).unwrap();
    assert_eq!(v.email, f.email());
    assert_eq!(v.holder.as_str(), "br.main");
    assert_eq!(v.scopes, vec!["login".to_string()]);
    // All three revocation refs surfaced for the caller to check fail-closed.
    assert!(v.access_status.is_some() && v.config_status.is_some() && v.warrant_status.is_some());
}

#[test]
fn config_cert_from_rogue_idp_is_rejected() {
    // The privilege-escalation fix: a config cert signed by a DIFFERENT IdP than
    // the access cert (a rogue authorization cert) must be rejected.
    let f = Fixture::new();
    let rogue_idp = seed_key(9);
    let pres = AccessPresentation {
        access_cert: f.access_cert(),
        assertion: f.assertion(),
        warrant: f.warrant(),
        config_cert: f.config_cert_signed_by(&rogue_idp, "evil.example"),
    };
    // Even if the resolver would hand back a key for evil.example, the iss mismatch
    // against the access cert is caught first.
    let idp_pub = f.idp.public_key();
    assert!(pres.verify(f.audience(), |_| Ok(idp_pub.clone())).is_err());
}

#[test]
fn wrong_audience_rejected() {
    let f = Fixture::new();
    let idp_pub = f.idp.public_key();
    assert!(f.presentation().verify("https://evil.example", |_| Ok(idp_pub.clone())).is_err());
}

#[test]
fn config_not_authorized_for_identity_rejected() {
    let f = Fixture::new();
    // Config cert authorizes a different identity.
    let cc = DeviceCert::from_claims(
        DeviceCertClaims {
            typ: TYP_DEVICE_CERT.into(), iss: f.idp_domain().into(), iat: IAT, exp: IAT + 90 * DAY,
            purpose: Purpose::Authorization, holder: Holder::new("br.main").unwrap(),
            identities: vec!["someone-else@sandmill.org".into()],
            public_key: f.config_key.public_key(), status: None, managed: None, constraints: None, prov: None,
        },
        &f.idp,
    ).unwrap();
    let pres = AccessPresentation { access_cert: f.access_cert(), assertion: f.assertion(), warrant: f.warrant(), config_cert: cc };
    let idp_pub = f.idp.public_key();
    assert!(pres.verify(f.audience(), |_| Ok(idp_pub.clone())).is_err());
}

#[test]
fn authentication_purpose_config_cert_rejected() {
    // A config cert must be `authorization` purpose, not `authentication`.
    let f = Fixture::new();
    let cc = DeviceCert::from_claims(
        DeviceCertClaims {
            typ: TYP_DEVICE_CERT.into(), iss: f.idp_domain().into(), iat: IAT, exp: IAT + 90 * DAY,
            purpose: Purpose::Authentication, holder: Holder::new("br.main").unwrap(),
            identities: vec![f.email().into()], public_key: f.config_key.public_key(), status: None, managed: None, constraints: None, prov: None,
        },
        &f.idp,
    ).unwrap();
    let pres = AccessPresentation { access_cert: f.access_cert(), assertion: f.assertion(), warrant: f.warrant(), config_cert: cc };
    let idp_pub = f.idp.public_key();
    assert!(pres.verify(f.audience(), |_| Ok(idp_pub.clone())).is_err());
}

#[test]
fn unknown_purpose_fails_closed() {
    // serde rejects unknown enum variants → parse fails (fail-closed).
    assert!(serde_json::from_value::<Purpose>(json!("frobnicate")).is_err());
    assert!(serde_json::from_value::<Purpose>(json!("authentication")).is_ok());
}

#[test]
fn holder_validation_fails_closed() {
    // A holder / matcher is an opaque string, but empty or over-long is rejected
    // at parse (fail-closed), and any well-formed string round-trips.
    assert!(serde_json::from_value::<Holder>(json!("")).is_err());
    assert!(serde_json::from_value::<Holder>(json!("br.main")).is_ok());
    let too_long = "x".repeat(HOLDER_MAX_BYTES + 1);
    assert!(serde_json::from_value::<Holder>(json!(too_long)).is_err());
    assert!(serde_json::from_value::<HolderMatcher>(json!("br.*")).is_ok());
    assert!(serde_json::from_value::<HolderMatcher>(json!("")).is_err());
}

#[test]
fn holder_matcher_semantics() {
    let m = |s: &str| HolderMatcher::new(s).unwrap();
    let h = |s: &str| Holder::new(s).unwrap();
    // `*` — any holder.
    assert!(m("*").matches(&h("br.main")));
    assert!(m("*").matches(&h("svc.mingo-poster")));
    // `<ns>.*` — same namespace only; a shared char-prefix does NOT match.
    assert!(m("br.*").matches(&h("br.main")));
    assert!(m("br.*").matches(&h("br.phone")));
    assert!(!m("br.*").matches(&h("brx.main")));
    assert!(!m("br.*").matches(&h("svc.main")));
    // `<id>` — exact holder only.
    assert!(m("svc.mingo-poster").matches(&h("svc.mingo-poster")));
    assert!(!m("svc.mingo-poster").matches(&h("svc.other")));
    assert!(!m("br.main").matches(&h("br.other")));
}

/// Checkpoint (build-sequence stage 1): the mint copies the device cert's holder
/// verbatim into the access cert, and a warrant matcher joins against it. This
/// is the passthrough+copy conformance property the isolation guarantee rests on.
#[test]
fn holder_passthrough_copy_and_isolation() {
    let f = Fixture::new();
    // The access cert carries exactly the device cert's holder (copied at mint).
    assert_eq!(f.access_cert().claims().holder, f.auth_device_cert_claims().holder);

    // Isolation: a warrant scoped to a DIFFERENT specific holder does not verify,
    // even though identity + audience match — the matcher rejects the holder.
    let isolated = Warrant::from_claims(
        WarrantClaims {
            typ: TYP_WARRANT.into(), iat: IAT, exp: IAT + 90 * DAY,
            grantor: f.email().into(),
            grantee: f.email().into(),
            holder: Some(HolderMatcher::new("svc.some-other-service").unwrap()), binding: None,
            audience: f.audience().into(), scopes: vec!["login".into()], status: None,
            unknown: Default::default(),
        },
        &f.config_key,
    ).unwrap();
    let pres = AccessPresentation {
        access_cert: f.access_cert(), assertion: f.assertion(),
        warrant: isolated, config_cert: f.config_cert_signed_by(&f.idp, f.idp_domain()),
    };
    let idp_pub = f.idp.public_key();
    assert!(pres.verify(f.audience(), |_| Ok(idp_pub.clone())).is_err());
}

// --- golden cross-language vectors ----------------------------------------

/// Deterministic tokens (fixed seed + fixed times) for cross-language checks.
/// The three certs/warrant are byte-frozen; the assertion is time-live (its exp
/// is verified, not frozen).
#[test]
fn golden_vectors() {
    let f = Fixture::new();
    let access_cert = f.access_cert();
    let config_cert = f.config_cert_signed_by(&f.idp, f.idp_domain());
    let warrant = f.warrant();

    let vectors = json!({
        "version": "device-cert-v1",
        "note": "Frozen wire vectors. The `jws` field of each object is AUTHORITATIVE — a conformant impl (Rust/JS/PHP) signing the same claims with the same seed key MUST reproduce that exact JWS string. To learn the canonical signed bytes, base64url-DECODE the jws payload: field order is struct-declaration order, compact JSON, no whitespace. The `claims` objects below are alphabetically SORTED for human readability and are NOT the signed byte order — do not sign them as shown. Ed25519 (RFC 8032) signatures are deterministic, so the JWS is reproducible.",
        "keys": {
            "idp_seed_b64": base64_seed(1),
            "idp_pub": f.idp.public_key().to_base64(),
            "config_key_seed_b64": base64_seed(4),
            "config_pub": f.config_key.public_key().to_base64(),
            "access_key_seed_b64": base64_seed(3),
            "access_pub": f.access_key.public_key().to_base64(),
        },
        "device_cert_authentication_example": {
            "claims": serde_json::to_value(f.auth_device_cert_claims()).unwrap(),
            "jws": DeviceCert::from_claims(f.auth_device_cert_claims(), &f.idp).unwrap().encoded(),
        },
        "access_cert": { "claims": serde_json::to_value(access_cert.claims()).unwrap(), "jws": access_cert.encoded() },
        "config_cert": { "claims": serde_json::to_value(config_cert.claims()).unwrap(), "jws": config_cert.encoded() },
        "warrant": { "claims": serde_json::to_value(warrant.claims()).unwrap(), "jws": warrant.encoded() },
        "accept": {
            "audience": f.audience(),
            "expect": { "email": f.email(), "holder": "br.main", "scopes": ["login"] }
        },
        "reject_cases": [
            "warrant grantee does not equal the access cert identity",
            "config cert not authoritative for the warrant grantor",
            "config cert with purpose=authentication",
            "access cert holder not covered by the warrant's holder matcher",
            "audience mismatch",
            "unknown purpose value, or an empty/over-long holder or matcher"
        ]
    });

    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/device-cert-v1.json");
    let pretty = serde_json::to_string_pretty(&vectors).unwrap();
    if std::env::var("REGEN_VECTORS").is_ok() {
        std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors")).unwrap();
        std::fs::write(path, &pretty).unwrap();
    } else if let Ok(committed) = std::fs::read_to_string(path) {
        // No drift: committed vectors must match a fresh deterministic generation.
        assert_eq!(committed.trim_end(), pretty.trim_end(), "golden vectors drifted — run REGEN_VECTORS=1");
    }

    // And the frozen tokens must still verify as a presentation (live assertion).
    let pres = AccessPresentation {
        access_cert: AccessCert::parse(access_cert.encoded()).unwrap(),
        assertion: f.assertion(),
        warrant: Warrant::parse(warrant.encoded()).unwrap(),
        config_cert: DeviceCert::parse(config_cert.encoded()).unwrap(),
    };
    let idp_pub = f.idp.public_key();
    pres.verify(f.audience(), |_| Ok(idp_pub.clone())).unwrap();
}

fn base64_seed(byte: u8) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 32])
}

impl Fixture {
    fn auth_device_cert_claims(&self) -> DeviceCertClaims {
        DeviceCertClaims {
            typ: TYP_DEVICE_CERT.into(),
            iss: self.idp_domain().into(),
            iat: IAT,
            exp: IAT + 90 * DAY,
            purpose: Purpose::Authentication,
            holder: Holder::new("br.main").unwrap(),
            identities: vec![self.email().into()],
            public_key: seed_key(2).public_key(),
            status: status("https://sandmill.org/.well-known/browserid-status", 1),
            managed: None,
            constraints: None, prov: None,
        }
    }
}

/// RFC-style subaddressing as a protocol rule: a cert naming the BASE identity
/// authorizes its `+tag` sub-addresses — no glob needed — while never matching
/// a different local part, a bare-vs-base mixup, or a foreign domain.
#[test]
fn base_identity_authorizes_subaddresses() {
    assert!(super::identity_matches("dan@mingo.place", "dan+claude@mingo.place"));
    assert!(super::identity_matches("dan@mingo.place", "dan+a+b@mingo.place"));
    // Exact still matches; the base never matches a DIFFERENT base.
    assert!(super::identity_matches("dan@mingo.place", "dan@mingo.place"));
    assert!(!super::identity_matches("dan@mingo.place", "daniel@mingo.place"));
    assert!(!super::identity_matches("dan@mingo.place", "danny+x@mingo.place"));
    // A sub-address does NOT authorize its base or siblings (only the base
    // implies downward, never upward/sideways).
    assert!(!super::identity_matches("dan+claude@mingo.place", "dan@mingo.place"));
    assert!(!super::identity_matches("dan+claude@mingo.place", "dan+other@mingo.place"));
    // Domain must match exactly.
    assert!(!super::identity_matches("dan@mingo.place", "dan+x@evil.place"));
    // Degenerate empty tag ("dan+@") matches the base rule — harmless: the
    // warrant identifier still pins the exact presentable identity.
    assert!(super::identity_matches("dan@mingo.place", "dan+@mingo.place"));
}

// --- constraints & managed identities (spec §4.7, §6.1 step 7) -------------

fn aud_allow(audiences: &[&str]) -> AudConstraint {
    let salt = "c2FsdHktc2FsdA"; // b64url("salty-salt")
    AudConstraint {
        salt: salt.into(),
        hashes: audiences
            .iter()
            .map(|a| AudConstraint::hash_audience(salt, a).unwrap())
            .collect(),
    }
}

fn constraints(
    aud: Option<AudConstraint>,
    scopes: Option<Vec<String>>,
    max_ttl: Option<i64>,
) -> Constraints {
    Constraints { aud, scopes, max_ttl, unknown: Default::default() }
}

#[test]
fn constraints_satisfied_passes() {
    let mut f = Fixture::new();
    f.access_constraints = Some(constraints(
        Some(aud_allow(&[f.audience(), "https://other.example"])),
        Some(vec!["login".into(), "post".into()]),
        Some(91 * DAY),
    ));
    let idp_pub = f.idp.public_key();
    let v = f.presentation().verify(f.audience(), |_| Ok(idp_pub.clone())).unwrap();
    assert_eq!(v.email, f.email());
}

#[test]
fn constraints_audience_not_allowed_rejects() {
    let mut f = Fixture::new();
    f.access_constraints =
        Some(constraints(Some(aud_allow(&["https://only-this.example"])), None, None));
    let idp_pub = f.idp.public_key();
    let err = f.presentation().verify(f.audience(), |_| Ok(idp_pub.clone())).unwrap_err();
    assert!(err.to_string().contains("audience not permitted"), "{err}");
}

#[test]
fn constraints_scope_outside_allowlist_rejects() {
    // warrant carries scope "login"; allowlist permits only "post".
    let mut f = Fixture::new();
    f.access_constraints = Some(constraints(None, Some(vec!["post".into()]), None));
    let idp_pub = f.idp.public_key();
    let err = f.presentation().verify(f.audience(), |_| Ok(idp_pub.clone())).unwrap_err();
    assert!(err.to_string().contains("scope 'login' not permitted"), "{err}");
}

#[test]
fn constraints_max_ttl_exceeded_rejects() {
    // warrant is 90 days; cap at 1 day.
    let mut f = Fixture::new();
    f.access_constraints = Some(constraints(None, None, Some(DAY)));
    let idp_pub = f.idp.public_key();
    let err = f.presentation().verify(f.audience(), |_| Ok(idp_pub.clone())).unwrap_err();
    assert!(err.to_string().contains("max-ttl"), "{err}");
}

#[test]
fn constraints_on_config_cert_enforced_too() {
    let mut f = Fixture::new();
    f.config_constraints =
        Some(constraints(Some(aud_allow(&["https://elsewhere.example"])), None, None));
    let idp_pub = f.idp.public_key();
    let err = f.presentation().verify(f.audience(), |_| Ok(idp_pub.clone())).unwrap_err();
    assert!(err.to_string().contains("config cert"), "{err}");
}

#[test]
fn unknown_constraint_key_rejects_fail_closed() {
    // A constraint vocabulary this build does not implement MUST reject —
    // a restriction ignored is a restriction escaped (spec §4.7).
    let mut unknown = std::collections::BTreeMap::new();
    unknown.insert("delegation".to_string(), serde_json::json!("none"));
    let mut f = Fixture::new();
    f.access_constraints = Some(Constraints { aud: None, scopes: None, max_ttl: None, unknown });
    let idp_pub = f.idp.public_key();
    let err = f.presentation().verify(f.audience(), |_| Ok(idp_pub.clone())).unwrap_err();
    assert!(err.to_string().contains("unrecognized constraint key"), "{err}");
}

#[test]
fn unknown_constraint_key_survives_wire_roundtrip() {
    // serde must CAPTURE unknown keys (flatten), not drop them — else a
    // re-encoded cert would silently shed the very restriction that should
    // fail it closed.
    let mut unknown = std::collections::BTreeMap::new();
    unknown.insert("cosign".to_string(), serde_json::json!({"endpoint": "/x"}));
    let c = Constraints { aud: None, scopes: None, max_ttl: Some(3600), unknown };
    let wire = serde_json::to_string(&c).unwrap();
    let back: Constraints = serde_json::from_str(&wire).unwrap();
    assert_eq!(back.unknown.len(), 1);
    assert!(back.unknown.contains_key("cosign"));
    assert_eq!(back.max_ttl, Some(3600));
}

#[test]
fn managed_marker_roundtrips_and_absent_stays_absent() {
    let f = Fixture::new();
    let mut claims = f.auth_device_cert_claims();
    claims.managed = Some(true);
    let cert = DeviceCert::from_claims(claims, &f.idp).unwrap();
    let parsed = DeviceCert::parse(cert.encoded()).unwrap();
    assert_eq!(parsed.claims().managed, Some(true));
    // Unmanaged wire form carries NO managed key at all (consumer certs
    // byte-identical to pre-§4.7 builds).
    let plain = DeviceCert::from_claims(f.auth_device_cert_claims(), &f.idp).unwrap();
    let payload = plain.encoded().split('.').nth(1).unwrap();
    use base64::Engine;
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    assert!(!String::from_utf8(json).unwrap().contains("managed"));
}

#[test]
fn access_request_audience_roundtrips() {
    let f = Fixture::new();
    let device_key = seed_key(9);
    let req = AccessRequest::create_for_audience(
        f.idp_domain(),
        f.email(),
        Holder::new("br.main").unwrap(),
        &f.access_key.public_key(),
        "jti-1",
        f.audience(),
        &device_key,
    )
    .unwrap();
    let parsed = AccessRequest::parse(req.encoded()).unwrap();
    assert_eq!(parsed.claims().audience.as_deref(), Some(f.audience()));
    // The default constructor stays audience-free (RP-blind).
    let plain = AccessRequest::create(
        f.idp_domain(),
        f.email(),
        Holder::new("br.main").unwrap(),
        &f.access_key.public_key(),
        "jti-2",
        &device_key,
    )
    .unwrap();
    assert!(plain.claims().audience.is_none());
}

// --- warrant v2 (spec §5, §6.1 steps 1+6, §6.6) ----------------------------

impl Fixture {
    /// A well-formed v2 holder-binding warrant (the v2 twin of `warrant()`).
    fn warrant_v2(&self) -> Warrant {
        self.warrant_v2_with(self.email(), Binding::Holder { matcher: HolderMatcher::new("br.*").unwrap() })
    }
    fn warrant_v2_with(&self, grantee: &str, binding: Binding) -> Warrant {
        Warrant::from_claims(
            WarrantClaims {
                typ: TYP_WARRANT_V2.into(),
                iat: IAT,
                exp: IAT + 90 * DAY,
                grantor: self.email().into(),
                grantee: grantee.into(),
                holder: None,
                binding: Some(binding.into()),
                audience: self.audience().into(),
                scopes: vec!["login".into()],
                status: status("https://browserid.me/.well-known/browserid-status", 43),
                unknown: Default::default(),
            },
            &self.config_key,
        )
        .unwrap()
    }
    fn connection_binding(&self) -> Binding {
        Binding::Connection {
            protocol: ConnectionProtocol::Oauth,
            id: "cn_8f3a".into(),
            client_host: "claude.ai".into(),
            client_name: "Claude".into(),
        }
    }
}

#[test]
fn v2_holder_binding_presentation_verifies() {
    let f = Fixture::new();
    let pres = AccessPresentation {
        access_cert: f.access_cert(),
        assertion: f.assertion(),
        warrant: Warrant::parse(f.warrant_v2().encoded()).unwrap(),
        config_cert: f.config_cert_signed_by(&f.idp, f.idp_domain()),
    };
    let idp_pub = f.idp.public_key();
    let v = pres.verify(f.audience(), |_| Ok(idp_pub.clone())).unwrap();
    assert_eq!(v.email, f.email());
    assert!(v.warrant_status.is_some());
}

#[test]
fn v2_parse_shape_matrix() {
    let f = Fixture::new();
    // Well-formed v2 (holder + connection) parse.
    assert!(Warrant::parse(f.warrant_v2().encoded()).is_ok());
    let conn = f.warrant_v2_with(f.email(), f.connection_binding());
    assert!(Warrant::parse(conn.encoded()).is_ok());

    let base = f.warrant_v2().claims().clone();
    let sign = |c: &WarrantClaims| Warrant::from_claims(c.clone(), &f.config_key).unwrap().encoded().to_string();

    // v2 without status rejects (REQUIRED, §5).
    let mut c = base.clone();
    c.status = None;
    assert!(Warrant::parse(&sign(&c)).is_err());
    // v2 without binding rejects.
    let mut c = base.clone();
    c.binding = None;
    assert!(Warrant::parse(&sign(&c)).is_err());
    // v2 with a top-level holder matcher rejects (v1 claim in a v2 record).
    let mut c = base.clone();
    c.holder = Some(HolderMatcher::new("br.*").unwrap());
    assert!(Warrant::parse(&sign(&c)).is_err());
    // v1 with a binding rejects (ambiguous hybrid).
    let mut c = base.clone();
    c.typ = TYP_WARRANT.into();
    c.holder = Some(HolderMatcher::new("br.*").unwrap());
    assert!(Warrant::parse(&sign(&c)).is_err());
    // Unknown typ rejects.
    let mut c = base.clone();
    c.typ = "browserid-warrant-v3".into();
    assert!(Warrant::parse(&sign(&c)).is_err());
    // Grantor is never a matcher (§6.6 invariant 6).
    for bad_grantor in ["*", "*@sandmill.org", "not-an-email"] {
        let mut c = base.clone();
        c.grantor = bad_grantor.into();
        assert!(Warrant::parse(&sign(&c)).is_err(), "grantor '{bad_grantor}' must reject");
    }
    // Connection must be a self-grant (§5).
    let mut c = base.clone();
    c.binding = Some(f.connection_binding().into());
    c.grantee = "other@sandmill.org".into();
    assert!(Warrant::parse(&sign(&c)).is_err());
    // Connection with empty id / client_host rejects.
    let mut c = base.clone();
    c.binding = Some(Binding::Connection { protocol: ConnectionProtocol::Oauth, id: "".into(), client_host: "claude.ai".into(), client_name: "Claude".into() }.into());
    assert!(Warrant::parse(&sign(&c)).is_err());
    let mut c = base.clone();
    c.binding = Some(Binding::Connection { protocol: ConnectionProtocol::Oauth, id: "cn_1".into(), client_host: "".into(), client_name: "Claude".into() }.into());
    assert!(Warrant::parse(&sign(&c)).is_err());
}

#[test]
fn unknown_binding_kind_and_protocol_fail_closed() {
    let f = Fixture::new();
    // Sign raw claims carrying an unimplemented kind / protocol: serde rejects
    // the unknown variant at decode, so the record rejects at parse (§5).
    let mut raw = serde_json::to_value(f.warrant_v2().claims()).unwrap();
    raw["binding"] = json!({"kind": "biometric", "template": "x"});
    let jws = crate::jws::jws_sign(&raw, &f.config_key).unwrap();
    assert!(Warrant::parse(&jws).is_err());

    let mut raw = serde_json::to_value(f.warrant_v2().claims()).unwrap();
    raw["binding"] = json!({"kind": "connection", "protocol": "saml", "id": "cn_1", "client_host": "h.example", "client_name": "H"});
    let jws = crate::jws::jws_sign(&raw, &f.config_key).unwrap();
    assert!(Warrant::parse(&jws).is_err());
}

#[test]
fn connection_bound_record_cannot_present() {
    // §6.6 invariant 1: admission-only records never verify in a bundle.
    let f = Fixture::new();
    let pres = AccessPresentation {
        access_cert: f.access_cert(),
        assertion: f.assertion(),
        warrant: f.warrant_v2_with(f.email(), f.connection_binding()),
        config_cert: f.config_cert_signed_by(&f.idp, f.idp_domain()),
    };
    let idp_pub = f.idp.public_key();
    let err = pres.verify(f.audience(), |_| Ok(idp_pub.clone())).unwrap_err();
    assert!(err.to_string().contains("admission-only"), "{err}");
}

#[test]
fn matcher_grantee_record_cannot_present() {
    // §6.6 invariant 1: a glob in P would transfer attribution to unknown actors.
    let f = Fixture::new();
    for grantee in ["*", "*@sandmill.org"] {
        let pres = AccessPresentation {
            access_cert: f.access_cert(),
            assertion: f.assertion(),
            warrant: f.warrant_v2_with(grantee, Binding::Holder { matcher: HolderMatcher::new("*").unwrap() }),
            config_cert: f.config_cert_signed_by(&f.idp, f.idp_domain()),
        };
        let idp_pub = f.idp.public_key();
        let err = pres.verify(f.audience(), |_| Ok(idp_pub.clone())).unwrap_err();
        assert!(err.to_string().contains("matcher-grantee"), "{err}");
    }
}

#[test]
fn presentation_join_uses_spec_identity_comparison() {
    // §6.1 step 6 compares grantee == access identity per §5: domain
    // case-insensitive (A-label), local part byte-exact.
    let f = Fixture::new();
    let idp_pub = f.idp.public_key();
    let ok = AccessPresentation {
        access_cert: f.access_cert(),
        assertion: f.assertion(),
        warrant: f.warrant_v2_with("danmills@SANDMILL.ORG", Binding::Holder { matcher: HolderMatcher::new("br.*").unwrap() }),
        config_cert: f.config_cert_signed_by(&f.idp, f.idp_domain()),
    };
    ok.verify(f.audience(), |_| Ok(idp_pub.clone())).unwrap();

    let bad = AccessPresentation {
        access_cert: f.access_cert(),
        assertion: f.assertion(),
        warrant: f.warrant_v2_with("DANMILLS@sandmill.org", Binding::Holder { matcher: HolderMatcher::new("br.*").unwrap() }),
        config_cert: f.config_cert_signed_by(&f.idp, f.idp_domain()),
    };
    assert!(bad.verify(f.audience(), |_| Ok(idp_pub.clone())).is_err());
}

#[test]
fn v1_normalizes_to_holder_binding() {
    let f = Fixture::new();
    let w = Warrant::parse(f.warrant().encoded()).unwrap();
    match w.claims().binding_set().entries() {
        [Binding::Holder { matcher }] => assert_eq!(matcher.as_str(), "br.*"),
        other => panic!("v1 must read as a one-entry holder set, got {other:?}"),
    }
    assert_eq!(w.claims().holder_matcher().unwrap().as_str(), "br.*");
}

#[test]
fn create_v2_signing_surface_refuses_malformed() {
    // §6.6 invariants 3+4 at the signing surface.
    let f = Fixture::new();
    let st = || StatusRef { uri: "https://browserid.me/.well-known/browserid-status".into(), idx: 9 };
    // Non-self-grant connection refused.
    assert!(Warrant::create_v2(
        f.email(), "other@sandmill.org", f.connection_binding(), f.audience(),
        vec![], chrono::Duration::days(90), &f.config_key, st(),
    ).is_err());
    // Well-formed v2 mints and round-trips through parse.
    let w = Warrant::create_v2(
        f.email(), f.email(), f.connection_binding(), f.audience(),
        vec!["tool:read_file".into()], chrono::Duration::days(90), &f.config_key, st(),
    ).unwrap();
    let parsed = Warrant::parse(w.encoded()).unwrap();
    assert_eq!(parsed.claims().typ, TYP_WARRANT_V2);
    assert!(parsed.claims().status.is_some());
}

#[test]
fn binding_wire_shape_matches_spec() {
    // Pin the §5 wire example: {"kind":"connection","protocol":"oauth",...} /
    // {"kind":"holder","matcher":...}.
    let f = Fixture::new();
    let conn = serde_json::to_value(f.connection_binding()).unwrap();
    assert_eq!(
        conn,
        json!({"kind": "connection", "protocol": "oauth", "id": "cn_8f3a",
               "client_host": "claude.ai", "client_name": "Claude"})
    );
    let holder = serde_json::to_value(Binding::Holder { matcher: HolderMatcher::new("br.*").unwrap() }).unwrap();
    assert_eq!(holder, json!({"kind": "holder", "matcher": "br.*"}));
}

// --- binding sets, requester channel, scope entries (spec §5 amendment,
// --- 2026-08-25: signing grants) ---------------------------------------------

impl Fixture {
    /// A signing-grant-shaped v2 record: self-grant, {holder, requester} set,
    /// parameterized scopes.
    fn signing_grant(&self) -> Warrant {
        self.signing_grant_with(|_| {})
    }
    fn signing_grant_with(&self, edit: impl FnOnce(&mut WarrantClaims)) -> Warrant {
        let mut claims = WarrantClaims {
            typ: TYP_WARRANT_V2.into(),
            iat: IAT,
            exp: IAT + 90 * DAY,
            grantor: self.email().into(),
            grantee: self.email().into(),
            holder: None,
            binding: Some(BindingSet::Many(vec![
                Binding::Holder { matcher: HolderMatcher::new("br.*").unwrap() },
                Binding::Requester { origin: "https://mingo.example".into() },
            ])),
            audience: self.audience().into(),
            scopes: vec![
                "sign:sbo:post".into(),
                ScopeEntry::Parameterized(ScopeParams {
                    scope: "sign:sbo:delete".into(),
                    mode: Some(ScopeMode::Prompt),
                }),
            ],
            status: status("https://browserid.me/.well-known/browserid-status", 171),
            unknown: Default::default(),
        };
        edit(&mut claims);
        Warrant::from_claims(claims, &self.config_key).unwrap()
    }
    fn stamped_assertion(&self, req_origin: Option<&str>) -> Assertion {
        Assertion::create_with_req_origin(
            self.audience(),
            req_origin,
            chrono::Duration::days(3650),
            &self.access_key,
        )
        .unwrap()
    }
}

#[test]
fn binding_set_wire_shapes() {
    let f = Fixture::new();
    // Singular shorthand round-trips byte-identical (deployed records).
    let single = f.warrant_v2();
    let reparsed = Warrant::parse(single.encoded()).unwrap();
    assert_eq!(reparsed.encoded(), single.encoded());
    assert!(!reparsed.claims().binding.as_ref().unwrap().is_set_form());
    // Array form parses, and serializes as an array.
    let set = f.signing_grant();
    let reparsed = Warrant::parse(set.encoded()).unwrap();
    assert!(reparsed.claims().binding.as_ref().unwrap().is_set_form());
    assert_eq!(reparsed.claims().binding_set().entries().len(), 2);
    let raw = serde_json::to_value(reparsed.claims()).unwrap();
    assert!(raw["binding"].is_array());
    // The requester entry's wire shape matches the spec example.
    assert_eq!(
        raw["binding"][1],
        json!({"kind": "requester", "origin": "https://mingo.example"})
    );
    // Scope entries: bare string + parameterized object.
    assert_eq!(raw["scopes"][0], json!("sign:sbo:post"));
    assert_eq!(raw["scopes"][1], json!({"scope": "sign:sbo:delete", "mode": "prompt"}));
}

#[test]
fn binding_set_shape_matrix() {
    let f = Fixture::new();
    let sign = |c: &WarrantClaims| {
        Warrant::from_claims(c.clone(), &f.config_key).unwrap().encoded().to_string()
    };
    let base = f.signing_grant().claims().clone();

    // Empty set rejects.
    let mut c = base.clone();
    c.binding = Some(BindingSet::Many(vec![]));
    assert!(Warrant::parse(&sign(&c)).is_err());
    // Multi-entry on a delegated record rejects (§6.6 invariant 10).
    let mut c = base.clone();
    c.grantee = "other@sandmill.org".into();
    assert!(Warrant::parse(&sign(&c)).is_err());
    // A singular requester entry on a delegated record rejects too (delegated
    // records carry exactly one HOLDER entry).
    let mut c = base.clone();
    c.grantee = "other@sandmill.org".into();
    c.binding = Some(Binding::Requester { origin: "https://mingo.example".into() }.into());
    assert!(Warrant::parse(&sign(&c)).is_err());
    // Dead paper rejects: {requester} alone (no op), {requester, connection}.
    let mut c = base.clone();
    c.binding = Some(Binding::Requester { origin: "https://mingo.example".into() }.into());
    assert!(Warrant::parse(&sign(&c)).is_err());
    let mut c = base.clone();
    c.binding = Some(BindingSet::Many(vec![
        Binding::Requester { origin: "https://mingo.example".into() },
        Binding::Connection {
            protocol: ConnectionProtocol::Oauth,
            id: "cn_1".into(),
            client_host: "claude.ai".into(),
            client_name: "Claude".into(),
        },
    ]));
    assert!(Warrant::parse(&sign(&c)).is_err());
    // {holder, connection} is admissible paper (op A) — parses.
    let mut c = base.clone();
    c.binding = Some(BindingSet::Many(vec![
        Binding::Holder { matcher: HolderMatcher::new("*").unwrap() },
        Binding::Connection {
            protocol: ConnectionProtocol::Oauth,
            id: "cn_1".into(),
            client_host: "claude.ai".into(),
            client_name: "Claude".into(),
        },
    ]));
    assert!(Warrant::parse(&sign(&c)).is_ok());
    // Malformed requester origins reject.
    for bad in ["", "mingo.example", "https://", "https://mingo.example/path", "ftp://x"] {
        let mut c = base.clone();
        c.binding = Some(BindingSet::Many(vec![
            Binding::Holder { matcher: HolderMatcher::new("*").unwrap() },
            Binding::Requester { origin: bad.into() },
        ]));
        assert!(Warrant::parse(&sign(&c)).is_err(), "origin '{bad}' must reject");
    }
}

#[test]
fn unknown_entry_fields_and_scope_params_fail_closed() {
    let f = Fixture::new();
    let mut raw = serde_json::to_value(f.signing_grant().claims()).unwrap();
    // Unknown field inside a known binding kind rejects (invariant 14).
    raw["binding"][1]["extra"] = json!("x");
    assert!(serde_json::from_value::<WarrantClaims>(raw.clone()).is_err());
    // Unknown scope parameter rejects.
    let mut raw = serde_json::to_value(f.signing_grant().claims()).unwrap();
    raw["scopes"][1] = json!({"scope": "sign:sbo:delete", "count": 5});
    assert!(serde_json::from_value::<WarrantClaims>(raw).is_err());
    // Unknown mode value rejects.
    let mut raw = serde_json::to_value(f.signing_grant().claims()).unwrap();
    raw["scopes"][1] = json!({"scope": "sign:sbo:delete", "mode": "sometimes"});
    assert!(serde_json::from_value::<WarrantClaims>(raw).is_err());
}

#[test]
fn unknown_claims_reject_on_set_form_only() {
    let f = Fixture::new();
    let sign_raw = |raw: &serde_json::Value| {
        let claims: WarrantClaims = serde_json::from_value(raw.clone()).unwrap();
        Warrant::from_claims(claims, &f.config_key).unwrap().encoded().to_string()
    };
    // A set-form record carrying an unknown claim rejects (invariant 14).
    let mut raw = serde_json::to_value(f.signing_grant().claims()).unwrap();
    raw["future_claim"] = json!(true);
    assert!(Warrant::parse(&sign_raw(&raw)).is_err());
    // A pre-amendment (singular) record keeps the ignore-unknown behavior.
    let mut raw = serde_json::to_value(f.warrant_v2().claims()).unwrap();
    raw["future_claim"] = json!(true);
    assert!(Warrant::parse(&sign_raw(&raw)).is_ok());
}

#[test]
fn signing_grant_presentation_requires_matching_req_origin() {
    let f = Fixture::new();
    let idp_pub = f.idp.public_key();
    let pres = |assertion: Assertion| AccessPresentation {
        access_cert: f.access_cert(),
        assertion,
        warrant: Warrant::parse(f.signing_grant().encoded()).unwrap(),
        config_cert: f.config_cert_signed_by(&f.idp, f.idp_domain()),
    };
    // Stamped with the record's requester origin: verifies, and the stamp +
    // scope entries ride back on the verified result.
    let v = pres(f.stamped_assertion(Some("https://mingo.example")))
        .verify(f.audience(), |_| Ok(idp_pub.clone()))
        .unwrap();
    assert_eq!(v.req_origin.as_deref(), Some("https://mingo.example"));
    assert_eq!(v.scopes, vec!["sign:sbo:post".to_string(), "sign:sbo:delete".to_string()]);
    assert_eq!(v.scope_entries[1].scope(), "sign:sbo:delete");
    assert!(matches!(v.scope_entries[1].mode(), ScopeMode::Prompt));
    assert!(matches!(v.scope_entries[0].mode(), ScopeMode::Auto));
    // No stamp → reject (invariant 13).
    assert!(pres(f.stamped_assertion(None))
        .verify(f.audience(), |_| Ok(idp_pub.clone()))
        .is_err());
    // Wrong stamp → reject.
    assert!(pres(f.stamped_assertion(Some("https://evil.example")))
        .verify(f.audience(), |_| Ok(idp_pub.clone()))
        .is_err());
    // A stamp on a requester-less record → reject (present iff, §5).
    let plain = AccessPresentation {
        access_cert: f.access_cert(),
        assertion: f.stamped_assertion(Some("https://mingo.example")),
        warrant: Warrant::parse(f.warrant_v2().encoded()).unwrap(),
        config_cert: f.config_cert_signed_by(&f.idp, f.idp_domain()),
    };
    assert!(plain.verify(f.audience(), |_| Ok(idp_pub.clone())).is_err());
    // Every holder entry is evaluated: a second, non-covering holder entry
    // fails the presentation even though the first covers.
    let strict = f.signing_grant_with(|c| {
        c.binding = Some(BindingSet::Many(vec![
            Binding::Holder { matcher: HolderMatcher::new("br.*").unwrap() },
            Binding::Holder { matcher: HolderMatcher::new("svc.other").unwrap() },
            Binding::Requester { origin: "https://mingo.example".into() },
        ]));
    });
    let p = AccessPresentation {
        access_cert: f.access_cert(),
        assertion: f.stamped_assertion(Some("https://mingo.example")),
        warrant: Warrant::parse(strict.encoded()).unwrap(),
        config_cert: f.config_cert_signed_by(&f.idp, f.idp_domain()),
    };
    assert!(p.verify(f.audience(), |_| Ok(idp_pub.clone())).is_err());
}
