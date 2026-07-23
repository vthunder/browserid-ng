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
}
impl Fixture {
    fn new() -> Self {
        Self { idp: seed_key(1), access_key: seed_key(3), config_key: seed_key(4) }
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
                holder: HolderMatcher::new("br.*").unwrap(),
                audience: self.audience().into(),
                scopes: vec!["login".into()],
                status: status("https://browserid.me/.well-known/browserid-status", 42),
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
        let _ = AssertionClaims { exp: 0, aud: String::new() }; // keep import honest
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
            public_key: f.config_key.public_key(), status: None,
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
            identities: vec![f.email().into()], public_key: f.config_key.public_key(), status: None,
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
            holder: HolderMatcher::new("svc.some-other-service").unwrap(),
            audience: f.audience().into(), scopes: vec!["login".into()], status: None,
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
