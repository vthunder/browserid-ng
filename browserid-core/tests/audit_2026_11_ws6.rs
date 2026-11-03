//! Security audit 2026-11, WS6 — regression tests encoding the threat-model
//! invariants for `browserid-core` (docs/design/threat-model.md I1–I5, I13;
//! spec decisions S3, S5, S6; WS1 candidates D1, D16).
//!
//! Tests marked `#[ignore]` with an `AUDIT-2026-11` comment encode an
//! invariant that FAILS today: they are the acceptance test for the fix and
//! must be un-ignored when it lands. Everything else passes today and pins
//! behaviour the audit re-verified.
//!
//! Report: docs/security-audit-2026-11-ws6-core-verifier.md.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use browserid_core::device::{
    AccessCert, AccessCertClaims, AccessPresentation, AudConstraint, Binding, Constraints,
    DeviceCert, DeviceCertClaims, HolderMatcher, Warrant, WarrantClaims, TYP_ACCESS_CERT,
    TYP_DEVICE_CERT, TYP_WARRANT_V2,
};
use browserid_core::{
    Assertion, Cap, Holder, KeyPair, PublicKey, Purpose, RecordBundle, ScopeEntry, ScopeParams,
    StatusListToken, StatusRef,
};
use serde_json::json;

/// Fixed clock for `verify_at` (2027-01-15T08:00:00Z).
const IAT: i64 = 1_800_000_000;
const DAY: i64 = 86_400;
const HOUR: i64 = 3_600;
/// The instant every `verify_at` call judges the bundle at.
const AT: i64 = IAT + 60;

const IDP: &str = "example.com";
const USER: &str = "user@example.com";
const AUD: &str = "https://rp.example";
const STATUS: &str = "https://example.com/.well-known/browserid-status";

fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(&[seed; 32]).unwrap()
}
fn sref(idx: u64) -> Option<StatusRef> {
    Some(StatusRef { uri: STATUS.into(), idx })
}

/// A valid as-you bundle for `USER` at `AUD`, every object editable before
/// signing. `idp` signs both certs; `config` signs the warrant; `access`
/// signs the assertion.
struct Fx {
    idp: KeyPair,
    access: KeyPair,
    config: KeyPair,
}

impl Fx {
    fn new() -> Self {
        Self { idp: key(1), access: key(3), config: key(4) }
    }
    fn idp_pub(&self) -> PublicKey {
        self.idp.public_key()
    }
    fn access_cert(&self, edit: impl FnOnce(&mut AccessCertClaims)) -> AccessCert {
        let mut c = AccessCertClaims {
            typ: TYP_ACCESS_CERT.into(),
            iss: IDP.into(),
            iat: IAT,
            exp: IAT + 24 * HOUR,
            identity: USER.into(),
            holder: Holder::new("br.main").unwrap(),
            access_key: self.access.public_key(),
            status: sref(7),
            constraints: None,
        };
        edit(&mut c);
        AccessCert::from_claims(c, &self.idp).unwrap()
    }
    fn device_cert(
        &self,
        purpose: Purpose,
        edit: impl FnOnce(&mut DeviceCertClaims),
    ) -> DeviceCert {
        let mut c = DeviceCertClaims {
            typ: TYP_DEVICE_CERT.into(),
            iss: IDP.into(),
            iat: IAT,
            exp: IAT + 90 * DAY,
            purpose,
            holder: Holder::new("br.main").unwrap(),
            identities: vec![USER.into()],
            public_key: self.config.public_key(),
            status: sref(2),
            managed: None,
            constraints: None,
            prov: None,
        };
        edit(&mut c);
        DeviceCert::from_claims(c, &self.idp).unwrap()
    }
    fn config_cert(&self, edit: impl FnOnce(&mut DeviceCertClaims)) -> DeviceCert {
        self.device_cert(Purpose::Authorization, edit)
    }
    fn warrant(&self, edit: impl FnOnce(&mut WarrantClaims)) -> Warrant {
        let mut c = WarrantClaims {
            typ: TYP_WARRANT_V2.into(),
            iat: IAT,
            exp: IAT + 90 * DAY,
            grantor: USER.into(),
            grantee: USER.into(),
            holder: None,
            binding: Some(Binding::Holder { matcher: HolderMatcher::new("br.*").unwrap() }.into()),
            audience: AUD.into(),
            scopes: vec![],
            status: sref(42),
            unknown: Default::default(),
        };
        edit(&mut c);
        Warrant::from_claims(c, &self.config).unwrap()
    }
    fn assertion(&self, aud: &str) -> Assertion {
        Assertion::create(aud, chrono::Duration::days(3650), &self.access).unwrap()
    }
    fn bundle(&self) -> AccessPresentation {
        AccessPresentation {
            access_cert: self.access_cert(|_| {}),
            assertion: self.assertion(AUD),
            warrant: self.warrant(|_| {}),
            config_cert: self.config_cert(|_| {}),
        }
    }
    fn verify(&self, p: &AccessPresentation) -> browserid_core::Result<browserid_core::VerifiedAccess> {
        let k = self.idp_pub();
        p.verify_at(AUD, AT, |_| Ok(k.clone()))
    }
}

/// Sign an arbitrary JSON claim set under an arbitrary JOSE header — for
/// objects whose constructors pin the fields the audit needs to vary.
fn raw_jws(header: &str, claims: &serde_json::Value, key: &KeyPair) -> String {
    let h = B64.encode(header);
    let c = B64.encode(claims.to_string());
    let msg = format!("{h}.{c}");
    let sig = B64.encode(key.sign(msg.as_bytes()));
    format!("{msg}.{sig}")
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

// ---------------------------------------------------------------------------
// Sanity: the fixture verifies.
// ---------------------------------------------------------------------------

#[test]
fn fixture_bundle_verifies() {
    let f = Fx::new();
    let v = f.verify(&f.bundle()).unwrap();
    assert_eq!(v.email, USER);
    assert_eq!(v.grantee, USER);
    assert_eq!(v.holder.as_str(), "br.main");
}

// ---------------------------------------------------------------------------
// D1 / I13 — subaddressing is an AUTHORIZATION rule only (spec §4.6).
// ---------------------------------------------------------------------------

/// Spec §4.6: an auth cert for `user@d` mints for `user@d` exactly; acting as
/// `user+tag@d` needs an auth cert issued for that sub-identity. Both mint
/// routes (`browserid-broker/src/routes/device.rs` `/access/mint`,
/// `routes/hosted_idp.rs` `/idp/access_cert`) gate on this predicate, so it
/// is the mint's whole identity check.
#[test]
fn d1_authentication_cert_for_base_identity_does_not_authorize_subaddress() {
    let f = Fx::new();
    let auth = f.device_cert(Purpose::Authentication, |_| {});
    assert!(auth.authorizes_identity(USER));
    assert!(
        !auth.authorizes_identity("user+agent@example.com"),
        "an authentication cert must not widen to a subaddress (I13)"
    );
}

/// The other half of I13 — a config cert for `user@d` MAY sign a warrant
/// whose grantor is `user+tag@d`. Holds today.
#[test]
fn i13_authorization_cert_for_base_identity_covers_subaddressed_grantor() {
    let f = Fx::new();
    let sub = "user+agent@example.com";
    let p = AccessPresentation {
        access_cert: f.access_cert(|c| c.identity = sub.into()),
        assertion: f.assertion(AUD),
        warrant: f.warrant(|w| {
            w.grantor = sub.into();
            w.grantee = sub.into();
        }),
        config_cert: f.config_cert(|_| {}), // identities: [USER]
    };
    let v = f.verify(&p).unwrap();
    assert_eq!(v.email, sub);
}

/// A subaddress never authorizes its base or a sibling, under either purpose.
#[test]
fn subaddress_never_widens_upward_or_sideways() {
    let f = Fx::new();
    for purpose in [Purpose::Authentication, Purpose::Authorization] {
        let c = f.device_cert(purpose, |c| c.identities = vec!["user+a@example.com".into()]);
        assert!(!c.authorizes_identity(USER));
        assert!(!c.authorizes_identity("user+b@example.com"));
        assert!(!c.authorizes_identity("user+a@other.example"));
    }
}

// ---------------------------------------------------------------------------
// S6 / D16 — iat has no lower bound anywhere.
// ---------------------------------------------------------------------------

#[test]
fn s6_warrant_with_iat_after_exp_rejects() {
    let f = Fx::new();
    let mut p = f.bundle();
    p.warrant = f.warrant(|w| w.iat = w.exp + 1);
    assert!(f.verify(&p).is_err(), "iat > exp must reject");
}

#[test]
fn s6_access_cert_issued_in_the_future_rejects() {
    let f = Fx::new();
    let mut p = f.bundle();
    p.access_cert = f.access_cert(|c| {
        c.iat = AT + DAY;
        c.exp = AT + 2 * DAY;
    });
    assert!(f.verify(&p).is_err(), "a cert dated a day after `at` must reject");
}

#[test]
fn s6_admission_record_issued_in_the_future_rejects() {
    let f = Fx::new();
    let t = now();
    let b = RecordBundle {
        warrant: f.warrant(|w| {
            w.iat = t + DAY;
            w.exp = t + 2 * DAY;
        }),
        config_cert: f.config_cert(|c| {
            c.iat = t - DAY;
            c.exp = t + 90 * DAY;
        }),
    };
    let k = f.idp_pub();
    assert!(b.validate(AUD, |_| Ok(k.clone())).is_err());
}

/// `max-ttl` is computed as `exp - iat`; with a future `iat` the difference
/// goes negative and the constraint is vacuous (D16).
#[test]
fn d16_future_iat_defeats_max_ttl() {
    let f = Fx::new();
    let p = AccessPresentation {
        access_cert: f.access_cert(|_| {}),
        assertion: f.assertion(AUD),
        warrant: f.warrant(|w| {
            // 90-day warrant whose iat is written AFTER its exp.
            w.exp = IAT + 90 * DAY;
            w.iat = w.exp + 1;
        }),
        config_cert: f.config_cert(|c| {
            c.constraints = Some(Constraints {
                aud: None,
                scopes: None,
                max_ttl: Some(HOUR),
                unknown: Default::default(),
            })
        }),
    };
    assert!(f.verify(&p).is_err(), "a 1 h max-ttl must bound a 90-day warrant");
}

/// `max-ttl` holds when `iat` is honest — the constraint itself works.
#[test]
fn max_ttl_bounds_an_honestly_dated_warrant() {
    let f = Fx::new();
    let p = AccessPresentation {
        access_cert: f.access_cert(|_| {}),
        assertion: f.assertion(AUD),
        warrant: f.warrant(|_| {}), // 90 days
        config_cert: f.config_cert(|c| {
            c.constraints = Some(Constraints {
                aud: None,
                scopes: None,
                max_ttl: Some(HOUR),
                unknown: Default::default(),
            })
        }),
    };
    assert!(f.verify(&p).is_err());
}

#[test]
fn d16_status_list_with_future_iat_is_not_fresh() {
    let k = key(9);
    let list = browserid_core::StatusList::from_revoked([], 8);
    let claims = json!({
        "typ": browserid_core::TYP_STATUS_LIST,
        "iss": IDP,
        "sub": STATUS,
        "iat": now() + 10 * 365 * DAY,
        "ttl": 300,
        "status_list": { "bits": 1, "lst": list.encode().unwrap() },
    });
    let tok = StatusListToken::parse(&raw_jws(r#"{"alg":"EdDSA","typ":"JWT"}"#, &claims, &k)).unwrap();
    tok.verify(&k.public_key(), STATUS).unwrap();
    assert!(
        !tok.is_fresh_capped(0, 300),
        "a list dated ten years ahead must not read as fresh (cap defeated)"
    );
}

// ---------------------------------------------------------------------------
// S3 / I10 — every accept path for `browserid-warrant-v1`.
//
// Decision (WS1 §5): drop v1 outright. Core accept paths today:
//   * `Warrant::parse` → `validate_claims` arm `TYP_WARRANT` (device.rs:1304)
//   * `AccessPresentation::parse` / `verify_at` (via Warrant::parse)
//   * `RecordBundle::parse` / `validate` (admission.rs)
//   * hosted `/verify` and `/validate-record` and `browserid-rp` — all via the
//     core parse above; no independent gate.
// ---------------------------------------------------------------------------

#[test]
#[ignore] // AUDIT-2026-11 S3: fails today — v1 (and status-less v1) warrants verify in a bundle
fn s3_v1_warrant_rejects_in_presentation() {
    let f = Fx::new();
    let v1 = Warrant::create(
        USER,
        USER,
        HolderMatcher::new("br.*").unwrap(),
        AUD,
        vec![],
        chrono::Duration::days(90),
        &f.config,
        None, // status-less: the I10 record no signer should emit
    )
    .unwrap();
    assert!(Warrant::parse(v1.encoded()).is_err(), "Warrant::parse must refuse v1");
    let mut p = f.bundle();
    p.warrant = v1;
    assert!(f.verify(&p).is_err());
}

#[test]
#[ignore] // AUDIT-2026-11 S3: fails today — admission validates a v1 record
fn s3_v1_record_rejects_in_admission() {
    let f = Fx::new();
    let t = now();
    let v1 = Warrant::create(
        USER,
        USER,
        HolderMatcher::new("*").unwrap(),
        AUD,
        vec![],
        chrono::Duration::days(90),
        &f.config,
        sref(1),
    )
    .unwrap();
    let b = RecordBundle {
        warrant: v1,
        config_cert: f.config_cert(|c| {
            c.iat = t - DAY;
            c.exp = t + 90 * DAY;
        }),
    };
    assert!(RecordBundle::parse(&b.encode()).is_err());
    let k = f.idp_pub();
    assert!(b.validate(AUD, |_| Ok(k.clone())).is_err());
}

// ---------------------------------------------------------------------------
// S5 / I8 — constraints: unknown keys reject; what the Rust path implements.
// ---------------------------------------------------------------------------

fn with_unknown_key() -> Constraints {
    let mut c = Constraints { aud: None, scopes: None, max_ttl: None, unknown: Default::default() };
    c.unknown.insert("geo".into(), json!(["EU"]));
    c
}

#[test]
fn s5_unknown_constraint_key_rejects_in_presentation_on_either_cert() {
    let f = Fx::new();
    let mut p = f.bundle();
    p.config_cert = f.config_cert(|c| c.constraints = Some(with_unknown_key()));
    assert!(f.verify(&p).is_err());

    let mut p = f.bundle();
    p.access_cert = f.access_cert(|c| c.constraints = Some(with_unknown_key()));
    assert!(f.verify(&p).is_err());
}

#[test]
fn s5_unknown_constraint_key_rejects_in_admission() {
    let f = Fx::new();
    let t = now();
    let b = RecordBundle {
        warrant: f.warrant(|w| {
            w.iat = t - 60;
            w.exp = t + DAY;
        }),
        config_cert: f.config_cert(|c| {
            c.iat = t - DAY;
            c.exp = t + 90 * DAY;
            c.constraints = Some(with_unknown_key());
        }),
    };
    let k = f.idp_pub();
    assert!(b.validate(AUD, |_| Ok(k.clone())).is_err());
}

/// The three keys the Rust path implements (`aud`, `scopes`, `max-ttl`) are
/// enforced — so under S5 this verifier counts as "implementing §4.7".
#[test]
fn s5_implemented_constraint_keys_are_enforced() {
    let f = Fx::new();
    let salt = "c2FsdHktc2FsdA";
    let allow = |a: &str| AudConstraint { salt: salt.into(), hashes: vec![AudConstraint::hash_audience(salt, a).unwrap()] };

    // aud: allowlist naming another audience rejects; naming ours passes.
    let mut p = f.bundle();
    p.access_cert = f.access_cert(|c| {
        c.constraints = Some(Constraints { aud: Some(allow("https://other.example")), scopes: None, max_ttl: None, unknown: Default::default() })
    });
    assert!(f.verify(&p).is_err());
    p.access_cert = f.access_cert(|c| {
        c.constraints = Some(Constraints { aud: Some(allow(AUD)), scopes: None, max_ttl: None, unknown: Default::default() })
    });
    assert!(f.verify(&p).is_ok());

    // scopes: a warrant scope outside the allowlist rejects.
    let mut p = f.bundle();
    p.warrant = f.warrant(|w| w.scopes = vec!["tool:write".into()]);
    p.access_cert = f.access_cert(|c| {
        c.constraints = Some(Constraints { aud: None, scopes: Some(vec!["tool:read".into()]), max_ttl: None, unknown: Default::default() })
    });
    assert!(f.verify(&p).is_err());
}

/// Documents the S5 corner the decision calls out: a `scopes` allowlist
/// cannot restrict a scope-less login warrant — nothing is outside the set.
/// Passes today; whether a login should be refused by a non-empty allowlist
/// is Dan's call (WS1 S5: "define that an allowlist applies to logins as []").
#[test]
fn s5_scope_allowlist_is_vacuous_for_a_scope_less_login_warrant() {
    let f = Fx::new();
    let mut p = f.bundle(); // warrant scopes: []
    p.access_cert = f.access_cert(|c| {
        c.constraints = Some(Constraints { aud: None, scopes: Some(vec!["tool:read".into()]), max_ttl: None, unknown: Default::default() })
    });
    assert!(f.verify(&p).is_ok());
}

// ---------------------------------------------------------------------------
// I1 — bundle shape and unknown typ / purpose fail closed.
// ---------------------------------------------------------------------------

#[test]
fn i1_bundle_shape_and_unknown_typ_or_purpose_reject() {
    let f = Fx::new();
    let enc = f.bundle().encode();
    let parts: Vec<&str> = enc.split('~').collect();
    assert!(AccessPresentation::parse(&parts[..3].join("~")).is_err());
    assert!(AccessPresentation::parse(&format!("{enc}~{}", parts[0])).is_err());

    // Warrant with a typ nobody implements.
    let w = raw_jws(
        r#"{"alg":"EdDSA","typ":"JWT"}"#,
        &json!({"typ":"browserid-warrant-v3","iat":IAT,"exp":IAT+DAY,"grantor":USER,"grantee":USER,
                "binding":{"kind":"holder","matcher":"*"},"audience":AUD,"status":{"uri":STATUS,"idx":1}}),
        &f.config,
    );
    assert!(Warrant::parse(&w).is_err());

    // Device cert with an unknown purpose.
    let d = raw_jws(
        r#"{"alg":"EdDSA","typ":"JWT"}"#,
        &json!({"typ":TYP_DEVICE_CERT,"iss":IDP,"iat":IAT,"exp":IAT+DAY,"purpose":"signing","holder":"br.main",
                "identities":[USER],"public-key":serde_json::to_value(f.config.public_key()).unwrap()}),
        &f.idp,
    );
    assert!(DeviceCert::parse(&d).is_err());

    // An access cert presented in the warrant slot (typ confusion).
    let mut swapped = parts.clone();
    swapped[2] = parts[0];
    assert!(AccessPresentation::parse(&swapped.join("~")).is_err());

    // Unknown binding kind.
    let w = raw_jws(
        r#"{"alg":"EdDSA","typ":"JWT"}"#,
        &json!({"typ":TYP_WARRANT_V2,"iat":IAT,"exp":IAT+DAY,"grantor":USER,"grantee":USER,
                "binding":{"kind":"geo","region":"EU"},"audience":AUD,"status":{"uri":STATUS,"idx":1}}),
        &f.config,
    );
    assert!(Warrant::parse(&w).is_err());
}

// ---------------------------------------------------------------------------
// I4 — audience is byte-exact on assertion, warrant, and expected audience.
// ---------------------------------------------------------------------------

#[test]
fn i4_audience_has_no_slack() {
    let f = Fx::new();
    for variant in ["https://rp.example/", "https://RP.example", "https://rp.example:443", "http://rp.example", "https://rp.example/path"] {
        let mut p = f.bundle();
        p.assertion = f.assertion(variant);
        assert!(f.verify(&p).is_err(), "assertion aud {variant:?} must not match {AUD:?}");

        let mut p = f.bundle();
        p.warrant = f.warrant(|w| w.audience = variant.into());
        assert!(f.verify(&p).is_err(), "warrant audience {variant:?} must not match {AUD:?}");
    }
}

// ---------------------------------------------------------------------------
// I5 — identity comparison: domain case-insensitive, local part byte-exact.
// ---------------------------------------------------------------------------

/// grantee ↔ access-cert identity uses the §5 rule (`identity_eq`).
#[test]
fn i5_grantee_join_uses_spec_comparison() {
    let f = Fx::new();
    let mut p = f.bundle();
    p.warrant = f.warrant(|w| w.grantee = "user@EXAMPLE.com".into());
    assert!(f.verify(&p).is_ok(), "domain case must not matter");

    let mut p = f.bundle();
    p.warrant = f.warrant(|w| w.grantee = "User@example.com".into());
    assert!(f.verify(&p).is_err(), "local part is byte-exact");

    let mut p = f.bundle();
    p.warrant = f.warrant(|w| w.grantee = "user+x@example.com".into());
    assert!(f.verify(&p).is_err(), "a subaddress is a different grantee");
}

/// The config-cert `identities` ↔ grantor match goes through
/// `identity_matches`, whose exact and subaddress branches compare the domain
/// BYTE-exact (device.rs:73, :107), not under §5. Stricter than spec (fail-
/// closed), so no security impact; recorded as W6-1. Issuers emit lowercase
/// A-labels, so it is unreachable in practice.
#[test]
#[ignore] // AUDIT-2026-11 W6-1: fails today — `identity_matches` exact/subaddress branches skip §5 domain normalization
fn w6_1_grantor_match_uses_spec_domain_comparison() {
    let f = Fx::new();
    let mut p = f.bundle();
    p.warrant = f.warrant(|w| w.grantor = "user@EXAMPLE.com".into());
    assert!(f.verify(&p).is_ok());
}

// ---------------------------------------------------------------------------
// Crypto hygiene: alg pin, key and signature length pins, header tampering.
// ---------------------------------------------------------------------------

#[test]
fn key_and_signature_lengths_are_pinned() {
    assert!(PublicKey::from_bytes(&[0u8; 31]).is_err());
    assert!(PublicKey::from_bytes(&[0u8; 33]).is_err());
    let k = key(5);
    let msg = b"m";
    let mut sig = k.sign(msg);
    assert!(k.public_key().verify(msg, &sig[..63]).is_err());
    sig.push(0);
    assert!(k.public_key().verify(msg, &sig).is_err());
    assert!(KeyPair::from_seed(&[0u8; 16]).is_err());
}

/// Every JWS object re-signed under a tampered header (`alg: none`, `HS256`)
/// — with a signature that IS valid over the tampered bytes — still rejects
/// at the typed verifier, so the alg gate is not merely the Ed25519 check.
#[test]
fn alg_header_is_pinned_to_eddsa_on_typed_objects() {
    let f = Fx::new();
    let cert = f.config_cert(|_| {});
    let claims: serde_json::Value = serde_json::from_slice(&B64.decode(cert.encoded().split('.').nth(1).unwrap()).unwrap()).unwrap();
    for header in [r#"{"alg":"none","typ":"JWT"}"#, r#"{"alg":"HS256","typ":"JWT"}"#, r#"{"typ":"JWT"}"#] {
        let forged = raw_jws(header, &claims, &f.idp);
        let parsed = DeviceCert::parse(&forged).unwrap(); // parse never checks the header
        assert!(parsed.verify(&f.idp_pub()).is_err(), "header {header} must be refused");
    }
    // Warrant and access cert share the helper; status lists too.
    let w = f.warrant(|_| {});
    let wclaims: serde_json::Value = serde_json::from_slice(&B64.decode(w.encoded().split('.').nth(1).unwrap()).unwrap()).unwrap();
    let forged = Warrant::parse(&raw_jws(r#"{"alg":"none"}"#, &wclaims, &f.config)).unwrap();
    assert!(forged.verify(&f.config.public_key()).is_err());
}

/// W6-2: `Assertion::verify` does not read the JOSE header at all — it goes
/// straight to Ed25519 over `header.payload`. A forged header therefore does
/// NOT bypass anything (the signature must still verify under the access
/// key), but the object lacks the alg pin every other object has. Passes
/// today; recorded for the typed-signing consistency item.
#[test]
fn w6_2_assertion_without_a_valid_ed25519_signature_rejects_regardless_of_header() {
    let f = Fx::new();
    let claims = json!({"aud": AUD, "exp": AT + 300});
    let h = B64.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let c = B64.encode(claims.to_string());
    let unsigned = format!("{h}.{c}.");
    assert!(Assertion::parse(&unsigned).and_then(|a| a.verify(&f.access.public_key())).is_err());
    let wrong_key = raw_jws(r#"{"alg":"EdDSA","typ":"JWT"}"#, &claims, &f.config);
    assert!(Assertion::parse(&wrong_key).unwrap().verify(&f.access.public_key()).is_err());
}

// ---------------------------------------------------------------------------
// I2 ordering, holder matcher boundaries, parameterized scopes survive core.
// ---------------------------------------------------------------------------

/// The resolver is asked ONLY for the two `iss` values and nothing else is
/// fetched; every other claim is acted on only after the signature over it
/// verified. Encoded by recording resolver calls and asserting a forged
/// bundle (bad access-cert signature) never reaches the config cert.
#[test]
fn i2_resolver_is_consulted_for_issuers_only_and_crypto_gates_the_rest() {
    use std::cell::RefCell;
    let f = Fx::new();
    let calls = RefCell::new(Vec::new());
    let v = f.bundle().verify_at(AUD, AT, |iss| {
        calls.borrow_mut().push(iss.to_string());
        Ok(f.idp_pub())
    });
    assert!(v.is_ok());
    assert_eq!(calls.borrow().as_slice(), [IDP.to_string()], "one resolution when both iss coincide");

    // Access cert signed by a stranger: the config cert is never resolved.
    let rogue = key(77);
    let mut p = f.bundle();
    p.access_cert = AccessCert::from_claims(
        AccessCertClaims {
            typ: TYP_ACCESS_CERT.into(), iss: IDP.into(), iat: IAT, exp: IAT + DAY, identity: USER.into(),
            holder: Holder::new("br.main").unwrap(), access_key: f.access.public_key(), status: None, constraints: None,
        },
        &rogue,
    ).unwrap();
    p.config_cert = f.config_cert(|c| c.iss = "other.example".into());
    let calls = RefCell::new(Vec::new());
    let r = p.verify_at(AUD, AT, |iss| {
        calls.borrow_mut().push(iss.to_string());
        Ok(f.idp_pub())
    });
    assert!(r.is_err());
    assert_eq!(calls.borrow().as_slice(), [IDP.to_string()], "second issuer never resolved after a failed signature");
}

#[test]
fn holder_matcher_namespace_boundary_is_exact() {
    let m = HolderMatcher::new("k3n9.*").unwrap();
    assert!(m.matches(&Holder::new("k3n9.a").unwrap()));
    assert!(!m.matches(&Holder::new("k3n9x.a").unwrap()));
    assert!(!m.matches(&Holder::new("k3n9").unwrap()));
    assert!(!m.matches(&Holder::new("xk3n9.a").unwrap()));
    let exact = HolderMatcher::new("k3n9.a").unwrap();
    assert!(!exact.matches(&Holder::new("k3n9.ab").unwrap()));
    assert!(Holder::new("").is_err());
    assert!(Holder::new("x".repeat(129)).is_err());
}

/// Core keeps scope parameters (`scope_entries`) — the loss WS1 D7 reports
/// happens at the hosted verifier's response shape, not here.
#[test]
fn core_verified_access_preserves_scope_parameters() {
    let f = Fx::new();
    let mut p = f.bundle();
    p.warrant = f.warrant(|w| {
        w.scopes = vec![ScopeEntry::Parameterized(ScopeParams {
            scope: "pay:usd".into(),
            mode: None,
            cap: Some(Cap { amount: "20.00".into(), currency: "USD".into(), window: Some("P1D".into()) }),
            counterparties: None,
            max_duration: None,
            min_reputation: None,
        })]
    });
    let v = f.verify(&p).unwrap();
    assert_eq!(v.scopes, vec!["pay:usd".to_string()]);
    assert_eq!(v.scope_entries[0].cap().unwrap().amount, "20.00");
}
