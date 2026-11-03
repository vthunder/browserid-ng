//! Security audit 2026-11, WS3 — property tests for `browserid-core`
//! (docs/design/threat-model.md I12–I14, S6/D16; decisions D1).
//!
//! Every property runs 256 cases (CI budget). Tests marked `#[ignore]` with
//! an `AUDIT-2026-11` comment encode an invariant that FAILS today; they are
//! the acceptance test for the fix. WS6 (`audit_2026_11_ws6.rs`) holds the
//! point tests for S3/S5/S6/D1/D16; this file holds the randomized
//! generalisations and does not repeat the point cases.
//!
//! Report: docs/security-audit-2026-11-ws3-fuzz-proptest.md.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use browserid_core::device::{
    AccessCert, AccessCertClaims, AccessPresentation, AccessRequest, AccessRequestClaims,
    Binding, Constraints, DeviceCert, DeviceCertClaims, Warrant, WarrantClaims,
    TYP_ACCESS_CERT, TYP_ACCESS_REQUEST, TYP_DEVICE_CERT, TYP_WARRANT_V2,
};
use browserid_core::device::{parse_iso_duration_secs, parse_money_minor};
use browserid_core::identity::{email_parts, grantee_covers, identity_eq, normalize_domain};
use browserid_core::{
    Assertion, Cap, DnsRecord, Holder, HolderMatcher, KeyPair, MinReputation, Purpose,
    RecordBundle, ScopeEntry, ScopeMode, ScopeParams, StatusList, StatusListToken, StatusRef,
};
use proptest::prelude::*;

const CASES: u32 = 256;
const IAT: i64 = 1_800_000_000;
const DAY: i64 = 86_400;
const AT: i64 = IAT + 60;
const AUD: &str = "https://rp.example";
const STATUS: &str = "https://example.com/.well-known/browserid-status";

fn cfg() -> ProptestConfig {
    ProptestConfig { cases: CASES, ..ProptestConfig::default() }
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

fn key_strategy() -> impl Strategy<Value = KeyPair> {
    any::<[u8; 32]>().prop_map(|s| KeyPair::from_seed(&s).unwrap())
}
/// Lowercase ASCII local part without `+` (so `+` is only ever the subaddress separator).
fn local() -> impl Strategy<Value = String> {
    "[a-z0-9][a-z0-9._-]{0,11}"
}
fn tag() -> impl Strategy<Value = String> {
    "[a-z0-9]{1,8}"
}
/// Lowercase ASCII domains, so that the §5 comparison (case-insensitive
/// A-label) coincides with byte equality and the identity properties can
/// compare strings directly.
fn domain() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{0,7}\\.(com|org|example)"
}
fn email() -> impl Strategy<Value = String> {
    (local(), domain()).prop_map(|(l, d)| format!("{l}@{d}"))
}
fn holder() -> impl Strategy<Value = Holder> {
    "[a-z0-9]{1,6}\\.[a-z0-9]{1,12}".prop_map(|s| Holder::new(s).unwrap())
}
/// The one scope grammar (registry-api-v1 §3).
fn scope_string() -> impl Strategy<Value = String> {
    "[a-z0-9_:.\\-/*@+]{1,128}"
}
fn iso_duration() -> impl Strategy<Value = String> {
    prop_oneof![
        (1u32..400).prop_map(|d| format!("P{d}D")),
        (1u32..1000).prop_map(|h| format!("PT{h}H")),
        (1u32..52).prop_map(|w| format!("P{w}W")),
        (1u32..30, 1u32..24).prop_map(|(d, h)| format!("P{d}DT{h}H")),
    ]
}
fn money() -> impl Strategy<Value = String> {
    prop_oneof![
        (0u64..1_000_000).prop_map(|w| w.to_string()),
        (0u64..1_000_000, 0u8..10).prop_map(|(w, f)| format!("{w}.{f}")),
        (0u64..1_000_000, 0u8..100).prop_map(|(w, f)| format!("{w}.{f:02}")),
    ]
}
fn cap() -> impl Strategy<Value = Cap> {
    (money(), "[A-Z]{3}", proptest::option::of(iso_duration()))
        .prop_map(|(amount, currency, window)| Cap { amount, currency, window })
}
fn min_rep() -> impl Strategy<Value = MinReputation> {
    ("https://[a-z]{1,8}\\.example", 0u8..=100)
        .prop_map(|(indexer, score)| MinReputation { indexer, score })
}
fn params() -> impl Strategy<Value = ScopeParams> {
    (
        scope_string(),
        proptest::option::of(prop_oneof![Just(ScopeMode::Auto), Just(ScopeMode::Prompt)]),
        proptest::option::of(cap()),
        proptest::option::of(proptest::collection::vec(email(), 0..4)),
        proptest::option::of(iso_duration()),
        proptest::option::of(min_rep()),
    )
        .prop_map(|(scope, mode, cap, counterparties, max_duration, min_reputation)| {
            ScopeParams { scope, mode, cap, counterparties, max_duration, min_reputation }
        })
}
fn scope_entry() -> impl Strategy<Value = ScopeEntry> {
    prop_oneof![
        scope_string().prop_map(ScopeEntry::Bare),
        params().prop_map(ScopeEntry::Parameterized),
    ]
}
fn sref() -> impl Strategy<Value = StatusRef> {
    any::<u64>().prop_map(|idx| StatusRef { uri: STATUS.into(), idx })
}
fn purpose() -> impl Strategy<Value = Purpose> {
    prop_oneof![Just(Purpose::Authentication), Just(Purpose::Authorization)]
}
/// Timestamps well inside i64 so `exp = iat + validity` is honest; the
/// overflow corners get their own properties below.
fn window() -> impl Strategy<Value = (i64, i64)> {
    (0i64..(1 << 40), 1i64..(1 << 31)).prop_map(|(iat, v)| (iat, iat + v))
}

fn device_claims() -> impl Strategy<Value = DeviceCertClaims> {
    (
        domain(),
        window(),
        purpose(),
        holder(),
        proptest::collection::vec(email(), 1..4),
        key_strategy(),
        proptest::option::of(sref()),
        proptest::option::of(any::<bool>()),
        proptest::option::of("[a-z]{3,7}"),
    )
        .prop_map(|(iss, (iat, exp), purpose, holder, identities, k, status, managed, prov)| {
            DeviceCertClaims {
                typ: TYP_DEVICE_CERT.into(),
                iss,
                iat,
                exp,
                purpose,
                holder,
                identities,
                public_key: k.public_key(),
                status,
                managed,
                constraints: None,
                prov,
            }
        })
}
fn access_claims() -> impl Strategy<Value = AccessCertClaims> {
    (domain(), window(), email(), holder(), key_strategy(), proptest::option::of(sref())).prop_map(
        |(iss, (iat, exp), identity, holder, k, status)| AccessCertClaims {
            typ: TYP_ACCESS_CERT.into(),
            iss,
            iat,
            exp,
            identity,
            holder,
            access_key: k.public_key(),
            status,
            constraints: None,
        },
    )
}
fn request_claims() -> impl Strategy<Value = AccessRequestClaims> {
    (
        window(),
        "[A-Za-z0-9_-]{16,32}",
        domain(),
        email(),
        holder(),
        key_strategy(),
        proptest::option::of("https://[a-z]{1,8}\\.example"),
    )
        .prop_map(|((iat, exp), jti, domain, identity, holder, k, audience)| {
            AccessRequestClaims {
                typ: TYP_ACCESS_REQUEST.into(),
                iat,
                exp,
                jti,
                domain,
                identity,
                holder,
                access_key: k.public_key(),
                audience,
            }
        })
}
fn holder_matcher() -> impl Strategy<Value = HolderMatcher> {
    prop_oneof![
        Just(HolderMatcher::new("*").unwrap()),
        "[a-z0-9]{1,6}\\.\\*".prop_map(|s| HolderMatcher::new(s).unwrap()),
        "[a-z0-9]{1,6}\\.[a-z0-9]{1,12}".prop_map(|s| HolderMatcher::new(s).unwrap()),
    ]
}
/// A well-formed as-you or delegated v2 warrant with a holder binding.
fn warrant_claims() -> impl Strategy<Value = WarrantClaims> {
    (
        window(),
        email(),
        proptest::option::of(email()),
        holder_matcher(),
        "https://[a-z]{1,8}\\.example",
        proptest::collection::vec(scope_entry(), 0..5),
        sref(),
    )
        .prop_map(|((iat, exp), grantor, grantee, m, audience, scopes, status)| WarrantClaims {
            typ: TYP_WARRANT_V2.into(),
            iat,
            exp,
            grantee: grantee.unwrap_or_else(|| grantor.clone()),
            grantor,
            holder: None,
            binding: Some(Binding::Holder { matcher: m }.into()),
            audience,
            scopes,
            status: Some(status),
            unknown: Default::default(),
        })
}

fn json<T: serde::Serialize>(t: &T) -> serde_json::Value {
    serde_json::to_value(t).unwrap()
}

// ---------------------------------------------------------------------------
// Sign → parse → verify round trips, every object type.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn device_cert_round_trips(c in device_claims(), idp in key_strategy(), other in key_strategy()) {
        let cert = DeviceCert::from_claims(c.clone(), &idp).unwrap();
        let back = DeviceCert::parse(cert.encoded()).unwrap();
        prop_assert_eq!(json(back.claims()), json(&c));
        prop_assert_eq!(back.encoded(), cert.encoded());
        prop_assert!(back.verify(&idp.public_key()).is_ok());
        prop_assume!(other.public_key() != idp.public_key());
        prop_assert!(back.verify(&other.public_key()).is_err());
        prop_assert_eq!(back.is_expired_at(c.exp), false);
        prop_assert!(back.is_expired_at(c.exp + 1));
    }

    #[test]
    fn access_cert_round_trips(c in access_claims(), idp in key_strategy(), other in key_strategy()) {
        let cert = AccessCert::from_claims(c.clone(), &idp).unwrap();
        let back = AccessCert::parse(cert.encoded()).unwrap();
        prop_assert_eq!(json(back.claims()), json(&c));
        prop_assert!(back.verify(&idp.public_key()).is_ok());
        prop_assume!(other.public_key() != idp.public_key());
        prop_assert!(back.verify(&other.public_key()).is_err());
    }

    #[test]
    fn access_request_round_trips(c in request_claims(), dev in key_strategy()) {
        let r = AccessRequest::from_claims(c.clone(), &dev).unwrap();
        let back = AccessRequest::parse(r.encoded()).unwrap();
        prop_assert_eq!(json(back.claims()), json(&c));
        prop_assert!(back.verify(&dev.public_key()).is_ok());
    }

    #[test]
    fn assertion_round_trips(aud in "[ -~]{1,64}", req in proptest::option::of("https://[a-z]{1,8}\\.example"), secs in 1i64..(1 << 31), k in key_strategy(), other in key_strategy()) {
        let a = Assertion::create_with_req_origin(&aud, req.as_deref(), chrono::Duration::seconds(secs), &k).unwrap();
        let back = Assertion::parse(a.encoded()).unwrap();
        prop_assert_eq!(back.audience(), aud.as_str());
        prop_assert_eq!(back.claims().req_origin.as_deref(), req.as_deref());
        prop_assert_eq!(back.claims().exp, a.claims().exp);
        prop_assert!(back.verify(&k.public_key()).is_ok());
        prop_assume!(other.public_key() != k.public_key());
        prop_assert!(back.verify(&other.public_key()).is_err());
    }

    #[test]
    fn warrant_v2_round_trips(c in warrant_claims(), cfgk in key_strategy(), other in key_strategy()) {
        let w = Warrant::from_claims(c.clone(), &cfgk).unwrap();
        let back = Warrant::parse(w.encoded()).unwrap();
        prop_assert_eq!(json(back.claims()), json(&c));
        prop_assert_eq!(back.claims().scope_strings(), c.scope_strings());
        prop_assert!(back.verify(&cfgk.public_key()).is_ok());
        prop_assume!(other.public_key() != cfgk.public_key());
        prop_assert!(back.verify(&other.public_key()).is_err());
    }

    #[test]
    fn status_list_token_round_trips(revoked in proptest::collection::btree_set(0u64..20_000, 0..64), probe in proptest::collection::vec(0u64..20_000, 8), k in key_strategy(), other in key_strategy()) {
        let list = StatusList::from_revoked(revoked.iter().copied(), 20_000);
        let tok = StatusListToken::create("example.com", STATUS, &list, &k).unwrap();
        let back = StatusListToken::parse(tok.encoded()).unwrap();
        prop_assert!(back.verify(&k.public_key(), STATUS).is_ok());
        prop_assert!(back.verify(&k.public_key(), "https://example.com/other").is_err());
        prop_assume!(other.public_key() != k.public_key());
        prop_assert!(back.verify(&other.public_key(), STATUS).is_err());
        for i in revoked.iter().copied().chain(probe) {
            prop_assert_eq!(back.is_revoked(i), revoked.contains(&i));
        }
    }

    /// A full as-you presentation built from random claims verifies, and the
    /// bundle survives `encode`/`parse` byte-for-byte.
    #[test]
    fn presentation_round_trips_and_verifies(idp in key_strategy(), access in key_strategy(), config in key_strategy(), user in email(), iss in domain(), h in holder(), scopes in proptest::collection::vec(scope_entry(), 0..4)) {
        let ac = AccessCert::from_claims(AccessCertClaims {
            typ: TYP_ACCESS_CERT.into(), iss: iss.clone(), iat: IAT, exp: IAT + DAY,
            identity: user.clone(), holder: h.clone(), access_key: access.public_key(),
            status: Some(StatusRef { uri: STATUS.into(), idx: 1 }), constraints: None,
        }, &idp).unwrap();
        let cc = DeviceCert::from_claims(DeviceCertClaims {
            typ: TYP_DEVICE_CERT.into(), iss, iat: IAT, exp: IAT + 90 * DAY,
            purpose: Purpose::Authorization, holder: h.clone(), identities: vec![user.clone()],
            public_key: config.public_key(), status: Some(StatusRef { uri: STATUS.into(), idx: 2 }),
            managed: None, constraints: None, prov: None,
        }, &idp).unwrap();
        let w = Warrant::from_claims(WarrantClaims {
            typ: TYP_WARRANT_V2.into(), iat: IAT, exp: IAT + DAY, grantor: user.clone(), grantee: user.clone(),
            holder: None, binding: Some(Binding::Holder { matcher: HolderMatcher::new(h.as_str()).unwrap() }.into()),
            audience: AUD.into(), scopes: scopes.clone(), status: Some(StatusRef { uri: STATUS.into(), idx: 3 }),
            unknown: Default::default(),
        }, &config).unwrap();
        let p = AccessPresentation { access_cert: ac, assertion: Assertion::create(AUD, chrono::Duration::days(3650), &access).unwrap(), warrant: w, config_cert: cc };
        let enc = p.encode();
        let back = AccessPresentation::parse(&enc).unwrap();
        prop_assert_eq!(back.encode(), enc);
        let k = idp.public_key();
        let v = back.verify_at(AUD, AT, |_| Ok(k.clone())).unwrap();
        prop_assert_eq!(v.email.as_str(), user.as_str());
        prop_assert_eq!(&v.holder, &h);
        prop_assert_eq!(v.scope_entries, scopes);
    }

    #[test]
    fn record_bundle_round_trips(c in warrant_claims(), cfgk in key_strategy(), dc in device_claims(), idp in key_strategy()) {
        let b = RecordBundle { warrant: Warrant::from_claims(c, &cfgk).unwrap(), config_cert: DeviceCert::from_claims(dc, &idp).unwrap() };
        let enc = b.encode();
        let back = RecordBundle::parse(&enc).unwrap();
        prop_assert_eq!(back.encode(), enc);
    }
}

// ---------------------------------------------------------------------------
// Canonicalization is idempotent.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn domain_normalization_is_idempotent(d in "\\PC{0,40}") {
        if let Some(n) = normalize_domain(&d) {
            prop_assert_eq!(normalize_domain(&n), Some(n.clone()));
            prop_assert!(n.is_ascii());
        }
    }

    #[test]
    fn identity_eq_is_an_equivalence_on_well_formed_emails(a in email(), b in email()) {
        prop_assert!(identity_eq(&a, &a));
        prop_assert_eq!(identity_eq(&a, &b), identity_eq(&b, &a));
        prop_assert_eq!(identity_eq(&a, &b), a == b);
        // Domain case is normalised, local part is byte-exact.
        prop_assert!(identity_eq(&a, &a.to_uppercase()) == (email_parts(&a).unwrap().0 == email_parts(&a.to_uppercase()).unwrap().0));
    }

    #[test]
    fn claims_json_serialization_is_stable(c in warrant_claims(), dc in device_claims()) {
        let once = serde_json::to_string(&c).unwrap();
        let back: WarrantClaims = serde_json::from_str(&once).unwrap();
        prop_assert_eq!(serde_json::to_string(&back).unwrap(), once);
        let once = serde_json::to_string(&dc).unwrap();
        let back: DeviceCertClaims = serde_json::from_str(&once).unwrap();
        prop_assert_eq!(serde_json::to_string(&back).unwrap(), once);
    }

    #[test]
    fn status_list_encoding_is_idempotent(revoked in proptest::collection::btree_set(0u64..50_000, 0..128), capacity in 0u64..50_000) {
        let list = StatusList::from_revoked(revoked.iter().copied(), capacity);
        let enc = list.encode().unwrap();
        let dec = StatusList::decode(&enc).unwrap();
        prop_assert_eq!(&dec, &list);
        prop_assert_eq!(dec.encode().unwrap(), enc);
    }
}

// ---------------------------------------------------------------------------
// I12 — the stricter-wins order never loosens a parameter.
// ---------------------------------------------------------------------------

/// Derive a strictly-no-looser variant of `p`: every present parameter is
/// kept or tightened; absent ones may be added.
fn tighten(p: &ScopeParams, seed: u64) -> ScopeParams {
    let mut q = p.clone();
    if seed & 1 == 1 {
        q.mode = Some(ScopeMode::Prompt);
    }
    if let Some(c) = &p.cap {
        let minor = c.amount_minor().unwrap();
        let cut = (seed >> 1) % (minor + 1);
        let new = minor - cut;
        q.cap = Some(Cap {
            amount: format!("{}.{:02}", new / 100, new % 100),
            currency: c.currency.clone(),
            window: match &c.window {
                None if seed & 2 == 2 => Some("P1D".into()),
                Some(w) if seed & 4 == 4 => Some(format!("PT{}S", parse_iso_duration_secs(w).unwrap() / 2)),
                w => w.clone(),
            },
        });
    }
    if let Some(cp) = &p.counterparties {
        let keep = (seed >> 8) as usize % (cp.len() + 1);
        q.counterparties = Some(cp[..keep].to_vec());
    }
    if let Some(d) = &p.max_duration {
        if seed & 8 == 8 {
            q.max_duration = Some(format!("PT{}S", parse_iso_duration_secs(d).unwrap() / 3));
        }
    }
    if let Some(m) = &p.min_reputation {
        q.min_reputation = Some(MinReputation { indexer: m.indexer.clone(), score: m.score.max(((seed >> 16) % 101) as u8) });
    }
    q
}

fn secs(d: &str) -> u64 {
    parse_iso_duration_secs(d).unwrap()
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn strictness_is_reflexive(p in params()) {
        prop_assert!(p.is_at_least_as_strict_as(&p));
    }

    #[test]
    fn tightening_is_at_least_as_strict_and_transitive(c in params(), s1 in any::<u64>(), s2 in any::<u64>()) {
        let b = tighten(&c, s1);
        let a = tighten(&b, s2);
        prop_assert!(b.is_at_least_as_strict_as(&c), "b={:?} c={:?}", b, c);
        prop_assert!(a.is_at_least_as_strict_as(&b), "a={:?} b={:?}", a, b);
        prop_assert!(a.is_at_least_as_strict_as(&c), "transitivity: a={:?} c={:?}", a, c);
    }

    /// I12 core: whenever the order says `a` is at least as strict as `b`,
    /// no parameter present on `b` is looser on `a`.
    #[test]
    fn strictness_never_loosens_any_parameter(a in params(), b in params(), s in any::<u64>()) {
        // Half the cases compare a derived pair (so the premise is often true).
        let a = if s & 1 == 1 { tighten(&b, s) } else { a };
        if !a.is_at_least_as_strict_as(&b) { return Ok(()); }
        prop_assert_eq!(&a.scope, &b.scope);
        if b.mode == Some(ScopeMode::Prompt) { prop_assert_eq!(a.mode, Some(ScopeMode::Prompt)); }
        if let Some(bc) = &b.cap {
            let ac = a.cap.as_ref().expect("cap must be present on the stricter side");
            prop_assert_eq!(&ac.currency, &bc.currency);
            prop_assert!(ac.amount_minor().unwrap() <= bc.amount_minor().unwrap());
            match (&ac.window, &bc.window) {
                (_, None) => {}
                (Some(x), Some(y)) => prop_assert!(secs(x) <= secs(y)),
                (None, Some(_)) => prop_assert!(false, "a lifetime window is looser than any finite one"),
            }
        }
        if let Some(bl) = &b.counterparties {
            let al = a.counterparties.as_ref().expect("counterparties must be present");
            prop_assert!(al.iter().all(|x| bl.contains(x)), "counterparties must be a subset");
        }
        if let Some(bd) = &b.max_duration {
            prop_assert!(secs(a.max_duration.as_ref().unwrap()) <= secs(bd));
        }
        if let Some(bm) = &b.min_reputation {
            let am = a.min_reputation.as_ref().unwrap();
            prop_assert_eq!(&am.indexer, &bm.indexer);
            prop_assert!(am.score >= bm.score);
        }
    }

    /// A cap with a malformed amount or window is never "at least as strict"
    /// as anything (fail-closed), in either position.
    #[test]
    fn malformed_cap_is_never_stricter(good in cap(), bad_amount in "[^0-9.]{1,8}|[0-9]+\\.[0-9]{3,5}", bad_window in "[^P][ -~]{0,8}") {
        let bad = Cap { amount: bad_amount, currency: good.currency.clone(), window: None };
        prop_assert!(!bad.is_at_least_as_strict_as(&good));
        prop_assert!(!good.is_at_least_as_strict_as(&bad));
        let bad = Cap { amount: good.amount.clone(), currency: good.currency.clone(), window: Some(bad_window) };
        prop_assert!(!bad.is_at_least_as_strict_as(&good));
        prop_assert!(!good.is_at_least_as_strict_as(&bad));
    }

    /// §4.7 `scopes` allowlist: a warrant passes iff its scope identities ⊆ the allowlist.
    #[test]
    fn scopes_constraint_passes_iff_subset(allowed in proptest::collection::btree_set(scope_string(), 0..6), scopes in proptest::collection::vec(scope_entry(), 0..6), c in warrant_claims()) {
        let w = WarrantClaims { scopes: scopes.clone(), ..c };
        let cons = Constraints { aud: None, scopes: Some(allowed.iter().cloned().collect()), max_ttl: None, unknown: Default::default() };
        let subset = scopes.iter().all(|s| allowed.contains(s.scope()));
        prop_assert_eq!(cons.check("config cert", AUD, &w).is_ok(), subset);
    }

    /// Money and duration parsers are total and agree with themselves.
    #[test]
    fn money_and_duration_parsers_are_total(s in "\\PC{0,24}", m in money(), d in iso_duration()) {
        let _ = parse_money_minor(&s);
        let _ = parse_iso_duration_secs(&s);
        let minor = parse_money_minor(&m).unwrap();
        prop_assert_eq!(parse_money_minor(&format!("{}.{:02}", minor / 100, minor % 100)), Some(minor));
        prop_assert!(parse_iso_duration_secs(&d).unwrap() > 0);
    }
}

// ---------------------------------------------------------------------------
// I13 / D1 — subaddressing: an authorization rule only.
// ---------------------------------------------------------------------------

fn cert_for(purpose: Purpose, identities: Vec<String>) -> DeviceCert {
    let k = KeyPair::from_seed(&[9u8; 32]).unwrap();
    DeviceCert::from_claims(
        DeviceCertClaims {
            typ: TYP_DEVICE_CERT.into(),
            iss: "example.com".into(),
            iat: IAT,
            exp: IAT + DAY,
            purpose,
            holder: Holder::new("br.main").unwrap(),
            identities,
            public_key: k.public_key(),
            status: None,
            managed: None,
            constraints: None,
            prov: None,
        },
        &k,
    )
    .unwrap()
}

proptest! {
    #![proptest_config(cfg())]

    /// A config cert for `l@d` covers `l@d` and `l+tag@d`, and nothing else:
    /// never another domain, never a non-`+` extension of the local part,
    /// never a different local part — and a subaddressed cert never widens
    /// upward or sideways.
    #[test]
    fn config_cert_subaddressing_is_plus_only_same_domain(l in local(), t in tag(), d in domain(), d2 in domain(), ext in "[a-z0-9._-]{1,6}", l2 in local()) {
        let base = format!("{}@{}", l, d);
        let tagged = format!("{}+{}@{}", l, t, d);
        let double = format!("{}+{}+{}@{}", l, t, ext, d);
        let cross = format!("{}@{}", l, d2);
        let cross_tag = format!("{}+{}@{}", l, t, d2);
        let prefix = format!("{}{}@{}", l, ext, d);
        let other = format!("{}@{}", l2, d);
        let other_tag = format!("{}+{}@{}", l2, t, d);
        let sibling_a = format!("{}+{}x@{}", l, t, d);
        let sibling_b = format!("{}+x{}@{}", l, t, d);
        let cert = cert_for(Purpose::Authorization, vec![base.clone()]);
        prop_assert!(cert.authorizes_identity(&base));
        prop_assert!(cert.authorizes_identity(&tagged));
        prop_assert!(cert.authorizes_identity(&double));
        prop_assume!(d2 != d);
        prop_assert!(!cert.authorizes_identity(&cross));
        prop_assert!(!cert.authorizes_identity(&cross_tag));
        prop_assert!(!cert.authorizes_identity(&prefix), "prefix without `+` must not match");
        prop_assume!(l2 != l);
        prop_assert!(!cert.authorizes_identity(&other));
        prop_assert!(!cert.authorizes_identity(&other_tag));
        // Upward / sideways: a cert for the subaddress covers neither the base nor a sibling.
        let sub = cert_for(Purpose::Authorization, vec![tagged]);
        prop_assert!(!sub.authorizes_identity(&base));
        prop_assert!(!sub.authorizes_identity(&sibling_a));
        prop_assert!(!sub.authorizes_identity(&sibling_b));
    }

    /// Spec §4.6 / D1: an AUTHENTICATION cert for `l@d` mints for `l@d` exactly.
    #[test]
    fn auth_cert_identity_is_exact(l in local(), t in tag(), d in domain()) {
        let base = format!("{}@{}", l, d);
        let tagged = format!("{}+{}@{}", l, t, d);
        let cert = cert_for(Purpose::Authentication, vec![base.clone()]);
        prop_assert!(cert.authorizes_identity(&base));
        prop_assert!(!cert.authorizes_identity(&tagged), "auth cert must not widen to a subaddress (I13)");
    }

    /// On a config cert, everything that is not `+`-subaddressing is exact.
    #[test]
    fn config_cert_non_subaddress_matching_is_exact(a in email(), b in email()) {
        let cert = cert_for(Purpose::Authorization, vec![a.clone()]);
        prop_assert!(cert.authorizes_identity(&a));
        let (al, ad) = email_parts(&a).unwrap();
        let (bl, bd) = email_parts(&b).unwrap();
        let is_sub = ad == bd && bl.len() > al.len() && bl.starts_with(al) && bl.as_bytes()[al.len()] == b'+';
        prop_assert_eq!(cert.authorizes_identity(&b), a == b || is_sub);
    }

    /// The §4.3 glob `pre*post@d` is confined to the local part of one domain.
    #[test]
    fn glob_is_local_part_only_and_domain_anchored(pre in "[a-z0-9]{0,4}", post in "[a-z0-9]{0,4}", mid in "[a-z0-9+]{0,8}", d in domain(), d2 in domain()) {
        let cert = cert_for(Purpose::Authorization, vec![format!("{}*{}@{}", pre, post, d)]);
        let candidate = format!("{}{}{}@{}", pre, mid, post, d);
        let cross = format!("{}{}{}@{}", pre, mid, post, d2);
        let subdomain = format!("{}{}{}@{}.{}", pre, mid, post, d, d2);
        let well_formed = email_parts(&candidate).is_some();
        prop_assert_eq!(cert.authorizes_identity(&candidate), well_formed);
        prop_assume!(d2 != d);
        prop_assert!(!cert.authorizes_identity(&cross));
        prop_assert!(!cert.authorizes_identity(&subdomain));
    }

    /// Grantee matchers (admission-only) cover exactly: any well-formed email
    /// for `*`, any local part at exactly that domain for `*@d`.
    #[test]
    fn grantee_matchers_cover_exactly_their_domain(subject in email(), d in domain(), junk in "[^@]{0,12}|[^@]*@[^@]*@[^@]*") {
        let (_, sd) = email_parts(&subject).unwrap();
        let matcher = format!("*@{}", d);
        let sub = format!("x@sub.{}", d);
        prop_assert!(grantee_covers("*", &subject));
        prop_assert_eq!(grantee_covers(&matcher, &subject), sd == d);
        prop_assert!(!grantee_covers(&matcher, &sub));
        prop_assert!(!grantee_covers("*", &junk));
        prop_assert!(!grantee_covers(&matcher, &junk));
    }
}

// ---------------------------------------------------------------------------
// I14 — the holder carried by a minted access cert is the device cert's, and
// the verifier binds the warrant to exactly that holder.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(cfg())]

    /// Core's half of I14: `AccessCert::create` copies the device cert's
    /// holder verbatim, and the presentation verifier accepts the bundle iff
    /// the warrant's matcher covers that holder (never some other holder).
    /// The mint-side equality check (requested holder == device holder) is
    /// `browserid-broker/src/routes/device.rs:495` and is WS5's surface.
    #[test]
    fn access_cert_holder_is_the_device_holder_and_the_verifier_binds_to_it(dc in device_claims(), idp in key_strategy(), access in key_strategy(), config in key_strategy(), m in holder_matcher(), other in holder()) {
        let dev = DeviceCert::from_claims(DeviceCertClaims { purpose: Purpose::Authentication, ..dc.clone() }, &idp).unwrap();
        let identity = dc.identities[0].clone();
        let ac = AccessCert::create(&dc.iss, &identity, dev.holder().clone(), &access.public_key(), chrono::Duration::hours(24), &idp, dc.status.clone()).unwrap();
        prop_assert_eq!(ac.claims().holder.as_str(), dev.holder().as_str());
        let reparsed = AccessCert::parse(ac.encoded()).unwrap();
        prop_assert_eq!(&reparsed.claims().holder, dev.holder());

        let cc = DeviceCert::from_claims(DeviceCertClaims { purpose: Purpose::Authorization, public_key: config.public_key(), identities: vec![identity.clone()], iat: IAT, exp: IAT + DAY, ..dc.clone() }, &idp).unwrap();
        let ac = AccessCert::from_claims(AccessCertClaims { typ: TYP_ACCESS_CERT.into(), iss: dc.iss.clone(), iat: IAT, exp: IAT + DAY, identity: identity.clone(), holder: dev.holder().clone(), access_key: access.public_key(), status: None, constraints: None }, &idp).unwrap();
        let w = Warrant::from_claims(WarrantClaims { typ: TYP_WARRANT_V2.into(), iat: IAT, exp: IAT + DAY, grantor: identity.clone(), grantee: identity, holder: None, binding: Some(Binding::Holder { matcher: m.clone() }.into()), audience: AUD.into(), scopes: vec![], status: Some(StatusRef { uri: STATUS.into(), idx: 0 }), unknown: Default::default() }, &config).unwrap();
        let p = AccessPresentation { access_cert: ac, assertion: Assertion::create(AUD, chrono::Duration::days(3650), &access).unwrap(), warrant: w, config_cert: cc };
        let k = idp.public_key();
        let r = p.verify_at(AUD, AT, |_| Ok(k.clone()));
        let expected = m.matches(dev.holder());
        prop_assert_eq!(r.is_ok(), expected, "matcher {:?} vs holder {:?}", m.as_str(), dev.holder().as_str());
        if let Ok(v) = r {
            prop_assert_eq!(&v.holder, dev.holder());
            prop_assume!(&other != dev.holder());
            prop_assert_ne!(&v.holder, &other);
        }
    }

    /// Holder matcher semantics are exact: `*` everything, `ns.*` exactly the
    /// namespace (dot required), anything else byte-equal.
    #[test]
    fn holder_matcher_semantics_are_exact(ns in "[a-z0-9]{1,6}", rest in "[a-z0-9.]{1,12}", h in "[ -~]{1,40}") {
        let holder = Holder::new(h.clone()).unwrap();
        prop_assert!(HolderMatcher::new("*").unwrap().matches(&holder));
        prop_assert_eq!(HolderMatcher::new(h.clone()).unwrap().matches(&holder), true);
        let m = HolderMatcher::new(format!("{}.*", ns)).unwrap();
        let inside = Holder::new(format!("{}.{}", ns, rest)).unwrap();
        let outside = Holder::new(format!("{}x.{}", ns, rest)).unwrap();
        let bare = Holder::new(ns.clone()).unwrap();
        prop_assert!(m.matches(&inside));
        prop_assert!(!m.matches(&outside));
        prop_assert!(!m.matches(&bare));
        prop_assert_eq!(m.matches(&holder), h.strip_prefix(ns.as_str()).is_some_and(|r| r.starts_with('.')));
    }

    #[test]
    fn holder_length_bounds(s in "[ -~]{0,200}") {
        let ok = !s.is_empty() && s.len() <= 128;
        prop_assert_eq!(Holder::new(s.clone()).is_ok(), ok);
        prop_assert_eq!(HolderMatcher::new(s).is_ok(), ok);
    }
}

// ---------------------------------------------------------------------------
// iat / exp bounds (S6 / D16 generalised).
// ---------------------------------------------------------------------------

fn fx_bundle(iat_w: i64, exp_w: i64) -> (AccessPresentation, KeyPair) {
    let idp = KeyPair::from_seed(&[1; 32]).unwrap();
    let access = KeyPair::from_seed(&[3; 32]).unwrap();
    let config = KeyPair::from_seed(&[4; 32]).unwrap();
    let user = "user@example.com";
    let h = Holder::new("br.main").unwrap();
    let ac = AccessCert::from_claims(AccessCertClaims { typ: TYP_ACCESS_CERT.into(), iss: "example.com".into(), iat: IAT, exp: IAT + DAY, identity: user.into(), holder: h.clone(), access_key: access.public_key(), status: None, constraints: None }, &idp).unwrap();
    let cc = DeviceCert::from_claims(DeviceCertClaims { typ: TYP_DEVICE_CERT.into(), iss: "example.com".into(), iat: IAT, exp: IAT + 90 * DAY, purpose: Purpose::Authorization, holder: h, identities: vec![user.into()], public_key: config.public_key(), status: None, managed: None, constraints: None, prov: None }, &idp).unwrap();
    let w = Warrant::from_claims(WarrantClaims { typ: TYP_WARRANT_V2.into(), iat: iat_w, exp: exp_w, grantor: user.into(), grantee: user.into(), holder: None, binding: Some(Binding::Holder { matcher: HolderMatcher::new("*").unwrap() }.into()), audience: AUD.into(), scopes: vec![], status: Some(StatusRef { uri: STATUS.into(), idx: 0 }), unknown: Default::default() }, &config).unwrap();
    (AccessPresentation { access_cert: ac, assertion: Assertion::create(AUD, chrono::Duration::days(3650), &access).unwrap(), warrant: w, config_cert: cc }, idp)
}

proptest! {
    #![proptest_config(cfg())]

    /// `max-ttl` is `exp − iat`: the subtraction must never overflow (today
    /// it panics under debug assertions and wraps in release, where a wrapped
    /// negative difference passes any `max-ttl`).
    #[test]
    fn max_ttl_check_never_overflows(iat in any::<i64>(), exp in any::<i64>(), max in 0i64..(1 << 40)) {
        let cons = Constraints { aud: None, scopes: None, max_ttl: Some(max), unknown: Default::default() };
        let w = WarrantClaims { typ: TYP_WARRANT_V2.into(), iat, exp, grantor: "u@example.com".into(), grantee: "u@example.com".into(), holder: None, binding: None, audience: AUD.into(), scopes: vec![], status: None, unknown: Default::default() };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cons.check("config cert", AUD, &w).is_ok()));
        let ok = r.expect("max-ttl check panicked (i64 overflow)");
        // Once fixed: an inverted window (iat > exp) never passes, and an
        // honest width is compared exactly (D16).
        if iat > exp { prop_assert!(!ok, "iat > exp passed max-ttl"); }
        else { prop_assert_eq!(ok, exp.checked_sub(iat).is_some_and(|d| d <= max)); }
    }

    /// `exp − iat` with an honest `iat` is enforced exactly at the boundary.
    #[test]
    fn max_ttl_is_exact_for_honest_windows(iat in 0i64..(1 << 40), width in 0i64..(1 << 31), max in 0i64..(1 << 31)) {
        let cons = Constraints { aud: None, scopes: None, max_ttl: Some(max), unknown: Default::default() };
        let w = WarrantClaims { typ: TYP_WARRANT_V2.into(), iat, exp: iat + width, grantor: "u@example.com".into(), grantee: "u@example.com".into(), holder: None, binding: None, audience: AUD.into(), scopes: vec![], status: None, unknown: Default::default() };
        prop_assert_eq!(cons.check("config cert", AUD, &w).is_ok(), width <= max);
    }

    /// S6 generalised: a warrant with `iat > exp`, or an `iat` in the future
    /// of the verification instant, never verifies.
    #[test]
    fn warrant_iat_is_bounded_by_exp_and_now(iat in (AT + 3600)..(AT + 10 * DAY), exp_after in 1i64..DAY, inverted in any::<bool>()) {
        // Inverted: not yet expired at AT, but issued after it expires.
        let (iat_w, exp_w) = if inverted { (AT + exp_after + 1, AT + 1) } else { (iat, iat + exp_after) };
        let (p, idp) = fx_bundle(iat_w, exp_w);
        let k = idp.public_key();
        let r = p.verify_at(AUD, AT, |_| Ok(k.clone()));
        prop_assert!(r.is_err(), "iat={} exp={} at={}", iat_w, exp_w, AT);
    }

    /// Expiry is a strict `at > exp` comparison on every object, with no
    /// arithmetic — total over the whole i64 range.
    #[test]
    fn expiry_comparison_is_total(exp in any::<i64>(), at in any::<i64>(), iat in any::<i64>()) {
        let k = KeyPair::from_seed(&[2; 32]).unwrap();
        let c = DeviceCert::from_claims(DeviceCertClaims { typ: TYP_DEVICE_CERT.into(), iss: "example.com".into(), iat, exp, purpose: Purpose::Authorization, holder: Holder::new("h").unwrap(), identities: vec!["u@example.com".into()], public_key: k.public_key(), status: None, managed: None, constraints: None, prov: None }, &k).unwrap();
        prop_assert_eq!(c.is_expired_at(at), at > exp);
        let a = AccessCert::from_claims(AccessCertClaims { typ: TYP_ACCESS_CERT.into(), iss: "example.com".into(), iat, exp, identity: "u@example.com".into(), holder: Holder::new("h").unwrap(), access_key: k.public_key(), status: None, constraints: None }, &k).unwrap();
        prop_assert_eq!(a.is_expired_at(at), at > exp);
    }

    /// Status-list freshness is `iat + ttl + grace`: with an issuer-chosen
    /// `iat`/`ttl` the sum must not overflow (today it panics under debug
    /// assertions; in release it wraps negative, which happens to fail
    /// closed). `ttl` is capped by `is_fresh_capped` but `iat` is not.
    #[test]
    fn status_list_freshness_never_overflows(iat in any::<i64>(), ttl in any::<i64>(), grace in 0i64..3600, max_ttl in 1i64..100_000) {
        let k = KeyPair::from_seed(&[5; 32]).unwrap();
        let claims = serde_json::json!({ "typ": browserid_core::TYP_STATUS_LIST, "iss": "example.com", "sub": STATUS, "iat": iat, "ttl": ttl, "status_list": { "bits": 1, "lst": StatusList::from_revoked([], 8).encode().unwrap() } });
        let h = B64.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let c = B64.encode(claims.to_string());
        let msg = format!("{h}.{c}");
        let tok = format!("{msg}.{}", B64.encode(k.sign(msg.as_bytes())));
        let t = StatusListToken::parse(&tok).unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (t.is_fresh(grace), t.is_fresh_capped(grace, max_ttl))));
        prop_assert!(r.is_ok(), "freshness arithmetic panicked for iat={} ttl={}", iat, ttl);
    }
}

// ---------------------------------------------------------------------------
// Parsers are total: JWS objects, DNS TXT, status lists, scope entries.
// ---------------------------------------------------------------------------

/// Reference check for the one scope grammar `^[a-z0-9_:.\-/*@+]{1,128}$`.
fn scope_grammar(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b':' | b'.' | b'-' | b'/' | b'*' | b'@' | b'+'))
}

proptest! {
    #![proptest_config(cfg())]

    /// Every compact-serialization parser returns `Err`, never panics, on
    /// arbitrary text — including three-part strings with arbitrary base64
    /// payloads and arbitrary JSON claim sets.
    #[test]
    fn jws_parsers_are_total(s in "\\PC{0,200}", parts in proptest::collection::vec("[A-Za-z0-9_-]{0,80}", 0..5), body in "\\PC{0,120}") {
        let dotted = parts.join(".");
        let three = format!("{}.{}.{}", B64.encode("{\"alg\":\"EdDSA\"}"), B64.encode(&body), B64.encode([0u8; 64]));
        for input in [s.as_str(), dotted.as_str(), three.as_str()] {
            let _ = DeviceCert::parse(input);
            let _ = AccessCert::parse(input);
            let _ = AccessRequest::parse(input);
            let _ = Warrant::parse(input);
            let _ = Assertion::parse(input);
            let _ = StatusListToken::parse(input);
            let _ = AccessPresentation::parse(input);
            let _ = RecordBundle::parse(input);
            let _ = DnsRecord::parse(input);
            let _ = StatusList::decode(input);
        }
    }

    /// A parsed object with a tampered payload never verifies under the key
    /// that signed the original.
    #[test]
    fn payload_tampering_is_detected(c in device_claims(), idp in key_strategy(), flip in 0usize..64) {
        let cert = DeviceCert::from_claims(c, &idp).unwrap();
        let parts: Vec<&str> = cert.encoded().split('.').collect();
        let mut payload = B64.decode(parts[1]).unwrap();
        let i = flip % payload.len();
        payload[i] ^= 0x01;
        let forged = format!("{}.{}.{}", parts[0], B64.encode(&payload), parts[2]);
        if let Ok(f) = DeviceCert::parse(&forged) {
            prop_assert!(f.verify(&idp.public_key()).is_err());
        }
    }

    /// DNS TXT parsing is total and never upgrades a malformed record to a
    /// key (July M5 class): `Ok` means exactly `v=browserid1`, exactly
    /// `Ed25519`, and a key byte-equal to the base64url of the `public-key`
    /// field. Spaces around `=` and `;` are tolerated; nothing else is.
    #[test]
    fn dns_txt_parser_is_total_and_never_upgrades(txt in "\\PC{0,160}", raw in proptest::collection::vec(any::<u8>(), 0..160), k in key_strategy(), junk in "[^;=]{0,20}", host in proptest::option::of("[a-z.]{1,20}")) {
        let _ = DnsRecord::parse(&txt);
        let lossy = String::from_utf8_lossy(&raw);
        if let Ok(r) = DnsRecord::parse(&lossy) {
            prop_assert_eq!(r.version.as_str(), "browserid1");
            prop_assert_eq!(r.algorithm.as_str(), "Ed25519");
            // The parser keeps the LAST `public-key=` field.
            let field = lossy.split(';').map(str::trim).filter_map(|p| p.split_once('=')).filter(|(k, _)| k.trim() == "public-key").last().map(|(_, v)| v.trim().to_string()).unwrap();
            prop_assert_eq!(r.public_key.to_base64(), field);
        }
        // A well-formed record round-trips its key; dropping any required
        // field, or any other version/algorithm, rejects.
        prop_assume!(!["v", "public-key-algorithm", "public-key", "host"].contains(&junk.trim()));
        let pk = k.public_key().to_base64();
        let hostpart = host.as_ref().map(|h| format!("; host={}", h)).unwrap_or_default();
        let good = format!("v=browserid1; public-key-algorithm=Ed25519; public-key={}{}; {}=x", pk, hostpart, junk);
        let r = DnsRecord::parse(&good).unwrap();
        prop_assert_eq!(r.public_key, k.public_key());
        prop_assert_eq!(r.host.as_deref(), host.as_deref());
        let bad = [
            format!("public-key-algorithm=Ed25519; public-key={}", pk),
            format!("v=browserid1; public-key={}", pk),
            "v=browserid1; public-key-algorithm=Ed25519".to_string(),
            format!("v=browserid2; public-key-algorithm=Ed25519; public-key={}", pk),
            format!("v=browserid1; public-key-algorithm=RSA; public-key={}", pk),
            format!("v=browserid1; public-key-algorithm=Ed25519; public-key={}", &pk[..pk.len() - 2]),
        ];
        for b in &bad {
            prop_assert!(DnsRecord::parse(b).is_err(), "accepted malformed record {:?}", b);
        }
    }

    /// Status-list bit reads are total over all of u64; decode rejects any
    /// non-base64 / non-zlib input without panicking.
    #[test]
    fn status_list_reads_are_total(idx in any::<u64>(), list_bytes in proptest::collection::vec(any::<u8>(), 0..64), noise in proptest::collection::vec(any::<u8>(), 0..64)) {
        let list = StatusList::from_revoked([], 8 * list_bytes.len() as u64);
        prop_assert!(!list.is_revoked(idx));
        let _ = StatusList::decode(&B64.encode(&noise));
        let _ = StatusList::decode(&B64.encode(&list_bytes));
    }

    /// Scope entry JSON: a bare string or a parameter object decodes; any
    /// unknown parameter key rejects (invariant 14); decode never panics.
    #[test]
    fn scope_entry_json_is_total_and_rejects_unknown_params(s in "\\PC{0,64}", p in params(), extra in "[a-z_]{1,10}") {
        let _ = serde_json::from_value::<ScopeEntry>(serde_json::Value::String(s));
        let mut v = json(&p);
        prop_assert!(serde_json::from_value::<ScopeEntry>(v.clone()).is_ok());
        prop_assume!(!["scope", "mode", "cap", "counterparties", "max_duration", "min_reputation"].contains(&extra.as_str()));
        v.as_object_mut().unwrap().insert(extra, serde_json::Value::Bool(true));
        prop_assert!(serde_json::from_value::<ScopeEntry>(v).is_err());
    }

    /// Core does not implement the scope-string grammar; this pins the
    /// reference predicate the registrar and fuzz targets share and records
    /// that `ScopeEntry` accepts strings outside it (the grammar is enforced
    /// at request time, registry-api-v1 §3 — see W3-3 for the gap there).
    #[test]
    fn scope_grammar_reference_matches_the_spec_regex(s in "\\PC{0,140}", g in scope_string()) {
        prop_assert!(scope_grammar(&g));
        let by_regex = regex::Regex::new(r"^[a-z0-9_:.\-/*@+]{1,128}$").unwrap().is_match(&s);
        prop_assert_eq!(scope_grammar(&s), by_regex);
        // ScopeEntry::Bare is grammar-agnostic.
        prop_assert!(serde_json::from_value::<ScopeEntry>(serde_json::Value::String(s)).is_ok());
    }
}

/// The W3-1 reproducer, inverted with the fix (bean gdo0): the overflowing
/// `exp − iat` neither panics (debug) nor wraps to a passing width (release)
/// — it is a max-ttl violation.
#[test]
fn w3_1_max_ttl_overflow_reproducer() {
    let cons = Constraints { aud: None, scopes: None, max_ttl: Some(DAY), unknown: Default::default() };
    let w = WarrantClaims { typ: TYP_WARRANT_V2.into(), iat: i64::MIN, exp: 1, grantor: "u@example.com".into(), grantee: "u@example.com".into(), holder: None, binding: None, audience: AUD.into(), scopes: vec![], status: None, unknown: Default::default() };
    let r = std::panic::catch_unwind(|| cons.check("config cert", AUD, &w).is_ok());
    assert_eq!(r.ok(), Some(false), "an overflowing validity width must be a max-ttl violation");
}
