//! Security audit 2026-11, WS3 — property tests for the registrar's
//! request-time shape checks (registry-api-v1 §3: "the one scope grammar",
//! request-kinds/warrant.json). Lives under `consent` because the checks
//! are `pub(crate)`.
//!
//! Report: docs/security-audit-2026-11-ws3-fuzz-proptest.md.

use super::{validate_grant_shape, validate_scope_params, RecordRequestBody, WarrantRequestBody};
use browserid_core::{Cap, MinReputation, ScopeEntry, ScopeParams};
use proptest::prelude::*;

const CASES: u32 = 256;

/// `^[a-z0-9_:.\-/*@+]{1,128}$` — registry-api-v1 §3.
fn scope_grammar(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b':' | b'.' | b'-' | b'/' | b'*' | b'@' | b'+'))
}

fn in_grammar() -> impl Strategy<Value = String> {
    "[a-z0-9_:.\\-/*@+]{1,128}"
}
fn good_audience() -> impl Strategy<Value = String> {
    "https://[a-z]{1,10}\\.example(:[0-9]{2,4})?"
}
fn iso_duration() -> impl Strategy<Value = String> {
    prop_oneof![(1u32..400).prop_map(|d| format!("P{d}D")), (1u32..1000).prop_map(|h| format!("PT{h}H"))]
}
fn good_params() -> impl Strategy<Value = ScopeParams> {
    (
        in_grammar(),
        proptest::option::of(("[0-9]{1,6}(\\.[0-9]{1,2})?", "[A-Z]{3}", proptest::option::of(iso_duration())).prop_map(|(amount, currency, window)| Cap { amount, currency, window })),
        proptest::option::of(proptest::collection::vec(prop_oneof!["[a-z]{1,8}@[a-z]{1,8}\\.example", "\\*@[a-z]{1,8}\\.example"], 1..5)),
        proptest::option::of(iso_duration()),
        proptest::option::of(("https://[a-z]{1,8}\\.example", 0u8..=100).prop_map(|(indexer, score)| MinReputation { indexer, score })),
    )
        .prop_map(|(scope, cap, counterparties, max_duration, min_reputation)| ScopeParams { scope, mode: None, cap, counterparties, max_duration, min_reputation })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: CASES, ..ProptestConfig::default() })]

    /// registry-api-v1 §3 and request-kinds/warrant.json both pin the scope
    /// string to the one grammar. The registrar's request-time check accepts
    /// a bare scope iff it matches (W3-3, bean lu7i: it calls
    /// `browserid_core::validate_scope_string`).
    #[test]
    fn grant_shape_accepts_exactly_the_scope_grammar(aud in good_audience(), s in "\\PC{0,140}", g in in_grammar()) {
        prop_assert!(validate_grant_shape(&aud, &[ScopeEntry::Bare(g)]).is_ok());
        prop_assert_eq!(validate_grant_shape(&aud, &[ScopeEntry::Bare(s.clone())]).is_ok(), scope_grammar(&s), "scope {:?}", s);
    }

    /// The shape check is total and bounds what it does bound: audience
    /// non-empty, no `*`, no whitespace/control, ≤ 512 bytes; ≤ 32 scopes,
    /// each in the grammar.
    #[test]
    fn grant_shape_is_total_and_bounds_sizes(aud in "\\PC{0,600}", scopes in proptest::collection::vec("\\PC{0,140}", 0..40)) {
        let entries: Vec<ScopeEntry> = scopes.iter().cloned().map(ScopeEntry::Bare).collect();
        let r = validate_grant_shape(&aud, &entries);
        let aud_ok = !aud.is_empty() && !aud.contains('*') && aud.len() <= 512 && !aud.chars().any(|c| c.is_whitespace() || c.is_control());
        let scopes_ok = entries.len() <= 32 && scopes.iter().all(|s| scope_grammar(s));
        prop_assert_eq!(r.is_ok(), aud_ok && scopes_ok);
    }

    /// Well-formed parameters pass; any parameter the consumer could not
    /// parse is refused at request time (never signed into a record).
    #[test]
    fn scope_params_well_formed_pass_and_malformed_reject(p in good_params(), bad_amount in "[^0-9.]{1,6}|[0-9]+\\.[0-9]{3,4}", bad_cur in "[a-z]{3}|[A-Z]{2}|[A-Z]{4}", bad_dur in "[^P][ -~]{0,6}", big in 101u8..=255) {
        prop_assert!(validate_scope_params(&ScopeEntry::Parameterized(p.clone())).is_ok(), "{:?}", p);
        let cap = p.cap.clone().unwrap_or(Cap { amount: "1".into(), currency: "USD".into(), window: None });
        let with = |cap: Cap| ScopeEntry::Parameterized(ScopeParams { cap: Some(cap), ..p.clone() });
        let bad = [
            with(Cap { amount: bad_amount, ..cap.clone() }),
            with(Cap { currency: bad_cur, ..cap.clone() }),
            with(Cap { window: Some(bad_dur.clone()), ..cap }),
            ScopeEntry::Parameterized(ScopeParams { max_duration: Some(bad_dur), ..p.clone() }),
            ScopeEntry::Parameterized(ScopeParams { min_reputation: Some(MinReputation { indexer: "https://i.example".into(), score: big }), ..p.clone() }),
            ScopeEntry::Parameterized(ScopeParams { counterparties: Some(vec![]), ..p.clone() }),
            ScopeEntry::Parameterized(ScopeParams { counterparties: Some(vec!["a@b@c".into()]), ..p }),
        ];
        for e in &bad {
            let rejected = validate_scope_params(e).is_err();
            prop_assert!(rejected, "accepted malformed parameter {:?}", e);
        }
    }

    /// Request-kind bodies: deserialization is total over arbitrary JSON and
    /// a schema-shaped `warrant` / `admission` body decodes.
    #[test]
    fn request_kind_bodies_decode_totally(v in proptest::arbitrary::any::<bool>().prop_flat_map(|_| arb_json(4)), aud in good_audience(), g in in_grammar(), p in good_params()) {
        let _ = serde_json::from_value::<WarrantRequestBody>(v.clone());
        let _ = serde_json::from_value::<RecordRequestBody>(v);
        let w = serde_json::json!({ "device_cert": "x.y.z", "identity": "a@b.example", "grants": [{ "audience": aud, "scopes": [g, serde_json::to_value(&p).unwrap()] }], "message": "m" });
        let w: WarrantRequestBody = serde_json::from_value(w).unwrap();
        let n = w.grants[0].scopes.len();
        prop_assert_eq!(n, 2);
        let a = serde_json::json!({ "type": "connection", "audience": aud, "scopes": [g], "client": { "client_host": "h.example" } });
        let ok = serde_json::from_value::<RecordRequestBody>(a).is_ok();
        prop_assert!(ok);
    }
}

fn arb_json(depth: u32) -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(|n| serde_json::json!(n)),
        "\\PC{0,20}".prop_map(serde_json::Value::String),
    ];
    leaf.prop_recursive(depth, 32, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(serde_json::Value::Array),
            proptest::collection::btree_map("[a-z_]{1,12}", inner, 0..6).prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
        ]
    })
}
