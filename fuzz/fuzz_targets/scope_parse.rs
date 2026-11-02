#![no_main]
//! WS3: scope entries and their parameters — JSON decode, the money and
//! duration parsers, and the stricter-wins order — never panic, and the
//! order is reflexive on anything well-formed.

use arbitrary::Arbitrary;
use browserid_core::device::{parse_iso_duration_secs, parse_money_minor};
use browserid_core::{Cap, ScopeEntry, ScopeParams};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    a: String,
    b: String,
    raw: String,
}

fn well_formed(p: &ScopeParams) -> bool {
    p.cap.as_ref().map_or(true, |c| c.amount_minor().is_some() && c.window_secs().is_ok())
        && p.max_duration.as_deref().map_or(true, |d| parse_iso_duration_secs(d).is_some())
}

fuzz_target!(|input: Input| {
    let _ = parse_money_minor(&input.raw);
    let _ = parse_iso_duration_secs(&input.raw);
    let _ = serde_json::from_str::<ScopeEntry>(&input.raw);
    let _ = serde_json::from_str::<Cap>(&input.raw);
    let a = serde_json::from_str::<ScopeEntry>(&input.a).ok();
    let b = serde_json::from_str::<ScopeEntry>(&input.b).ok();
    if let Some(a) = &a {
        let _ = (a.scope(), a.mode(), a.cap(), a.counterparties(), a.max_duration(), a.min_reputation());
        if let Some(p) = a.params() {
            let refl = p.is_at_least_as_strict_as(p);
            assert!(refl || !well_formed(p), "stricter-wins order not reflexive on well-formed {p:?}");
            if let Some(m) = &p.min_reputation {
                let _ = m.is_well_formed();
                assert!(m.is_at_least_as_strict_as(m));
            }
            if let Some(c) = &p.cap {
                let _ = c.is_at_least_as_strict_as(c);
            }
        }
    }
    if let (Some(a), Some(b)) = (a.as_ref().and_then(ScopeEntry::params), b.as_ref().and_then(ScopeEntry::params)) {
        let ab = a.is_at_least_as_strict_as(b);
        let ba = b.is_at_least_as_strict_as(a);
        // Antisymmetry on the observable projections: mutual strictness means
        // equal cap amounts and equal durations.
        if ab && ba {
            if let (Some(x), Some(y)) = (&a.cap, &b.cap) {
                assert_eq!(x.amount_minor(), y.amount_minor());
            }
            if let (Some(x), Some(y)) = (&a.max_duration, &b.max_duration) {
                assert_eq!(parse_iso_duration_secs(x), parse_iso_duration_secs(y));
            }
        }
    }
});
