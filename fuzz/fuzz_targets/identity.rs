#![no_main]
//! WS3: identity comparison and holder matching are total on arbitrary
//! strings, and `identity_matches` (via a config cert) agrees with a
//! reference re-implementation of spec §4.3/§4.6 — glob confined to the
//! local part, `+`-subaddressing only, never cross-domain.

use arbitrary::Arbitrary;
use browserid_core::device::{DeviceCert, DeviceCertClaims, TYP_DEVICE_CERT};
use browserid_core::identity::{domain_eq, email_parts, grantee_covers, identity_eq, normalize_domain};
use browserid_core::{Holder, HolderMatcher, Purpose};
use browserid_fuzz::{keys, DAY, IAT};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    pattern: String,
    email: String,
    holder: String,
    matcher: String,
}

/// Reference: spec §4.3 glob + §4.6 subaddressing as `device.rs` documents it
/// (domain byte-exact in the exact and subaddress branches — W6-1).
fn reference(pattern: &str, email: &str) -> bool {
    if pattern == email {
        return true;
    }
    let (Some((pl, pd)), Some((el, ed))) = (email_parts(pattern), email_parts(email)) else { return false };
    if pattern.contains('*') {
        if pd.contains('*') || !domain_eq(pd, ed) { return false; }
        let Some((pre, post)) = pl.split_once('*') else { return false };
        if post.contains('*') { return false; }
        return el.len() >= pre.len() + post.len() && el.starts_with(pre) && el.ends_with(post);
    }
    pd == ed && el.len() > pl.len() && el.starts_with(pl) && el.as_bytes()[pl.len()] == b'+'
}

fuzz_target!(|input: Input| {
    let _ = identity_eq(&input.pattern, &input.email);
    let _ = grantee_covers(&input.pattern, &input.email);
    let _ = email_parts(&input.email);
    if let Some(n) = normalize_domain(&input.pattern) {
        assert_eq!(normalize_domain(&n).as_deref(), Some(n.as_str()), "domain normalization not idempotent");
    }
    if let (Ok(h), Ok(m)) = (Holder::new(input.holder.clone()), HolderMatcher::new(input.matcher.clone())) {
        let got = m.matches(&h);
        let expect = m.as_str() == "*"
            || m.as_str().strip_suffix(".*").map_or(m.as_str() == h.as_str(), |ns| h.as_str().strip_prefix(ns).is_some_and(|r| r.starts_with('.')));
        assert_eq!(got, expect);
    }
    let k = &keys().idp;
    let cert = DeviceCert::from_claims(DeviceCertClaims {
        typ: TYP_DEVICE_CERT.into(), iss: "example.com".into(), iat: IAT, exp: IAT + DAY,
        purpose: Purpose::Authorization, holder: Holder::new("h").unwrap(), identities: vec![input.pattern.clone()],
        public_key: k.public_key(), status: None, managed: None, constraints: None, prov: None,
    }, k).unwrap();
    let got = cert.authorizes_identity(&input.email);
    assert_eq!(got, reference(&input.pattern, &input.email), "identity_matches({:?}, {:?})", input.pattern, input.email);
    if got && input.pattern != input.email {
        // Never cross-domain, whichever branch matched.
        let (_, pd) = email_parts(&input.pattern).unwrap();
        let (_, ed) = email_parts(&input.email).unwrap();
        assert!(domain_eq(pd, ed), "matched across domains: {:?} vs {:?}", input.pattern, input.email);
    }
});
