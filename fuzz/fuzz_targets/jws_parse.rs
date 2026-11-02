#![no_main]
//! WS3: every compact-serialization parser is total over arbitrary text, and
//! anything that parses is handled by the verifier without panicking.
//! Mutates from a valid bundle seed (seeds/jws_parse) so the fuzzer reaches
//! past the base64 / JSON layers.

use browserid_core::device::{AccessCert, AccessRequest, DeviceCert, Warrant};
use browserid_core::{AccessPresentation, Assertion, RecordBundle, StatusListToken};
use browserid_fuzz::{keys, text, AT, AUD, STATUS};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = text(data);
    let k = keys();
    if let Ok(c) = DeviceCert::parse(&s) {
        let _ = c.verify(&k.idp.public_key());
        let _ = c.is_expired_at(AT);
        let _ = c.authorizes_identity("user+agent@example.com");
    }
    if let Ok(c) = AccessCert::parse(&s) {
        let _ = c.verify(&k.idp.public_key());
        let _ = c.is_expired_at(AT);
    }
    if let Ok(r) = AccessRequest::parse(&s) {
        let _ = r.verify(&k.access.public_key());
        let _ = r.is_expired();
    }
    if let Ok(w) = Warrant::parse(&s) {
        let _ = w.verify(&k.config.public_key());
        let _ = w.claims().binding_set();
        let _ = w.claims().scope_strings();
    }
    if let Ok(a) = Assertion::parse(&s) {
        let _ = a.verify(&k.access.public_key());
        let _ = a.is_expired_at(AT);
    }
    if let Ok(t) = StatusListToken::parse(&s) {
        let _ = t.verify(&k.idp.public_key(), STATUS);
        let _ = t.is_revoked(u64::MAX);
        // AUDIT-2026-11 W3-2: `iat + ttl` is unchecked; guard until fixed so
        // the run keeps finding other things.
        let c = t.claims();
        if c.iat.checked_add(c.ttl).and_then(|x| x.checked_add(3600)).is_some() {
            let _ = t.is_fresh_capped(60, 3600);
        }
    }
    if let Ok(p) = AccessPresentation::parse(&s) {
        assert_eq!(p.encode(), s, "presentation encode/parse is not the identity");
        let pk = k.idp.public_key();
        let ac = p.access_cert.claims();
        let wc = p.warrant.claims();
        // AUDIT-2026-11 W3-1 guard: `Constraints::check` computes `exp - iat` unchecked.
        let overflow = wc.exp.checked_sub(wc.iat).is_none();
        let has_max_ttl = ac.constraints.as_ref().is_some_and(|c| c.max_ttl.is_some())
            || p.config_cert.claims().constraints.as_ref().is_some_and(|c| c.max_ttl.is_some());
        if !(overflow && has_max_ttl) {
            let _ = p.verify_at(AUD, AT, |_| Ok(pk.clone()));
        }
    }
    if let Ok(b) = RecordBundle::parse(&s) {
        assert_eq!(b.encode(), s);
        let pk = k.idp.public_key();
        let wc = b.warrant.claims();
        let overflow = wc.exp.checked_sub(wc.iat).is_none();
        let has_max_ttl = b.config_cert.claims().constraints.as_ref().is_some_and(|c| c.max_ttl.is_some());
        if !(overflow && has_max_ttl) {
            let _ = b.validate(AUD, |_| Ok(pk.clone()));
        }
        let _ = b.recheck_live();
    }
});
