#![no_main]
//! WS3: arbitrary JSON claim sets for every object type, signed under the
//! fixture keys and pushed through the typed parsers and the verifier. This
//! reaches the claim-level validation (`validate_claims`, `Constraints::check`,
//! binding deserialization) that `jws_parse` only hits once the fuzzer has
//! reconstructed base64.

use arbitrary::Arbitrary;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use browserid_core::device::{AccessCert, AccessRequest, DeviceCert, Warrant};
use browserid_core::{AccessPresentation, RecordBundle, StatusListToken};
use browserid_fuzz::{self as fx, keys, AT, AUD};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Which {
    Device,
    Access,
    Request,
    Warrant,
    Status,
}

#[derive(Arbitrary, Debug)]
struct Input {
    which: Which,
    /// The claim set, as JSON text (the fuzzer learns the shape from seeds).
    json: String,
    /// Header to sign under — `None` means the canonical EdDSA header.
    header: Option<String>,
}

fn sign(header: &str, claims: &str, key: &browserid_core::KeyPair) -> String {
    let msg = format!("{}.{}", B64.encode(header), B64.encode(claims));
    format!("{msg}.{}", B64.encode(key.sign(msg.as_bytes())))
}

fuzz_target!(|input: Input| {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&input.json) else { return };
    let claims = v.to_string();
    let header = input.header.as_deref().unwrap_or(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let k = keys();
    match input.which {
        Which::Device => {
            let s = sign(header, &claims, &k.idp);
            if let Ok(c) = DeviceCert::parse(&s) {
                let _ = c.verify(&k.idp.public_key());
                let _ = c.authorizes_identity(fx::USER);
                let _ = c.authorizes_identity("user+a@example.com");
                // Reparse of a reserialization is stable.
                let again = serde_json::to_string(c.claims()).unwrap();
                let c2 = DeviceCert::parse(&sign(header, &again, &k.idp)).unwrap();
                assert_eq!(serde_json::to_value(c2.claims()).unwrap(), serde_json::to_value(c.claims()).unwrap());
                // As a config cert in an otherwise valid bundle.
                let wc = fx::warrant();
                let p = AccessPresentation { access_cert: fx::access_cert(), assertion: fx::assertion(), warrant: wc, config_cert: c };
                let pk = k.idp.public_key();
                let _ = p.verify_at(AUD, AT, |_| Ok(pk.clone()));
            }
        }
        Which::Access => {
            let s = sign(header, &claims, &k.idp);
            if let Ok(c) = AccessCert::parse(&s) {
                let _ = c.verify(&k.idp.public_key());
                let p = AccessPresentation { access_cert: c, assertion: fx::assertion(), warrant: fx::warrant(), config_cert: fx::config_cert() };
                let pk = k.idp.public_key();
                let _ = p.verify_at(AUD, AT, |_| Ok(pk.clone()));
            }
        }
        Which::Request => {
            let s = sign(header, &claims, &k.access);
            if let Ok(r) = AccessRequest::parse(&s) {
                let _ = r.verify(&k.access.public_key());
            }
        }
        Which::Warrant => {
            let s = sign(header, &claims, &k.config);
            if let Ok(w) = Warrant::parse(&s) {
                let _ = w.verify(&k.config.public_key());
                let bs = w.claims().binding_set();
                let _ = (bs.has_holder(), bs.has_connection(), bs.has_requester(), bs.holder_matcher(), bs.requester_origin(), bs.connection());
                let p = AccessPresentation { access_cert: fx::access_cert(), assertion: fx::assertion(), warrant: w.clone(), config_cert: fx::config_cert() };
                let pk = k.idp.public_key();
                let _ = p.verify_at(AUD, AT, |_| Ok(pk.clone()));
                let b = RecordBundle { warrant: w, config_cert: fx::config_cert() };
                let _ = b.validate(AUD, |_| Ok(pk.clone()));
            }
        }
        Which::Status => {
            let s = sign(header, &claims, &k.idp);
            if let Ok(t) = StatusListToken::parse(&s) {
                let _ = t.verify(&k.idp.public_key(), fx::STATUS);
                let _ = t.is_revoked(0);
                // Freshness arithmetic is checked (W3-2 fixed, bean gdo0).
                let _ = t.is_fresh_capped(60, 3600);
                let _ = t.is_fresh_capped_at(AT, 60, 3600);
            }
        }
    }
});
