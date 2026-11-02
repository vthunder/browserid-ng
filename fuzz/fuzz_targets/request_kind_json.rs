#![no_main]
//! WS3: request-kind JSON (docs/specs/request-kinds/*.json) — the schema
//! validator is total over arbitrary JSON, and the registrar's body structs
//! deserialize totally. Differential: a body warrant.json accepts that
//! carries the filed-form fields must deserialize into the registrar's
//! `WarrantRequestBody` (the schema is the wire contract on both lanes).

use browserid_registrar::consent::{RecordRequestBody, WarrantRequestBody};
use jsonschema::Validator;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const SCHEMAS: [(&str, &str); 5] = [
    ("warrant", include_str!("../../docs/specs/request-kinds/warrant.json")),
    ("admission", include_str!("../../docs/specs/request-kinds/admission.json")),
    ("login", include_str!("../../docs/specs/request-kinds/login.json")),
    ("signature", include_str!("../../docs/specs/request-kinds/signature.json")),
    ("provision", include_str!("../../docs/specs/request-kinds/provision.json")),
];

fn validators() -> &'static Vec<(&'static str, Validator)> {
    static V: OnceLock<Vec<(&'static str, Validator)>> = OnceLock::new();
    V.get_or_init(|| {
        // provision.json `$ref`s warrant.json by its `$id`: register every
        // schema under its `$id` so cross-references resolve offline.
        let docs: Vec<(&str, serde_json::Value)> =
            SCHEMAS.iter().map(|(k, s)| (*k, serde_json::from_str(s).unwrap())).collect();
        docs.iter()
            .map(|(k, v)| {
                let mut opts = jsonschema::options();
                for (_, other) in &docs {
                    opts.with_resource(
                        other["$id"].as_str().unwrap().to_string(),
                        jsonschema::Resource::from_contents(other.clone()).unwrap(),
                    );
                }
                (*k, opts.build(v).unwrap())
            })
            .collect()
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else { return };
    let mut valid_kind = None;
    for (kind, val) in validators() {
        if val.is_valid(&v) {
            valid_kind = Some(*kind);
        }
        // The error iterator is the hot path the wallet-side validator uses.
        let _ = val.iter_errors(&v).count();
    }
    let _ = serde_json::from_value::<WarrantRequestBody>(v.clone());
    let _ = serde_json::from_value::<RecordRequestBody>(v.clone());
    // warrant.json leaves scope-family parameters open (`additionalProperties:
    // true`, "a consumer validates it against the family's schema"), while the
    // registrar's `ScopeParams`/`Cap` deny unknown fields — so the differential
    // holds only for the schema's own core subset: bare strings, or objects
    // whose keys are exactly `scope` / `mode`. A family-parameter object the
    // registrar refuses is the fail-closed behaviour the schema text asks for.
    let core_subset = v["grants"].as_array().map_or(true, |gs| {
        gs.iter().all(|g| {
            g["scopes"].as_array().map_or(true, |ss| {
                ss.iter().all(|s| match s {
                    serde_json::Value::Object(o) => o.keys().all(|k| k == "scope" || k == "mode"),
                    _ => true,
                })
            })
        })
    });
    if valid_kind == Some("warrant") && core_subset {
        // The registrar's filed form needs device_cert + identity on top of
        // the schema's shape; with those present the grants must decode.
        let mut body = v.clone();
        let o = body.as_object_mut().unwrap();
        o.remove("kind");
        o.entry("device_cert").or_insert("x.y.z".into());
        o.entry("identity").or_insert("a@b.example".into());
        if let Err(e) = serde_json::from_value::<WarrantRequestBody>(body) {
            panic!("warrant.json accepted a body the registrar rejects: {e}: {v}");
        }
    }
});
