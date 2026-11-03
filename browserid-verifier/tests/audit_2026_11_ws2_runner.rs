//! Security audit 2026-11, WS2 — conformance-vector RUNNER for the hosted
//! verifier, in-process (`verify_access_with_dns` behind `POST /verify`,
//! `validate_record_with_dns` behind `POST /validate-record`).
//!
//! Discovery is scripted from the vector environment (no DNS); the broker's
//! own status list answers from the environment's revoked set; the primary's
//! foreign list is pre-seeded into the cache as a token signed by the
//! primary's key, so no status fetch touches the network except the two
//! vectors that deliberately point at a private or unresolvable host.
//!
//! Besides judging each vector, the test RECORDS the hosted response per
//! vector into `test-vectors/conformance-2026-11.hosted.json`; the SDK
//! runners (sdk/js, sdk/python-mcp-auth, sdk/mcp-auth, sdk/gate) replay
//! those responses through an injected fetch, so they exercise the SDK's own
//! request shaping and response handling against what the hosted service
//! actually returns. Regenerate after a verifier change with
//!
//!     WS2_REGEN=1 cargo test -p browserid-verifier --test audit_2026_11_ws2_runner
//!
//! Admission subject matching (§6.4 step 3) is not a hosted call — the SDKs
//! do it — so op-A vectors stop at record validation here.
//!
//! Report: docs/security-audit-2026-11-ws2-conformance.md.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::RwLock;

use browserid_core::discovery::SupportDocument;
use browserid_core::{KeyPair, PublicKey, StatusList, StatusListToken};
use browserid_verifier::{validate_record_with_dns, verify_access_with_dns, Discoverer, FallbackResult, StatusCtx, VerifierError};
use serde_json::{json, Value};

/// Vectors the hosted verifier gets wrong today, with the finding each pins.
const EXPECTED_FAIL: &[(&str, &str)] = &[
    // AUDIT-2026-11 S3: v1 still parses (core device.rs:1304).
    ("P-TYP-01", "S3"),
    ("P-TYP-02", "S3"),
    ("A-REJ-13", "S3"),
    // AUDIT-2026-11 D16/S6: no lower bound on iat.
    ("P-TIME-05", "D16"),
    ("P-TIME-06", "D16"),
    ("P-TIME-07", "D16"),
    ("P-TIME-08", "D16"),
    ("P-TIME-09", "D16"),
    ("A-REJ-21", "D16"),
    // AUDIT-2026-11 W6-1: grantor domain compared byte-exact in core.
    ("P-OK-12", "W6-1"),
    // AUDIT-2026-11 W6-4: cert status.uri host never compared to iss (verify.rs:754-771).
    ("P-STAT-06", "W6-4"),
];

struct Mock {
    primaries: HashMap<String, PublicKey>,
    fallback: (String, PublicKey),
}
impl Mock {
    fn lookup(&self, domain: &str) -> Result<FallbackResult, VerifierError> {
        let doc = |k: &PublicKey| -> SupportDocument {
            serde_json::from_value(json!({ "public-key": serde_json::to_value(k).unwrap() })).unwrap()
        };
        if let Some(k) = self.primaries.get(domain) {
            return Ok(FallbackResult { document: doc(k), authoritative_domain: domain.to_string(), is_primary: true, serving_host: None });
        }
        Ok(FallbackResult { document: doc(&self.fallback.1), authoritative_domain: self.fallback.0.clone(), is_primary: false, serving_host: None })
    }
}
impl Discoverer for Mock {
    fn discover(&self, domain: &str) -> impl std::future::Future<Output = Result<FallbackResult, VerifierError>> + Send {
        let r = self.lookup(domain);
        async move { r }
    }
}

fn pk(v: &Value) -> PublicKey {
    serde_json::from_value(v.clone()).unwrap()
}

fn load() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/conformance-2026-11.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn hosted_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/conformance-2026-11.hosted.json")
}

/// `Some(why)` when the response disagrees with the vector's expectation.
fn mismatch(op: &str, expect: &Value, got: &Value) -> Option<String> {
    let okay = got["status"] == "okay";
    // A `stage: match` reject is a record that validates but whose subject
    // must fail §6.4 step 3 — the hosted call stops at step 1, so it must
    // answer okay here; the SDK runners judge the match.
    if expect["stage"] == "match" {
        return if okay { None } else { Some(format!("record expected to validate (reject is at the match stage), got failure: {}", got["reason"])) };
    }
    let want_accept = expect["verdict"] == "accept";
    match (want_accept, okay) {
        (true, false) => Some(format!("expected accept, got failure: {}", got["reason"])),
        (false, true) => Some(format!("expected reject ({}), got okay", expect["reason_class"])),
        (false, false) => None,
        (true, true) => {
            let mut d = vec![];
            let (email, grantee) = if op == "P" { (&got["email"], &got["grantee"]) } else { (&got["grantor"], &got["grantee"]) };
            if expect["email"] != *email {
                d.push(format!("email {} != {email}", expect["email"]));
            }
            if expect["grantee"] != *grantee {
                d.push(format!("grantee {} != {grantee}", expect["grantee"]));
            }
            if op == "P" && expect["holder"] != got["holder"] {
                d.push(format!("holder {} != {}", expect["holder"], got["holder"]));
            }
            if expect["scopes"] != got["scopes"] {
                d.push(format!("scopes {} != {}", expect["scopes"], got["scopes"]));
            }
            if d.is_empty() { None } else { Some(d.join("; ")) }
        }
    }
}

/// Reasons carry transport error text on the two network vectors; compare
/// recorded responses with the reason reduced to its stable prefix.
fn stable(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(r) = v.get("reason").and_then(Value::as_str) {
        let cut = r.split(" (fail-closed)").next().unwrap_or(r).to_string();
        v["reason"] = json!(cut);
    }
    v
}

#[tokio::test]
async fn hosted_conformance_vectors() {
    let doc = load();
    let e = &doc["environment"];
    let own_uri = e["own_status_uri"].as_str().unwrap().to_string();
    let revoked: HashMap<String, BTreeSet<u64>> = e["status_lists"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(uri, l)| (uri.clone(), l["revoked"].as_array().unwrap().iter().map(|i| i.as_u64().unwrap()).collect()))
        .collect();
    let own_revoked = revoked[&own_uri].clone();
    let disc = Mock {
        primaries: e["primaries"].as_object().unwrap().iter().map(|(d, k)| (d.clone(), pk(k))).collect(),
        fallback: (e["fallback"]["domain"].as_str().unwrap().into(), pk(&e["fallback"]["public_key"])),
    };
    let accepted: Vec<String> = e["accepted_fallbacks"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().into()).collect();

    // Pre-seed every non-own list as a verified, fresh foreign token signed by
    // its issuer's deterministic key (seed byte from the environment).
    let cache: RwLock<HashMap<String, StatusListToken>> = RwLock::new(HashMap::new());
    for (uri, l) in e["status_lists"].as_object().unwrap() {
        if *uri == own_uri {
            continue;
        }
        let issuer = l["issuer"].as_str().unwrap();
        let issuer_pub = serde_json::to_value(&disc.primaries[issuer]).unwrap();
        let seed = e["keys"].as_object().unwrap().values().find(|k| k["public_key"] == issuer_pub).map(|k| k["seed_byte"].as_u64().unwrap() as u8).unwrap();
        let key = KeyPair::from_seed(&[seed; 32]).unwrap();
        let list = StatusList::from_revoked(revoked[uri].iter().copied(), 1024);
        let tok = StatusListToken::create(issuer, uri, &list, &key).unwrap();
        cache.write().unwrap().insert(uri.clone(), tok);
    }
    let is_own_revoked = move |idx: u64| -> Result<bool, String> { Ok(own_revoked.contains(&idx)) };
    let ctx = || StatusCtx { own_uri: own_uri.clone(), is_own_revoked: &is_own_revoked, cache: &cache, allow_private_hosts: false };

    let expected_fail: HashMap<&str, &str> = EXPECTED_FAIL.iter().copied().collect();
    let mut recorded: BTreeMap<String, Value> = BTreeMap::new();
    let (mut pass, mut xfail, mut skipped) = (0, 0, 0);
    let (mut unexpected, mut fixed) = (vec![], vec![]);
    for v in doc["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let op = v["op"].as_str().unwrap();
        if op == "T" {
            skipped += 1; // the TXT parser is core's (`DnsRecord::parse`); browserid-dnssec calls it
            continue;
        }
        let aud = v["audience"].as_str().unwrap();
        let bundle = v["bundle"].as_str().unwrap();
        let got = match op {
            "P" => serde_json::to_value(verify_access_with_dns(bundle, aud, &disc, &accepted, ctx()).await).unwrap(),
            "A" => serde_json::to_value(validate_record_with_dns(bundle, aud, &disc, &accepted, ctx()).await).unwrap(),
            _ => unreachable!(),
        };
        let mm = mismatch(op, &v["expect"], &got);
        let short = if got["status"] == "okay" { format!("okay {}", got["email"].as_str().or(got["grantor"].as_str()).unwrap_or("")) } else { format!("failure: {}", got["reason"]) };
        match (mm, expected_fail.get(id)) {
            (None, None) => { pass += 1; println!("ok    {id:10} {short}"); }
            (Some(why), Some(fid)) => { xfail += 1; println!("XFAIL {id:10} [{fid}] {why}"); }
            (Some(why), None) => { println!("FAIL  {id:10} {why}"); unexpected.push(format!("{id}: {why}")); }
            (None, Some(fid)) => { println!("FIXED {id:10} [{fid}] now agrees — remove it from EXPECTED_FAIL"); fixed.push(format!("{id} [{fid}]")); }
        }
        recorded.insert(id.to_string(), stable(&got));
    }
    println!("\nhosted: {pass} pass, {xfail} expected-fail, {skipped} skipped (op T), {} unexpected, {} fixed", unexpected.len(), fixed.len());

    let out = json!({
        "suite": "hosted /verify and /validate-record responses per conformance vector (recorded by browserid-verifier/tests/audit_2026_11_ws2_runner.rs)",
        "regenerate": "WS2_REGEN=1 cargo test -p browserid-verifier --test audit_2026_11_ws2_runner",
        "responses": recorded,
    });
    let rendered = serde_json::to_string_pretty(&out).unwrap() + "\n";
    if std::env::var_os("WS2_REGEN").is_some() {
        std::fs::write(hosted_path(), &rendered).unwrap();
    } else {
        let committed = std::fs::read_to_string(hosted_path()).unwrap_or_default();
        assert!(committed == rendered, "test-vectors/conformance-2026-11.hosted.json is stale; regenerate with WS2_REGEN=1 cargo test -p browserid-verifier --test audit_2026_11_ws2_runner");
    }
    assert!(unexpected.is_empty(), "vectors disagreeing with the hosted verifier:\n{}", unexpected.join("\n"));
    assert!(fixed.is_empty(), "vectors now passing; drop them from EXPECTED_FAIL:\n{}", fixed.join("\n"));
}
