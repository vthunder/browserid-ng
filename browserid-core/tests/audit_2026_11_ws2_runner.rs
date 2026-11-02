//! Security audit 2026-11, WS2 — conformance-vector RUNNER for the Rust
//! core (`AccessPresentation::verify_at`, `RecordBundle::validate`,
//! `ValidatedRecord::matches_login`).
//!
//! Reads `test-vectors/conformance-2026-11.json` and judges every vector
//! with core plus exactly the two caller obligations core documents: a
//! DNSSEC-conformant issuer resolver (§6.1 step 2 / §8.1, scripted from the
//! vector environment) and fail-closed status against the environment's
//! revoked sets (step 8). Nothing else is added, so every rule the spec puts
//! on the verifier that core does not enforce shows up here as a mismatch.
//!
//! Vectors that disagree with their expected verdict today are listed in
//! `EXPECTED_FAIL` with their audit id (`AUDIT-2026-11 <id>`); the test fails
//! if any other vector disagrees, and ALSO if a listed vector starts
//! agreeing — removing it from the list is the acceptance test for the fix.
//!
//! Report: docs/security-audit-2026-11-ws2-conformance.md.

use std::collections::{BTreeSet, HashMap};

use browserid_core::device::AccessPresentation;
use browserid_core::DnsRecord;
use browserid_core::identity::email_domain;
use browserid_core::{Error, Holder, PublicKey, RecordBundle, StatusRef};
use serde_json::Value;

/// Vectors the Rust core gets wrong today, with the finding each pins.
const EXPECTED_FAIL: &[(&str, &str)] = &[
    // AUDIT-2026-11 S3: `Warrant::validate_claims` still has a v1 arm (device.rs:1304).
    ("P-TYP-01", "S3"),
    ("P-TYP-02", "S3"),
    ("A-REJ-13", "S3"),
    // AUDIT-2026-11 D16/S6: no `iat ≤ exp`, `iat ≤ now + skew` bound anywhere in core.
    ("P-TIME-05", "D16"),
    ("P-TIME-06", "D16"),
    ("P-TIME-07", "D16"),
    ("P-TIME-08", "D16"),
    ("P-TIME-09", "D16"),
    ("A-REJ-21", "D16"),
    // AUDIT-2026-11 W6-1: `identity_matches` compares the grantor's domain byte-exact (device.rs:73-74).
    ("P-OK-12", "W6-1"),
    // AUDIT-2026-11 S5: core implements §4.7 (aud/scopes/max-ttl) while the spec says no reference verifier does; a satisfied constraint verifies.
    ("P-CONS-01", "S5"),
    ("P-CONS-06", "S5"),
    // AUDIT-2026-11 W6-4: cert `status.uri` host is never compared to the cert's `iss` (a verifier rule, §6.3; core surfaces the ref only).
    ("P-STAT-06", "W6-4"),
    // AUDIT-2026-11 W2-6: `DnsRecord::parse` keeps the LAST of duplicated fields (dns.rs:30-45); a record naming two keys resolves to the second instead of rejecting.
    ("T-REJ-11", "W2-6"),
];

struct Env {
    at: i64,
    primaries: HashMap<String, PublicKey>,
    fallback: (String, PublicKey),
    accepted_fallbacks: Vec<String>,
    revoked: HashMap<String, BTreeSet<u64>>,
}

fn pk(v: &Value) -> PublicKey {
    serde_json::from_value(v.clone()).unwrap()
}

impl Env {
    fn load(doc: &Value) -> Self {
        let e = &doc["environment"];
        Self {
            at: e["at"].as_i64().unwrap(),
            primaries: e["primaries"].as_object().unwrap().iter().map(|(d, k)| (d.clone(), pk(k))).collect(),
            fallback: (e["fallback"]["domain"].as_str().unwrap().into(), pk(&e["fallback"]["public_key"])),
            accepted_fallbacks: e["accepted_fallbacks"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().into()).collect(),
            revoked: e["status_lists"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(uri, l)| (uri.clone(), l["revoked"].as_array().unwrap().iter().map(|i| i.as_u64().unwrap()).collect()))
                .collect(),
        }
    }

    /// §6.1 step 2 / §8.1: `iss` must be `domain`'s primary, or an accepted
    /// fallback when `domain` has no primary.
    fn resolve(&self, domain: &str, iss: &str) -> Result<PublicKey, String> {
        if let Some(k) = self.primaries.get(domain) {
            return if iss == domain { Ok(k.clone()) } else { Err(format!("issuer '{iss}' is not the primary for '{domain}'")) };
        }
        if iss == self.fallback.0 && self.accepted_fallbacks.iter().any(|f| f == iss) {
            return Ok(self.fallback.1.clone());
        }
        Err(format!("issuer '{iss}' is not an accepted fallback for '{domain}'"))
    }

    /// §6.1 step 8: fail-closed against the environment's lists.
    fn status(&self, label: &str, r: &Option<StatusRef>) -> Result<(), String> {
        let Some(r) = r else { return Ok(()) };
        match self.revoked.get(&r.uri) {
            Some(set) if set.contains(&r.idx) => Err(format!("{label} revoked")),
            Some(_) => Ok(()),
            None => Err(format!("{label} status unavailable (fail-closed): {}", r.uri)),
        }
    }
}

#[derive(Debug)]
enum Verdict {
    Accept { email: String, grantee: String, holder: String, scopes: Value },
    Reject(String),
}

fn run_p(env: &Env, v: &Value) -> Verdict {
    let aud = v["audience"].as_str().unwrap();
    let pres = match AccessPresentation::parse(v["bundle"].as_str().unwrap()) {
        Ok(p) => p,
        Err(e) => return Verdict::Reject(format!("parse: {e}")),
    };
    let ac = pres.access_cert.claims();
    let Some(grantee_domain) = email_domain(&ac.identity) else { return Verdict::Reject("identity is not an email".into()) };
    let Some(grantor_domain) = email_domain(&pres.warrant.claims().grantor) else { return Verdict::Reject("grantor is not an email".into()) };
    let access_key = match env.resolve(grantee_domain, &ac.iss) {
        Ok(k) => k,
        Err(e) => return Verdict::Reject(e),
    };
    let cc_iss = pres.config_cert.claims().iss.clone();
    let config_key = match env.resolve(grantor_domain, &cc_iss) {
        Ok(k) => k,
        Err(e) => return Verdict::Reject(e),
    };
    let ac_iss = ac.iss.clone();
    let r = pres.verify_at(aud, env.at, |iss| {
        if iss == ac_iss {
            Ok(access_key.clone())
        } else if iss == cc_iss {
            Ok(config_key.clone())
        } else {
            Err(Error::InvalidProvisioning(format!("issuer '{iss}' not resolved")))
        }
    });
    let va = match r {
        Ok(v) => v,
        Err(e) => return Verdict::Reject(e.to_string()),
    };
    for (label, r) in [("access cert", &va.access_status), ("config cert", &va.config_status), ("warrant", &va.warrant_status)] {
        if let Err(e) = env.status(label, r) {
            return Verdict::Reject(e);
        }
    }
    Verdict::Accept {
        email: va.email,
        grantee: va.grantee,
        holder: va.holder.as_str().to_string(),
        scopes: serde_json::to_value(&va.scope_entries).unwrap(),
    }
}

fn run_a(env: &Env, v: &Value) -> Verdict {
    let aud = v["audience"].as_str().unwrap();
    let rec = match RecordBundle::parse(v["bundle"].as_str().unwrap()) {
        Ok(r) => r,
        Err(e) => return Verdict::Reject(format!("parse: {e}")),
    };
    let Some(grantor_domain) = email_domain(&rec.warrant.claims().grantor) else { return Verdict::Reject("grantor is not an email".into()) };
    let cc_iss = rec.config_cert.claims().iss.clone();
    let config_key = match env.resolve(grantor_domain, &cc_iss) {
        Ok(k) => k,
        Err(e) => return Verdict::Reject(e),
    };
    let vr = match rec.validate(aud, |iss| {
        if iss == cc_iss { Ok(config_key.clone()) } else { Err(Error::InvalidProvisioning(format!("issuer '{iss}' not resolved"))) }
    }) {
        Ok(r) => r,
        Err(e) => return Verdict::Reject(e.to_string()),
    };
    for (label, r) in [("config cert", &vr.config_status), ("warrant", &vr.warrant_status)] {
        if let Err(e) = env.status(label, r) {
            return Verdict::Reject(e);
        }
    }
    let mut holder = String::new();
    if let Some(s) = v.get("subject") {
        let identity = s["identity"].as_str().unwrap();
        let h = s["holder"].as_str().map(|h| Holder::new(h).unwrap());
        if let Err(e) = vr.matches_login(identity, h.as_ref()) {
            return Verdict::Reject(e.to_string());
        }
        holder = s["holder"].as_str().unwrap_or("").to_string();
    }
    Verdict::Accept {
        email: vr.grantor,
        grantee: vr.grantee,
        holder,
        scopes: serde_json::to_value(&vr.scope_entries).unwrap(),
    }
}

/// Op T: the `_browserid` TXT record parser (§3).
fn run_t(v: &Value) -> Verdict {
    match DnsRecord::parse(v["bundle"].as_str().unwrap()) {
        Ok(r) => Verdict::Accept {
            email: serde_json::to_string(&r.public_key).unwrap(),
            grantee: r.host.clone().unwrap_or_default(),
            holder: String::new(),
            scopes: Value::Null,
        },
        Err(e) => Verdict::Reject(e.to_string()),
    }
}

/// `Some(why)` when the verdict disagrees with the vector's expectation.
fn mismatch(expect: &Value, got: &Verdict) -> Option<String> {
    let want_accept = expect["verdict"] == "accept";
    if expect.get("public_key").is_some() {
        // Op T accept: `email` carries the parsed key as JSON, `grantee` the host.
        return match got {
            Verdict::Reject(r) => Some(format!("expected accept, got reject: {r}")),
            Verdict::Accept { email, grantee, .. } => {
                let want_key = serde_json::to_string(&expect["public_key"]).unwrap();
                let want_host = expect["host"].as_str().unwrap_or("");
                if *email != want_key { Some(format!("key {want_key} != {email}")) }
                else if grantee != want_host { Some(format!("host {want_host:?} != {grantee:?}")) }
                else { None }
            }
        };
    }
    match (want_accept, got) {
        (true, Verdict::Reject(r)) => Some(format!("expected accept, got reject: {r}")),
        (false, Verdict::Accept { email, .. }) => Some(format!("expected reject ({}), got accept as {email}", expect["reason_class"])),
        (false, Verdict::Reject(_)) => None,
        (true, Verdict::Accept { email, grantee, holder, scopes }) => {
            let mut diffs = vec![];
            if expect["email"] != *email {
                diffs.push(format!("email {} != {email}", expect["email"]));
            }
            if expect["grantee"] != *grantee {
                diffs.push(format!("grantee {} != {grantee}", expect["grantee"]));
            }
            if expect["holder"] != *holder {
                diffs.push(format!("holder {} != {holder}", expect["holder"]));
            }
            if expect["scopes"] != *scopes {
                diffs.push(format!("scopes {} != {scopes}", expect["scopes"]));
            }
            if diffs.is_empty() { None } else { Some(diffs.join("; ")) }
        }
    }
}

fn load() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/conformance-2026-11.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn core_conformance_vectors() {
    let doc = load();
    let env = Env::load(&doc);
    let expected_fail: HashMap<&str, &str> = EXPECTED_FAIL.iter().copied().collect();
    let mut unexpected = vec![];
    let mut fixed = vec![];
    let (mut pass, mut xfail) = (0, 0);
    for v in doc["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let got = match v["op"].as_str().unwrap() {
            "P" => run_p(&env, v),
            "A" => run_a(&env, v),
            "T" => run_t(v),
            op => panic!("unknown op {op}"),
        };
        let mm = mismatch(&v["expect"], &got);
        let short = match &got {
            Verdict::Accept { email, .. } => format!("accept {email}"),
            Verdict::Reject(r) => format!("reject: {r}"),
        };
        match (mm, expected_fail.get(id)) {
            (None, None) => {
                pass += 1;
                println!("ok    {id:10} {short}");
            }
            (Some(why), Some(fid)) => {
                xfail += 1;
                println!("XFAIL {id:10} [{fid}] {why}");
            }
            (Some(why), None) => {
                println!("FAIL  {id:10} {why}");
                unexpected.push(format!("{id}: {why}"));
            }
            (None, Some(fid)) => {
                println!("FIXED {id:10} [{fid}] now agrees — remove it from EXPECTED_FAIL");
                fixed.push(format!("{id} [{fid}]"));
            }
        }
    }
    println!("\nrust-core: {pass} pass, {xfail} expected-fail, {} unexpected, {} fixed", unexpected.len(), fixed.len());
    assert!(unexpected.is_empty(), "vectors disagreeing with the core verifier:\n{}", unexpected.join("\n"));
    assert!(fixed.is_empty(), "vectors now passing; drop them from EXPECTED_FAIL:\n{}", fixed.join("\n"));
}
