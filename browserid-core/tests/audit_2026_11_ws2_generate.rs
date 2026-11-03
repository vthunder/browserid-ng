//! Security audit 2026-11, WS2 — the conformance vector GENERATOR.
//!
//! Produces `test-vectors/conformance-2026-11.json`: an accept+reject suite
//! derived from the threat-model invariants I1–I11
//! (docs/design/threat-model.md) and spec §4–§6 as amended on the audit
//! branch. Every signed object is built from deterministic seeds and signed
//! as a raw JWS over a JSON claim set, so malformed objects (unknown typ,
//! bad identities, alg:none, …) can be produced as easily as valid ones and
//! the file is byte-for-byte regenerable.
//!
//! The test below REGENERATES the suite and compares it to the committed
//! file; a mismatch fails the test. To update the file after changing a
//! vector:
//!
//!     WS2_REGEN=1 cargo test -p browserid-core --test audit_2026_11_ws2_generate
//!
//! Runners (one per verifier) live beside their verifier and read the file:
//! `browserid-core/tests/audit_2026_11_ws2_runner.rs` (Rust core),
//! `browserid-verifier/tests/audit_2026_11_ws2_runner.rs` (hosted /verify
//! and /validate-record, in-process; also records
//! `test-vectors/conformance-2026-11.hosted.json`), `sdk/js`,
//! `sdk/python-mcp-auth`, `sdk/mcp-auth`, `sdk/gate`.
//!
//! Report: docs/security-audit-2026-11-ws2-conformance.md.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use browserid_core::device::AudConstraint;
use browserid_core::KeyPair;
use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------
// Fixed environment
// ---------------------------------------------------------------------------

/// Issuance instant for every valid object: 2025-10-09T07:33:20Z. In the
/// past for wall-clock verifiers, and the deterministic clock `AT` sits 60 s
/// after it for `verify_at` consumers.
const IAT: i64 = 1_760_000_000;
const AT: i64 = IAT + 60;
/// Ten years: accept vectors stay in-window for wall-clock verifiers until
/// 2035 without being regenerated.
const EXP: i64 = IAT + 10 * 365 * 86_400;
/// A post-dated object (2096-10-02) — spec §6.1 time bounds reject it.
const FUTURE: i64 = 4_000_000_000;

const AUD: &str = "https://rp.example";
const SBO_AUD: &str = "sbo+raw://avail:turing:506/";
const BROKER: &str = "browserid.me";
const PRIMARY: &str = "primary.example";
const OWN_LIST: &str = "https://browserid.me/.well-known/browserid-status";
const PRIMARY_LIST: &str = "https://primary.example/.well-known/browserid-status";

const U: &str = "user@example.com";
const AG: &str = "user+agent@example.com";
const PAT: &str = "pat@primary.example";
const SITE: &str = "https://site.example";

const TYP_DC: &str = "browserid-device-cert-v1";
const TYP_AC: &str = "browserid-access-cert-v1";
const TYP_W2: &str = "browserid-warrant-v2";
const TYP_W1: &str = "browserid-warrant-v1";

/// Own-list indices that the environment marks revoked.
const REVOKED_OWN: [u64; 3] = [100, 101, 102];
/// Primary-list indices marked revoked.
const REVOKED_PRIMARY: [u64; 1] = [200];

fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(&[seed; 32]).unwrap()
}
struct Keys {
    broker: KeyPair,
    primary: KeyPair,
    access: KeyPair,
    config: KeyPair,
    rogue: KeyPair,
    access2: KeyPair,
}
impl Keys {
    fn new() -> Self {
        Self {
            broker: key(1),
            primary: key(2),
            access: key(3),
            config: key(4),
            rogue: key(5),
            access2: key(6),
        }
    }
    fn idp_for(&self, iss: &str) -> &KeyPair {
        match iss {
            BROKER => &self.broker,
            PRIMARY => &self.primary,
            _ => &self.rogue,
        }
    }
}

fn pubv(k: &KeyPair) -> Value {
    serde_json::to_value(k.public_key()).unwrap()
}

fn list_for(iss: &str) -> &'static str {
    if iss == PRIMARY {
        PRIMARY_LIST
    } else {
        OWN_LIST
    }
}

// ---------------------------------------------------------------------------
// Raw JWS
// ---------------------------------------------------------------------------

const HDR: &str = r#"{"alg":"EdDSA","typ":"JWT"}"#;

fn jws_with_header(header: &str, claims: &Value, key: &KeyPair) -> String {
    let h = B64.encode(header);
    let c = B64.encode(claims.to_string());
    let msg = format!("{h}.{c}");
    let sig = B64.encode(key.sign(msg.as_bytes()));
    format!("{msg}.{sig}")
}
fn jws(claims: &Value, key: &KeyPair) -> String {
    jws_with_header(HDR, claims, key)
}

// ---------------------------------------------------------------------------
// Object builders (claim sets as JSON values, edited by closures)
// ---------------------------------------------------------------------------

fn sref(uri: &str, idx: u64) -> Value {
    json!({ "uri": uri, "idx": idx })
}

fn access_cert_claims(k: &Keys, identity: &str, iss: &str) -> Value {
    json!({
        "typ": TYP_AC,
        "iss": iss,
        "iat": IAT,
        "exp": EXP,
        "identity": identity,
        "holder": "br.main",
        "public-key": pubv(&k.access),
        "status": sref(list_for(iss), 7),
    })
}

fn config_cert_claims(k: &Keys, identities: &[&str], iss: &str) -> Value {
    json!({
        "typ": TYP_DC,
        "iss": iss,
        "iat": IAT,
        "exp": EXP,
        "purpose": "authorization",
        "holder": "br.main",
        "identities": identities,
        "public-key": pubv(&k.config),
        "status": sref(list_for(iss), 2),
    })
}

fn warrant_claims(grantor: &str, grantee: &str) -> Value {
    json!({
        "typ": TYP_W2,
        "iat": IAT,
        "exp": EXP,
        "grantor": grantor,
        "grantee": grantee,
        "binding": { "kind": "holder", "matcher": "br.*" },
        "audience": AUD,
        "scopes": [],
        "status": sref(OWN_LIST, 42),
    })
}

fn assertion_claims(aud: &str) -> Value {
    json!({ "iat": IAT, "aud": aud, "exp": EXP })
}

fn set(v: &mut Value, k: &str, val: Value) {
    v.as_object_mut().unwrap().insert(k.to_string(), val);
}
fn del(v: &mut Value, k: &str) {
    v.as_object_mut().unwrap().remove(k);
}

/// One presentation under construction: four claim sets plus the key each
/// is signed with. `ac`/`cc` are signed by the IdP of their `iss`; the
/// assertion by the access key; the warrant by the config key. Any of the
/// signers can be swapped to produce signature failures.
struct P<'k> {
    k: &'k Keys,
    ac: Value,
    as_: Value,
    w: Value,
    cc: Value,
    ac_signer: Option<&'k KeyPair>,
    as_signer: Option<&'k KeyPair>,
    w_signer: Option<&'k KeyPair>,
    cc_signer: Option<&'k KeyPair>,
    w_header: Option<&'static str>,
}

impl<'k> P<'k> {
    /// As-you login of `U` at `AUD`, fallback-issued.
    fn as_you(k: &'k Keys) -> Self {
        Self::new(k, U, BROKER, U, BROKER)
    }
    fn new(k: &'k Keys, grantee: &str, grantee_iss: &str, grantor: &str, grantor_iss: &str) -> Self {
        Self {
            k,
            ac: access_cert_claims(k, grantee, grantee_iss),
            as_: assertion_claims(AUD),
            w: warrant_claims(grantor, grantee),
            cc: config_cert_claims(k, &[grantor], grantor_iss),
            ac_signer: None,
            as_signer: None,
            w_signer: None,
            cc_signer: None,
            w_header: None,
        }
    }
    fn ac(mut self, f: impl FnOnce(&mut Value)) -> Self {
        f(&mut self.ac);
        self
    }
    fn assertion(mut self, f: impl FnOnce(&mut Value)) -> Self {
        f(&mut self.as_);
        self
    }
    fn w(mut self, f: impl FnOnce(&mut Value)) -> Self {
        f(&mut self.w);
        self
    }
    fn cc(mut self, f: impl FnOnce(&mut Value)) -> Self {
        f(&mut self.cc);
        self
    }
    fn parts(&self) -> [String; 4] {
        let k = self.k;
        let ac_iss = self.ac["iss"].as_str().unwrap_or(BROKER).to_string();
        let cc_iss = self.cc["iss"].as_str().unwrap_or(BROKER).to_string();
        [
            jws(&self.ac, self.ac_signer.unwrap_or_else(|| k.idp_for(&ac_iss))),
            jws(&self.as_, self.as_signer.unwrap_or(&k.access)),
            jws_with_header(self.w_header.unwrap_or(HDR), &self.w, self.w_signer.unwrap_or(&k.config)),
            jws(&self.cc, self.cc_signer.unwrap_or_else(|| k.idp_for(&cc_iss))),
        ]
    }
    fn bundle(&self) -> String {
        self.parts().join("~")
    }
    fn record(&self) -> String {
        let p = self.parts();
        format!("{}~{}", p[2], p[3])
    }
    fn objects_p(&self) -> Value {
        json!({ "access_cert": self.ac, "assertion": self.as_, "warrant": self.w, "config_cert": self.cc })
    }
    fn objects_a(&self) -> Value {
        json!({ "warrant": self.w, "config_cert": self.cc })
    }
}

// ---------------------------------------------------------------------------
// Vector assembly
// ---------------------------------------------------------------------------

struct Vec_ {
    id: &'static str,
    op: &'static str,
    invariant: &'static str,
    title: &'static str,
    audience: String,
    bundle: String,
    objects: Value,
    subject: Option<Value>,
    expect: Value,
    known: Vec<&'static str>,
}

fn accept(email: &str, grantee: &str, holder: &str, scopes: Value) -> Value {
    json!({ "verdict": "accept", "email": email, "grantee": grantee, "holder": holder, "scopes": scopes })
}
fn reject(class: &str) -> Value {
    json!({ "verdict": "reject", "reason_class": class })
}
/// A record that validates (§6.4 step 1) but whose subject must fail the
/// match (step 3). Hosted record validation stops before step 3, so a runner
/// judging only validation expects `okay` here.
fn reject_at_match(class: &str) -> Value {
    json!({ "verdict": "reject", "reason_class": class, "stage": "match" })
}

fn p(id: &'static str, inv: &'static str, title: &'static str, b: &P, expect: Value) -> Vec_ {
    Vec_ {
        id,
        op: "P",
        invariant: inv,
        title,
        audience: AUD.into(),
        bundle: b.bundle(),
        objects: b.objects_p(),
        subject: None,
        expect,
        known: vec![],
    }
}
fn a(id: &'static str, inv: &'static str, title: &'static str, b: &P, subject: Option<(&str, Option<&str>)>, expect: Value) -> Vec_ {
    Vec_ {
        id,
        op: "A",
        invariant: inv,
        title,
        audience: AUD.into(),
        bundle: b.record(),
        objects: b.objects_a(),
        subject: subject.map(|(i, h)| json!({ "identity": i, "holder": h })),
        expect,
        known: vec![],
    }
}
impl Vec_ {
    fn known(mut self, ids: &[&'static str]) -> Self {
        self.known = ids.to_vec();
        self
    }
    fn audience(mut self, aud: &str) -> Self {
        self.audience = aud.into();
        self
    }
    fn bundle(mut self, b: String) -> Self {
        self.bundle = b;
        self
    }
}

fn holder_binding(m: &str) -> Value {
    json!({ "kind": "holder", "matcher": m })
}
fn requester_binding(origin: &str) -> Value {
    json!({ "kind": "requester", "origin": origin })
}
fn connection_binding() -> Value {
    json!({ "kind": "connection", "protocol": "oauth", "id": "cn_8f3a", "client_host": "claude.ai", "client_name": "Claude" })
}

fn build() -> Vec<Vec_> {
    let k = Keys::new();
    let mut v: Vec<Vec_> = vec![];
    let no_scopes = json!([]);
    let as_you = |_b: &P| accept(U, U, "br.main", no_scopes.clone());

    // ===================================================================
    // Operation P — accept
    // ===================================================================
    {
        let b = P::as_you(&k);
        v.push(p("P-OK-01", "I11", "as-you login, fallback-issued, singular holder binding", &b, as_you(&b)));
    }
    {
        let b = P::new(&k, PAT, PRIMARY, PAT, PRIMARY);
        v.push(p("P-OK-02", "I3", "as-you login, primary-issued (status refs on the primary's list)", &b,
            accept(PAT, PAT, "br.main", no_scopes.clone())));
    }
    {
        let b = P::new(&k, AG, BROKER, U, BROKER)
            .ac(|c| set(c, "public-key", pubv(&k.access2)))
            .w(|w| set(w, "scopes", json!(["tool:read"])));
        let mut b = b;
        b.as_signer = Some(&k.access2);
        v.push(p("P-OK-03", "I13", "delegated grant: grantee user+agent, grantor user, config cert covers the base identity", &b,
            accept(U, AG, "br.main", json!(["tool:read"]))));
    }
    {
        let b = P::new(&k, PAT, PRIMARY, U, BROKER).w(|w| set(w, "scopes", json!(["tool:read"])));
        v.push(p("P-OK-04", "I3", "cross-issuer delegation: primary-issued grantee, fallback-issued grantor", &b,
            accept(U, PAT, "br.main", json!(["tool:read"]))));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", json!([holder_binding("br.*")])));
        v.push(p("P-OK-05", "I1", "array-form binding set with one holder entry", &b, as_you(&b)));
    }
    {
        let b = P::as_you(&k)
            .w(|w| set(w, "binding", json!([holder_binding("br.main"), requester_binding(SITE)])))
            .assertion(|s| set(s, "req_origin", json!(SITE)));
        v.push(p("P-OK-06", "I7", "requester entry matched by the assertion's req_origin stamp", &b, as_you(&b)));
    }
    {
        let scopes = json!(["sign:sbo:post", { "scope": "sign:sbo:delete", "mode": "prompt" }]);
        let b = P::as_you(&k).w(|w| {
            set(w, "scopes", scopes.clone());
            set(w, "audience", json!(SBO_AUD));
        }).assertion(|s| set(s, "aud", json!(SBO_AUD)));
        v.push(p("P-OK-07", "I11", "scope entry with the `mode` parameter; non-web audience with trailing slash; entries returned verbatim", &b,
            accept(U, U, "br.main", scopes)).audience(SBO_AUD).known(&["D7"]));
    }
    {
        let scopes = json!([{ "scope": "pay:usd", "cap": { "amount": "20.00", "currency": "USD", "window": "P1D" } }]);
        let b = P::as_you(&k).w(|w| set(w, "scopes", scopes.clone()));
        v.push(p("P-OK-08", "I11", "scope entry with a family parameter (`cap`); a relay carries it verbatim", &b,
            accept(U, U, "br.main", scopes)).known(&["D7"]));
    }
    {
        let b = P::new(&k, AG, BROKER, AG, BROKER).cc(|c| set(c, "identities", json!([U])));
        v.push(p("P-OK-09", "I13", "subaddressed grantor user+agent covered by a config cert for user (authorization-only widening)", &b,
            accept(AG, AG, "br.main", no_scopes.clone())));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("br.main")));
        v.push(p("P-OK-10", "I6", "exact holder matcher equal to the access cert holder", &b, as_you(&b)));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "grantee", json!("user@EXAMPLE.com")));
        v.push(p("P-OK-11", "I5", "grantee domain differs only in case from the access identity (domain is case-insensitive)", &b, as_you(&b)));
    }
    {
        let b = P::as_you(&k).w(|w| {
            set(w, "grantor", json!("user@EXAMPLE.com"));
            set(w, "grantee", json!("user@EXAMPLE.com"));
        });
        v.push(p("P-OK-12", "I5", "grantor domain differs only in case from the config cert identity (spec §5 rule)", &b,
            accept("user@EXAMPLE.com", U, "br.main", no_scopes.clone())).known(&["W6-1"]));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("*")));
        v.push(p("P-OK-13", "I6", "wildcard holder matcher", &b, as_you(&b)));
    }

    // ===================================================================
    // Operation P — signatures (I2)
    // ===================================================================
    {
        let mut b = P::as_you(&k);
        b.ac_signer = Some(&k.rogue);
        v.push(p("P-SIG-01", "I2", "access cert signed by a key that is not the issuer's", &b, reject("signature")));
    }
    {
        let mut b = P::as_you(&k);
        b.cc_signer = Some(&k.rogue);
        v.push(p("P-SIG-02", "I2", "config cert signed by a key that is not the issuer's", &b, reject("signature")));
    }
    {
        let mut b = P::as_you(&k);
        b.w_signer = Some(&k.rogue);
        v.push(p("P-SIG-03", "I2", "warrant not signed by the config cert's key", &b, reject("signature")));
    }
    {
        let mut b = P::as_you(&k);
        b.as_signer = Some(&k.rogue);
        v.push(p("P-SIG-04", "I2", "assertion not signed by the access cert's key", &b, reject("signature")));
    }
    {
        // Sign a valid access cert, then swap the identity in the payload.
        let b = P::as_you(&k);
        let mut parts = b.parts();
        let tampered = {
            let mut c = b.ac.clone();
            set(&mut c, "identity", json!("other@example.com"));
            let sig = parts[0].rsplit('.').next().unwrap().to_string();
            format!("{}.{}.{}", B64.encode(HDR), B64.encode(c.to_string()), sig)
        };
        parts[0] = tampered;
        v.push(p("P-SIG-05", "I2", "access cert payload altered after signing (identity swapped)", &b, reject("signature")).bundle(parts.join("~")));
    }
    {
        let mut b = P::as_you(&k);
        b.w_header = Some(r#"{"alg":"none","typ":"JWT"}"#);
        v.push(p("P-SIG-06", "I2", "warrant JOSE header alg:none (signature bytes still present)", &b, reject("signature")));
    }
    {
        let b = P::as_you(&k);
        let mut parts = b.parts();
        parts[2] = parts[2].rsplit_once('.').map(|(m, _)| format!("{m}.")).unwrap();
        v.push(p("P-SIG-07", "I2", "warrant with an empty signature segment", &b, reject("signature")).bundle(parts.join("~")));
    }

    // ===================================================================
    // Operation P — audience (I4)
    // ===================================================================
    for (id, aud, title) in [
        ("P-AUD-01", "https://rp.example/", "assertion aud with a trailing slash"),
        ("P-AUD-02", "https://RP.example", "assertion aud differs in case"),
        ("P-AUD-03", "https://rp.example:443", "assertion aud with an explicit default port"),
        ("P-AUD-04", "http://rp.example", "assertion aud with a different scheme"),
        ("P-AUD-05", "https://rp.example/path", "assertion aud with a path"),
        ("P-AUD-06", "https://evil.example", "assertion aud for a different origin"),
    ] {
        let b = P::as_you(&k).assertion(|s| set(s, "aud", json!(aud)));
        v.push(p(id, "I4", title, &b, reject("audience")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "audience", json!("https://evil.example")));
        v.push(p("P-AUD-07", "I4", "warrant audience differs from the assertion's and the RP's", &b, reject("audience")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "audience", json!("https://rp.example/")));
        v.push(p("P-AUD-08", "I4", "warrant audience with a trailing slash", &b, reject("audience")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "audience", json!([AUD])));
        v.push(p("P-AUD-09", "I4", "warrant audience is an array (exactly one string required)", &b, reject("audience")));
    }

    // ===================================================================
    // Operation P — time bounds (§6.1; S6 / D16)
    // ===================================================================
    {
        let b = P::as_you(&k).ac(|c| set(c, "exp", json!(IAT + 1)));
        v.push(p("P-TIME-01", "I2", "access cert expired", &b, reject("expired")));
    }
    {
        let b = P::as_you(&k).cc(|c| set(c, "exp", json!(IAT + 1)));
        v.push(p("P-TIME-02", "I2", "config cert expired", &b, reject("expired")));
    }
    {
        let b = P::as_you(&k).w(|c| set(c, "exp", json!(IAT + 1)));
        v.push(p("P-TIME-03", "I2", "warrant expired", &b, reject("expired")));
    }
    {
        let b = P::as_you(&k).assertion(|c| set(c, "exp", json!(IAT + 1)));
        v.push(p("P-TIME-04", "I2", "assertion expired", &b, reject("expired")));
    }
    {
        let b = P::as_you(&k).ac(|c| { set(c, "iat", json!(FUTURE)); set(c, "exp", json!(FUTURE + 86_400)); });
        v.push(p("P-TIME-05", "I2", "access cert post-dated (iat far in the future)", &b, reject("future_iat")).known(&["D16"]));
    }
    {
        let b = P::as_you(&k).w(|c| { set(c, "iat", json!(FUTURE)); set(c, "exp", json!(FUTURE + 86_400)); });
        v.push(p("P-TIME-06", "I2", "warrant post-dated (iat far in the future)", &b, reject("future_iat")).known(&["D16"]));
    }
    {
        let b = P::as_you(&k).cc(|c| { set(c, "iat", json!(FUTURE)); set(c, "exp", json!(FUTURE + 86_400)); });
        v.push(p("P-TIME-07", "I2", "config cert post-dated (iat far in the future)", &b, reject("future_iat")).known(&["D16"]));
    }
    {
        let b = P::as_you(&k).ac(|c| { set(c, "iat", json!(EXP + 1)); });
        v.push(p("P-TIME-08", "I2", "access cert iat > exp", &b, reject("iat_after_exp")).known(&["D16"]));
    }
    {
        let b = P::as_you(&k).w(|c| { set(c, "iat", json!(EXP + 1)); });
        v.push(p("P-TIME-09", "I2", "warrant iat > exp", &b, reject("iat_after_exp")).known(&["D16"]));
    }
    {
        let b = P::as_you(&k).w(|c| del(c, "exp"));
        v.push(p("P-TIME-10", "I2", "warrant without exp", &b, reject("shape")));
    }
    // W4-40 / Q19 (a): the assertion carries `iat` and the same rule applies.
    {
        let b = P::as_you(&k).assertion(|c| { set(c, "iat", json!(FUTURE)); set(c, "exp", json!(FUTURE + 86_400)); });
        v.push(p("P-TIME-11", "I2", "assertion post-dated (iat far in the future)", &b, reject("future_iat")).known(&["W4-40"]));
    }
    {
        let b = P::as_you(&k).assertion(|c| set(c, "iat", json!(EXP + 1)));
        v.push(p("P-TIME-12", "I2", "assertion iat > exp", &b, reject("iat_after_exp")).known(&["W4-40"]));
    }
    {
        // Transition (W4-40): a pre-audit assertion without `iat` is accepted
        // on `exp` alone until `browserid_core::assertion::IAT_SUNSET`
        // (2027-02-01); this vector flips to reject("shape") at the sunset.
        let b = P::as_you(&k).assertion(|c| del(c, "iat"));
        v.push(p("P-TIME-13", "I2", "assertion without iat (pre-sunset transition: accepted on exp alone)", &b, accept(U, U, "br.main", json!([]))).known(&["W4-40"]));
    }

    // ===================================================================
    // Operation P — typ / purpose / shape (I1)
    // ===================================================================
    {
        let b = P::as_you(&k).w(|w| {
            set(w, "typ", json!(TYP_W1));
            del(w, "binding");
            del(w, "status");
            set(w, "holder", json!("br.*"));
        });
        v.push(p("P-TYP-01", "I1", "retired browserid-warrant-v1 (top-level holder, no status)", &b, reject("typ")).known(&["S3"]));
    }
    {
        let b = P::as_you(&k).w(|w| {
            set(w, "typ", json!(TYP_W1));
            del(w, "binding");
            set(w, "holder", json!("br.*"));
        });
        v.push(p("P-TYP-02", "I1", "retired browserid-warrant-v1 carrying a status ref", &b, reject("typ")).known(&["S3"]));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "typ", json!("browserid-warrant-v3")));
        v.push(p("P-TYP-03", "I1", "warrant with an unknown typ", &b, reject("typ")));
    }
    {
        let b = P::as_you(&k).ac(|c| set(c, "typ", json!("browserid-access-cert-v2")));
        v.push(p("P-TYP-04", "I1", "access cert with an unknown typ", &b, reject("typ")));
    }
    {
        let b = P::as_you(&k).cc(|c| set(c, "typ", json!(TYP_AC)));
        v.push(p("P-TYP-05", "I1", "config cert slot holds an access-cert typ", &b, reject("typ")));
    }
    {
        let b = P::as_you(&k).cc(|c| set(c, "purpose", json!("authentication")));
        v.push(p("P-TYP-06", "I1", "config cert with purpose authentication (an auth cert is never presented)", &b, reject("purpose")));
    }
    {
        let b = P::as_you(&k).cc(|c| set(c, "purpose", json!("signing")));
        v.push(p("P-TYP-07", "I1", "config cert with an unknown purpose", &b, reject("purpose")));
    }
    {
        let b = P::as_you(&k).cc(|c| del(c, "holder"));
        v.push(p("P-TYP-08", "I1", "config cert without a holder", &b, reject("shape")));
    }
    {
        let b = P::as_you(&k).ac(|c| set(c, "holder", json!("")));
        v.push(p("P-TYP-09", "I1", "access cert with an empty holder", &b, reject("shape")));
    }
    {
        let b = P::as_you(&k);
        let parts = b.parts();
        v.push(p("P-SHAPE-01", "I1", "three objects (config cert missing)", &b, reject("shape")).bundle(parts[..3].join("~")));
    }
    {
        let b = P::as_you(&k);
        let mut parts = b.parts().to_vec();
        parts.push(parts[3].clone());
        v.push(p("P-SHAPE-02", "I1", "five objects (config cert repeated)", &b, reject("shape")).bundle(parts.join("~")));
    }
    {
        let b = P::as_you(&k);
        let parts = b.parts();
        let swapped = [parts[1].clone(), parts[0].clone(), parts[2].clone(), parts[3].clone()];
        v.push(p("P-SHAPE-03", "I1", "assertion and access cert swapped", &b, reject("shape")).bundle(swapped.join("~")));
    }
    {
        let b = P::as_you(&k);
        let parts = b.parts();
        let swapped = [parts[0].clone(), parts[1].clone(), parts[3].clone(), parts[2].clone()];
        v.push(p("P-SHAPE-04", "I1", "warrant and config cert swapped", &b, reject("shape")).bundle(swapped.join("~")));
    }
    {
        let b = P::as_you(&k);
        v.push(p("P-SHAPE-05", "I1", "empty presentation", &b, reject("shape")).bundle(String::new()));
    }
    {
        let b = P::as_you(&k);
        let parts = b.parts();
        v.push(p("P-SHAPE-06", "I1", "warrant slot is not a JWS", &b, reject("shape"))
            .bundle(format!("{}~{}~not-a-jws~{}", parts[0], parts[1], parts[3])));
    }

    // ===================================================================
    // Operation P — binding set (I6, I7)
    // ===================================================================
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", connection_binding()));
        v.push(p("P-BIND-01", "I6", "connection-bound record presented in a bundle", &b, reject("connection_in_p")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", json!([holder_binding("br.*"), connection_binding()])));
        v.push(p("P-BIND-02", "I6", "holder plus connection entries: connection is unsatisfiable in P", &b, reject("connection_in_p")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", json!([requester_binding(SITE)]))).assertion(|s| set(s, "req_origin", json!(SITE)));
        v.push(p("P-BIND-03", "I6", "requester entry only, no holder entry (dead paper)", &b, reject("missing_holder")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", json!([])));
        v.push(p("P-BIND-04", "I1", "empty binding set", &b, reject("binding")));
    }
    {
        let b = P::as_you(&k).w(|w| del(w, "binding"));
        v.push(p("P-BIND-05", "I1", "warrant without a binding claim", &b, reject("binding")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", json!({ "kind": "geo", "country": "NO" })));
        v.push(p("P-BIND-06", "I8", "binding entry of an unimplemented kind", &b, reject("binding")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", json!([holder_binding("br.*"), { "kind": "geo", "country": "NO" }])));
        v.push(p("P-BIND-07", "I8", "holder entry plus an unimplemented kind (conjunctive: the unknown entry fails)", &b, reject("binding")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", json!({ "kind": "holder" })));
        v.push(p("P-BIND-08", "I1", "holder entry without a matcher", &b, reject("binding")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("agents.*")));
        v.push(p("P-BIND-09", "I6", "holder matcher for another namespace", &b, reject("holder")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("br.other")));
        v.push(p("P-BIND-10", "I6", "exact holder matcher naming a different holder", &b, reject("holder")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("br")));
        v.push(p("P-BIND-11", "I6", "matcher equal to the namespace without `.*` (no prefix slack)", &b, reject("holder")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("b.*")));
        v.push(p("P-BIND-12", "I6", "namespace matcher that is a string prefix of the holder's namespace", &b, reject("holder")));
    }
    {
        let b = P::as_you(&k)
            .w(|w| set(w, "binding", json!([holder_binding("br.*"), requester_binding(SITE)])))
            .assertion(|s| set(s, "req_origin", json!("https://evil.example")));
        v.push(p("P-BIND-13", "I7", "requester entry with a mismatching req_origin stamp", &b, reject("requester")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", json!([holder_binding("br.*"), requester_binding(SITE)])));
        v.push(p("P-BIND-14", "I7", "requester entry but the assertion carries no req_origin", &b, reject("requester")));
    }
    {
        let b = P::as_you(&k).assertion(|s| set(s, "req_origin", json!(SITE)));
        v.push(p("P-BIND-15", "I7", "req_origin stamped but the record has no requester entry", &b, reject("requester")));
    }
    {
        let b = P::as_you(&k)
            .w(|w| set(w, "binding", json!([holder_binding("br.*"), requester_binding("https://site.example/")])))
            .assertion(|s| set(s, "req_origin", json!(SITE)));
        v.push(p("P-BIND-16", "I7", "requester origin with a trailing slash is not a web origin", &b, reject("binding")));
    }
    {
        let b = P::new(&k, AG, BROKER, U, BROKER)
            .ac(|c| set(c, "public-key", pubv(&k.access2)))
            .w(|w| set(w, "binding", json!([holder_binding("br.*"), requester_binding(SITE)])))
            .assertion(|s| set(s, "req_origin", json!(SITE)));
        let mut b = b;
        b.as_signer = Some(&k.access2);
        v.push(p("P-BIND-17", "I6", "delegated record with a multi-entry set (self-grant-only)", &b, reject("binding")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", json!([holder_binding("br.*"), holder_binding("agents.*")])));
        v.push(p("P-BIND-18", "I6", "two holder entries, one not covering the holder (conjunctive)", &b, reject("holder")));
    }

    // ===================================================================
    // Operation P — grantee / grantor / identity form (I5, I6)
    // ===================================================================
    {
        let b = P::as_you(&k).w(|w| set(w, "grantee", json!("*@example.com")));
        v.push(p("P-ID-01", "I6", "domain grantee matcher presented in a bundle", &b, reject("matcher_in_p")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "grantee", json!("*")));
        v.push(p("P-ID-02", "I6", "wildcard grantee matcher presented in a bundle", &b, reject("matcher_in_p")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "grantee", json!("other@example.com")));
        v.push(p("P-ID-03", "I5", "grantee differs from the access cert identity", &b, reject("join")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "grantee", json!("User@example.com")));
        v.push(p("P-ID-04", "I5", "grantee local part differs in case from the access identity (local part is byte-exact)", &b, reject("join")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "grantee", json!(AG)));
        v.push(p("P-ID-05", "I5", "grantee is a subaddress of the access identity", &b, reject("join")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "grantor", json!("other@example.com")));
        v.push(p("P-ID-06", "I5", "grantor not in the config cert's identities", &b, reject("grantor")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "grantor", json!("User@example.com")));
        v.push(p("P-ID-07", "I5", "grantor local part differs in case from the config cert identity", &b, reject("grantor")));
    }
    {
        let b = P::new(&k, U, BROKER, U, BROKER).cc(|c| set(c, "identities", json!([AG])));
        v.push(p("P-ID-08", "I13", "config cert for a subaddress does not cover the base grantor (never widens upward)", &b, reject("grantor")));
    }
    {
        let b = P::new(&k, U, BROKER, U, BROKER).cc(|c| set(c, "identities", json!(["user+other@example.com"])));
        v.push(p("P-ID-09", "I13", "config cert for a sibling subaddress does not cover the grantor", &b, reject("grantor")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "grantor", json!("*@example.com")));
        v.push(p("P-ID-10", "I6", "grantor is a matcher (attribution is always exact)", &b, reject("grantor")));
    }
    for (id, bad, title) in [
        ("P-ID-11", "a@b@c.example", "identity with two @ signs"),
        ("P-ID-12", "@example.com", "identity with an empty local part"),
        ("P-ID-13", "user@", "identity with an empty domain"),
        ("P-ID-14", "userexample.com", "identity with no @"),
    ] {
        let b = P::new(&k, bad, BROKER, bad, BROKER);
        v.push(p(id, "I5", title, &b, reject("identity_malformed")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "grantee", json!("a@b@c.example")));
        v.push(p("P-ID-15", "I5", "well-formed access identity, malformed warrant grantee", &b, reject("identity_malformed")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "grantor", json!("@example.com")));
        v.push(p("P-ID-16", "I5", "malformed warrant grantor", &b, reject("identity_malformed")));
    }
    {
        let b = P::as_you(&k).ac(|c| set(c, "identity", json!("User@example.com"))).w(|w| {
            set(w, "grantee", json!("User@example.com"));
            set(w, "grantor", json!("User@example.com"));
        });
        v.push(p("P-ID-17", "I5", "mixed-case local part end to end; the config cert names the lowercase identity", &b, reject("grantor")).known(&["D17"]));
    }

    // ===================================================================
    // Operation P — issuer authority (I3)
    // ===================================================================
    {
        let b = P::new(&k, PAT, BROKER, PAT, BROKER);
        v.push(p("P-ISS-01", "I3", "fallback-issued certs for a domain that has a DNSSEC primary", &b, reject("issuer")));
    }
    {
        let b = P::new(&k, PAT, PRIMARY, PAT, BROKER);
        v.push(p("P-ISS-02", "I3", "primary-issued access cert, fallback-issued config cert for the same primary domain", &b, reject("issuer")));
    }
    {
        let b = P::new(&k, U, "rogue.example", U, "rogue.example");
        v.push(p("P-ISS-03", "I3", "certs from an issuer outside the RP's accepted fallback set", &b, reject("issuer")));
    }
    {
        let b = P::new(&k, U, PRIMARY, U, PRIMARY);
        v.push(p("P-ISS-04", "I3", "a primary vouching for identities in a domain it is not authoritative for", &b, reject("issuer")));
    }
    {
        let b = P::new(&k, PAT, PRIMARY, U, PRIMARY);
        v.push(p("P-ISS-05", "I3", "cross-issuer: grantee's primary signs the grantor's config cert for another domain", &b, reject("issuer")));
    }
    {
        let b = P::new(&k, U, BROKER, U, BROKER).ac(|c| set(c, "iss", json!(PRIMARY)));
        let mut b = b;
        b.ac_signer = Some(&k.broker);
        v.push(p("P-ISS-06", "I3", "access cert claims iss primary.example but is signed by the broker's key", &b, reject("signature")));
    }
    {
        let b = P::as_you(&k).ac(|c| del(c, "iss"));
        v.push(p("P-ISS-07", "I3", "access cert without iss", &b, reject("shape")));
    }

    // ===================================================================
    // Operation P — status (I9)
    // ===================================================================
    {
        let b = P::as_you(&k).ac(|c| set(c, "status", sref(OWN_LIST, 100)));
        v.push(p("P-STAT-01", "I9", "access cert status bit set", &b, reject("revoked")));
    }
    {
        let b = P::as_you(&k).cc(|c| set(c, "status", sref(OWN_LIST, 101)));
        v.push(p("P-STAT-02", "I9", "config cert status bit set (revoked intermediate)", &b, reject("revoked")));
    }
    {
        let b = P::as_you(&k).w(|c| set(c, "status", sref(OWN_LIST, 102)));
        v.push(p("P-STAT-03", "I9", "warrant status bit set", &b, reject("revoked")));
    }
    {
        let b = P::new(&k, PAT, PRIMARY, PAT, PRIMARY).ac(|c| set(c, "status", sref(PRIMARY_LIST, 200)));
        v.push(p("P-STAT-04", "I9", "access cert revoked on the primary's foreign list", &b, reject("revoked")));
    }
    {
        let b = P::as_you(&k).w(|w| del(w, "status"));
        v.push(p("P-STAT-05", "I9", "v2 warrant without a status ref", &b, reject("status")));
    }
    {
        let b = P::as_you(&k).ac(|c| set(c, "status", sref(PRIMARY_LIST, 7)));
        v.push(p("P-STAT-06", "I9", "access cert status.uri host differs from its iss (broker cert pointing at the primary's list)", &b, reject("status_uri_host")).known(&["W6-4"]));
    }
    {
        let b = P::as_you(&k).ac(|c| set(c, "status", sref("https://10.0.0.1/.well-known/browserid-status", 7)));
        v.push(p("P-STAT-07", "I9", "access cert status.uri on a non-public host", &b, reject("status")));
    }
    {
        let b = P::as_you(&k).ac(|c| set(c, "status", sref("https://unreachable.invalid/.well-known/browserid-status", 7)));
        v.push(p("P-STAT-08", "I9", "access cert status.uri on an unreachable host (cannot prove unrevoked)", &b, reject("status")));
    }
    {
        let b = P::as_you(&k).ac(|c| set(c, "status", json!({ "uri": OWN_LIST })));
        v.push(p("P-STAT-09", "I9", "status ref without an idx", &b, reject("shape")));
    }

    // ===================================================================
    // Operation P — constraints (I8)
    // ===================================================================
    {
        let salt = B64.encode([9u8; 16]);
        let h = AudConstraint::hash_audience(&salt, AUD).unwrap();
        let b = P::as_you(&k).ac(move |c| set(c, "constraints", json!({ "aud": { "salt": salt, "hashes": [h] } })));
        v.push(p("P-CONS-01", "I8", "access cert carries a satisfied `aud` constraint; §4.7 (2026-11): core implements aud/scopes/max-ttl, so a satisfied constraint verifies", &b, as_you(&b)));
    }
    {
        let salt = B64.encode([9u8; 16]);
        let h = AudConstraint::hash_audience(&salt, "https://other.example").unwrap();
        let b = P::as_you(&k).ac(move |c| set(c, "constraints", json!({ "aud": { "salt": salt, "hashes": [h] } })));
        v.push(p("P-CONS-02", "I8", "access cert `aud` constraint that does not permit the RP", &b, reject("constraints")));
    }
    {
        let b = P::as_you(&k)
            .cc(|c| set(c, "constraints", json!({ "scopes": ["tool:read"] })))
            .w(|w| set(w, "scopes", json!(["tool:read", "tool:write"])));
        v.push(p("P-CONS-03", "I12", "warrant scopes wider than the config cert's `scopes` allowlist (widened scope in chain)", &b, reject("constraints")));
    }
    {
        let b = P::as_you(&k).cc(|c| set(c, "constraints", json!({ "max-ttl": 86_400 })));
        v.push(p("P-CONS-04", "I8", "warrant validity exceeds the config cert's `max-ttl`", &b, reject("constraints")));
    }
    {
        let b = P::as_you(&k).ac(|c| set(c, "constraints", json!({ "geo": ["NO"] })));
        v.push(p("P-CONS-05", "I8", "access cert with an unknown constraint key", &b, reject("constraints")));
    }
    {
        let b = P::as_you(&k).cc(|c| set(c, "constraints", json!({})));
        v.push(p("P-CONS-06", "I8", "config cert with an empty constraints object (no keys to enforce; §4.7 2026-11: core implements the section, so an empty object verifies)", &b, as_you(&b)));
    }

    // ===================================================================
    // Operation P — scope entries (I8, S7)
    // ===================================================================
    {
        let b = P::as_you(&k).w(|w| set(w, "scopes", json!([{ "scope": "tool:read", "burst": 5 }])));
        v.push(p("P-SCOPE-01", "I8", "scope entry with an unknown parameter", &b, reject("scope")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "scopes", json!([{ "mode": "prompt" }])));
        v.push(p("P-SCOPE-02", "I8", "scope entry object without a scope string", &b, reject("scope")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "scopes", json!([{ "scope": "sign:sbo:post", "mode": "loud" }])));
        v.push(p("P-SCOPE-03", "I8", "`mode` with a value outside auto/prompt", &b, reject("scope")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "scopes", json!("tool:read")));
        v.push(p("P-SCOPE-04", "I1", "scopes is a string, not an array", &b, reject("shape")));
    }
    {
        let b = P::as_you(&k).w(|w| {
            set(w, "binding", json!([holder_binding("br.*")]));
            set(w, "extra", json!(1));
        });
        v.push(p("P-SCOPE-05", "I8", "set-form record with an unrecognized top-level claim", &b, reject("shape")));
    }

    // ===================================================================
    // Operation A — accept
    // ===================================================================
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("*")));
        v.push(a("A-OK-01", "I6", "holder-* record, login without a holder", &b, Some((U, None)), accept(U, U, "", no_scopes.clone())));
    }
    {
        let b = P::as_you(&k);
        v.push(a("A-OK-02", "I6", "namespace matcher, login holder in the namespace", &b, Some((U, Some("br.k9"))), accept(U, U, "br.k9", no_scopes.clone())));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "grantee", json!("*@example.com")); set(w, "binding", holder_binding("*")); set(w, "scopes", json!(["tool:read"])); });
        v.push(a("A-OK-03", "I6", "domain grantee matcher covers a login at that domain (permission, not attribution)", &b, Some(("anyone@example.com", None)),
            accept(U, "*@example.com", "", json!(["tool:read"]))));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "grantee", json!("*@example.com")); set(w, "binding", holder_binding("*")); });
        v.push(a("A-OK-04", "I5", "domain matcher covers a subaddressed login with a differently-cased domain", &b, Some(("anyone+tag@Example.COM", None)),
            accept(U, "*@example.com", "", no_scopes.clone())));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "grantee", json!("*")); set(w, "binding", holder_binding("*")); });
        v.push(a("A-OK-05", "I6", "wildcard grantee covers any authenticated email", &b, Some(("x@y.example", None)), accept(U, "*", "", no_scopes.clone())));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "binding", connection_binding()); set(w, "scopes", json!(["tool:read"])); });
        v.push(a("A-OK-06", "I6", "connection-bound self-grant validates (subject authenticated by the custody dance, not a login)", &b, None,
            accept(U, U, "", json!(["tool:read"]))));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", json!([holder_binding("*")])));
        v.push(a("A-OK-07", "I1", "array-form binding on an admission record", &b, Some((U, None)), accept(U, U, "", no_scopes.clone())));
    }
    {
        let scopes = json!(["sign:sbo:post", { "scope": "sign:sbo:delete", "mode": "prompt" }]);
        let b = P::as_you(&k).w(|w| { set(w, "binding", holder_binding("*")); set(w, "scopes", scopes.clone()); });
        v.push(a("A-OK-08", "I11", "parameterized scope entries on an admission record are returned verbatim", &b, Some((U, None)),
            accept(U, U, "", scopes)).known(&["D7"]));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("*")));
        v.push(a("A-OK-09", "I5", "login domain differs only in case from the grantee", &b, Some(("user@EXAMPLE.com", None)), accept(U, U, "", no_scopes.clone())));
    }
    {
        let b = P::new(&k, AG, BROKER, U, BROKER).w(|w| set(w, "binding", holder_binding("agents.*")));
        v.push(a("A-OK-10", "I6", "delegated admission record: agent login with a covered holder", &b, Some((AG, Some("agents.x1"))),
            accept(U, AG, "agents.x1", no_scopes.clone())));
    }

    // ===================================================================
    // Operation A — reject
    // ===================================================================
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", json!([holder_binding("*"), requester_binding(SITE)])));
        v.push(a("A-REJ-01", "I6", "requester entry is unsatisfiable in admission", &b, Some((U, None)), reject_at_match("requester_in_a")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", connection_binding()));
        v.push(a("A-REJ-02", "I6", "connection-bound record does not match a login", &b, Some((U, None)), reject_at_match("connection_login")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("svc.one")));
        v.push(a("A-REJ-03", "I6", "exact holder matcher, login with a different holder", &b, Some((U, Some("svc.two"))), reject_at_match("holder")).known(&["D5"]));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("agents.*")));
        v.push(a("A-REJ-04", "I6", "namespace matcher, login holder outside the namespace", &b, Some((U, Some("br.main"))), reject_at_match("holder")).known(&["D5"]));
    }
    {
        let b = P::as_you(&k);
        v.push(a("A-REJ-05", "I6", "non-* matcher against a holder-less login", &b, Some((U, None)), reject_at_match("holder")).known(&["D5"]));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "grantee", json!("*@example.com")); set(w, "binding", holder_binding("*")); });
        v.push(a("A-REJ-06", "I5", "domain matcher does not cover a subdomain login", &b, Some(("a@sub.example.com", None)), reject_at_match("grantee")));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "grantee", json!("*")); set(w, "binding", holder_binding("*")); });
        v.push(a("A-REJ-07", "I5", "wildcard grantee never covers a malformed identity (a@b@c)", &b, Some(("a@b@c.example", None)), reject_at_match("identity_malformed")).known(&["D17"]));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "grantee", json!("*")); set(w, "binding", holder_binding("*")); });
        v.push(a("A-REJ-08", "I5", "wildcard grantee never covers an identity with an empty local part", &b, Some(("@example.com", None)), reject_at_match("identity_malformed")).known(&["D17"]));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "grantee", json!("*@example.com")); set(w, "binding", holder_binding("*")); });
        v.push(a("A-REJ-09", "I5", "domain matcher never covers a malformed identity", &b, Some(("a@b@example.com", None)), reject_at_match("identity_malformed")).known(&["D17"]));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("*")));
        v.push(a("A-REJ-10", "I5", "login local part differs in case from the grantee", &b, Some(("User@example.com", None)), reject_at_match("grantee")).known(&["D17"]));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("*")));
        v.push(a("A-REJ-11", "I5", "login is a subaddress of the grantee", &b, Some((AG, None)), reject_at_match("grantee")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("*")));
        v.push(a("A-REJ-12", "I5", "login is a different identity", &b, Some(("other@example.com", None)), reject_at_match("grantee")));
    }
    {
        let b = P::as_you(&k).w(|w| {
            set(w, "typ", json!(TYP_W1));
            del(w, "binding");
            del(w, "status");
            set(w, "holder", json!("*"));
        });
        v.push(a("A-REJ-13", "I1", "retired v1 record held for admission", &b, Some((U, None)), reject("typ")).known(&["S3"]));
    }
    {
        let b = P::new(&k, AG, BROKER, U, BROKER).w(|w| set(w, "binding", connection_binding()));
        v.push(a("A-REJ-14", "I6", "connection-bound record that is not a self-grant", &b, None, reject("binding")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", json!({ "kind": "connection", "protocol": "saml", "id": "cn_1", "client_host": "claude.ai", "client_name": "Claude" })));
        v.push(a("A-REJ-15", "I8", "connection entry with an unimplemented protocol", &b, None, reject("binding")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", json!({ "kind": "connection", "protocol": "oauth", "id": "", "client_host": "claude.ai", "client_name": "Claude" })));
        v.push(a("A-REJ-16", "I6", "connection entry with an empty id (instance must be pinned)", &b, None, reject("binding")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", json!({ "kind": "connection", "protocol": "oauth", "id": "cn_1", "client_name": "Claude" })));
        v.push(a("A-REJ-17", "I6", "connection entry without client_host", &b, None, reject("binding")));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "binding", holder_binding("*")); set(w, "audience", json!("https://evil.example")); });
        v.push(a("A-REJ-18", "I4", "record audience differs from the resource", &b, Some((U, None)), reject("audience")));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "binding", holder_binding("*")); set(w, "audience", json!("https://rp.example/")); });
        v.push(a("A-REJ-19", "I4", "record audience with a trailing slash", &b, Some((U, None)), reject("audience")));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "binding", holder_binding("*")); set(w, "exp", json!(IAT + 1)); });
        v.push(a("A-REJ-20", "I2", "expired record", &b, Some((U, None)), reject("expired")));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "binding", holder_binding("*")); set(w, "iat", json!(FUTURE)); set(w, "exp", json!(FUTURE + 86_400)); });
        v.push(a("A-REJ-21", "I2", "post-dated record", &b, Some((U, None)), reject("future_iat")).known(&["D16"]));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "binding", holder_binding("*")); set(w, "status", sref(OWN_LIST, 102)); });
        v.push(a("A-REJ-22", "I9", "record status bit set", &b, Some((U, None)), reject("revoked")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("*"))).cc(|c| set(c, "status", sref(OWN_LIST, 101)));
        v.push(a("A-REJ-23", "I9", "config cert under the record is revoked", &b, Some((U, None)), reject("revoked")));
    }
    {
        let mut b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("*")));
        b.w_signer = Some(&k.rogue);
        v.push(a("A-REJ-24", "I2", "record not signed by the config cert's key", &b, Some((U, None)), reject("signature")));
    }
    {
        let mut b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("*")));
        b.cc_signer = Some(&k.rogue);
        v.push(a("A-REJ-25", "I2", "config cert under the record not signed by its issuer", &b, Some((U, None)), reject("signature")));
    }
    {
        let b = P::as_you(&k)
            .w(|w| { set(w, "binding", holder_binding("*")); set(w, "scopes", json!(["tool:read", "tool:write"])); })
            .cc(|c| set(c, "constraints", json!({ "scopes": ["tool:read"] })));
        v.push(a("A-REJ-26", "I12", "record scopes wider than the config cert's allowlist", &b, Some((U, None)), reject("constraints")));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "binding", holder_binding("*")); set(w, "grantor", json!("other@example.com")); });
        v.push(a("A-REJ-27", "I5", "record grantor not covered by the config cert", &b, Some((U, None)), reject("grantor")));
    }
    {
        let b = P::new(&k, PAT, BROKER, PAT, BROKER).w(|w| set(w, "binding", holder_binding("*")));
        v.push(a("A-REJ-28", "I3", "fallback-issued config cert for a domain with a primary", &b, Some((PAT, None)), reject("issuer")));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "binding", holder_binding("*")); del(w, "status"); });
        v.push(a("A-REJ-29", "I9", "v2 record without a status ref", &b, Some((U, None)), reject("status")));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "binding", holder_binding("*")); set(w, "scopes", json!([{ "scope": "tool:read", "burst": 5 }])); });
        v.push(a("A-REJ-30", "I8", "record scope entry with an unknown parameter", &b, Some((U, None)), reject("scope")));
    }
    {
        let b = P::as_you(&k).w(|w| set(w, "binding", holder_binding("*")));
        let full = b.bundle();
        v.push(a("A-REJ-31", "I1", "four-object bundle handed to the record validator", &b, Some((U, None)), reject("shape")).bundle(full));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "grantee", json!("*@EXAMPLE.com")); set(w, "binding", holder_binding("*")); });
        v.push(a("A-REJ-32", "I5", "domain matcher with a differently-cased domain does not cover a subdomain login", &b, Some(("a@sub.example.com", None)), reject_at_match("grantee")));
    }
    {
        let b = P::as_you(&k).w(|w| { set(w, "grantee", json!("*@example.com")); set(w, "binding", holder_binding("*")); });
        v.push(a("A-REJ-33", "I5", "domain matcher does not cover a look-alike domain", &b, Some(("a@examplexcom", None)), reject_at_match("grantee")));
    }

    // ===================================================================
    // DNS TXT record (§3) — the `_browserid` record value, parsed by
    // `DnsRecord::parse` (the one parser in the repo; browserid-dnssec calls
    // it). `bundle` is the TXT value; accept carries the expected key/host.
    // ===================================================================
    let key_b64 = k.broker.public_key().to_base64();
    let t = |id: &'static str, title: &'static str, txt: String, expect: Value| Vec_ {
        id, op: "T", invariant: "I3", title, audience: String::new(), bundle: txt, objects: json!({}), subject: None, expect, known: vec![],
    };
    let t_ok = |host: Option<&str>| json!({ "verdict": "accept", "public_key": pubv(&k.broker), "host": host });
    v.push(t("T-OK-01", "minimal record", format!("v=browserid1; public-key-algorithm=Ed25519; public-key={key_b64}"), t_ok(None)));
    v.push(t("T-OK-02", "record with host delegation", format!("v=browserid1; public-key-algorithm=Ed25519; public-key={key_b64}; host=idp.browserid.me"), t_ok(Some("idp.browserid.me"))));
    v.push(t("T-OK-03", "extra whitespace around fields and separators", format!("  v=browserid1 ;  public-key-algorithm=Ed25519 ;public-key={key_b64}  ; "), t_ok(None)));
    v.push(t("T-OK-04", "unknown field is ignored (forward compatibility)", format!("v=browserid1; public-key-algorithm=Ed25519; public-key={key_b64}; note=hello"), t_ok(None)));
    v.push(t("T-OK-05", "fields in a different order", format!("public-key={key_b64}; host=idp.browserid.me; public-key-algorithm=Ed25519; v=browserid1"), t_ok(Some("idp.browserid.me"))));
    v.push(t("T-REJ-01", "missing v", format!("public-key-algorithm=Ed25519; public-key={key_b64}"), reject("malformed_txt")));
    v.push(t("T-REJ-02", "unsupported version", format!("v=browserid2; public-key-algorithm=Ed25519; public-key={key_b64}"), reject("malformed_txt")));
    v.push(t("T-REJ-03", "unsupported algorithm", format!("v=browserid1; public-key-algorithm=RSA; public-key={key_b64}"), reject("malformed_txt")));
    v.push(t("T-REJ-04", "missing public-key", "v=browserid1; public-key-algorithm=Ed25519".to_string(), reject("malformed_txt")));
    v.push(t("T-REJ-05", "empty public-key", "v=browserid1; public-key-algorithm=Ed25519; public-key=".to_string(), reject("malformed_txt")));
    v.push(t("T-REJ-06", "public-key too short (31 bytes)", format!("v=browserid1; public-key-algorithm=Ed25519; public-key={}", B64.encode([7u8; 31])), reject("malformed_txt")));
    v.push(t("T-REJ-07", "public-key too long (33 bytes)", format!("v=browserid1; public-key-algorithm=Ed25519; public-key={}", B64.encode([7u8; 33])), reject("malformed_txt")));
    v.push(t("T-REJ-08", "public-key in standard base64 alphabet with padding, not base64url", format!("v=browserid1; public-key-algorithm=Ed25519; public-key={}", base64::engine::general_purpose::STANDARD.encode(k.broker.public_key().as_bytes())), reject("malformed_txt")));
    v.push(t("T-REJ-09", "public-key is not base64 at all", "v=browserid1; public-key-algorithm=Ed25519; public-key=not*base64!".to_string(), reject("malformed_txt")));
    v.push(t("T-REJ-10", "empty record", String::new(), reject("malformed_txt")));
    v.push(t("T-REJ-11", "two public-key fields in one record (ambiguous root)", format!("v=browserid1; public-key-algorithm=Ed25519; public-key={}; public-key={key_b64}", k.rogue.public_key().to_base64()), reject("malformed_txt")));
    v.push(t("T-REJ-12", "fields separated by commas instead of semicolons", format!("v=browserid1, public-key-algorithm=Ed25519, public-key={key_b64}"), reject("malformed_txt")));
    v.push(t("T-REJ-13", "field names in upper case", format!("V=browserid1; PUBLIC-KEY-ALGORITHM=Ed25519; PUBLIC-KEY={key_b64}"), reject("malformed_txt")));

    v
}

fn environment(k: &Keys) -> Value {
    json!({
        "at": AT,
        "skew": 300,
        "audience": AUD,
        "accepted_fallbacks": [BROKER],
        "primaries": { PRIMARY: pubv(&k.primary) },
        "fallback": { "domain": BROKER, "public_key": pubv(&k.broker) },
        "own_status_uri": OWN_LIST,
        "status_lists": {
            OWN_LIST: { "issuer": BROKER, "revoked": REVOKED_OWN },
            PRIMARY_LIST: { "issuer": PRIMARY, "revoked": REVOKED_PRIMARY },
        },
        "keys": {
            "broker_idp": { "seed_byte": 1, "public_key": pubv(&k.broker) },
            "primary_idp": { "seed_byte": 2, "public_key": pubv(&k.primary) },
            "access": { "seed_byte": 3, "public_key": pubv(&k.access) },
            "config": { "seed_byte": 4, "public_key": pubv(&k.config) },
            "rogue": { "seed_byte": 5, "public_key": pubv(&k.rogue) },
            "access2": { "seed_byte": 6, "public_key": pubv(&k.access2) },
        },
    })
}

pub fn render() -> String {
    let k = Keys::new();
    let vectors = build();
    let mut ids = std::collections::BTreeSet::new();
    for v in &vectors {
        assert!(ids.insert(v.id), "duplicate vector id {}", v.id);
    }
    let vs: Vec<Value> = vectors
        .iter()
        .map(|v| {
            let mut m = Map::new();
            m.insert("id".into(), json!(v.id));
            m.insert("op".into(), json!(v.op));
            m.insert("invariant".into(), json!(v.invariant));
            m.insert("title".into(), json!(v.title));
            m.insert("audience".into(), json!(v.audience));
            m.insert("bundle".into(), json!(v.bundle));
            m.insert("objects".into(), v.objects.clone());
            if let Some(s) = &v.subject {
                m.insert("subject".into(), s.clone());
            }
            m.insert("expect".into(), v.expect.clone());
            if !v.known.is_empty() {
                m.insert("known_findings".into(), json!(v.known));
            }
            Value::Object(m)
        })
        .collect();
    let doc = json!({
        "suite": "browserid-ng conformance vectors, security audit 2026-11 (WS2)",
        "generator": "browserid-core/tests/audit_2026_11_ws2_generate.rs",
        "regenerate": "WS2_REGEN=1 cargo test -p browserid-core --test audit_2026_11_ws2_generate",
        "format": {
            "op": "P = presentation (§6.1): `bundle` is access_cert~assertion~warrant~config_cert. A = admission (§6.4): `bundle` is warrant~config_cert and `subject` is the independently authenticated login to match (holder may be null); a vector without `subject` stops after record validation. T = discovery (§3): `bundle` is a `_browserid` TXT record value; accept carries the expected public_key and host.",
            "expect.stage": "op A only: `match` marks a record that validates (§6.4 step 1) but whose subject fails step 3; a runner that only validates records expects okay for it.",
            "expect.verdict": "accept | reject. For accept: email (grantor), grantee, holder (access-cert holder in P, login holder in A, empty when the login carried none), scopes (entries verbatim). For reject: reason_class is the expected class; runners compare verdicts, reason classes are informational.",
            "known_findings": "audit ids this vector is expected to expose today (see docs/security-audit-2026-11-ws2-conformance.md); runners carry their own expected-fail lists.",
            "environment.at": "the instant a deterministic verifier judges the bundle at; wall-clock verifiers are in-window for every accept vector until 2035.",
        },
        "environment": environment(&k),
        "vectors": vs,
    });
    serde_json::to_string_pretty(&doc).unwrap() + "\n"
}

fn path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/conformance-2026-11.json")
}

/// Regenerates the suite and compares it to the committed file. Set
/// `WS2_REGEN=1` to rewrite the file instead.
#[test]
fn vectors_are_regenerable_and_current() {
    let rendered = render();
    let path = path();
    if std::env::var_os("WS2_REGEN").is_some() {
        std::fs::write(&path, &rendered).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == rendered,
        "test-vectors/conformance-2026-11.json is stale; regenerate with WS2_REGEN=1 cargo test -p browserid-core --test audit_2026_11_ws2_generate"
    );
}
