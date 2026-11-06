//! Write the seed corpus for every target (`cargo run --bin gen_seeds` from
//! `fuzz/`). Seeds are committed under `fuzz/seeds/<target>/`; libFuzzer
//! reads them read-only and writes new findings to `fuzz/corpus/<target>/`.

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use browserid_fuzz as fx;

fn put(dir: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join(name), bytes).unwrap();
}

fn bomb(inflated: usize) -> String {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    let chunk = vec![0u8; 1 << 20];
    let mut left = inflated;
    while left > 0 {
        let n = left.min(chunk.len());
        enc.write_all(&chunk[..n]).unwrap();
        left -= n;
    }
    B64.encode(enc.finish().unwrap())
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds");
    let b = fx::bundle();

    let d = root.join("jws_parse");
    put(&d, "bundle", b.encode().as_bytes());
    put(&d, "device_cert", b.config_cert.encoded().as_bytes());
    put(&d, "access_cert", b.access_cert.encoded().as_bytes());
    put(&d, "warrant", b.warrant.encoded().as_bytes());
    put(&d, "assertion", b.assertion.encoded().as_bytes());
    put(&d, "record", format!("{}~{}", b.warrant.encoded(), b.config_cert.encoded()).as_bytes());
    let list = browserid_core::StatusList::from_revoked([3, 42], 1000);
    let tok = browserid_core::StatusListToken::create("example.com", fx::STATUS, &list, &fx::keys().idp).unwrap();
    put(&d, "status_list", tok.encoded().as_bytes());

    // claims_json: Arbitrary-shaped input = [which:u32-ish bytes][json string]... Keep
    // it simple: the derive consumes a leading byte for the enum, then the
    // string; libFuzzer will mutate the rest.
    let d = root.join("claims_json");
    let payload = |enc: &str| -> Vec<u8> {
        let parts: Vec<&str> = enc.split('.').collect();
        B64.decode(parts[1]).unwrap()
    };
    put(&d, "device", &[&[0u8, 0, 0, 0][..], &payload(b.config_cert.encoded())].concat());
    put(&d, "access", &[&[1u8, 0, 0, 0][..], &payload(b.access_cert.encoded())].concat());
    put(&d, "warrant", &[&[3u8, 0, 0, 0][..], &payload(b.warrant.encoded())].concat());
    put(&d, "status", &[&[4u8, 0, 0, 0][..], &payload(tok.encoded())].concat());
    let param_warrant = serde_json::json!({
        "typ": "browserid-warrant-v2", "iat": fx::IAT, "exp": fx::IAT + 86400, "grantor": fx::USER, "grantee": fx::USER,
        "binding": [{"kind": "holder", "matcher": "br.*"}, {"kind": "requester", "origin": "https://app.example"}],
        "audience": fx::AUD, "status": {"uri": fx::STATUS, "idx": 9},
        "scopes": ["read", {"scope": "pay:send", "cap": {"amount": "20.00", "currency": "USD", "window": "P30D"}, "counterparties": ["*@shop.example"], "max_duration": "P1Y", "min_reputation": {"indexer": "https://idx.example", "score": 70}, "mode": "prompt"}]
    });
    put(&d, "warrant_params", &[&[3u8, 0, 0, 0][..], param_warrant.to_string().as_bytes()].concat());
    let managed = serde_json::json!({
        "typ": "browserid-device-cert-v1", "iss": "example.com", "iat": fx::IAT, "exp": fx::IAT + 86400 * 90,
        "purpose": "authorization", "holder": "br.main", "identities": [fx::USER, "danmills+*@example.com"],
        "public-key": fx::keys().config.public_key().to_base64(), "status": {"uri": fx::STATUS, "idx": 2}, "managed": true,
        "constraints": {"aud": {"salt": "AAAA", "hashes": []}, "scopes": ["read"], "max-ttl": 3600}
    });
    put(&d, "device_constraints", &[&[0u8, 0, 0, 0][..], managed.to_string().as_bytes()].concat());

    let d = root.join("scope_parse");
    put(&d, "bare", br#""read""#);
    put(&d, "params", br#"{"scope":"pay:send","cap":{"amount":"20.00","currency":"USD","window":"P30D"},"counterparties":["a@b.example"],"max_duration":"P1Y","min_reputation":{"indexer":"https://idx.example","score":70},"mode":"prompt"}"#);
    put(&d, "duration", b"P1DT12H30M");
    put(&d, "money", b"123.45");

    let d = root.join("identity");
    put(&d, "exact", b"user@example.com\0user@example.com\0br.main\0br.*");
    put(&d, "sub", b"user@example.com\0user+agent@example.com\0k3n9.x\0*");
    put(&d, "glob", b"danmills+*@sandmill.org\0danmills+bsky@sandmill.org\0a.b\0a.b");
    put(&d, "idn", "a@bücher.example\0a@xn--bcher-kva.example\0h\0h".as_bytes());

    let d = root.join("dns_txt");
    let pk = fx::keys().idp.public_key().to_base64();
    put(&d, "good", format!("v=browserid1; public-key-algorithm=Ed25519; public-key={pk}").as_bytes());
    put(&d, "host", format!("v=browserid1; public-key-algorithm=Ed25519; public-key={pk}; host=idp.browserid.me").as_bytes());
    put(&d, "dup", format!("v=browserid1; public-key-algorithm=Ed25519; public-key=AAAA; public-key={pk}").as_bytes());
    put(&d, "spaces", format!("  v = browserid1 ;public-key-algorithm= Ed25519;public-key = {pk} ; x=y").as_bytes());

    let d = root.join("status_list");
    put(&d, "small", list.encode().unwrap().as_bytes());
    put(&d, "bomb_32mib", bomb(32 << 20).as_bytes());

    let d = root.join("request_kind_json");
    put(&d, "warrant", br#"{"kind":"warrant","grants":[{"audience":"https://rp.example","scopes":["read",{"scope":"pay:send","mode":"prompt","cap":{"amount":"1","currency":"USD"}}]}],"message":"hi","grantee":"agent@example.com","holder":"ag.1","grantor":"*","return_url":"https://rp.example/cb"}"#);
    put(&d, "admission", br#"{"kind":"admission","code":"abc"}"#);
    put(&d, "login", br#"{"kind":"login","acceptedFallbacks":["browserid.me"]}"#);
    put(&d, "signature", br#"{"kind":"signature","audience":"https://rp.example","object":{"typ":"x"}}"#);
    put(&d, "provision", br#"{"kind":"provision","code":"abc"}"#);
    put(&d, "filed_warrant", br#"{"device_cert":"a.b.c","identity":"agent@example.com","grants":[{"audience":"https://rp.example","scopes":["read"]}],"label":"l","grantor":"self","message":"m","return_url":"https://rp.example/cb"}"#);
    put(&d, "record", br#"{"type":"connection","audience":"https://rp.example","scopes":["read"],"client":{"client_host":"rp.example","client_name":"RP"},"grantor":"user@example.com","message":"m","return_url":"https://rp.example/cb"}"#);
    println!("seeds written under {}", root.display());
}
