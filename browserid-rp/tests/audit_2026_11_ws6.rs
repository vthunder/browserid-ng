//! Security audit 2026-11, WS6 — the `browserid-rp` pinned-table status path
//! (threat-model I9; WS1 candidate D15; July H1/M3 class).
//!
//! `Verifier::verify_dnssec` runs the hosted verifier's SSRF-guarded,
//! issuer-bound, ttl-capped fetch. The pinned-table path (`Verifier::verify`
//! + `Verifier::refresh_status` / `StatusCache::refresh`) does not: it fetches
//! with `reqwest::get` (redirects followed, any scheme, any host) and honours
//! the issuer-declared `ttl` with no ceiling.
//!
//! Report: docs/security-audit-2026-11-ws6-core-verifier.md.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use browserid_core::{KeyPair, StatusList, StatusListToken, StatusRef, TYP_STATUS_LIST};
use browserid_rp::{StatusCache, StatusVerdict};
use serde_json::json;

const ISSUER: &str = "browserid.example";

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// A status-list token with caller-chosen `iat`/`ttl` (the constructor pins
/// `ttl` to the 300 s reference).
fn list_token(key: &KeyPair, uri: &str, iat: i64, ttl: i64) -> String {
    let claims = json!({
        "typ": TYP_STATUS_LIST,
        "iss": ISSUER,
        "sub": uri,
        "iat": iat,
        "ttl": ttl,
        "status_list": { "bits": 1, "lst": StatusList::from_revoked([], 8).encode().unwrap() },
    });
    let h = B64.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let c = B64.encode(claims.to_string());
    let msg = format!("{h}.{c}");
    let sig = B64.encode(key.sign(msg.as_bytes()));
    format!("{msg}.{sig}")
}

/// Serve exactly one HTTP/1.1 response on a fresh loopback port.
fn one_shot_server(status_line: &'static str, headers: Vec<String>, body: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let mut got = Vec::new();
        loop {
            let n = sock.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if got.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let mut resp = format!("{status_line}\r\n");
        for h in headers {
            resp.push_str(&h);
            resp.push_str("\r\n");
        }
        resp.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()));
        sock.write_all(resp.as_bytes()).unwrap();
        let _ = sock.flush();
    });
    format!("http://{addr}")
}

/// A valid list whose issuer-declared `ttl` is ten years: the pinned path's
/// cache keeps honouring it for the process lifetime (July M3, closed only on
/// the hosted path with `is_fresh_capped`).
#[test]
#[ignore] // AUDIT-2026-11 D15: fails today — `StatusCache::verdict` uses `is_fresh(grace)` with no ttl ceiling (lib.rs StatusCache::verdict)
fn d15_pinned_status_cache_caps_the_issuer_declared_ttl() {
    let key = KeyPair::generate();
    let uri = "https://browserid.example/.well-known/browserid-status";
    let year = 365 * 86_400;
    // Fetched "a year ago" per its own iat, still inside a ten-year ttl.
    let token = StatusListToken::parse(&list_token(&key, uri, now() - year, 10 * year)).unwrap();
    token.verify(&key.public_key(), uri).unwrap();
    let cache = StatusCache::new();
    cache.insert(uri, token);
    let verdict = cache.check(&StatusRef { uri: uri.into(), idx: 3 });
    assert!(
        matches!(verdict, StatusVerdict::Unknown),
        "a year-old list must be Unknown regardless of its declared ttl; got {verdict:?}"
    );
}

/// `StatusCache::refresh` follows a redirect from the configured URI to a
/// loopback `http` host and accepts the list served there, so long as the
/// token's `sub` names the ORIGINAL uri. The hosted path refuses all three
/// (no redirects, https only, no non-global hosts).
#[test]
#[ignore] // AUDIT-2026-11 D15: fails today — `reqwest::get(uri)` in StatusCache::refresh / Verifier::refresh_status (lib.rs ~272-290, ~723)
fn d15_pinned_status_refresh_refuses_redirects_and_private_hosts() {
    let key = KeyPair::generate();
    // Bind the redirecting server first so its uri is known before the list
    // (whose `sub` must equal that uri) is signed.
    let redirector = TcpListener::bind("127.0.0.1:0").unwrap();
    let uri = format!("http://{}/.well-known/browserid-status", redirector.local_addr().unwrap());
    let body = list_token(&key, &uri, now(), 300);
    let hop = one_shot_server("HTTP/1.1 200 OK", vec!["Content-Type: application/jwt".into()], body);
    thread::spawn(move || {
        let (mut sock, _) = redirector.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf);
        let resp = format!(
            "HTTP/1.1 302 Found\r\nLocation: {hop}/list\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        sock.write_all(resp.as_bytes()).unwrap();
    });

    let cache = StatusCache::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let r = rt.block_on(cache.refresh(&uri, &key.public_key()));
    assert!(
        r.is_err(),
        "a plain-http loopback uri reached through a redirect must be refused (I9), but the list was accepted"
    );
    assert!(cache.age(&uri).is_none(), "nothing may be cached from that fetch");
}
