//! Fallback-IdP surface (apgv): SMTP /auth establishes an email cookie that
//! gates /cert_key, which issues a short cert (iss = this broker's domain) for
//! an email whose domain the broker doesn't own.

mod common;

use browserid_core::{Certificate, KeyPair};
use common::create_test_server;
use serde_json::{json, Value};

#[tokio::test]
async fn smtp_auth_then_cert_key_issues_a_cert() {
    let (server, email_sender) = create_test_server();
    let email = "someone@gmail.com"; // a domain this broker does NOT own
    let user_kp = KeyPair::generate();

    // 1. Provision without a session → 401 (dialog would drop to /auth).
    let r = server
        .post("/cert_key")
        .json(&json!({ "email": email, "pubkey": { "algorithm": "Ed25519", "publicKey": user_kp.public_key().to_base64() } }))
        .await;
    assert_eq!(r.status_code(), 401, "no session yet: {:?}", r.text());

    // 2. SMTP challenge.
    let r = server.post("/auth/send").json(&json!({ "email": email })).await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    let code = email_sender.get_code(email).expect("code emailed");

    // 3. Wrong code rejected.
    let r = server.post("/auth/verify").json(&json!({ "email": email, "code": "000000" })).await;
    assert_eq!(r.status_code(), 401);

    // 4. Right code sets the email cookie.
    let r = server.post("/auth/verify").json(&json!({ "email": email, "code": code })).await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    let cookie = r.maybe_cookie("fb_email").expect("email cookie set");

    // 5. whoami reflects it.
    let who: Value = server.get("/whoami").add_cookie(cookie.clone()).await.json();
    assert_eq!(who["authenticated"], true);
    assert_eq!(who["email"], email);

    // 6. cert_key now issues a cert bound to the email, iss = broker domain.
    let r = server
        .post("/cert_key")
        .add_cookie(cookie.clone())
        .json(&json!({ "email": email, "pubkey": { "algorithm": "Ed25519", "publicKey": user_kp.public_key().to_base64() } }))
        .await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    let body: Value = r.json();
    let cert = Certificate::parse(body["cert"].as_str().unwrap()).unwrap();
    assert_eq!(cert.email(), Some(email));
    assert_eq!(cert.issuer(), "localhost:3000"); // the test broker's domain
    assert!(!cert.is_agent());

    // 7. The cookie only authorizes its own email — not a different one.
    let r = server
        .post("/cert_key")
        .add_cookie(cookie)
        .json(&json!({ "email": "other@gmail.com", "pubkey": { "algorithm": "Ed25519", "publicKey": user_kp.public_key().to_base64() } }))
        .await;
    assert_eq!(r.status_code(), 401, "cookie must not vouch for a different email");
}

#[tokio::test]
async fn auth_send_rate_limited_per_email() {
    let (server, _e) = create_test_server();
    let email = "flood-unique@example.com";
    for _ in 0..5 {
        let r = server.post("/auth/send").json(&json!({ "email": email })).await;
        assert_eq!(r.status_code(), 200, "{:?}", r.text());
    }
    let r = server.post("/auth/send").json(&json!({ "email": email })).await;
    assert_eq!(r.status_code(), 429, "6th send to one address must be capped");
}

#[tokio::test]
async fn verify_code_brute_force_is_capped() {
    let (server, email_sender) = create_test_server();
    let email = "brute-unique@example.com";
    server.post("/auth/send").json(&json!({ "email": email })).await;
    let code = email_sender.get_code(email).unwrap();
    // 5 wrong attempts burn the code.
    for _ in 0..5 {
        let r = server.post("/auth/verify").json(&json!({ "email": email, "code": "999998" })).await;
        assert_eq!(r.status_code(), 401);
    }
    // Even the correct code now fails — it was burned.
    let r = server.post("/auth/verify").json(&json!({ "email": email, "code": code })).await;
    assert_eq!(r.status_code(), 401, "code must be burned after too many wrong attempts");
}
