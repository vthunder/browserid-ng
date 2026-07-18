//! Integration test for the device-cert model endpoints:
//! /device/issue → /access/mint → /warrant/issue → /verify-access.

mod common;

use std::sync::Arc;

use axum_test::TestServer;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::device::{AccessRequest, Subject};
use browserid_core::{Assertion, KeyPair};
use chrono::Duration;
use common::{create_user, MockEmailSender};
use serde_json::{json, Value};

const DOMAIN: &str = "localhost:3000";
const AUDIENCE: &str = "https://rp.example.com";

fn make_server() -> (TestServer, MockEmailSender) {
    let keypair = KeyPair::generate();
    let email_sender = Arc::new(MockEmailSender::new());
    let state = AppState::new_with_arcs(
        keypair,
        DOMAIN.to_string(),
        Arc::new(InMemoryUserStore::new()),
        Arc::new(InMemorySessionStore::new()),
        email_sender.clone(),
    );
    let server = TestServer::new(routes::create_router(Arc::new(state))).unwrap();
    (server, MockEmailSender { sent: email_sender.sent.clone() })
}

async fn csrf(server: &TestServer, session: &str) -> String {
    server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .await
        .json::<Value>()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn device_cert_login_roundtrip() {
    let (server, sender) = make_server();
    let email = "human@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
    let c = csrf(&server, &session).await;

    // 1. Device cert (authentication) for a fresh device key.
    let device_kp = KeyPair::generate();
    let body: Value = server
        .post("/device/issue")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "email": email, "device_pubkey": device_kp.public_key().to_base64() }))
        .await
        .json();
    assert_eq!(body["success"], true, "device/issue: {body}");
    let device_cert = body["device_cert"].as_str().unwrap().to_string();

    // 2. Mint a fresh-key access cert (device cert is the credential — no session).
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(DOMAIN, email, Subject::User, &access_kp.public_key(), &device_kp).unwrap();
    let body: Value = server
        .post("/access/mint")
        .json(&json!({ "device_cert": device_cert, "access_request": areq.encoded() }))
        .await
        .json();
    assert_eq!(body["success"], true, "access/mint: {body}");
    assert_eq!(body["email"], email);
    let access_cert = body["access_cert"].as_str().unwrap().to_string();

    // 3. Warrant (+ config cert), issued by the broker's server-side config cert.
    let body: Value = server
        .post("/warrant/issue")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "email": email, "audience": AUDIENCE }))
        .await
        .json();
    assert_eq!(body["success"], true, "warrant/issue: {body}");
    let warrant = body["warrant"].as_str().unwrap().to_string();
    let config_cert = body["config_cert"].as_str().unwrap().to_string();

    // 4. Assertion + present the bundle to the (convenience) verifier.
    let assertion = Assertion::create(AUDIENCE, Duration::minutes(5), &access_kp).unwrap();
    let presentation = format!("{access_cert}~{}~{warrant}~{config_cert}", assertion.encoded());
    let body: Value = server
        .post("/verify-access")
        .json(&json!({ "presentation": presentation, "audience": AUDIENCE }))
        .await
        .json();
    assert_eq!(body["status"], "okay", "verify-access: {body}");
    assert_eq!(body["email"], email);
    assert_eq!(body["subject"], "user");

    // Negative: wrong audience is rejected.
    let body: Value = server
        .post("/verify-access")
        .json(&json!({ "presentation": presentation, "audience": "https://evil.example" }))
        .await
        .json();
    assert_eq!(body["status"], "failure");
}

#[tokio::test]
async fn access_mint_rejects_foreign_device_cert() {
    let (server, sender) = make_server();
    let email = "human@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
    let c = csrf(&server, &session).await;
    let device_kp = KeyPair::generate();
    let body: Value = server
        .post("/device/issue")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "email": email, "device_pubkey": device_kp.public_key().to_base64() }))
        .await
        .json();
    let device_cert = body["device_cert"].as_str().unwrap().to_string();

    // An access request signed by a DIFFERENT key than the device cert certifies.
    let attacker = KeyPair::generate();
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(DOMAIN, email, Subject::User, &access_kp.public_key(), &attacker).unwrap();
    let resp = server
        .post("/access/mint")
        .json(&json!({ "device_cert": device_cert, "access_request": areq.encoded() }))
        .await;
    assert_ne!(resp.status_code(), 200, "mint must reject a request not signed by the device key");
}
