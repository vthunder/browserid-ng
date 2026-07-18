//! HTTP integration test for DC Phase 2 endpoints: /device/issue + /access/mint.
//! (verify-access conformance is covered in verifier_test.rs.)

mod common;

use std::sync::Arc;

use axum_test::TestServer;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::device::{AccessRequest, DeviceCert, Purpose, Subject};
use browserid_core::KeyPair;
use common::{create_user, MockEmailSender};
use serde_json::{json, Value};

const DOMAIN: &str = "localhost:3000";

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
async fn device_issue_then_access_mint() {
    let (server, sender) = make_server();
    let email = "human@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
    let c = csrf(&server, &session).await;

    // 1. Batch-issue a user device cert + a config cert.
    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let body: Value = server
        .post("/device/issue")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "csrf": c, "email": email,
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": config_kp.public_key().to_base64(),
        }))
        .await
        .json();
    assert_eq!(body["success"], true, "device/issue: {body}");
    let device_cert = DeviceCert::parse(body["device_cert"].as_str().unwrap()).unwrap();
    let config_cert = DeviceCert::parse(body["config_cert"].as_str().unwrap()).unwrap();
    assert_eq!(device_cert.purpose(), Purpose::Authentication);
    assert_eq!(config_cert.purpose(), Purpose::Authorization);
    assert!(device_cert.authorizes_identity(email));
    // Per-device status refs allocated + distinct.
    assert!(device_cert.claims().status.is_some() && config_cert.claims().status.is_some());
    assert_ne!(device_cert.claims().status, config_cert.claims().status);

    // 2. Mint a fresh-key access cert with the device key.
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(
        DOMAIN, email, Subject::User, &access_kp.public_key(), "nonce-1", &device_kp,
    ).unwrap();
    let body: Value = server
        .post("/access/mint")
        .json(&json!({ "device_cert": body["device_cert"], "access_request": areq.encoded() }))
        .await
        .json();
    assert_eq!(body["success"], true, "access/mint: {body}");
    assert_eq!(body["email"], email);
    // Access cert inherits the device's status index (B3: revoke-device kills access certs).
    let access_body = body.clone();
    let ac = browserid_core::device::AccessCert::parse(access_body["access_cert"].as_str().unwrap()).unwrap();
    assert_eq!(ac.claims().status, device_cert.claims().status);
}

#[tokio::test]
async fn access_mint_rejects_request_not_signed_by_device_key() {
    let (server, sender) = make_server();
    let email = "human@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
    let c = csrf(&server, &session).await;
    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let body: Value = server
        .post("/device/issue")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "email": email, "device_pubkey": device_kp.public_key().to_base64(), "config_pubkey": config_kp.public_key().to_base64() }))
        .await
        .json();
    let device_cert = body["device_cert"].clone();

    // Access request signed by a DIFFERENT key than the device cert certifies.
    let attacker = KeyPair::generate();
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(DOMAIN, email, Subject::User, &access_kp.public_key(), "nonce-2", &attacker).unwrap();
    let resp = server
        .post("/access/mint")
        .json(&json!({ "device_cert": device_cert, "access_request": areq.encoded() }))
        .await;
    assert_ne!(resp.status_code(), 200, "must reject a request not signed by the device key");
}
