//! HTTP integration tests for the status distribution endpoints (bean 6u70):
//! `POST /status/check` (RP-backend revocation re-check, fail-closed) and
//! `GET /status/proxy` (page-side poll via the broker).

mod common;

use std::sync::Arc;

use axum_test::TestServer;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::device::DeviceCert;
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

/// Issue a device cert, REVOKE it, and return (its status ref as JSON, the
/// cert record id).
async fn issue_and_revoke_device(
    server: &TestServer,
    sender: &MockEmailSender,
    email: &str,
) -> (Value, u64) {
    let session = create_user(server, sender, email, "testpassword").await;
    let c = csrf(server, &session).await;
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
    let cert = DeviceCert::parse(body["device_cert"].as_str().unwrap()).unwrap();
    let status = cert.claims().status.clone().expect("device cert has a status ref");

    let certs: Value = server
        .get("/wsapi/device_certs")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let id = certs["certs"][0]["id"].as_u64().unwrap();

    let refv = json!({ "uri": status.uri, "idx": status.idx });
    server
        .post("/wsapi/revoke_device_cert")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": csrf(server, &session).await, "id": id }))
        .await
        .assert_status_ok();
    (refv, id)
}

#[tokio::test]
async fn status_check_reports_valid_then_revoked() {
    let (server, sender) = make_server();
    let email = "status-check@localhost:3000";

    // Full path: issue a device (allocates a status idx), revoke it, and
    // confirm /status/check sees the flipped bit on the broker's own list.
    let (refv, _id) = issue_and_revoke_device(&server, &sender, email).await;

    let body: Value = server
        .post("/status/check")
        .json(&json!({ "refs": [refv] }))
        .await
        .json();
    assert_eq!(body["ok"], true, "/status/check: {body}");
    assert_eq!(body["revoked"], true);
    assert_eq!(body["results"][0]["state"], "revoked");
}

#[tokio::test]
async fn status_check_unallocated_idx_is_valid() {
    let (server, _sender) = make_server();
    let own_uri = format!("http://{DOMAIN}/.well-known/browserid-status");
    let body: Value = server
        .post("/status/check")
        .json(&json!({ "refs": [{ "uri": own_uri, "idx": 424242 }] }))
        .await
        .json();
    assert_eq!(body["ok"], true, "/status/check: {body}");
    assert_eq!(body["revoked"], false);
    assert_eq!(body["results"][0]["state"], "valid");
}

#[tokio::test]
async fn status_check_rejects_empty_and_oversized_ref_lists() {
    let (server, _sender) = make_server();
    let r = server.post("/status/check").json(&json!({ "refs": [] })).await;
    assert!(!r.status_code().is_success(), "empty refs must be rejected");

    let own_uri = format!("http://{DOMAIN}/.well-known/browserid-status");
    let refs: Vec<Value> =
        (0..17).map(|i| json!({ "uri": own_uri, "idx": i })).collect();
    let r = server.post("/status/check").json(&json!({ "refs": refs })).await;
    assert!(!r.status_code().is_success(), "oversized ref list must be rejected");
}

#[tokio::test]
async fn status_check_unreachable_foreign_authority_is_unavailable_not_valid() {
    let (server, _sender) = make_server();
    // Port 9 (discard) on loopback — allowed by the dev-relaxed SSRF guard,
    // but nothing is listening: the check must fail closed, not report valid.
    let body: Value = server
        .post("/status/check")
        .json(&json!({ "refs": [{ "uri": "http://127.0.0.1:9/.well-known/browserid-status", "idx": 1 }] }))
        .await
        .json();
    assert_eq!(body["ok"], false, "/status/check must fail closed: {body}");
    assert_eq!(body["results"][0]["state"], "unavailable");
}

#[tokio::test]
async fn status_proxy_redirects_own_uri_to_well_known() {
    let (server, _sender) = make_server();
    let own_uri = format!("http://{DOMAIN}/.well-known/browserid-status");
    let r = server
        .get("/status/proxy")
        .add_query_param("uri", &own_uri)
        .await;
    assert_eq!(r.status_code(), 307, "own-list proxy should redirect: {}", r.text());
    assert_eq!(
        r.headers().get("location").unwrap().to_str().unwrap(),
        "/.well-known/browserid-status"
    );
}

#[tokio::test]
async fn status_proxy_unreachable_foreign_uri_errors() {
    let (server, _sender) = make_server();
    let r = server
        .get("/status/proxy")
        .add_query_param("uri", "http://127.0.0.1:9/.well-known/browserid-status")
        .await;
    assert!(!r.status_code().is_success(), "unreachable foreign list must error");
}

#[tokio::test]
async fn own_status_list_serves_a_parseable_token() {
    let (server, _sender) = make_server();
    let r = server.get("/.well-known/browserid-status").await;
    r.assert_status_ok();
    let token = browserid_core::StatusListToken::parse(r.text().trim()).unwrap();
    assert_eq!(token.claims().iss, DOMAIN);
}
