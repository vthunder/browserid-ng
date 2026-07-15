//! /wsapi/admin/cert_key — the demo-seeding cert mint (mingo-b2yz).
//!
//! Impersonation-grade, so both cages are tested: the route mounts only when
//! a token is configured, and even a valid token can only mint principals on
//! the hard allowlist.

mod common;

use std::sync::Arc;

use browserid_broker::routes;
use browserid_broker::state::AppState;
use browserid_broker::store::{InMemorySessionStore, InMemoryUserStore};
use browserid_core::{Certificate, KeyPair};
use common::MockEmailSender;
use serde_json::json;

const TOKEN: &str = "seed-token-123";

fn server_with(
    token: Option<&str>,
    allowlist: &[&str],
) -> (axum_test::TestServer, KeyPair) {
    let keypair = KeyPair::generate();
    let broker_key = keypair.clone();
    let mut state = AppState::new_with_arcs(
        keypair,
        "localhost:3000".to_string(),
        Arc::new(InMemoryUserStore::new()),
        Arc::new(InMemorySessionStore::new()),
        Arc::new(MockEmailSender::new()),
    );
    state.admin_mint_token = token.map(str::to_string);
    state.admin_mint_allowlist = allowlist.iter().map(|s| s.to_string()).collect();
    let app = routes::create_router(Arc::new(state));
    (
        axum_test::TestServer::new(app).expect("test server"),
        broker_key,
    )
}

fn mint_body(email: &str, kp: &KeyPair) -> serde_json::Value {
    json!({
        "email": email,
        "pubkey": { "algorithm": "Ed25519", "publicKey": kp.public_key().to_base64() },
    })
}

#[tokio::test]
async fn unconfigured_token_means_route_not_mounted() {
    let (server, _) = server_with(None, &["example.com"]);
    let kp = KeyPair::generate();
    let resp = server
        .post("/wsapi/admin/cert_key")
        .json(&mint_body("petra@example.com", &kp))
        .await;
    assert_eq!(resp.status_code(), 404);
}

#[tokio::test]
async fn wrong_or_missing_token_is_unauthorized() {
    let (server, _) = server_with(Some(TOKEN), &["example.com"]);
    let kp = KeyPair::generate();
    let resp = server
        .post("/wsapi/admin/cert_key")
        .json(&mint_body("petra@example.com", &kp))
        .await;
    assert_eq!(resp.status_code(), 401, "missing token");
    let resp = server
        .post("/wsapi/admin/cert_key")
        .add_header("X-Admin-Token", "wrong")
        .json(&mint_body("petra@example.com", &kp))
        .await;
    assert_eq!(resp.status_code(), 401, "wrong token");
}

#[tokio::test]
async fn off_allowlist_principal_is_refused_even_with_valid_token() {
    // Empty allowlist refuses everything; a populated one refuses strangers.
    let (server, _) = server_with(Some(TOKEN), &[]);
    let kp = KeyPair::generate();
    let resp = server
        .post("/wsapi/admin/cert_key")
        .add_header("X-Admin-Token", TOKEN)
        .json(&mint_body("petra@example.com", &kp))
        .await;
    assert_eq!(resp.status_code(), 403, "empty allowlist must refuse");

    let (server, _) = server_with(Some(TOKEN), &["example.com"]);
    let resp = server
        .post("/wsapi/admin/cert_key")
        .add_header("X-Admin-Token", TOKEN)
        .json(&mint_body("victim@gmail.com", &kp))
        .await;
    assert_eq!(resp.status_code(), 403, "off-list domain must refuse");
}

#[tokio::test]
async fn allowlisted_mint_returns_a_valid_fallback_cert() {
    let (server, broker_key) =
        server_with(Some(TOKEN), &["example.com", "vthunder@gmail.com"]);
    let kp = KeyPair::generate();
    let resp = server
        .post("/wsapi/admin/cert_key")
        .add_header("X-Admin-Token", TOKEN)
        .json(&mint_body("petra@example.com", &kp))
        .await;
    assert_eq!(resp.status_code(), 200);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["success"], true);
    let cert = Certificate::parse(body["cert"].as_str().expect("cert present"))
        .expect("mint returns a parseable certificate");
    // Identical shape to a /wsapi/cert_key fallback cert: broker-issued,
    // email principal, NOT agent-typed, verifiable with the broker key.
    assert_eq!(cert.issuer(), "localhost:3000");
    assert_eq!(cert.email(), Some("petra@example.com"));
    assert!(!cert.is_agent());
    cert.verify(&broker_key.public_key())
        .expect("cert verifies against the broker key");
}
