//! Tests for /.well-known/browserid endpoint

mod common;

use common::create_test_server;
use serde_json::Value;

/// Test: .well-known/browserid returns support document
#[tokio::test]
async fn test_well_known_browserid() {
    let (server, _) = create_test_server();

    let response = server.get("/.well-known/browserid").await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();

    // Should have public key
    assert!(body["public-key"].is_object());
    let pubkey = &body["public-key"];
    assert_eq!(pubkey["algorithm"], "Ed25519");
    assert!(pubkey["publicKey"].is_string());

    // Should have authentication and provisioning URLs
    assert!(body["authentication"].is_string());
    assert!(body["provisioning"].is_string());
}
