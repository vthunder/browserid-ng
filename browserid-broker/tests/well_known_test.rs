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

    // The support document carries NO key (spec §3/§3.1, bean zexp): the IdP
    // key comes solely from the authenticated `_browserid` DNSSEC record.
    assert!(body.get("public-key").is_none(), "served doc must not advertise a key");

    // Should have authentication and provisioning URLs
    assert!(body["authentication"].is_string());
    assert!(body["provisioning"].is_string());
}
