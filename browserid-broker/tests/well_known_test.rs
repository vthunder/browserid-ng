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

    // The test server's domain is localhost, so the DEV exception applies:
    // the key IS served (the fallback fetcher's dev_local_broker path trusts
    // it — there is no DNSSEC to consult locally). In production (a
    // non-localhost domain) the doc carries NO key (spec §3/§3.1, bean
    // zexp): the IdP key comes solely from the authenticated `_browserid`
    // DNSSEC record — covered below by a prod-domain server.
    assert!(body.get("public-key").is_some(), "localhost dev doc serves the key (dev_local_broker path)");

    // Should have authentication and provisioning URLs
    assert!(body["authentication"].is_string());
    assert!(body["provisioning"].is_string());
}

/// Production (non-localhost) domains must never advertise a key: the
/// DNSSEC record is the sole trust root (bean zexp / 0p5f).
#[tokio::test]
async fn test_well_known_prod_domain_serves_no_key() {
    let (server, _) = common::create_test_server_with_domain("broker.example.com");
    let response = server.get("/.well-known/browserid").await;
    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert!(body.get("public-key").is_none(), "prod doc must not advertise a key");
}
