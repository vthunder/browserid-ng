//! Tests for address_info endpoint (ported from address-info-test.js)

mod common;

use common::{create_test_server, create_user};
use serde_json::Value;

/// Test: address_info returns "unknown" for non-existent email
#[tokio::test]
async fn test_address_info_unknown_email() {
    let (server, _) = create_test_server();

    let response = server
        .get("/wsapi/address_info?email=unknown@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["type"], "secondary");
    assert_eq!(body["state"], "unknown");
    assert_eq!(body["disabled"], false);
}

/// Test: address_info returns "known" for existing email
#[tokio::test]
async fn test_address_info_known_email() {
    let (server, email_sender) = create_test_server();
    let email = "known@example.com";

    create_user(&server, &email_sender, email, "testpassword").await;

    let response = server
        .get(&format!("/wsapi/address_info?email={}", email))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["type"], "secondary");
    assert_eq!(body["state"], "known");
    assert_eq!(body["disabled"], false);
    assert_eq!(body["normalizedEmail"], email);
}

/// Test: address_info is case-insensitive for email lookup
#[tokio::test]
async fn test_address_info_case_insensitive() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";

    create_user(&server, &email_sender, email, "testpassword").await;

    // Query with uppercase
    let response = server
        .get("/wsapi/address_info?email=TEST@EXAMPLE.COM")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["state"], "known");
    assert_eq!(body["normalizedEmail"], "test@example.com");
}

/// Test: address_info normalizes email to lowercase
#[tokio::test]
async fn test_address_info_normalizes_email() {
    let (server, _) = create_test_server();

    let response = server
        .get("/wsapi/address_info?email=Test@Example.COM")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["normalizedEmail"], "test@example.com");
}

/// Test: address_info returns issuer
#[tokio::test]
async fn test_address_info_returns_issuer() {
    let (server, _) = create_test_server();

    let response = server
        .get("/wsapi/address_info?email=test@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    // Our test server uses "localhost:3000" as the domain
    assert!(body["issuer"].is_string());
}

/// Test: address_info with mixed case preserves known email's original case
#[tokio::test]
async fn test_address_info_mixed_case_lookup() {
    let (server, email_sender) = create_test_server();
    let email = "mixedcase@example.com";

    create_user(&server, &email_sender, email, "testpassword").await;

    // Query with different case
    let response = server
        .get("/wsapi/address_info?email=MixedCase@Example.Com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["state"], "known");
    // normalizedEmail should be lowercase
    assert_eq!(body["normalizedEmail"], "mixedcase@example.com");
}

/// Test: address_info doesn't require authentication
#[tokio::test]
async fn test_address_info_no_auth_required() {
    let (server, email_sender) = create_test_server();
    let email = "noauth@example.com";

    create_user(&server, &email_sender, email, "testpassword").await;

    // No session cookie
    let response = server
        .get(&format!("/wsapi/address_info?email={}", email))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["state"], "known");
}
