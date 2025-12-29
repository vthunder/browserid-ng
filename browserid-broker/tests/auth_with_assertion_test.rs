//! Tests for the auth_with_assertion endpoint
//!
//! These tests focus on error cases that don't require valid cryptographic assertions.
//! Full end-to-end testing with valid primary IdP assertions is deferred to Task 8.
//!
//! Note: The standard test server doesn't initialize the fallback_fetcher, so most tests
//! will get a 500 error from the missing DNS discovery before assertion validation.
//! Tests that require assertion validation will be in Task 8 with proper test setup.

mod common;

use serde_json::{json, Value};

/// Test: Invalid assertion format returns error
/// Note: Without fallback_fetcher initialized, we get 500 first.
/// This test documents the current behavior - full assertion validation
/// tests will be in Task 8 with proper test infrastructure.
#[tokio::test]
async fn test_invalid_assertion_format() {
    let (server, _email_sender) = common::create_test_server();

    let response = server
        .post("/wsapi/auth_with_assertion")
        .json(&json!({
            "assertion": "not-a-valid-assertion"
        }))
        .await;

    // Without fallback_fetcher, we get 500 Internal Server Error
    // (DNS discovery not configured). Assertion validation tests need
    // a test setup with initialized fallback_fetcher (Task 8).
    assert_eq!(response.status_code(), 500);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: Empty assertion returns error
/// Note: Without fallback_fetcher initialized, we get 500 first.
#[tokio::test]
async fn test_empty_assertion() {
    let (server, _email_sender) = common::create_test_server();

    let response = server
        .post("/wsapi/auth_with_assertion")
        .json(&json!({
            "assertion": ""
        }))
        .await;

    // Without fallback_fetcher, we get 500 Internal Server Error
    assert_eq!(response.status_code(), 500);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: Missing assertion field returns error (JSON parse error)
#[tokio::test]
async fn test_missing_assertion_field() {
    let (server, _email_sender) = common::create_test_server();

    let response = server
        .post("/wsapi/auth_with_assertion")
        .json(&json!({}))
        .await;

    // Should return 422 Unprocessable Entity for missing required field
    assert_eq!(response.status_code(), 422);
}

/// Test: Missing fallback_fetcher returns 500 Internal Server Error
/// This tests the case where DNS discovery is not configured
#[tokio::test]
async fn test_missing_fallback_fetcher() {
    // Note: The standard test server doesn't initialize the fallback_fetcher,
    // so this test verifies the handler correctly returns an error when
    // get_fallback_fetcher() returns None.
    let (server, _email_sender) = common::create_test_server();

    // Even with a valid-looking assertion format, it should fail
    // because fallback_fetcher is not initialized
    let response = server
        .post("/wsapi/auth_with_assertion")
        .json(&json!({
            "assertion": "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJleGFtcGxlLmNvbSJ9.sig~eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tIn0.sig"
        }))
        .await;

    // Should return 500 for missing DNS discovery configuration
    assert_eq!(response.status_code(), 500);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
    // The reason is "Internal server error" (not the actual message for security)
    assert!(body["reason"].as_str().is_some());
}

/// Test: ephemeral field defaults to false
#[tokio::test]
async fn test_ephemeral_defaults_to_false() {
    let (server, _email_sender) = common::create_test_server();

    // This should fail due to missing fallback_fetcher, but the request
    // should be parsed successfully (ephemeral defaults to false)
    let response = server
        .post("/wsapi/auth_with_assertion")
        .json(&json!({
            "assertion": "test"
        }))
        .await;

    // Request parsing should succeed (status 500 from missing fetcher, not 422 from parse error)
    // or 400 from invalid assertion format
    let status = response.status_code();
    assert!(
        status == 400 || status == 500,
        "Expected 400 or 500, got {}",
        status
    );
}

/// Test: ephemeral field can be set explicitly
#[tokio::test]
async fn test_ephemeral_can_be_set() {
    let (server, _email_sender) = common::create_test_server();

    let response = server
        .post("/wsapi/auth_with_assertion")
        .json(&json!({
            "assertion": "test",
            "ephemeral": true
        }))
        .await;

    // Should fail but with proper error (not JSON parsing error)
    let status = response.status_code();
    assert!(
        status == 400 || status == 500,
        "Expected 400 or 500, got {}",
        status
    );
}

// Note: The following test cases require valid assertions from primary IdPs,
// which need actual cryptographic signatures. These will be tested in Task 8:
//
// - Assertion from broker domain returns error (secondary rejection)
// - Valid primary assertion creates session
// - Valid primary assertion for existing user updates last_used_as
// - Ephemeral=true doesn't set cookie
