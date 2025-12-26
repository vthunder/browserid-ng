//! Tests for user_creation_status endpoint (ported from registration-status-wsapi-test.js)

mod common;

use common::{create_test_server, create_user};
use serde_json::{json, Value};

/// Test: user_creation_status without email parameter returns 400
#[tokio::test]
async fn test_status_without_email_returns_400() {
    let (server, _) = create_test_server();

    let response = server.get("/wsapi/user_creation_status").await;

    assert_eq!(response.status_code(), 400);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: user_creation_status without pending registration returns 400
#[tokio::test]
async fn test_status_without_pending_returns_400() {
    let (server, _) = create_test_server();

    let response = server
        .get("/wsapi/user_creation_status?email=unknown@example.com")
        .await;

    assert_eq!(response.status_code(), 400);
}

/// Test: user_creation_status returns "pending" after staging user
#[tokio::test]
async fn test_status_pending_after_staging() {
    let (server, _) = create_test_server();
    let email = "test@example.com";

    // Stage user
    let response = server
        .post("/wsapi/stage_user")
        .json(&json!({
            "email": email,
            "pass": "testpassword"
        }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Check status
    let response = server
        .get(&format!("/wsapi/user_creation_status?email={}", email))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["status"], "pending");
}

/// Test: user_creation_status returns "complete" after verification
#[tokio::test]
async fn test_status_complete_after_verification() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";

    create_user(&server, &email_sender, email, "testpassword").await;

    // Check status
    let response = server
        .get(&format!("/wsapi/user_creation_status?email={}", email))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["status"], "complete");
}

/// Test: user_creation_status still returns "complete" on second call
#[tokio::test]
async fn test_status_complete_is_idempotent() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";

    create_user(&server, &email_sender, email, "testpassword").await;

    // First call
    let response = server
        .get(&format!("/wsapi/user_creation_status?email={}", email))
        .await;
    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["status"], "complete");

    // Second call
    let response = server
        .get(&format!("/wsapi/user_creation_status?email={}", email))
        .await;
    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["status"], "complete");
}

/// Test: re-registering existing email is rejected (use password reset instead)
#[tokio::test]
async fn test_reregistration_rejected() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";

    // Create initial user
    create_user(&server, &email_sender, email, "firstpassword").await;

    // Try to re-register - should be rejected
    let response = server
        .post("/wsapi/stage_user")
        .json(&json!({
            "email": email,
            "pass": "secondpassword"
        }))
        .await;

    // Should return 409 Conflict
    assert_eq!(response.status_code(), 409);
}
