//! Tests for verification code handling

mod common;

use common::{create_test_server, create_user};
use serde_json::{json, Value};

/// Test: invalid verification code fails
#[tokio::test]
async fn test_invalid_verification_code() {
    let (server, _) = create_test_server();

    // Stage user
    server
        .post("/wsapi/stage_user")
        .json(&json!({
            "email": "verify@example.com",
            "pass": "testpassword"
        }))
        .await;

    // Try with wrong code
    let response = server
        .post("/wsapi/complete_user_creation")
        .json(&json!({ "token": "000000" }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: verification code is 6 digits
#[tokio::test]
async fn test_verification_code_format() {
    let (server, email_sender) = create_test_server();
    let email = "codeformat@example.com";

    // Stage user
    server
        .post("/wsapi/stage_user")
        .json(&json!({
            "email": email,
            "pass": "testpassword"
        }))
        .await;

    // Get code
    let code = email_sender.get_code(email).unwrap();

    // Should be 6 digits
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

/// Test: email already exists
#[tokio::test]
async fn test_email_already_exists() {
    let (server, email_sender) = create_test_server();
    let email = "exists@example.com";
    let password = "testpassword";

    // Create user
    create_user(&server, &email_sender, email, password).await;

    // Try to create another user with same email
    let response = server
        .post("/wsapi/stage_user")
        .json(&json!({
            "email": email,
            "pass": "anotherpass"
        }))
        .await;

    assert_eq!(response.status_code(), 409); // Conflict
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}
