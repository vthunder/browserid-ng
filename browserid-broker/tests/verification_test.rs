//! Tests for verification code handling (unified sign-in code lane; the
//! stage_user path and its 409 existence oracle were retired in 8gqm).

mod common;

use common::{create_test_server, create_user};
use serde_json::{json, Value};

/// Test: invalid verification code fails
#[tokio::test]
async fn test_invalid_verification_code() {
    let (server, _) = create_test_server();

    // Stage
    server
        .post("/wsapi/stage_signin_code")
        .json(&json!({
            "email": "verify@example.com",
            "pass": "testpassword"
        }))
        .await;

    // Try with wrong code
    let response = server
        .post("/wsapi/complete_signin_code")
        .json(&json!({ "email": "verify@example.com", "token": "000000" }))
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

    // Stage
    server
        .post("/wsapi/stage_signin_code")
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

/// Restaging an EXISTING email is not refused — the old stage_user 409 was
/// the signup-side enumeration oracle (M7). The response is the same 200 a
/// new address gets; completion runs the reset branch instead of create.
#[tokio::test]
async fn test_existing_email_restages_without_conflict() {
    let (server, email_sender) = create_test_server();
    let email = "exists@example.com";
    let password = "testpassword";

    // Create user
    create_user(&server, &email_sender, email, password).await;

    // Staging again succeeds identically to a fresh address.
    let response = server
        .post("/wsapi/stage_signin_code")
        .json(&json!({
            "email": email,
            "pass": "anotherpass1"
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);
}
