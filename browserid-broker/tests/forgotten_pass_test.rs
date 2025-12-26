//! Tests for password reset flow (ported from forgotten-pass-test.js)

mod common;

use common::{create_test_server, create_user};
use serde_json::{json, Value};

/// Test: password_reset_status returns 'complete' before any reset is started
#[tokio::test]
async fn test_reset_status_complete_before_reset() {
    let (server, email_sender) = create_test_server();
    let email = "resetstatus@example.com";

    // Create user first
    create_user(&server, &email_sender, email, "testpassword").await;

    // Check reset status - should be 'complete' (no pending reset)
    let response = server
        .get(&format!("/wsapi/password_reset_status?email={}", email))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["status"], "complete");
}

/// Test: stage_reset initiates password reset flow
#[tokio::test]
async fn test_stage_reset_works() {
    let (server, email_sender) = create_test_server();
    let email = "stagereset@example.com";

    // Create user
    create_user(&server, &email_sender, email, "testpassword").await;

    // Stage reset
    let response = server
        .post("/wsapi/stage_reset")
        .json(&json!({ "email": email }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Verify a code was sent
    let code = email_sender.get_code(email);
    assert!(code.is_some());
    assert_eq!(code.unwrap().len(), 6);
}

/// Test: password_reset_status returns 'pending' after stage_reset
#[tokio::test]
async fn test_reset_status_pending_after_stage() {
    let (server, email_sender) = create_test_server();
    let email = "pendingstatus@example.com";

    // Create user
    create_user(&server, &email_sender, email, "testpassword").await;

    // Stage reset
    server
        .post("/wsapi/stage_reset")
        .json(&json!({ "email": email }))
        .await;

    // Check status - should be 'pending'
    let response = server
        .get(&format!("/wsapi/password_reset_status?email={}", email))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["status"], "pending");
}

/// Test: old password still works during pending reset
#[tokio::test]
async fn test_old_password_works_during_pending_reset() {
    let (server, email_sender) = create_test_server();
    let email = "oldpassworks@example.com";
    let password = "oldpassword";

    // Create user
    create_user(&server, &email_sender, email, password).await;

    // Stage reset
    server
        .post("/wsapi/stage_reset")
        .json(&json!({ "email": email }))
        .await;

    // Old password should still work
    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": email,
            "pass": password,
            "ephemeral": false
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);
}

/// Test: complete_reset changes password
#[tokio::test]
async fn test_complete_reset_changes_password() {
    let (server, email_sender) = create_test_server();
    let email = "completereset@example.com";
    let old_password = "oldpassword";
    let new_password = "newpassword";

    // Create user
    create_user(&server, &email_sender, email, old_password).await;

    // Stage reset
    server
        .post("/wsapi/stage_reset")
        .json(&json!({ "email": email }))
        .await;

    // Get reset code
    let code = email_sender.get_code(email).unwrap();

    // Complete reset
    let response = server
        .post("/wsapi/complete_reset")
        .json(&json!({
            "token": code,
            "pass": new_password
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);
}

/// Test: after reset, old password fails
#[tokio::test]
async fn test_old_password_fails_after_reset() {
    let (server, email_sender) = create_test_server();
    let email = "oldpassfails@example.com";
    let old_password = "oldpassword";
    let new_password = "newpassword";

    // Create user
    create_user(&server, &email_sender, email, old_password).await;

    // Stage and complete reset
    server
        .post("/wsapi/stage_reset")
        .json(&json!({ "email": email }))
        .await;

    let code = email_sender.get_code(email).unwrap();

    server
        .post("/wsapi/complete_reset")
        .json(&json!({
            "token": code,
            "pass": new_password
        }))
        .await;

    // Old password should fail
    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": email,
            "pass": old_password,
            "ephemeral": false
        }))
        .await;

    // Response is 401 or has success: false
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: after reset, new password works
#[tokio::test]
async fn test_new_password_works_after_reset() {
    let (server, email_sender) = create_test_server();
    let email = "newpassworks@example.com";
    let old_password = "oldpassword";
    let new_password = "newpassword";

    // Create user
    create_user(&server, &email_sender, email, old_password).await;

    // Stage and complete reset
    server
        .post("/wsapi/stage_reset")
        .json(&json!({ "email": email }))
        .await;

    let code = email_sender.get_code(email).unwrap();

    server
        .post("/wsapi/complete_reset")
        .json(&json!({
            "token": code,
            "pass": new_password
        }))
        .await;

    // New password should work
    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": email,
            "pass": new_password,
            "ephemeral": false
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);
}

/// Test: password_reset_status returns 'complete' after reset is done
#[tokio::test]
async fn test_reset_status_complete_after_reset() {
    let (server, email_sender) = create_test_server();
    let email = "statusaftercomplete@example.com";

    // Create user
    create_user(&server, &email_sender, email, "oldpassword").await;

    // Stage and complete reset
    server
        .post("/wsapi/stage_reset")
        .json(&json!({ "email": email }))
        .await;

    let code = email_sender.get_code(email).unwrap();

    server
        .post("/wsapi/complete_reset")
        .json(&json!({
            "token": code,
            "pass": "newpassword"
        }))
        .await;

    // Check status - should be 'complete'
    let response = server
        .get(&format!("/wsapi/password_reset_status?email={}", email))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["status"], "complete");
}

/// Test: stage_reset fails for non-existent email
#[tokio::test]
async fn test_stage_reset_nonexistent_email() {
    let (server, _) = create_test_server();

    let response = server
        .post("/wsapi/stage_reset")
        .json(&json!({ "email": "nonexistent@example.com" }))
        .await;

    assert_eq!(response.status_code(), 404);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: complete_reset with invalid token fails
#[tokio::test]
async fn test_complete_reset_invalid_token() {
    let (server, email_sender) = create_test_server();
    let email = "invalidtoken@example.com";

    // Create user
    create_user(&server, &email_sender, email, "testpassword").await;

    // Stage reset
    server
        .post("/wsapi/stage_reset")
        .json(&json!({ "email": email }))
        .await;

    // Try with wrong token
    let response = server
        .post("/wsapi/complete_reset")
        .json(&json!({
            "token": "000000",
            "pass": "newpassword"
        }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: complete_reset validates password length
#[tokio::test]
async fn test_complete_reset_password_too_short() {
    let (server, email_sender) = create_test_server();
    let email = "shortpass@example.com";

    // Create user
    create_user(&server, &email_sender, email, "testpassword").await;

    // Stage reset
    server
        .post("/wsapi/stage_reset")
        .json(&json!({ "email": email }))
        .await;

    let code = email_sender.get_code(email).unwrap();

    // Try with short password
    let response = server
        .post("/wsapi/complete_reset")
        .json(&json!({
            "token": code,
            "pass": "short"
        }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: password reset for user with multiple emails updates password for all
#[tokio::test]
async fn test_reset_affects_all_emails() {
    let (server, email_sender) = create_test_server();
    let email1 = "first@example.com";
    let email2 = "second@example.com";
    let old_password = "oldpassword";
    let new_password = "newpassword";

    // Create user with first email
    let session = create_user(&server, &email_sender, email1, old_password).await;

    // Add second email
    server
        .post("/wsapi/stage_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "email": email2 }))
        .await;

    let code = email_sender.get_code(email2).unwrap();

    server
        .post("/wsapi/complete_email_addition")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "token": code }))
        .await;

    // Reset password using first email
    server
        .post("/wsapi/stage_reset")
        .json(&json!({ "email": email1 }))
        .await;

    let reset_code = email_sender.get_code(email1).unwrap();

    server
        .post("/wsapi/complete_reset")
        .json(&json!({
            "token": reset_code,
            "pass": new_password
        }))
        .await;

    // Both emails should now work with new password
    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": email1,
            "pass": new_password,
            "ephemeral": false
        }))
        .await;
    let body: Value = response.json();
    assert_eq!(body["success"], true);

    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": email2,
            "pass": new_password,
            "ephemeral": false
        }))
        .await;
    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Old password should fail for both
    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": email1,
            "pass": old_password,
            "ephemeral": false
        }))
        .await;
    let body: Value = response.json();
    assert_eq!(body["success"], false);

    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": email2,
            "pass": old_password,
            "ephemeral": false
        }))
        .await;
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}
