//! Tests for email_addition_status endpoint (ported from email-addition-status-test.js)

mod common;

use common::{create_test_server, create_user};
use serde_json::{json, Value};

/// Test: email_addition_status returns "failed" for email not being added
#[tokio::test]
async fn test_status_failed_for_unknown_email() {
    let (server, _) = create_test_server();

    let response = server
        .get("/wsapi/email_addition_status?email=unknown@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["status"], "failed");
}

/// Test: email_addition_status returns "pending" after staging email
#[tokio::test]
async fn test_status_pending_after_staging() {
    let (server, email_sender) = create_test_server();
    let first_email = "first@example.com";
    let second_email = "second@example.com";

    // Create initial user
    let session = create_user(&server, &email_sender, first_email, "testpassword").await;

    // Stage a second email
    let response = server
        .post("/wsapi/stage_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "email": second_email }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Check status
    let response = server
        .get(&format!("/wsapi/email_addition_status?email={}", second_email))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["status"], "pending");
}

/// Test: email_addition_status returns "complete" after verification
#[tokio::test]
async fn test_status_complete_after_verification() {
    let (server, email_sender) = create_test_server();
    let first_email = "first@example.com";
    let second_email = "second@example.com";

    // Create initial user
    let session = create_user(&server, &email_sender, first_email, "testpassword").await;

    // Stage a second email
    server
        .post("/wsapi/stage_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "email": second_email }))
        .await;

    // Get verification code
    let code = email_sender.get_code(second_email).expect("No code sent");

    // Complete email addition
    let response = server
        .post("/wsapi/complete_email_addition")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "token": code }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Check status - should be complete
    let response = server
        .get(&format!("/wsapi/email_addition_status?email={}", second_email))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["status"], "complete");
}

/// Test: initial email also shows as complete
#[tokio::test]
async fn test_initial_email_shows_complete() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";

    create_user(&server, &email_sender, email, "testpassword").await;

    // The initial email should show as complete (it's verified during account creation)
    // Note: Our implementation checks if the email exists and is verified
    let response = server
        .get(&format!("/wsapi/email_addition_status?email={}", email))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["status"], "complete");
}
