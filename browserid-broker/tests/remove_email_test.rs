//! Tests ported from browserid/tests/remove-email-test.js

mod common;

use common::{create_test_server, create_user};
use serde_json::{json, Value};

/// Test: cannot remove last email
#[tokio::test]
async fn test_cannot_remove_last_email() {
    let (server, email_sender) = create_test_server();
    let email = "onlyone@example.com";
    let password = "testpassword";

    // Create user
    let session_cookie = create_user(&server, &email_sender, email, password).await;

    // Try to remove the only email
    let response = server
        .post("/wsapi/remove_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .json(&json!({ "email": email }))
        .await;

    // Should fail
    assert_eq!(response.status_code(), 500); // Internal error for "cannot remove last email"
}

/// Test: can remove second email
#[tokio::test]
async fn test_can_remove_second_email() {
    let (server, email_sender) = create_test_server();
    let email1 = "keep@example.com";
    let email2 = "remove@example.com";
    let password = "testpassword";

    // Create user with first email
    let session_cookie = create_user(&server, &email_sender, email1, password).await;

    // Add second email
    server
        .post("/wsapi/stage_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .json(&json!({ "email": email2 }))
        .await;

    let code = email_sender.get_code(email2).unwrap();

    server
        .post("/wsapi/complete_email_addition")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .json(&json!({ "token": code }))
        .await;

    // Verify we have 2 emails
    let response = server
        .get("/wsapi/list_emails")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .await;
    let body: Value = response.json();
    assert_eq!(body["emails"].as_array().unwrap().len(), 2);

    // Remove second email
    let response = server
        .post("/wsapi/remove_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .json(&json!({ "email": email2 }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Verify we now have 1 email
    let response = server
        .get("/wsapi/list_emails")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .await;
    let body: Value = response.json();
    let emails = body["emails"].as_array().unwrap();
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0]["email"], email1);
}

/// Test: cannot remove email that doesn't exist
#[tokio::test]
async fn test_cannot_remove_nonexistent_email() {
    let (server, email_sender) = create_test_server();
    let email1 = "exists@example.com";
    let email2 = "second@example.com";
    let password = "testpassword";

    // Create user with first email, add second so we can try to remove
    let session_cookie = create_user(&server, &email_sender, email1, password).await;

    // Add second email
    server
        .post("/wsapi/stage_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .json(&json!({ "email": email2 }))
        .await;

    let code = email_sender.get_code(email2).unwrap();
    server
        .post("/wsapi/complete_email_addition")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .json(&json!({ "token": code }))
        .await;

    // Try to remove a different email that doesn't exist
    let response = server
        .post("/wsapi/remove_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .json(&json!({ "email": "notmine@example.com" }))
        .await;

    assert_eq!(response.status_code(), 404);
}
