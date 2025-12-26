//! Tests ported from browserid/tests/list-emails-wsapi-test.js

mod common;

use common::{create_test_server, create_user};
use serde_json::{json, Value};

/// Test: list_emails requires authentication
#[tokio::test]
async fn test_list_emails_requires_auth() {
    let (server, _) = create_test_server();

    let response = server.get("/wsapi/list_emails").await;

    // Should fail with 401 when not authenticated
    assert_eq!(response.status_code(), 401);
}

/// Test: list_emails returns the user's email after account creation
#[tokio::test]
async fn test_list_emails_after_creation() {
    let (server, email_sender) = create_test_server();
    let email = "listme@example.com";
    let password = "testpassword";

    // Create user
    let session_cookie = create_user(&server, &email_sender, email, password).await;

    // List emails
    let response = server
        .get("/wsapi/list_emails")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);

    let emails = body["emails"].as_array().unwrap();
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0]["email"], email);
    assert_eq!(emails[0]["verified"], true);
}

/// Test: list_emails returns multiple emails after adding one
#[tokio::test]
async fn test_list_emails_multiple() {
    let (server, email_sender) = create_test_server();
    let email1 = "first@example.com";
    let email2 = "second@example.com";
    let password = "testpassword";

    // Create user with first email
    let session_cookie = create_user(&server, &email_sender, email1, password).await;

    // Stage second email
    let response = server
        .post("/wsapi/stage_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .json(&json!({ "email": email2 }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Get verification code for second email
    let code = email_sender.get_code(email2).expect("No code for second email");

    // Complete email addition
    let response = server
        .post("/wsapi/complete_email_addition")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .json(&json!({ "token": code }))
        .await;
    assert_eq!(response.status_code(), 200);

    // List emails - should have both
    let response = server
        .get("/wsapi/list_emails")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();

    let emails = body["emails"].as_array().unwrap();
    assert_eq!(emails.len(), 2);

    let email_addresses: Vec<&str> = emails
        .iter()
        .map(|e| e["email"].as_str().unwrap())
        .collect();
    assert!(email_addresses.contains(&email1));
    assert!(email_addresses.contains(&email2));
}
