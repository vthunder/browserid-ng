//! Tests for account_cancel endpoint (ported from account-cancel-test.js)

mod common;

use common::{create_test_server, create_user};
use serde_json::{json, Value};

/// Test: account_cancel requires authentication
#[tokio::test]
async fn test_account_cancel_requires_auth() {
    let (server, _) = create_test_server();

    let response = server
        .post("/wsapi/account_cancel")
        .json(&json!({
            "email": "test@example.com",
            "pass": "testpassword"
        }))
        .await;

    assert_eq!(response.status_code(), 401);
}

/// Test: account_cancel requires correct password
#[tokio::test]
async fn test_account_cancel_wrong_password() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";
    let password = "testpassword";

    let session = create_user(&server, &email_sender, email, password).await;

    let response = server
        .post("/wsapi/account_cancel")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "email": email,
            "pass": "wrongpassword"
        }))
        .await;

    assert_eq!(response.status_code(), 401);
}

/// Test: account_cancel requires matching email
#[tokio::test]
async fn test_account_cancel_wrong_email() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";
    let password = "testpassword";

    let session = create_user(&server, &email_sender, email, password).await;

    let response = server
        .post("/wsapi/account_cancel")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "email": "other@example.com",
            "pass": password
        }))
        .await;

    assert_eq!(response.status_code(), 401);
}

/// Test: account_cancel successfully deletes account
#[tokio::test]
async fn test_account_cancel_success() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";
    let password = "testpassword";

    let session = create_user(&server, &email_sender, email, password).await;

    let response = server
        .post("/wsapi/account_cancel")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "email": email,
            "pass": password
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);
}

/// Test: after cancellation, email shows as unknown
#[tokio::test]
async fn test_email_unknown_after_cancel() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";
    let password = "testpassword";

    let session = create_user(&server, &email_sender, email, password).await;

    // Verify email is known before cancel
    let response = server
        .get(&format!("/wsapi/address_info?email={}", email))
        .await;
    let body: Value = response.json();
    assert_eq!(body["state"], "known");

    // Cancel account
    let response = server
        .post("/wsapi/account_cancel")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "email": email,
            "pass": password
        }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Verify email is now unknown
    let response = server
        .get(&format!("/wsapi/address_info?email={}", email))
        .await;
    let body: Value = response.json();
    assert_eq!(body["state"], "unknown");
}

/// Test: after cancellation, old session is invalid
#[tokio::test]
async fn test_session_invalid_after_cancel() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";
    let password = "testpassword";

    let session = create_user(&server, &email_sender, email, password).await;

    // Cancel account
    server
        .post("/wsapi/account_cancel")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "email": email,
            "pass": password
        }))
        .await;

    // Try to use the old session
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await;

    let body: Value = response.json();
    assert_eq!(body["authenticated"], false);
}

/// Test: after cancellation, cannot authenticate with old credentials
#[tokio::test]
async fn test_cannot_auth_after_cancel() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";
    let password = "testpassword";

    let session = create_user(&server, &email_sender, email, password).await;

    // Cancel account
    server
        .post("/wsapi/account_cancel")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "email": email,
            "pass": password
        }))
        .await;

    // Try to authenticate with old credentials
    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": email,
            "pass": password
        }))
        .await;

    assert_eq!(response.status_code(), 401);
}

/// Test: can re-register with same email after cancel
#[tokio::test]
async fn test_can_reregister_after_cancel() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";
    let password = "testpassword";

    let session = create_user(&server, &email_sender, email, password).await;

    // Cancel account
    server
        .post("/wsapi/account_cancel")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "email": email,
            "pass": password
        }))
        .await;

    // Re-register with same email
    let new_session = create_user(&server, &email_sender, email, "newpassword").await;
    assert!(!new_session.is_empty());

    // Verify the new account works
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", new_session.clone()))
        .await;
    let body: Value = response.json();
    assert_eq!(body["authenticated"], true);
}
