//! Tests for password update flow (ported from password-update-test.js)

mod common;

use common::{create_test_server, create_user};
use serde_json::{json, Value};

/// Test: update_password requires authentication
#[tokio::test]
async fn test_update_password_requires_auth() {
    let (server, _) = create_test_server();

    let response = server
        .post("/wsapi/update_password")
        .json(&json!({
            "oldpass": "oldpassword",
            "newpass": "newpassword"
        }))
        .await;

    assert_eq!(response.status_code(), 401);
}

/// Test: update_password fails with wrong old password
#[tokio::test]
async fn test_update_password_wrong_old_password() {
    let (server, email_sender) = create_test_server();
    let email = "wrongold@example.com";
    let password = "correctpassword";

    let session = create_user(&server, &email_sender, email, password).await;

    let response = server
        .post("/wsapi/update_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({
            "oldpass": "wrongpassword",
            "newpass": "newpassword"
        }))
        .await;

    assert_eq!(response.status_code(), 401);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: update_password fails with short new password
#[tokio::test]
async fn test_update_password_short_new_password() {
    let (server, email_sender) = create_test_server();
    let email = "shortnew@example.com";
    let password = "oldpassword";

    let session = create_user(&server, &email_sender, email, password).await;

    let response = server
        .post("/wsapi/update_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({
            "oldpass": password,
            "newpass": "short"  // too short
        }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: update_password succeeds with correct credentials
#[tokio::test]
async fn test_update_password_success() {
    let (server, email_sender) = create_test_server();
    let email = "updatesuccess@example.com";
    let old_password = "oldpassword";
    let new_password = "newpassword";

    let session = create_user(&server, &email_sender, email, old_password).await;

    let response = server
        .post("/wsapi/update_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({
            "oldpass": old_password,
            "newpass": new_password
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);
}

/// Test: after password update, old password no longer works
#[tokio::test]
async fn test_old_password_fails_after_update() {
    let (server, email_sender) = create_test_server();
    let email = "oldfails@example.com";
    let old_password = "oldpassword";
    let new_password = "newpassword";

    let session = create_user(&server, &email_sender, email, old_password).await;

    // Update password
    server
        .post("/wsapi/update_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({
            "oldpass": old_password,
            "newpass": new_password
        }))
        .await;

    // Try to authenticate with old password
    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": email,
            "pass": old_password,
            "ephemeral": false
        }))
        .await;

    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: after password update, new password works
#[tokio::test]
async fn test_new_password_works_after_update() {
    let (server, email_sender) = create_test_server();
    let email = "newworks@example.com";
    let old_password = "oldpassword";
    let new_password = "newpassword";

    let session = create_user(&server, &email_sender, email, old_password).await;

    // Update password
    server
        .post("/wsapi/update_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({
            "oldpass": old_password,
            "newpass": new_password
        }))
        .await;

    // Authenticate with new password
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

/// Test: can update password again after first update
#[tokio::test]
async fn test_can_update_password_twice() {
    let (server, email_sender) = create_test_server();
    let email = "updatetwice@example.com";
    let password1 = "password1abc";
    let password2 = "password2abc";
    let password3 = "password3abc";

    let session = create_user(&server, &email_sender, email, password1).await;

    // First update
    let response = server
        .post("/wsapi/update_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "oldpass": password1,
            "newpass": password2
        }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Second update
    let response = server
        .post("/wsapi/update_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({
            "oldpass": password2,
            "newpass": password3
        }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Only password3 should work now
    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": email,
            "pass": password3,
            "ephemeral": false
        }))
        .await;
    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // password1 and password2 should fail
    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": email,
            "pass": password1,
            "ephemeral": false
        }))
        .await;
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: password update works with any email on the account
#[tokio::test]
async fn test_update_password_with_multiple_emails() {
    let (server, email_sender) = create_test_server();
    let email1 = "multi1@example.com";
    let email2 = "multi2@example.com";
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
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "token": code }))
        .await;

    // Update password
    server
        .post("/wsapi/update_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({
            "oldpass": old_password,
            "newpass": new_password
        }))
        .await;

    // Both emails should work with new password
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
}
