//! Forgotten-password behavior on the unified sign-in code lane (ported from
//! forgotten-pass-test.js). The classic stage_reset / complete_reset /
//! password_reset_status endpoints were retired in M7 (browserid-ng-8gqm) —
//! a reset is now: stage_signin_code with the NEW password, then confirm
//! with the mailed code. Existence-indistinguishability of the lane itself
//! is covered in signin_code_test.rs.

mod common;

use common::{create_test_server, create_user, get_csrf};
use serde_json::{json, Value};

/// An UNREDEEMED staging must change nothing: the old password keeps working
/// until the mailed code proves the mailbox.
#[tokio::test]
async fn test_old_password_works_while_code_pending() {
    let (server, email_sender) = create_test_server();
    let email = "oldpassworks@example.com";
    let password = "oldpassword";

    create_user(&server, &email_sender, email, password).await;

    // Stage a reset (new password chosen up front) — but never complete it.
    let response = server
        .post("/wsapi/stage_signin_code")
        .json(&json!({ "email": email, "pass": "attempted-new-pass" }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Old password still works; the staged one does not.
    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": email, "pass": password, "ephemeral": false }))
        .await;
    assert_eq!(response.status_code(), 200);

    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": email, "pass": "attempted-new-pass", "ephemeral": false }))
        .await;
    assert_eq!(response.status_code(), 401);
}

/// Completing the code flips the password: new works, old fails.
#[tokio::test]
async fn test_completed_reset_changes_password() {
    let (server, email_sender) = create_test_server();
    let email = "completereset@example.com";
    let old_password = "oldpassword";
    let new_password = "newpassword";

    create_user(&server, &email_sender, email, old_password).await;

    server
        .post("/wsapi/stage_signin_code")
        .json(&json!({ "email": email, "pass": new_password }))
        .await;
    let code = email_sender.get_code(email).unwrap();
    let response = server
        .post("/wsapi/complete_signin_code")
        .json(&json!({ "email": email, "token": code }))
        .await;
    assert_eq!(response.status_code(), 200);

    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": email, "pass": new_password, "ephemeral": false }))
        .await;
    assert_eq!(response.status_code(), 200);

    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": email, "pass": old_password, "ephemeral": false }))
        .await;
    assert_eq!(response.status_code(), 401);
}

/// Wrong token is rejected (the code_guard path).
#[tokio::test]
async fn test_invalid_token_rejected() {
    let (server, email_sender) = create_test_server();
    let email = "invalidtoken@example.com";

    create_user(&server, &email_sender, email, "testpassword").await;

    server
        .post("/wsapi/stage_signin_code")
        .json(&json!({ "email": email, "pass": "newpassword" }))
        .await;

    let response = server
        .post("/wsapi/complete_signin_code")
        .json(&json!({ "email": email, "token": "000000" }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Password length is validated at STAGING (the password is chosen up
/// front on this lane).
#[tokio::test]
async fn test_reset_password_too_short() {
    let (server, email_sender) = create_test_server();
    let email = "shortpass@example.com";

    create_user(&server, &email_sender, email, "testpassword").await;

    let response = server
        .post("/wsapi/stage_signin_code")
        .json(&json!({ "email": email, "pass": "short" }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// The password is account-level: after a reset via one address, every
/// address on the account authenticates with the new password only.
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
    let csrf = get_csrf(&server, &session).await;
    server
        .post("/wsapi/stage_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "email": email2, "csrf": csrf }))
        .await;

    let code = email_sender.get_code(email2).unwrap();

    server
        .post("/wsapi/complete_email_addition")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "email": email2, "token": code, "csrf": csrf }))
        .await;

    // Reset password using first email
    server
        .post("/wsapi/stage_signin_code")
        .json(&json!({ "email": email1, "pass": new_password }))
        .await;
    let reset_code = email_sender.get_code(email1).unwrap();
    server
        .post("/wsapi/complete_signin_code")
        .json(&json!({ "email": email1, "token": reset_code }))
        .await;

    // Both emails should now work with new password
    for email in [email1, email2] {
        let response = server
            .post("/wsapi/authenticate_user")
            .json(&json!({ "email": email, "pass": new_password, "ephemeral": false }))
            .await;
        let body: Value = response.json();
        assert_eq!(body["success"], true, "{email} should sign in with the new password");

        let response = server
            .post("/wsapi/authenticate_user")
            .json(&json!({ "email": email, "pass": old_password, "ephemeral": false }))
            .await;
        let body: Value = response.json();
        assert_eq!(body["success"], false, "{email} must not sign in with the old password");
    }
}
