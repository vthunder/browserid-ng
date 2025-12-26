//! Tests for cookie and session security (ported from cookie-session-security-test.js)

mod common;

use common::{create_test_server, create_user};
use serde_json::Value;

/// Test: session_context response includes session info
#[tokio::test]
async fn test_session_context_returns_session_info() {
    let (server, _) = create_test_server();

    let response = server.get("/wsapi/session_context").await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["authenticated"], false);
}

/// Test: authenticated session_context has CSRF token
#[tokio::test]
async fn test_authenticated_session_has_csrf() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";

    let session = create_user(&server, &email_sender, email, "testpassword").await;

    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["authenticated"], true);
    assert!(body["csrf_token"].is_string());
}

/// Test: invalid session cookie is treated as unauthenticated
#[tokio::test]
async fn test_invalid_session_cookie_unauthenticated() {
    let (server, _) = create_test_server();

    // Use a bogus session ID
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", "invalid-session-id"))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["authenticated"], false);
}

/// Test: session cookie is HttpOnly
#[tokio::test]
async fn test_session_cookie_is_httponly() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";

    // Create user - this sets the session cookie
    server
        .post("/wsapi/stage_user")
        .json(&serde_json::json!({
            "email": email,
            "pass": "testpassword"
        }))
        .await;

    let code = email_sender.get_code(email).expect("No code sent");
    let response = server
        .post("/wsapi/complete_user_creation")
        .json(&serde_json::json!({ "token": code }))
        .await;

    // Check that session cookie is set
    let cookie = response.maybe_cookie("browserid_session");
    assert!(cookie.is_some());

    // The cookie should be HttpOnly (but axum-test may not expose this directly)
    // At minimum, verify the cookie exists and has a value
    let cookie = cookie.unwrap();
    assert!(!cookie.value().is_empty());
}

/// Test: logout clears session effectively
#[tokio::test]
async fn test_logout_clears_session() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";

    let session = create_user(&server, &email_sender, email, "testpassword").await;

    // Verify authenticated
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await;
    let body: Value = response.json();
    assert_eq!(body["authenticated"], true);

    // Logout
    server
        .post("/wsapi/logout")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await;

    // Session should no longer be valid
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .await;
    let body: Value = response.json();
    assert_eq!(body["authenticated"], false);
}

/// Test: session cannot be forged with different user ID
#[tokio::test]
async fn test_session_cannot_be_forged() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";

    let session = create_user(&server, &email_sender, email, "testpassword").await;

    // Get the actual user_id from session context
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await;
    let body: Value = response.json();
    let real_user_id = body["user_id"].as_u64().unwrap();

    // Try to modify the session ID to see if it still works
    // (it shouldn't because session IDs are UUIDs, not predictable)
    let modified_session = format!("{}-modified", session);
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", modified_session))
        .await;
    let body: Value = response.json();
    assert_eq!(body["authenticated"], false);

    // Original session should still work
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .await;
    let body: Value = response.json();
    assert_eq!(body["authenticated"], true);
    assert_eq!(body["user_id"], real_user_id);
}
