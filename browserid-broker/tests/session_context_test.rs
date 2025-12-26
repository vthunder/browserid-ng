//! Tests ported from browserid/tests/session-context-test.js

mod common;

use common::{create_test_server, create_user};
use serde_json::{json, Value};

/// Test: session_context when not authenticated
#[tokio::test]
async fn test_session_context_unauthenticated() {
    let (server, _) = create_test_server();

    let response = server.get("/wsapi/session_context").await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();

    // Should not be authenticated
    assert_eq!(body["authenticated"], false);
    // Should not have CSRF token when not authenticated
    assert!(body["csrf_token"].is_null());
    // Should have server_time
    assert!(body["server_time"].is_i64());
}

/// Test: session_context after authentication
#[tokio::test]
async fn test_session_context_authenticated() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";
    let password = "thisismypassword";

    // Create user
    let session_cookie = create_user(&server, &email_sender, email, password).await;

    // Check session context with cookie
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();

    // Should be authenticated
    assert_eq!(body["authenticated"], true);
    // Should have CSRF token
    assert!(body["csrf_token"].is_string());
    assert!(!body["csrf_token"].as_str().unwrap().is_empty());
    // Should have user_id
    assert!(body["user_id"].is_u64());
    // Should have server_time
    assert!(body["server_time"].is_i64());

    // Verify server_time is recent (within 5 seconds)
    let server_time = body["server_time"].as_i64().unwrap();
    let now = chrono::Utc::now().timestamp();
    assert!((now - server_time).abs() < 5);
}

/// Test: session_context returns consistent user_id after re-auth
#[tokio::test]
async fn test_session_context_user_id_persists() {
    let (server, email_sender) = create_test_server();
    let email = "persist@example.com";
    let password = "mypassword123";

    // Create user
    let session_cookie = create_user(&server, &email_sender, email, password).await;

    // Get initial user_id
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .await;
    let body: Value = response.json();
    let user_id = body["user_id"].as_u64().unwrap();

    // Logout
    server
        .post("/wsapi/logout")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .await;

    // Re-authenticate
    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": email,
            "pass": password
        }))
        .await;
    assert_eq!(response.status_code(), 200);

    let new_session = response
        .maybe_cookie("browserid_session")
        .expect("No session cookie after re-auth")
        .value()
        .to_string();

    // Check user_id is the same
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", new_session))
        .await;
    let body: Value = response.json();
    assert_eq!(body["user_id"].as_u64().unwrap(), user_id);
}
