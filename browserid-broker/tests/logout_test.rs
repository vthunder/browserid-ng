//! Tests ported from browserid/tests/logout-test.js

mod common;

use common::{create_test_server, create_user};
use serde_json::{json, Value};

/// Test: logout when authenticated succeeds
#[tokio::test]
async fn test_logout_when_authenticated() {
    let (server, email_sender) = create_test_server();
    let email = "logout@example.com";
    let password = "testpassword";

    // Create user
    let session_cookie = create_user(&server, &email_sender, email, password).await;

    // Verify authenticated
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .await;
    let body: Value = response.json();
    assert_eq!(body["authenticated"], true);

    // Logout
    let response = server
        .post("/wsapi/logout")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);
}

/// Test: after logout, session_context shows unauthenticated
#[tokio::test]
async fn test_unauthenticated_after_logout() {
    let (server, email_sender) = create_test_server();
    let email = "afterlogout@example.com";
    let password = "testpassword";

    // Create user
    let session_cookie = create_user(&server, &email_sender, email, password).await;

    // Logout
    server
        .post("/wsapi/logout")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .await;

    // Check session context with old cookie - should be unauthenticated
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .await;
    let body: Value = response.json();
    assert_eq!(body["authenticated"], false);
}

/// Test: can re-login after logout
#[tokio::test]
async fn test_can_relogin_after_logout() {
    let (server, email_sender) = create_test_server();
    let email = "relogin@example.com";
    let password = "testpassword";

    // Create user
    let session_cookie = create_user(&server, &email_sender, email, password).await;

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
    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Should have new session cookie
    let new_session = response
        .maybe_cookie("browserid_session")
        .expect("No session cookie after re-login")
        .value()
        .to_string();

    // Verify authenticated with new cookie
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", new_session))
        .await;
    let body: Value = response.json();
    assert_eq!(body["authenticated"], true);
}
