//! Tests for authentication (derived from various browserid tests)

mod common;

use common::{create_test_server, create_user};
use serde_json::{json, Value};

/// Test: authentication with unknown user fails
#[tokio::test]
async fn test_auth_unknown_user() {
    let (server, _) = create_test_server();

    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": "unknown@example.com",
            "pass": "somepassword"
        }))
        .await;

    assert_eq!(response.status_code(), 401);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: authentication with wrong password fails
#[tokio::test]
async fn test_auth_wrong_password() {
    let (server, email_sender) = create_test_server();
    let email = "wrongpass@example.com";
    let password = "correctpassword";

    // Create user
    create_user(&server, &email_sender, email, password).await;

    // Try to authenticate with wrong password
    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": email,
            "pass": "wrongpassword"
        }))
        .await;

    assert_eq!(response.status_code(), 401);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: authentication with correct credentials succeeds
#[tokio::test]
async fn test_auth_success() {
    let (server, email_sender) = create_test_server();
    let email = "authme@example.com";
    let password = "correctpassword";

    // Create user
    create_user(&server, &email_sender, email, password).await;

    // Authenticate
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
    assert!(body["userid"].is_u64());

    // Should have session cookie
    assert!(response.maybe_cookie("browserid_session").is_some());
}
