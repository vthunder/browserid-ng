//! Tests for email staging endpoints

mod common;

use common::{create_test_server, create_user};
use serde_json::json;

/// Test: stage_email requires authentication
#[tokio::test]
async fn test_stage_email_requires_auth() {
    let (server, _) = create_test_server();

    let response = server
        .post("/wsapi/stage_email")
        .json(&json!({ "email": "new@example.com" }))
        .await;

    assert_eq!(response.status_code(), 401);
}

/// Test: cannot add email that already exists
#[tokio::test]
async fn test_cannot_add_existing_email() {
    let (server, email_sender) = create_test_server();

    // Create first user
    let email1 = "first@example.com";
    create_user(&server, &email_sender, email1, "password1").await;

    // Create second user
    let email2 = "second@example.com";
    let session = create_user(&server, &email_sender, email2, "password2").await;

    // Try to add first user's email to second user
    let response = server
        .post("/wsapi/stage_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "email": email1 }))
        .await;

    assert_eq!(response.status_code(), 409);
}

/// Test: complete_email_addition requires authentication
#[tokio::test]
async fn test_complete_email_requires_auth() {
    let (server, _) = create_test_server();

    let response = server
        .post("/wsapi/complete_email_addition")
        .json(&json!({ "token": "123456" }))
        .await;

    assert_eq!(response.status_code(), 401);
}
