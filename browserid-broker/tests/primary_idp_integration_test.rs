//! Integration tests for primary IdP support
//!
//! These tests cover the state table logic and endpoint behavior for primary IdP flows.
//! Since we can't easily mock DNS in integration tests, these focus on:
//! - State transition tests (transition_no_password)
//! - set_password endpoint authentication tests
//! - Address info state table tests

mod common;

use std::sync::Arc;

use axum_test::TestServer;
use browserid_broker::{
    routes, AppState, EmailType, InMemorySessionStore, InMemoryUserStore, SessionStore, UserStore,
};
use browserid_core::KeyPair;
use common::MockEmailSender;
use serde_json::{json, Value};

/// Create a test server with access to underlying stores
fn create_test_context_with_stores() -> (
    TestServer,
    Arc<InMemoryUserStore>,
    Arc<InMemorySessionStore>,
    MockEmailSender,
) {
    let keypair = KeyPair::generate();
    let email_sender = Arc::new(MockEmailSender::new());
    let user_store = Arc::new(InMemoryUserStore::new());
    let session_store = Arc::new(InMemorySessionStore::new());

    let state = Arc::new(AppState::new_with_arcs(
        keypair,
        "localhost:3000".to_string(),
        user_store.clone(),
        session_store.clone(),
        email_sender.clone(),
    ));

    let app = routes::create_router(state);
    let server = TestServer::new(app).expect("Failed to create test server");

    (
        server,
        user_store,
        session_store,
        MockEmailSender {
            sent: email_sender.sent.clone(),
        },
    )
}

/// Test: address_info returns "unknown" state for an email that doesn't exist
#[tokio::test]
async fn test_address_info_secondary_unknown() {
    let (server, _user_store, _session_store, _email_sender) = create_test_context_with_stores();

    let response = server
        .get("/wsapi/address_info?email=unknown@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["type"], "secondary");
    assert_eq!(body["state"], "unknown");
    assert_eq!(body["disabled"], false);
    assert_eq!(body["normalizedEmail"], "unknown@example.com");
}

/// Test: address_info returns "known" state for an existing secondary user with password
#[tokio::test]
async fn test_address_info_secondary_known() {
    let (server, user_store, _session_store, _email_sender) = create_test_context_with_stores();

    // Create user with password and add email as secondary
    let user_id = user_store.create_user("hashed_password").unwrap();
    user_store
        .add_email_with_type(user_id, "known@example.com", true, EmailType::Secondary)
        .unwrap();

    let response = server
        .get("/wsapi/address_info?email=known@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["type"], "secondary");
    assert_eq!(body["state"], "known");
    assert_eq!(body["normalizedEmail"], "known@example.com");
}

/// Test: address_info returns "transition_no_password" for user created via primary IdP
/// without a password, when accessed as secondary
#[tokio::test]
async fn test_transition_no_password_state() {
    let (server, user_store, _session_store, _email_sender) = create_test_context_with_stores();

    // Create user without password (simulating primary IdP user)
    let user_id = user_store.create_user_no_password().unwrap();
    // Add email with last_used_as = Secondary (so it's not marked as primary)
    user_store
        .add_email_with_type(user_id, "primaryuser@example.com", true, EmailType::Secondary)
        .unwrap();

    let response = server
        .get("/wsapi/address_info?email=primaryuser@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["type"], "secondary");
    // No password + last_used_as secondary + current secondary = transition_no_password
    assert_eq!(body["state"], "transition_no_password");
}

/// Test: set_password requires authentication (returns 401 without session)
#[tokio::test]
async fn test_set_password_requires_auth() {
    let (server, _user_store, _session_store, _email_sender) = create_test_context_with_stores();

    // Call set_password without a session cookie
    let response = server
        .post("/wsapi/set_password")
        .json(&json!({
            "email": "test@example.com",
            "pass": "newpassword123"
        }))
        .await;

    // Should return 401 NotAuthenticated
    assert_eq!(response.status_code(), 401);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
    assert!(body["reason"]
        .as_str()
        .unwrap()
        .contains("Not authenticated"));
}

/// Test: set_password succeeds for authenticated user without password
#[tokio::test]
async fn test_set_password_success() {
    let (server, user_store, session_store, _email_sender) = create_test_context_with_stores();

    // Create user without password (simulating primary IdP user)
    let user_id = user_store.create_user_no_password().unwrap();
    user_store
        .add_email_with_type(user_id, "primaryuser@example.com", true, EmailType::Primary)
        .unwrap();

    // Create a session for this user
    let session = session_store.create(user_id).unwrap();

    // Call set_password with session cookie
    let response = server
        .post("/wsapi/set_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session.id.0.clone()))
        .json(&json!({
            "email": "primaryuser@example.com",
            "pass": "newpassword123"
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Verify password was set (user now has password)
    assert!(user_store.has_password(user_id).unwrap());

    // Verify user can now authenticate with the password
    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({
            "email": "primaryuser@example.com",
            "pass": "newpassword123"
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);
}

/// Test: set_password rejects attempt to set password for another user's email
#[tokio::test]
async fn test_set_password_rejects_wrong_user() {
    let (server, user_store, session_store, _email_sender) = create_test_context_with_stores();

    // Create user A without password
    let user_a_id = user_store.create_user_no_password().unwrap();
    user_store
        .add_email_with_type(user_a_id, "usera@example.com", true, EmailType::Primary)
        .unwrap();

    // Create user B without password
    let user_b_id = user_store.create_user_no_password().unwrap();
    user_store
        .add_email_with_type(user_b_id, "userb@example.com", true, EmailType::Primary)
        .unwrap();

    // Create session for user A
    let session_a = session_store.create(user_a_id).unwrap();

    // Try to set password for user B's email while logged in as user A
    let response = server
        .post("/wsapi/set_password")
        .add_cookie(cookie::Cookie::new(
            "browserid_session",
            session_a.id.0.clone(),
        ))
        .json(&json!({
            "email": "userb@example.com",
            "pass": "newpassword123"
        }))
        .await;

    // Should return 401 (email doesn't belong to authenticated user)
    assert_eq!(response.status_code(), 401);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: set_password rejects attempt for user who already has a password
#[tokio::test]
async fn test_set_password_rejects_already_has_password() {
    let (server, user_store, session_store, _email_sender) = create_test_context_with_stores();

    // Create user with password
    let user_id = user_store.create_user("existing_password_hash").unwrap();
    user_store
        .add_email_with_type(user_id, "haspassword@example.com", true, EmailType::Secondary)
        .unwrap();

    // Create session for this user
    let session = session_store.create(user_id).unwrap();

    // Try to call set_password (should fail because user already has password)
    let response = server
        .post("/wsapi/set_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session.id.0.clone()))
        .json(&json!({
            "email": "haspassword@example.com",
            "pass": "newpassword123"
        }))
        .await;

    // Should return 500 (Internal error: User already has a password)
    assert_eq!(response.status_code(), 500);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: set_password validates password length (too short)
#[tokio::test]
async fn test_set_password_password_too_short() {
    let (server, user_store, session_store, _email_sender) = create_test_context_with_stores();

    // Create user without password
    let user_id = user_store.create_user_no_password().unwrap();
    user_store
        .add_email_with_type(user_id, "shortpass@example.com", true, EmailType::Primary)
        .unwrap();

    // Create session
    let session = session_store.create(user_id).unwrap();

    // Try to set a password that's too short
    let response = server
        .post("/wsapi/set_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session.id.0.clone()))
        .json(&json!({
            "email": "shortpass@example.com",
            "pass": "short"
        }))
        .await;

    // Should return 400 (Password too short)
    assert_eq!(response.status_code(), 400);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
    assert!(body["reason"]
        .as_str()
        .unwrap()
        .contains("Password too short"));
}

/// Test: set_password validates password length (too long)
#[tokio::test]
async fn test_set_password_password_too_long() {
    let (server, user_store, session_store, _email_sender) = create_test_context_with_stores();

    // Create user without password
    let user_id = user_store.create_user_no_password().unwrap();
    user_store
        .add_email_with_type(user_id, "longpass@example.com", true, EmailType::Primary)
        .unwrap();

    // Create session
    let session = session_store.create(user_id).unwrap();

    // Try to set a password that's too long (> 80 chars)
    let long_password = "a".repeat(81);
    let response = server
        .post("/wsapi/set_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session.id.0.clone()))
        .json(&json!({
            "email": "longpass@example.com",
            "pass": long_password
        }))
        .await;

    // Should return 400 (Password too long)
    assert_eq!(response.status_code(), 400);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
    assert!(body["reason"]
        .as_str()
        .unwrap()
        .contains("Password too long"));
}

/// Test: set_password returns error for non-existent email
#[tokio::test]
async fn test_set_password_email_not_found() {
    let (server, user_store, session_store, _email_sender) = create_test_context_with_stores();

    // Create user without password but with a different email
    let user_id = user_store.create_user_no_password().unwrap();
    user_store
        .add_email_with_type(user_id, "existing@example.com", true, EmailType::Primary)
        .unwrap();

    // Create session
    let session = session_store.create(user_id).unwrap();

    // Try to set password for a non-existent email
    let response = server
        .post("/wsapi/set_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session.id.0.clone()))
        .json(&json!({
            "email": "nonexistent@example.com",
            "pass": "validpassword123"
        }))
        .await;

    // Should return 404 (Email not found)
    assert_eq!(response.status_code(), 404);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: address_info returns "transition_to_secondary" for primary user with password
/// who is now being accessed as secondary (domain lost DNSSEC)
#[tokio::test]
async fn test_transition_to_secondary_state() {
    let (server, user_store, _session_store, _email_sender) = create_test_context_with_stores();

    // Create user with password
    let user_id = user_store.create_user("hashed_password").unwrap();
    // Add email with last_used_as = Primary (simulating previous primary usage)
    user_store
        .add_email_with_type(user_id, "former_primary@example.com", true, EmailType::Primary)
        .unwrap();

    let response = server
        .get("/wsapi/address_info?email=former_primary@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    // has password + last_used_as primary + current secondary = transition_to_secondary
    assert_eq!(body["state"], "transition_to_secondary");
}

/// Test: set_password updates email's last_used_as to secondary
#[tokio::test]
async fn test_set_password_updates_last_used_as() {
    let (server, user_store, session_store, _email_sender) = create_test_context_with_stores();

    // Create user without password
    let user_id = user_store.create_user_no_password().unwrap();
    user_store
        .add_email_with_type(user_id, "updatetype@example.com", true, EmailType::Primary)
        .unwrap();

    // Verify initial state is Primary
    let email_record = user_store.get_email("updatetype@example.com").unwrap().unwrap();
    assert_eq!(email_record.last_used_as, EmailType::Primary);

    // Create session and set password
    let session = session_store.create(user_id).unwrap();
    let response = server
        .post("/wsapi/set_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session.id.0.clone()))
        .json(&json!({
            "email": "updatetype@example.com",
            "pass": "newpassword123"
        }))
        .await;

    assert_eq!(response.status_code(), 200);

    // Verify last_used_as was updated to Secondary
    let email_record = user_store.get_email("updatetype@example.com").unwrap().unwrap();
    assert_eq!(email_record.last_used_as, EmailType::Secondary);
}

/// Test: address_info after set_password shows "known" state
#[tokio::test]
async fn test_address_info_after_set_password() {
    let (server, user_store, session_store, _email_sender) = create_test_context_with_stores();

    // Create user without password
    let user_id = user_store.create_user_no_password().unwrap();
    user_store
        .add_email_with_type(user_id, "transition@example.com", true, EmailType::Secondary)
        .unwrap();

    // Verify initial state is transition_no_password
    let response = server
        .get("/wsapi/address_info?email=transition@example.com")
        .await;
    let body: Value = response.json();
    assert_eq!(body["state"], "transition_no_password");

    // Create session and set password
    let session = session_store.create(user_id).unwrap();
    let response = server
        .post("/wsapi/set_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session.id.0.clone()))
        .json(&json!({
            "email": "transition@example.com",
            "pass": "newpassword123"
        }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Verify state is now "known" (user has password)
    let response = server
        .get("/wsapi/address_info?email=transition@example.com")
        .await;
    let body: Value = response.json();
    assert_eq!(body["state"], "known");
}
