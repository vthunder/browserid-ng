//! Tests for address_info endpoint with primary IdP and state transitions
//!
//! These tests focus on the state machine logic for address_info.
//! Primary IdP discovery tests are deferred to integration tests (Task 8)
//! since they require DNS mocking.

mod common;

use std::sync::Arc;

use axum_test::TestServer;
use browserid_broker::{
    routes, AppState, EmailType, InMemorySessionStore, InMemoryUserStore, UserStore,
};
use browserid_core::KeyPair;
use common::MockEmailSender;
use serde_json::Value;

/// Create a test server with access to underlying stores
fn create_test_context_with_stores() -> (TestServer, Arc<InMemoryUserStore>, MockEmailSender) {
    let keypair = KeyPair::generate();
    let email_sender = Arc::new(MockEmailSender::new());
    let user_store = Arc::new(InMemoryUserStore::new());
    let session_store = Arc::new(InMemorySessionStore::new());

    let state = Arc::new(AppState::new_with_arcs(
        keypair,
        "localhost:3000".to_string(),
        user_store.clone(),
        session_store,
        email_sender.clone(),
    ));

    let app = routes::create_router(state);
    let server = TestServer::new(app).expect("Failed to create test server");

    (
        server,
        user_store,
        MockEmailSender {
            sent: email_sender.sent.clone(),
        },
    )
}

/// Test: Secondary unknown email (no fallback_fetcher triggered)
#[tokio::test]
async fn test_secondary_unknown_email() {
    let (server, _user_store, _email_sender) = create_test_context_with_stores();

    let response = server
        .get("/wsapi/address_info?email=unknown@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["type"], "secondary");
    assert_eq!(body["state"], "unknown");
    assert_eq!(body["disabled"], false);
    assert_eq!(body["normalizedEmail"], "unknown@example.com");
    // No auth/prov for secondary
    assert!(body.get("auth").is_none());
    assert!(body.get("prov").is_none());
}

/// Test: Secondary known email with password (state = "known")
#[tokio::test]
async fn test_secondary_known_email_with_password() {
    let (server, user_store, _email_sender) = create_test_context_with_stores();

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

/// Test: Known email without password, used as secondary (state = "transition_no_password")
/// This is the case where a user was created via primary and now trying to use secondary
#[tokio::test]
async fn test_secondary_known_email_no_password() {
    let (server, user_store, _email_sender) = create_test_context_with_stores();

    // Create user without password (primary-only user)
    let user_id = user_store.create_user_no_password().unwrap();
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

/// Test: Email transitions - was secondary, last used as secondary, still secondary = known
#[tokio::test]
async fn test_secondary_to_secondary_with_password() {
    let (server, user_store, _email_sender) = create_test_context_with_stores();

    let user_id = user_store.create_user("hashed_password").unwrap();
    user_store
        .add_email_with_type(user_id, "stable@example.com", true, EmailType::Secondary)
        .unwrap();

    let response = server
        .get("/wsapi/address_info?email=stable@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["state"], "known");
}

/// Test: Email that was last used as primary, now accessed as secondary with password
/// This simulates: domain lost DNSSEC, user has password = transition_to_secondary
#[tokio::test]
async fn test_primary_to_secondary_with_password() {
    let (server, user_store, _email_sender) = create_test_context_with_stores();

    let user_id = user_store.create_user("hashed_password").unwrap();
    // Add email with last_used_as = Primary (simulating it was previously used with primary IdP)
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

/// Test: Email that was last used as primary, now accessed as secondary without password
/// This simulates: domain lost DNSSEC, user has no password = transition_no_password
#[tokio::test]
async fn test_primary_to_secondary_no_password() {
    let (server, user_store, _email_sender) = create_test_context_with_stores();

    let user_id = user_store.create_user_no_password().unwrap();
    // Add email with last_used_as = Primary
    user_store
        .add_email_with_type(
            user_id,
            "primary_no_pass@example.com",
            true,
            EmailType::Primary,
        )
        .unwrap();

    let response = server
        .get("/wsapi/address_info?email=primary_no_pass@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    // no password + last_used_as primary + current secondary = transition_no_password
    assert_eq!(body["state"], "transition_no_password");
}

/// Test: address_info returns error for invalid email (no @ sign)
#[tokio::test]
async fn test_invalid_email_no_at_sign() {
    let (server, _user_store, _email_sender) = create_test_context_with_stores();

    let response = server.get("/wsapi/address_info?email=notanemail").await;

    assert_eq!(response.status_code(), 400);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
    assert!(body["reason"].as_str().unwrap().contains("Invalid email"));
}

/// Test: address_info normalizes email to lowercase
#[tokio::test]
async fn test_email_normalization() {
    let (server, user_store, _email_sender) = create_test_context_with_stores();

    let user_id = user_store.create_user("hashed_password").unwrap();
    user_store
        .add_email_with_type(user_id, "mixed@example.com", true, EmailType::Secondary)
        .unwrap();

    // Query with uppercase
    let response = server
        .get("/wsapi/address_info?email=MIXED@EXAMPLE.COM")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["state"], "known");
    assert_eq!(body["normalizedEmail"], "mixed@example.com");
}

/// Test: issuer is broker domain for secondary
#[tokio::test]
async fn test_issuer_is_broker_for_secondary() {
    let (server, _user_store, _email_sender) = create_test_context_with_stores();

    let response = server
        .get("/wsapi/address_info?email=test@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["issuer"], "localhost:3000");
}

/// Test: disabled is always false (for now)
#[tokio::test]
async fn test_disabled_is_false() {
    let (server, _user_store, _email_sender) = create_test_context_with_stores();

    let response = server
        .get("/wsapi/address_info?email=test@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["disabled"], false);
}

// Note: Primary IdP tests (with DNS discovery) are deferred to integration tests (Task 8)
// because they require mocking the DNS and HTTP fetchers. The tests above cover:
// - Secondary flow (no fallback_fetcher initialization)
// - State machine logic (compute_state function)
// - Error handling (invalid email)
// - Email normalization
