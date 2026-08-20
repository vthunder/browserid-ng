//! Tests for address_info state transitions (the compute_state machine).
//!
//! Since audit M7 (browserid-ng-dw35) the account-level `state` is only
//! disclosed to a session that OWNS the address, so every state-machine test
//! here performs the lookup under such a session. Unauthenticated behavior
//! (no `state` at all) is covered in address_info_test.rs.

mod common;

use browserid_broker::store::{SessionLevel, UserId};
use browserid_broker::{EmailType, SessionStore, UserStore};
use common::{create_test_context, TestContext};
use serde_json::Value;

/// GET address_info under a session belonging to `user_id`.
async fn address_info_as_owner(ctx: &TestContext, user_id: UserId, email: &str) -> Value {
    let session = ctx.session_store.create(user_id, SessionLevel::Full).unwrap();
    let response = ctx
        .server
        .get(&format!("/wsapi/address_info?email={}", email))
        .add_cookie(cookie::Cookie::new("browserid_session", session.id.0.clone()))
        .await;
    assert_eq!(response.status_code(), 200);
    response.json()
}

/// Test: Secondary unknown email — unauthenticated, so no account state.
#[tokio::test]
async fn test_secondary_unknown_email() {
    let ctx = create_test_context();

    let response = ctx
        .server
        .get("/wsapi/address_info?email=unknown@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["type"], "secondary");
    assert!(body.get("state").is_none(), "state must not leak to cold callers");
    assert_eq!(body["disabled"], false);
    assert_eq!(body["normalizedEmail"], "unknown@example.com");
    // No auth/prov for secondary
    assert!(body.get("auth").is_none());
    assert!(body.get("prov").is_none());
}

/// Test: Secondary known email with password (state = "known")
#[tokio::test]
async fn test_secondary_known_email_with_password() {
    let ctx = create_test_context();

    // Create user with password and add email as secondary
    let user_id = ctx.user_store.create_user("hashed_password").unwrap();
    ctx.user_store
        .add_email_with_type(user_id, "known@example.com", true, EmailType::Secondary)
        .unwrap();

    let body = address_info_as_owner(&ctx, user_id, "known@example.com").await;
    assert_eq!(body["type"], "secondary");
    assert_eq!(body["state"], "known");
    assert_eq!(body["normalizedEmail"], "known@example.com");
}

/// Test: Known email without password, used as secondary (state = "transition_no_password")
/// This is the case where a user was created via primary and now trying to use secondary
#[tokio::test]
async fn test_secondary_known_email_no_password() {
    let ctx = create_test_context();

    // Create user without password (primary-only user)
    let user_id = ctx.user_store.create_user_no_password().unwrap();
    ctx.user_store
        .add_email_with_type(user_id, "primaryuser@example.com", true, EmailType::Secondary)
        .unwrap();

    let body = address_info_as_owner(&ctx, user_id, "primaryuser@example.com").await;
    assert_eq!(body["type"], "secondary");
    // No password + last_used_as secondary + current secondary = transition_no_password
    assert_eq!(body["state"], "transition_no_password");
}

/// Test: Email transitions - was secondary, last used as secondary, still secondary = known
#[tokio::test]
async fn test_secondary_to_secondary_with_password() {
    let ctx = create_test_context();

    let user_id = ctx.user_store.create_user("hashed_password").unwrap();
    ctx.user_store
        .add_email_with_type(user_id, "stable@example.com", true, EmailType::Secondary)
        .unwrap();

    let body = address_info_as_owner(&ctx, user_id, "stable@example.com").await;
    assert_eq!(body["state"], "known");
}

/// Test: Email that was last used as primary, now accessed as secondary with password
/// This simulates: domain lost DNSSEC, user has password = transition_to_secondary
#[tokio::test]
async fn test_primary_to_secondary_with_password() {
    let ctx = create_test_context();

    let user_id = ctx.user_store.create_user("hashed_password").unwrap();
    // Add email with last_used_as = Primary (simulating it was previously used with primary IdP)
    ctx.user_store
        .add_email_with_type(user_id, "former_primary@example.com", true, EmailType::Primary)
        .unwrap();

    let body = address_info_as_owner(&ctx, user_id, "former_primary@example.com").await;
    // has password + last_used_as primary + current secondary = transition_to_secondary
    assert_eq!(body["state"], "transition_to_secondary");
}

/// Test: Email that was last used as primary, now accessed as secondary without password
/// This simulates: domain lost DNSSEC, user has no password = transition_no_password
#[tokio::test]
async fn test_primary_to_secondary_no_password() {
    let ctx = create_test_context();

    let user_id = ctx.user_store.create_user_no_password().unwrap();
    // Add email with last_used_as = Primary
    ctx.user_store
        .add_email_with_type(
            user_id,
            "primary_no_pass@example.com",
            true,
            EmailType::Primary,
        )
        .unwrap();

    let body = address_info_as_owner(&ctx, user_id, "primary_no_pass@example.com").await;
    // no password + last_used_as primary + current secondary = transition_no_password
    assert_eq!(body["state"], "transition_no_password");
}

/// Test: a session that does NOT own the address gets no state either —
/// being signed in to some account must not open the oracle for others'.
#[tokio::test]
async fn test_state_hidden_from_non_owning_session() {
    let ctx = create_test_context();

    let owner = ctx.user_store.create_user("hashed_password").unwrap();
    ctx.user_store
        .add_email_with_type(owner, "victim@example.com", true, EmailType::Secondary)
        .unwrap();
    let other = ctx.user_store.create_user("hashed_password").unwrap();
    ctx.user_store
        .add_email_with_type(other, "probe@example.com", true, EmailType::Secondary)
        .unwrap();

    let body = address_info_as_owner(&ctx, other, "victim@example.com").await;
    assert!(
        body.get("state").is_none(),
        "state must not be disclosed to a session that doesn't own the address"
    );
}

/// Test: address_info returns error for invalid email (no @ sign)
#[tokio::test]
async fn test_invalid_email_no_at_sign() {
    let ctx = create_test_context();

    let response = ctx.server.get("/wsapi/address_info?email=notanemail").await;

    assert_eq!(response.status_code(), 400);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
    assert!(body["reason"].as_str().unwrap().contains("Invalid email"));
}

/// Test: address_info normalizes email to lowercase
#[tokio::test]
async fn test_email_normalization() {
    let ctx = create_test_context();

    let user_id = ctx.user_store.create_user("hashed_password").unwrap();
    ctx.user_store
        .add_email_with_type(user_id, "mixed@example.com", true, EmailType::Secondary)
        .unwrap();

    // Query with uppercase
    let body = address_info_as_owner(&ctx, user_id, "MIXED@EXAMPLE.COM").await;
    assert_eq!(body["state"], "known");
    assert_eq!(body["normalizedEmail"], "mixed@example.com");
}

/// Test: issuer is broker domain for secondary
#[tokio::test]
async fn test_issuer_is_broker_for_secondary() {
    let ctx = create_test_context();

    let response = ctx
        .server
        .get("/wsapi/address_info?email=test@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["issuer"], "localhost:3000");
}

/// Test: disabled is always false (for now)
#[tokio::test]
async fn test_disabled_is_false() {
    let ctx = create_test_context();

    let response = ctx
        .server
        .get("/wsapi/address_info?email=test@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["disabled"], false);
}
