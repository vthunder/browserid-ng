//! Tests for address_info endpoint (ported from address-info-test.js)
//!
//! Since audit M7 (browserid-ng-dw35) an unauthenticated address_info reveals
//! only domain-level facts — the response for an existing address must be
//! BYTE-IDENTICAL to the response for a non-existing one on the same domain.
//! Account `state` appears only under a session that owns the address.

mod common;

use std::collections::{HashMap, HashSet};

use browserid_broker::authority::AuthorityChecker;
use browserid_broker::UserStore;
use common::{create_test_context, create_test_context_with_authority, create_test_server, create_user};
use serde_json::Value;

/// Test: unauthenticated address_info carries no account state at all
#[tokio::test]
async fn test_address_info_unknown_email() {
    let (server, _) = create_test_server();

    let response = server
        .get("/wsapi/address_info?email=unknown@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["type"], "secondary");
    assert!(body.get("state").is_none());
    assert_eq!(body["disabled"], false);
}

/// Test: existing account — still no state for a cold caller
#[tokio::test]
async fn test_address_info_known_email_cold() {
    let (server, email_sender) = create_test_server();
    let email = "known@example.com";

    create_user(&server, &email_sender, email, "testpassword").await;

    let response = server
        .get(&format!("/wsapi/address_info?email={}", email))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["type"], "secondary");
    assert!(body.get("state").is_none());
    assert_eq!(body["disabled"], false);
    assert_eq!(body["normalizedEmail"], email);
}

/// Test: the owning session DOES see the account state
#[tokio::test]
async fn test_address_info_state_for_owning_session() {
    let (server, email_sender) = create_test_server();
    let email = "owned@example.com";

    let session = create_user(&server, &email_sender, email, "testpassword").await;

    let response = server
        .get(&format!("/wsapi/address_info?email={}", email))
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["state"], "known");
}

/// The M7 core property: for each proof lane, an existing and a non-existing
/// address on the same domain produce byte-identical unauthenticated
/// responses (modulo the queried local part, so we compare with equal
/// local parts across two servers — one where the account exists, one where
/// it doesn't).
#[tokio::test]
async fn test_unauthenticated_responses_indistinguishable_per_proof() {
    // smtp / oidc-less default: same server, two addresses on one domain.
    let (server, email_sender) = create_test_server();
    create_user(&server, &email_sender, "exists@example.com", "testpassword").await;

    let existing = server
        .get("/wsapi/address_info?email=exists@example.com")
        .await;
    let missing = server
        .get("/wsapi/address_info?email=missing@example.com")
        .await;
    assert_eq!(existing.status_code(), missing.status_code());
    let a = existing.text().replace("exists@example.com", "X");
    let b = missing.text().replace("missing@example.com", "X");
    assert_eq!(a, b, "smtp-domain responses must be indistinguishable");

    // atproto + unprovable lanes, via a fixed authority checker.
    let ctx = create_test_context_with_authority(AuthorityChecker::fixed(
        HashMap::from([("handle.test".to_string(), "did:plc:h".to_string())]),
        HashSet::from(["mail.test".to_string()]),
        Some("https://bridge.test/idp/claim".to_string()),
    ));
    // An attached identity at the handle domain (as after an atproto claim).
    let uid = ctx.user_store.create_user_no_password().unwrap();
    ctx.user_store.add_email(uid, "me@handle.test", true).unwrap();

    let existing = ctx
        .server
        .get("/wsapi/address_info?email=me@handle.test")
        .await;
    let missing = ctx
        .server
        .get("/wsapi/address_info?email=nobody@handle.test")
        .await;
    assert_eq!(existing.status_code(), missing.status_code());
    let a = existing.text().replace("me@handle.test", "X");
    let b = missing.text().replace("nobody@handle.test", "X");
    assert_eq!(a, b, "atproto-domain responses must be indistinguishable");
    assert!(existing.json::<Value>().get("state").is_none());

    // Unprovable domain: no state either way.
    let dead = ctx
        .server
        .get("/wsapi/address_info?email=me@dead.test")
        .await;
    assert!(dead.json::<Value>().get("state").is_none());
}

/// Test: address_info is case-insensitive for email lookup (owner view)
#[tokio::test]
async fn test_address_info_case_insensitive() {
    let (server, email_sender) = create_test_server();
    let email = "test@example.com";

    let session = create_user(&server, &email_sender, email, "testpassword").await;

    // Query with uppercase
    let response = server
        .get("/wsapi/address_info?email=TEST@EXAMPLE.COM")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["state"], "known");
    assert_eq!(body["normalizedEmail"], "test@example.com");
}

/// Test: address_info normalizes email to lowercase
#[tokio::test]
async fn test_address_info_normalizes_email() {
    let (server, _) = create_test_server();

    let response = server
        .get("/wsapi/address_info?email=Test@Example.COM")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["normalizedEmail"], "test@example.com");
}

/// Test: address_info returns issuer
#[tokio::test]
async fn test_address_info_returns_issuer() {
    let (server, _) = create_test_server();

    let response = server
        .get("/wsapi/address_info?email=test@example.com")
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    // Our test server uses "localhost:3000" as the domain
    assert!(body["issuer"].is_string());
}

/// Test: address_info still serves discovery without any session
#[tokio::test]
async fn test_address_info_no_auth_required() {
    let ctx = create_test_context();
    let response = ctx
        .server
        .get("/wsapi/address_info?email=noauth@example.com")
        .await;
    assert_eq!(response.status_code(), 200);
}
