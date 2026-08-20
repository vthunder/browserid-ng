//! Unified sign-in code (browserid-ng-dw35): the dialog's enumeration-safe
//! SMTP escape hatch. Staging must not reveal whether an account exists;
//! completion creates the account or resets the existing password — with the
//! reset path's security fences — server-side, after the mailbox proof.

mod common;

use std::collections::{HashMap, HashSet};

use browserid_broker::authority::AuthorityChecker;
use browserid_broker::store::{SqliteStore, VerificationType};
use browserid_broker::UserStore;
use common::{create_test_context, create_test_context_with_authority, create_user};
use serde_json::{json, Value};

/// Staging returns identical status + body for an existing and a
/// non-existing address (the M7 core property).
#[tokio::test]
async fn stage_is_existence_indistinguishable() {
    let ctx = create_test_context();
    create_user(&ctx.server, &ctx.email_sender, "exists@example.com", "originalpass").await;

    let stage = |email: &'static str| {
        let server = &ctx.server;
        async move {
            server
                .post("/wsapi/stage_signin_code")
                .json(&json!({ "email": email, "pass": "chosen-password" }))
                .await
        }
    };

    let existing = stage("exists@example.com").await;
    let missing = stage("missing@example.com").await;

    assert_eq!(existing.status_code(), 200);
    assert_eq!(missing.status_code(), 200);
    assert_eq!(existing.text(), missing.text());

    // Both got a code mailed.
    assert!(ctx.email_sender.get_code("exists@example.com").is_some());
    assert!(ctx.email_sender.get_code("missing@example.com").is_some());
}

/// New address: completion creates the account with the staged password and
/// the follow-up authenticate signs in.
#[tokio::test]
async fn completes_as_account_creation_for_new_address() {
    let ctx = create_test_context();

    let response = ctx
        .server
        .post("/wsapi/stage_signin_code")
        .json(&json!({ "email": "newbie@example.com", "pass": "chosen-password" }))
        .await;
    assert_eq!(response.status_code(), 200);

    let code = ctx.email_sender.get_code("newbie@example.com").unwrap();
    let response = ctx
        .server
        .post("/wsapi/complete_signin_code")
        .json(&json!({ "email": "newbie@example.com", "token": code }))
        .await;
    assert_eq!(response.status_code(), 200);
    // No session minted at completion — the dialog authenticates next.
    assert!(response.maybe_cookie("browserid_session").is_none());

    let response = ctx
        .server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": "newbie@example.com", "pass": "chosen-password" }))
        .await;
    assert_eq!(response.status_code(), 200);
}

/// Existing address: completion is a password reset — new password works,
/// old one doesn't, existing sessions are evicted (H2) and sibling E3
/// addresses are marked for re-verification (kgb9).
#[tokio::test]
async fn completes_as_password_reset_for_existing_address() {
    let ctx = create_test_context();
    let session =
        create_user(&ctx.server, &ctx.email_sender, "resetme@example.com", "old-password").await;
    // A sibling SMTP address on the same account.
    let uid = ctx
        .user_store
        .get_user_by_email("resetme@example.com")
        .unwrap()
        .unwrap()
        .id;
    ctx.user_store.add_email(uid, "sibling@example.com", true).unwrap();

    let response = ctx
        .server
        .post("/wsapi/stage_signin_code")
        .json(&json!({ "email": "resetme@example.com", "pass": "new-password" }))
        .await;
    assert_eq!(response.status_code(), 200);

    let code = ctx.email_sender.get_code("resetme@example.com").unwrap();
    let response = ctx
        .server
        .post("/wsapi/complete_signin_code")
        .json(&json!({ "email": "resetme@example.com", "token": code }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Old password dead, new one works.
    let response = ctx
        .server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": "resetme@example.com", "pass": "old-password" }))
        .await;
    assert_eq!(response.status_code(), 401);
    let response = ctx
        .server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": "resetme@example.com", "pass": "new-password" }))
        .await;
    assert_eq!(response.status_code(), 200);

    // H2: the pre-reset session is gone.
    let response = ctx
        .server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .await;
    let body: Value = response.json();
    assert_eq!(body["authenticated"], false);

    // kgb9: the sibling E3 must re-verify; the reset address stays verified.
    let emails = ctx.user_store.list_emails(uid).unwrap();
    let by_addr = |a: &str| emails.iter().find(|e| e.email == a).unwrap();
    assert!(!by_addr("sibling@example.com").verified);
    assert!(by_addr("resetme@example.com").verified);
}

/// A wrong code is rejected without saying whether the account existed.
#[tokio::test]
async fn wrong_code_is_rejected() {
    let ctx = create_test_context();

    let response = ctx
        .server
        .post("/wsapi/stage_signin_code")
        .json(&json!({ "email": "someone@example.com", "pass": "chosen-password" }))
        .await;
    assert_eq!(response.status_code(), 200);

    let response = ctx
        .server
        .post("/wsapi/complete_signin_code")
        .json(&json!({ "email": "someone@example.com", "token": "000000" }))
        .await;
    assert_ne!(response.status_code(), 200);
}

/// The mailed-code lane only proves ownership where the mailbox is the
/// authority (tsqk) — handle/unprovable domains are refused at staging.
#[tokio::test]
async fn stage_refuses_non_smtp_domains() {
    let ctx = create_test_context_with_authority(AuthorityChecker::fixed(
        HashMap::from([("handle.test".to_string(), "did:plc:h".to_string())]),
        HashSet::from(["mail.test".to_string()]),
        Some("https://bridge.test/idp/claim".to_string()),
    ));

    let stage = |email: &'static str| {
        let server = &ctx.server;
        async move {
            server
                .post("/wsapi/stage_signin_code")
                .json(&json!({ "email": email, "pass": "chosen-password" }))
                .await
        }
    };

    assert_eq!(stage("me@handle.test").await.status_code(), 403);
    assert_eq!(stage("me@dead.test").await.status_code(), 403);
    assert!(ctx.email_sender.sent.read().unwrap().is_empty());
    assert_eq!(stage("me@mail.test").await.status_code(), 200);
}

/// Restaging after an account appeared in the meantime must reset, never
/// create a duplicate account (the completion re-checks existence).
#[tokio::test]
async fn completion_rechecks_existence() {
    let ctx = create_test_context();

    // Stage while the address has no account…
    let response = ctx
        .server
        .post("/wsapi/stage_signin_code")
        .json(&json!({ "email": "racer@example.com", "pass": "code-password" }))
        .await;
    assert_eq!(response.status_code(), 200);
    let code = ctx.email_sender.get_code("racer@example.com").unwrap();

    // …then an account appears through another flow.
    let uid = ctx.user_store.create_user("some-hash").unwrap();
    ctx.user_store.add_email(uid, "racer@example.com", true).unwrap();

    let response = ctx
        .server
        .post("/wsapi/complete_signin_code")
        .json(&json!({ "email": "racer@example.com", "token": code }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Same single account, now carrying the staged password.
    assert_eq!(
        ctx.user_store.get_user_by_email("racer@example.com").unwrap().unwrap().id,
        uid
    );
    let response = ctx
        .server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": "racer@example.com", "pass": "code-password" }))
        .await;
    assert_eq!(response.status_code(), 200);
}

/// SigninCode pendings survive the real SQLite store (the TEXT enum mapping
/// is sqlite-only and invisible to memory-store tests), and the status
/// oracles never see them: has_pending_reset stays false.
#[test]
fn sqlite_signin_code_pending_roundtrip() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("test.db");
    let store = SqliteStore::open(path.to_str().unwrap()).unwrap();

    store
        .create_pending(browserid_broker::store::PendingVerification {
            secret: "123456".to_string(),
            email: "sqlite@example.com".to_string(),
            user_id: None,
            password_hash: Some("hash".to_string()),
            verification_type: VerificationType::SigninCode,
            created_at: chrono::Utc::now(),
        })
        .unwrap();

    let pending = store
        .get_pending_by_email("sqlite@example.com", VerificationType::SigninCode)
        .unwrap()
        .expect("signin_code pending must round-trip through sqlite");
    assert_eq!(pending.secret, "123456");
    assert_eq!(pending.verification_type, VerificationType::SigninCode);
    // A staged sign-in code is NOT a pending password reset — the reset
    // status endpoint must not learn of it.
    assert!(!store.has_pending_reset("sqlite@example.com").unwrap());
    // Nor a pending account creation / email addition.
    assert!(store
        .get_pending_by_email("sqlite@example.com", VerificationType::NewAccount)
        .unwrap()
        .is_none());
}
