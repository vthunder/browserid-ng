//! Tests for /wsapi/set_password — the in-session first-password shortcut for
//! passwordless accounts (browserid-ng-iudv). A session already proves control
//! of the account, so setting the FIRST password must not cost a mailed code;
//! the reset flow stays the cold/no-session path.

mod common;

use browserid_broker::store::{SessionStore, SqliteStore, UserStore};
use common::{create_test_context, create_user, get_csrf, TestContext};
use serde_json::{json, Value};

/// A passwordless account with one verified email and a live session — the
/// production analogue of an account established by an E1/E2 proof (primary
/// presentation / bridge claim), which never sets a password.
fn passwordless_session(ctx: &TestContext, email: &str) -> String {
    let user_id = ctx.user_store.create_user_no_password().unwrap();
    ctx.user_store.add_email(user_id, email, true).unwrap();
    ctx.session_store.create(user_id).unwrap().id.0
}

async fn csrf_for(ctx: &TestContext, session: &str) -> String {
    get_csrf(&ctx.server, session).await
}

#[tokio::test]
async fn set_password_requires_auth() {
    let ctx = create_test_context();

    let response = ctx
        .server
        .post("/wsapi/set_password")
        .json(&json!({ "pass": "newpassword" }))
        .await;

    assert_eq!(response.status_code(), 401);
}

#[tokio::test]
async fn set_password_requires_csrf() {
    let ctx = create_test_context();
    let session = passwordless_session(&ctx, "nopass-csrf@example.com");

    let response = ctx
        .server
        .post("/wsapi/set_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "pass": "newpassword" }))
        .await;

    assert_eq!(response.status_code(), 403);
}

#[tokio::test]
async fn set_password_rejects_short_password() {
    let ctx = create_test_context();
    let session = passwordless_session(&ctx, "nopass-short@example.com");
    let csrf = csrf_for(&ctx, &session).await;

    let response = ctx
        .server
        .post("/wsapi/set_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "pass": "short", "csrf": csrf }))
        .await;

    assert_eq!(response.status_code(), 400);
}

/// Once a password exists, set_password is refused: changing it requires the
/// old password (update_password) or the reset ceremony — otherwise any live
/// session could silently swap the password.
#[tokio::test]
async fn set_password_refused_when_password_exists() {
    let ctx = create_test_context();
    let email = "haspass@example.com";
    let session = create_user(&ctx.server, &ctx.email_sender, email, "originalpass").await;
    let csrf = csrf_for(&ctx, &session).await;

    let response = ctx
        .server
        .post("/wsapi/set_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "pass": "attackerpass", "csrf": csrf }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: Value = response.json();
    assert_eq!(body["success"], false);

    // The original password still works.
    let response = ctx
        .server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": email, "pass": "originalpass" }))
        .await;
    assert_eq!(response.status_code(), 200);
}

#[tokio::test]
async fn set_password_success_on_passwordless_account() {
    let ctx = create_test_context();
    let email = "nopass-success@example.com";
    let session = passwordless_session(&ctx, email);
    let csrf = csrf_for(&ctx, &session).await;

    // list_emails reports the passwordless state (drives the UI prompt).
    let response = ctx
        .server
        .get("/wsapi/list_emails")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await;
    let body: Value = response.json();
    assert_eq!(body["has_password"], false);

    let response = ctx
        .server
        .post("/wsapi/set_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "pass": "chosen-password", "csrf": csrf }))
        .await;
    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // No mail was ever sent — the whole point of the in-session path.
    assert!(ctx.email_sender.sent.read().unwrap().is_empty());

    // The account now signs in with the chosen password…
    let response = ctx
        .server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": email, "pass": "chosen-password" }))
        .await;
    assert_eq!(response.status_code(), 200);

    // …and list_emails flips.
    let response = ctx
        .server
        .get("/wsapi/list_emails")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .await;
    let body: Value = response.json();
    assert_eq!(body["has_password"], true);
}

/// The bean's headline flow: a passwordless account adds an SMTP (E3) address
/// and ends up verified WITH a password after exactly ONE mailed code — the
/// add code. No stage_reset, no second roundtrip.
#[tokio::test]
async fn passwordless_add_email_costs_one_code_then_sets_password() {
    let ctx = create_test_context();
    let first = "bridge-born@example.com";
    let added = "inbox@example.com";
    let session = passwordless_session(&ctx, first);
    let csrf = csrf_for(&ctx, &session).await;

    // Stage + complete the E3 addition (the one SMTP roundtrip).
    let response = ctx
        .server
        .post("/wsapi/stage_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "email": added, "csrf": csrf }))
        .await;
    assert_eq!(response.status_code(), 200);
    let code = ctx.email_sender.get_code(added).expect("add code sent");

    let response = ctx
        .server
        .post("/wsapi/complete_email_addition")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "email": added, "token": code, "csrf": csrf }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Set the password in-session — no further mail.
    let response = ctx
        .server
        .post("/wsapi/set_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "pass": "chosen-password", "csrf": csrf }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Exactly one code was ever mailed, and it went to the added address.
    let sent = ctx.email_sender.sent.read().unwrap();
    assert_eq!(sent.len(), 1, "expected exactly one mailed code, got {sent:?}");
    assert_eq!(sent[0].0, added);
    drop(sent);

    // The added address signs in with the new password.
    let response = ctx
        .server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": added, "pass": "chosen-password" }))
        .await;
    assert_eq!(response.status_code(), 200);
}

/// set_password / has_password on the real SQLite store — memory-store tests
/// miss sqlite-only constraints, and this store method had no production
/// caller before browserid-ng-iudv.
#[test]
fn sqlite_set_password_flips_has_password() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("test.db");
    let store = SqliteStore::open(path.to_str().unwrap()).unwrap();

    let user_id = store.create_user_no_password().unwrap();
    store.add_email(user_id, "sqlite-nopass@example.com", true).unwrap();
    assert!(!store.has_password(user_id).unwrap());

    store.set_password(user_id, "argon2-hash-placeholder").unwrap();
    assert!(store.has_password(user_id).unwrap());
    assert_eq!(
        store.get_user(user_id).unwrap().unwrap().password_hash,
        "argon2-hash-placeholder"
    );
}
