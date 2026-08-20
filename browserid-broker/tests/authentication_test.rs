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

/// Audit M7 (browserid-ng-dw35): a failed login must not reveal WHY it
/// failed — no such account, an account without a password, and a wrong
/// password all return identical status and body (and each path burns one
/// bcrypt verification, so timing doesn't tell them apart either).
#[tokio::test]
async fn test_auth_failure_is_existence_indistinguishable() {
    let ctx = common::create_test_context();
    use browserid_broker::UserStore;

    // An account with a password…
    common::create_user(&ctx.server, &ctx.email_sender, "haspass@example.com", "correcthorse").await;
    // …an account WITHOUT a password (bridge/primary-established)…
    let uid = ctx.user_store.create_user_no_password().unwrap();
    ctx.user_store.add_email(uid, "nopass@example.com", true).unwrap();
    // …and no account at all.

    let attempt = |email: &'static str| {
        let server = &ctx.server;
        async move {
            server
                .post("/wsapi/authenticate_user")
                .json(&json!({ "email": email, "pass": "not-the-password" }))
                .await
        }
    };

    let wrong_pass = attempt("haspass@example.com").await;
    let no_pass = attempt("nopass@example.com").await;
    let no_account = attempt("missing@example.com").await;

    assert_eq!(wrong_pass.status_code(), 401);
    assert_eq!(no_pass.status_code(), 401, "password-less account must not 500");
    assert_eq!(no_account.status_code(), 401);
    assert_eq!(wrong_pass.text(), no_account.text());
    assert_eq!(no_pass.text(), no_account.text());
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

// Brute-force throttle on password login (bean ytjn): repeated failures from
// one client get 429'd, without letting anyone lock out an account.
#[tokio::test]
async fn login_is_rate_limited_after_repeated_failures() {
    let (server, email_sender) = create_test_server();
    let email = "throttle-me@localhost:3000";
    create_user(&server, &email_sender, email, "correct-password").await;

    // 10 failed attempts are each rejected as invalid credentials (401).
    for _ in 0..10 {
        let r = server
            .post("/wsapi/authenticate_user")
            .json(&json!({ "email": email, "pass": "wrong" }))
            .await;
        assert_eq!(r.status_code(), 401);
    }
    // The 11th (still wrong) is throttled with 429, not 401.
    let throttled = server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": email, "pass": "wrong" }))
        .await;
    assert_eq!(throttled.status_code(), 429, "should be rate-limited");

    // Even a CORRECT password is throttled once the window is exhausted (the
    // brute-forcer's own IP is blocked); the window auto-resets later.
    let blocked = server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": email, "pass": "correct-password" }))
        .await;
    assert_eq!(blocked.status_code(), 429);
}
