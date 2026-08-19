//! Password reset re-verifies sibling E3 addresses (browserid-ng-kgb9, epic
//! shyj invariant 4): control of ONE inbox + a reset must not pivot to
//! minting the account's OTHER SMTP addresses. The reset address is freshly
//! proven; every other Secondary+Smtp email needs a new SMTP challenge before
//! it signs in or mints again. E1/E2/agent identities are untouched.

mod common;

use browserid_broker::store::{EmailType, ProofMethod, SqliteStore, UserStore};
use browserid_core::KeyPair;
use common::{create_test_context, create_user, get_csrf, TestContext};
use serde_json::{json, Value};

const RESET_ADDR: &str = "reset-me@example.com";
const OTHER_E3: &str = "other-e3@example.com";

/// An account with a password and the full provenance zoo: the reset target
/// (E3), a sibling E3, an E2 (oidc), an E1 (primary), and an agent identity.
async fn seeded_account(ctx: &TestContext) {
    create_user(&ctx.server, &ctx.email_sender, RESET_ADDR, "password123").await;
    let user = ctx.user_store.get_user_by_email(RESET_ADDR).unwrap().unwrap();
    ctx.user_store.add_email(user.id, OTHER_E3, true).unwrap();
    ctx.user_store
        .add_email_with_type(user.id, "bridge@example.com", true, EmailType::Secondary)
        .unwrap();
    ctx.user_store
        .set_email_proof("bridge@example.com", ProofMethod::Oidc, Some("s"))
        .unwrap();
    ctx.user_store
        .add_email_with_type(user.id, "me@primary.example", true, EmailType::Primary)
        .unwrap();
    ctx.user_store
        .add_email_with_type(user.id, "reset-me+bot@example.com", true, EmailType::Agent)
        .unwrap();
}

async fn run_reset(ctx: &TestContext, email: &str, new_pass: &str) {
    let response = ctx
        .server
        .post("/wsapi/stage_reset")
        .json(&json!({ "email": email }))
        .await;
    assert_eq!(response.status_code(), 200);
    let code = ctx.email_sender.get_code(email).expect("reset code sent");
    let response = ctx
        .server
        .post("/wsapi/complete_reset")
        .json(&json!({ "email": email, "token": code, "pass": new_pass }))
        .await;
    assert_eq!(response.status_code(), 200);
}

#[tokio::test]
async fn reset_unverifies_only_sibling_e3_addresses() {
    let ctx = create_test_context();
    seeded_account(&ctx).await;

    run_reset(&ctx, RESET_ADDR, "new-password-1").await;

    let verified = |email: &str| ctx.user_store.get_email(email).unwrap().unwrap().verified;
    assert!(verified(RESET_ADDR), "the reset address was just proven");
    assert!(!verified(OTHER_E3), "sibling E3 must need re-verification");
    assert!(verified("bridge@example.com"), "E2 trust doesn't rest on the password");
    assert!(verified("me@primary.example"), "E1 trust doesn't rest on the password");
    assert!(verified("reset-me+bot@example.com"), "agent identities ride the account");
}

/// The attack the invariant closes, end-to-end: attacker controlling ONE E3
/// inbox resets the password, gets a full session — and still cannot mint the
/// OTHER E3 until its inbox is re-proven. Re-proving it restores minting
/// without duplicating the email row.
#[tokio::test]
async fn reset_pivot_is_blocked_until_reverification() {
    let ctx = create_test_context();
    seeded_account(&ctx).await;
    run_reset(&ctx, RESET_ADDR, "new-password-1").await;

    // Full session with the new password (reset killed the old sessions).
    let response = ctx
        .server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": RESET_ADDR, "pass": "new-password-1" }))
        .await;
    assert_eq!(response.status_code(), 200);
    let session = response
        .maybe_cookie("browserid_session")
        .unwrap()
        .value()
        .to_string();
    let csrf = get_csrf(&ctx.server, &session).await;

    let issue = |email: String, csrf: String, session: String| {
        let server = &ctx.server;
        async move {
            server
                .post("/device/issue")
                .add_cookie(cookie::Cookie::new("browserid_session", session))
                .json(&json!({
                    "csrf": csrf, "email": email,
                    "device_pubkey": KeyPair::generate().public_key().to_base64(),
                    "config_pubkey": KeyPair::generate().public_key().to_base64(),
                }))
                .await
        }
    };

    // The reset address mints (full session, freshly proven)…
    let response = issue(RESET_ADDR.to_string(), csrf.clone(), session.clone()).await;
    assert_eq!(response.status_code(), 200);

    // …the sibling E3 does NOT until re-verified.
    let response = issue(OTHER_E3.to_string(), csrf.clone(), session.clone()).await;
    assert_ne!(response.status_code(), 200, "unverified sibling must not mint");

    // The dialog sees it as needing re-verification.
    let info: Value = ctx
        .server
        .get(&format!("/wsapi/address_info?email={OTHER_E3}"))
        .await
        .json();
    assert_eq!(info["state"], "unverified");

    // Re-verify: the owning account re-stages the existing address (kgb9's
    // stage_email carve-out) and completes — one fresh SMTP roundtrip.
    let response = ctx
        .server
        .post("/wsapi/stage_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "email": OTHER_E3, "csrf": csrf }))
        .await;
    assert_eq!(response.status_code(), 200);
    let code = ctx.email_sender.get_code(OTHER_E3).unwrap();
    let response = ctx
        .server
        .post("/wsapi/complete_email_addition")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "email": OTHER_E3, "token": code, "csrf": csrf }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Verified again, exactly one row, and it mints.
    let user = ctx.user_store.get_user_by_email(RESET_ADDR).unwrap().unwrap();
    let rows: Vec<_> = ctx
        .user_store
        .list_emails(user.id)
        .unwrap()
        .into_iter()
        .filter(|e| e.email == OTHER_E3)
        .collect();
    assert_eq!(rows.len(), 1, "re-verification must not duplicate the row");
    assert!(rows[0].verified);
    let response = issue(OTHER_E3.to_string(), csrf, session).await;
    assert_eq!(response.status_code(), 200);
}

/// The stage_email carve-out is owner-only: someone else's account cannot
/// stage a code for an address it doesn't hold.
#[tokio::test]
async fn restaging_someone_elses_email_is_refused() {
    let ctx = create_test_context();
    seeded_account(&ctx).await;
    let intruder =
        create_user(&ctx.server, &ctx.email_sender, "intruder@example.com", "password123").await;
    let csrf = get_csrf(&ctx.server, &intruder).await;

    let response = ctx
        .server
        .post("/wsapi/stage_email")
        .add_cookie(cookie::Cookie::new("browserid_session", intruder))
        .json(&json!({ "email": OTHER_E3, "csrf": csrf }))
        .await;
    assert_eq!(response.status_code(), 409);
}

/// unverify_email gets its FIRST production caller with kgb9 — prove the
/// SQLite implementation round-trips (memory-store coverage isn't enough).
#[test]
fn sqlite_unverify_and_reverify_round_trip() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("test.db");
    let store = SqliteStore::open(path.to_str().unwrap()).unwrap();
    let user_id = store.create_user("hash").unwrap();
    store.add_email(user_id, "flip@example.com", true).unwrap();

    store.unverify_email("flip@example.com").unwrap();
    let rec = store.get_email("flip@example.com").unwrap().unwrap();
    assert!(!rec.verified);

    store.verify_email("flip@example.com").unwrap();
    let rec = store.get_email("flip@example.com").unwrap().unwrap();
    assert!(rec.verified);
    assert_eq!(store.list_emails(user_id).unwrap().len(), 1);
}
