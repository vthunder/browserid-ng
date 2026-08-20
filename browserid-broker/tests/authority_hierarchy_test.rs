//! Claim-time authority hierarchy (browserid-ng-tsqk): `address_info`
//! reports which proof the fallback demands for a no-primary domain, and
//! every route that mails a verification/reset code refuses domains whose
//! authority is not the mailbox.

mod common;

use std::collections::{HashMap, HashSet};

use browserid_broker::authority::AuthorityChecker;
use browserid_broker::UserStore;
use common::{create_test_context_with_authority, create_user, get_csrf, TestContext};
use serde_json::{json, Value};

/// `handle.test` is a resolved atproto handle, `mail.test` has MX,
/// `dead.test` has neither.
fn hierarchy_context() -> TestContext {
    create_test_context_with_authority(AuthorityChecker::fixed(
        HashMap::from([("handle.test".to_string(), "did:plc:h".to_string())]),
        HashSet::from(["mail.test".to_string()]),
        Some("https://bridge.test/idp/claim".to_string()),
    ))
}

#[tokio::test]
async fn address_info_reports_the_proof_lane() {
    let ctx = hierarchy_context();

    // A handle domain: still an ordinary secondary identity (issuer is the
    // broker), but the proof is atproto and the dialog gets the claim URL.
    let body: Value = ctx
        .server
        .get("/wsapi/address_info?email=me@handle.test")
        .await
        .json();
    assert_eq!(body["type"], "secondary");
    assert_eq!(body["proof"], "atproto");
    assert_eq!(body["claim"], "https://bridge.test/idp/claim");

    // A mail domain: the SMTP loop, no claim URL.
    let body: Value = ctx
        .server
        .get("/wsapi/address_info?email=me@mail.test")
        .await
        .json();
    assert_eq!(body["proof"], "smtp");
    assert!(body.get("claim").is_none());

    // No proof method at all.
    let body: Value = ctx
        .server
        .get("/wsapi/address_info?email=me@dead.test")
        .await
        .json();
    assert_eq!(body["proof"], "none");
}

// The code-mailing gate itself (refusal for atproto/unprovable domains, with
// a reason naming the real lane) is tested on the ONE remaining mailed-code
// entry point, stage_signin_code — see signin_code_test.rs. The retired
// stage_user / stage_reset lanes (M7, browserid-ng-8gqm) carried the same
// gate; the takeover they closed — a mailed reset for a handle-authority
// domain — is closed at the same chokepoint.

/// Refusal reasons still point at the real lane on the unified endpoint.
#[tokio::test]
async fn signin_code_refusal_names_the_atproto_lane() {
    let ctx = hierarchy_context();

    let resp = ctx
        .server
        .post("/wsapi/stage_signin_code")
        .json(&json!({ "email": "me@handle.test", "pass": "password123" }))
        .await;
    assert_eq!(resp.status_code(), 403);
    let reason = resp.json::<Value>()["reason"].as_str().unwrap().to_string();
    assert!(reason.contains("handle"), "unhelpful reason: {reason}");
    assert!(ctx.email_sender.sent.read().unwrap().is_empty());
}

#[tokio::test]
async fn stage_email_refuses_non_smtp_domains() {
    let ctx = hierarchy_context();
    let session = create_user(&ctx.server, &ctx.email_sender, "me@mail.test", "password123").await;
    let csrf = get_csrf(&ctx.server, &session).await;

    let resp = ctx
        .server
        .post("/wsapi/stage_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "email": "second@handle.test", "csrf": csrf }))
        .await;
    assert_eq!(resp.status_code(), 403);
    // Only the account-creation email ever went out.
    assert_eq!(ctx.email_sender.sent.read().unwrap().len(), 1);
}

/// The takeover the gate closes: an identity at an atproto-authority domain
/// must not be password-resettable through whoever happens to route its
/// mail. The reset path IS the signin_code lane now — refused for an
/// EXISTING handle-domain identity too.
#[tokio::test]
async fn signin_code_refuses_reset_of_handle_domain_identity() {
    let ctx = hierarchy_context();
    // An identity that exists at a handle domain (as it would after the
    // atproto claim flow attaches one).
    let uid = ctx.user_store.create_user("unused-hash").unwrap();
    ctx.user_store.add_email(uid, "me@handle.test", true).unwrap();

    let resp = ctx
        .server
        .post("/wsapi/stage_signin_code")
        .json(&json!({ "email": "me@handle.test", "pass": "password123" }))
        .await;
    assert_eq!(resp.status_code(), 403);
    assert!(ctx.email_sender.sent.read().unwrap().is_empty());
}
