//! Cookie-session admission (bean 160l, handoff
//! docs/plans/2026-09-15-cookie-session-admission-handoff.md): an issuer
//! cookie session reveals and manages the account only once it is bound to
//! a login key the registry enrolled on that account. Until then it is an
//! identity session — issuer-role work for the identities it proved, and
//! nothing account-wide.

mod common;

use browserid_broker::store::{SessionId, SessionLevel, SessionStore, UserStore};
use browserid_core::KeyPair;
use common::registry::{admit_session, admit_with, api_login, api_post};
use common::{create_test_context, create_user, create_user_unadmitted, get_csrf, TestContext};
use serde_json::{json, Value};

async fn ctx_json(ctx: &TestContext, session: &str) -> Value {
    ctx.server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .await
        .json()
}

async fn get(ctx: &TestContext, session: &str, path: &str) -> (u16, Value) {
    let r = ctx
        .server
        .get(path)
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .await;
    (r.status_code().as_u16(), r.json())
}

async fn post(ctx: &TestContext, session: &str, path: &str, mut body: Value) -> (u16, Value) {
    let csrf = get_csrf(&ctx.server, session).await;
    body["csrf"] = json!(csrf);
    let r = ctx
        .server
        .post(path)
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .json(&body)
        .await;
    (r.status_code().as_u16(), r.json())
}

async fn device_issue(ctx: &TestContext, session: &str, email: &str) -> (u16, Value) {
    post(
        ctx,
        session,
        "/device/issue",
        json!({
            "email": email,
            "device_pubkey": KeyPair::generate().public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
        }),
    )
    .await
}

fn assert_not_admitted((status, body): (u16, Value), what: &str) {
    assert_eq!(status, 403, "{what}: {body}");
    assert_eq!(body["reason"], "not_admitted", "{what}: {body}");
}

/// A password sign-in opens an identity session: it proved every
/// broker-vouched address, but the account-wide endpoints refuse until
/// the registry admits the browser.
#[tokio::test]
async fn password_session_is_an_identity_session_until_admitted() {
    let ctx = create_test_context();
    let email = "owner@example.com";
    let session = create_user_unadmitted(&ctx.server, &ctx.email_sender, email, "password123").await;

    let c = ctx_json(&ctx, &session).await;
    assert_eq!(c["authenticated"], true);
    assert_eq!(c["admitted"], false);
    assert_eq!(c["proved_emails"], json!([email]));
    // The account id stays: it is what the device logs in to the registry with.
    assert!(c["account"].is_string(), "{c}");

    assert_not_admitted(get(&ctx, &session, "/wsapi/list_emails").await, "list_emails");
    // The browsers-namespace prefix is not account data an identity session
    // lacks (its own cert's holder carries it): open, so the device issued
    // before the registry step already sits in the account's namespace.
    let (status, body) = get(&ctx, &session, "/wsapi/browser_holder").await;
    assert_eq!(status, 200, "{body}");
    assert_not_admitted(
        get(&ctx, &session, &format!("/wsapi/parent_of?email={email}")).await,
        "parent_of",
    );
    assert_not_admitted(
        get(&ctx, &session, "/wsapi/issuer_revoke_url?iss=other.example").await,
        "issuer_revoke_url",
    );
    assert_not_admitted(
        post(&ctx, &session, "/wsapi/set_public_name", json!({ "email": email, "public_name": "x" })).await,
        "set_public_name",
    );
    assert_not_admitted(
        post(&ctx, &session, "/wsapi/set_parent", json!({ "email": email, "parent_email": email })).await,
        "set_parent",
    );
    assert_not_admitted(
        post(&ctx, &session, "/wsapi/remove_email", json!({ "email": email })).await,
        "remove_email",
    );
    assert_not_admitted(
        post(&ctx, &session, "/wsapi/update_password", json!({ "oldpass": "password123", "newpass": "password456" })).await,
        "update_password",
    );
    assert_not_admitted(
        post(&ctx, &session, "/wsapi/account_cancel", json!({ "email": email, "pass": "password123" })).await,
        "account_cancel",
    );
    // Adding a NEW address is account-wide too.
    assert_not_admitted(
        post(&ctx, &session, "/wsapi/stage_email", json!({ "email": "new@example.com" })).await,
        "stage_email (new address)",
    );

    // Issuer-role work for the proved identity stays open.
    let (status, body) = device_issue(&ctx, &session, email).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = get(&ctx, &session, &format!("/wsapi/address_info?email={email}")).await;
    assert_eq!(status, 200);
    assert_eq!(body["state"], "known", "{body}");
    let (status, body) = post(&ctx, &session, "/wsapi/stage_email", json!({ "email": email })).await;
    assert_eq!(status, 200, "re-verifying a proved address: {body}");
}

/// A session that proved ONE identity of a multi-address account (the
/// shape auth_with_presentation and the bridge claims open) sees and issues
/// for that identity only.
#[tokio::test]
async fn identity_session_is_scoped_to_what_it_proved() {
    let ctx = create_test_context();
    let a = "a@example.com";
    let b = "b@example.com";
    let _ = create_user_unadmitted(&ctx.server, &ctx.email_sender, a, "password123").await;
    let user = ctx.user_store.get_user_by_email(a).unwrap().unwrap();
    ctx.user_store.add_email(user.id, b, true).unwrap();
    let session = ctx
        .session_store
        .create(user.id, SessionLevel::Full, vec![a.to_string()])
        .unwrap()
        .id
        .0;

    let (status, body) = device_issue(&ctx, &session, a).await;
    assert_eq!(status, 200, "{body}");
    assert_not_admitted(device_issue(&ctx, &session, b).await, "device/issue for a sibling");

    let (_, body) = get(&ctx, &session, &format!("/wsapi/address_info?email={a}")).await;
    assert_eq!(body["state"], "known", "{body}");
    let (_, body) = get(&ctx, &session, &format!("/wsapi/address_info?email={b}")).await;
    assert!(body["state"].is_null(), "a sibling's state is not disclosed: {body}");

    let (status, _) = post(&ctx, &session, "/wsapi/stage_email", json!({ "email": a })).await;
    assert_eq!(status, 200);
    assert_not_admitted(
        post(&ctx, &session, "/wsapi/stage_email", json!({ "email": b })).await,
        "re-verifying a sibling",
    );

    // Set a first password stays open (it is what lets the device pass the
    // bar) — on a passwordless account.
    let c = "c@example.com";
    let cu = ctx.user_store.create_user_no_password().unwrap();
    ctx.user_store.add_email(cu, c, true).unwrap();
    let cs = ctx
        .session_store
        .create(cu, SessionLevel::Lightweight, vec![c.to_string()])
        .unwrap()
        .id
        .0;
    let (status, body) = post(&ctx, &cs, "/wsapi/set_password", json!({ "pass": "chosen-password" })).await;
    assert_eq!(status, 200, "{body}");
}

/// session_admit binds the cookie session to the registry login key the
/// call is made under; the registry session must be on the same account.
/// Admitted, the session does all of it; a revoked key un-admits it.
#[tokio::test]
async fn admission_binds_then_revocation_unbinds() {
    let ctx = create_test_context();
    let a = "a@example.com";
    let b = "b@example.com";
    let session = create_user_unadmitted(&ctx.server, &ctx.email_sender, a, "password123").await;
    let user = ctx.user_store.get_user_by_email(a).unwrap().unwrap();
    ctx.user_store.add_email(user.id, b, true).unwrap();

    // Another account's registry session cannot admit this cookie.
    let other = create_user(&ctx.server, &ctx.email_sender, "other@example.com", "password123").await;
    let other_reg = api_login(&ctx.server, &other, "password123").await;
    let r = admit_with(&ctx.server, &session, &other_reg).await;
    assert_eq!(r.status_code(), 403, "{}", r.text());
    assert_eq!(ctx_json(&ctx, &session).await["admitted"], false);

    // The account's own registry session does. Idempotent.
    let reg = admit_session(&ctx.server, &session, "password123").await;
    let r = admit_with(&ctx.server, &session, &reg).await;
    assert_eq!(r.status_code(), 200, "{}", r.text());
    let c = ctx_json(&ctx, &session).await;
    assert_eq!(c["admitted"], true);

    let (status, body) = get(&ctx, &session, "/wsapi/list_emails").await;
    assert_eq!(status, 200, "{body}");
    let mut emails: Vec<String> = body["emails"].as_array().unwrap().iter().map(|e| e.as_str().unwrap().to_string()).collect();
    emails.sort();
    assert_eq!(emails, vec![a.to_string(), b.to_string()]);
    let (status, body) = get(&ctx, &session, "/wsapi/browser_holder").await;
    assert_eq!(status, 200, "{body}");
    // Any identity of the account issues now — b was never proved by this session.
    let (status, body) = device_issue(&ctx, &session, b).await;
    assert_eq!(status, 200, "{body}");
    let (_, body) = get(&ctx, &session, &format!("/wsapi/address_info?email={b}")).await;
    assert_eq!(body["state"], "known", "{body}");

    // Admission is per session: a brand-new password login on the same
    // account is unadmitted again.
    let r = ctx
        .server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": a, "pass": "password123" }))
        .await;
    let fresh = r.maybe_cookie("browserid_session").unwrap().value().to_string();
    assert_eq!(ctx_json(&ctx, &fresh).await["admitted"], false);

    // Revoking the login key un-admits every cookie session bound to it.
    let session2 = create_user_unadmitted(&ctx.server, &ctx.email_sender, "z@example.com", "password123").await;
    let reg2 = admit_session(&ctx.server, &session2, "password123").await;
    assert_eq!(ctx_json(&ctx, &session2).await["admitted"], true);
    let r = api_post(&ctx.server, &reg2, "/api/v1/login-keys/revoke", json!({ "kid": reg2.key.public_key().kid() })).await;
    assert_eq!(r.status_code(), 200, "{}", r.text());
    let c = ctx_json(&ctx, &session2).await;
    assert_eq!(c["authenticated"], true, "the session stays, as an identity session");
    assert_eq!(c["admitted"], false);
    assert_not_admitted(get(&ctx, &session2, "/wsapi/list_emails").await, "list_emails after revoke");
    // A revoked key cannot re-admit.
    let r = admit_with(&ctx.server, &session2, &reg2).await;
    assert_ne!(r.status_code(), 200);
}

/// update_password's re-minted session keeps its admission (the cookie the
/// response sets is admitted), and logout ends it.
#[tokio::test]
async fn remint_keeps_admission_and_logout_ends_it() {
    let ctx = create_test_context();
    let email = "remint@example.com";
    let session = create_user(&ctx.server, &ctx.email_sender, email, "password123").await;
    let csrf = get_csrf(&ctx.server, &session).await;
    let r = ctx
        .server
        .post("/wsapi/update_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "oldpass": "password123", "newpass": "password456", "csrf": csrf }))
        .await;
    assert_eq!(r.status_code(), 200, "{}", r.text());
    let fresh = r.maybe_cookie("browserid_session").unwrap().value().to_string();
    assert_ne!(fresh, session);
    let c = ctx_json(&ctx, &fresh).await;
    assert_eq!(c["admitted"], true);
    assert_eq!(c["proved_emails"], json!([email]));

    let (status, _) = post(&ctx, &fresh, "/wsapi/logout", json!({})).await;
    assert_eq!(status, 200);
    assert_eq!(ctx_json(&ctx, &fresh).await["authenticated"], false);
    // The store row is gone, not merely unbound.
    assert!(ctx.session_store.get(&SessionId(fresh)).unwrap().is_none());
}
