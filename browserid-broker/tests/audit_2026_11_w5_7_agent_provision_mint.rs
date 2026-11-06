//! Audit 2026-11 W5-7 (decision Q6, bean o1zy): `agent-provision/complete`
//! goes through the issuer's mint chokepoint before the registrar signs an
//! agent device cert — the same bar `/device/issue` applies to the
//! identity being certified — instead of `owns_verified_email` alone.
//!
//! Lanes: an identity session that did not prove the parent is
//! `not_admitted`; an E3 (mailbox-proofed) parent needs a password session
//! and a fresh proof (`password required` / re-verification); a named
//! (handle) agent follows the agent rule (password session); an as-you
//! agent for a bridged (E2) parent needs a live bridge grant, redeemed
//! once, and takes the bridge's TTL.

mod common;

use axum_test::TestResponse;
use browserid_broker::store::{EmailType, ProofMethod, SessionLevel, SessionStore, UserStore};
use browserid_core::device::DeviceCert;
use browserid_core::KeyPair;
use chrono::{Duration, Utc};
use common::{create_test_context_customized, create_user, get_csrf, TestContext};
use serde_json::{json, Value};

const OWNER: &str = "owner@example.com";
const PASSWORD: &str = "password123";

fn ctx() -> TestContext {
    create_test_context_customized(|s| s.agent_provisioning_enabled = true)
}

/// A grant-less pairing request (no `prepare` needed): the code.
async fn file(ctx: &TestContext, handle: Option<&str>) -> String {
    let device_kp = KeyPair::generate();
    let mut body = json!({
        "provisioning_pubkey": { "algorithm": "Ed25519", "publicKey": device_kp.public_key().to_base64() },
    });
    if let Some(h) = handle {
        body["requested_handles"] = json!({ "names": [h] });
    }
    let r = ctx.server.post("/agent-provision/request").json(&body).await;
    assert_eq!(r.status_code(), 200, "request: {}", r.text());
    r.json::<Value>()["code"].as_str().unwrap().to_string()
}

/// Approve `code` under `session` for `identity` in `mode`.
async fn approve(ctx: &TestContext, session: &str, code: &str, identity: &str, mode: &str, handle: Option<&str>) -> TestResponse {
    let csrf = get_csrf(&ctx.server, session).await;
    let mut body = json!({ "csrf": csrf, "code": code, "approve": true, "identity_email": identity, "identity_mode": mode });
    if let Some(h) = handle {
        body["handle"] = json!(h);
    }
    ctx.server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .json(&body)
        .await
}

async fn issued_cert(ctx: &TestContext, code: &str) -> DeviceCert {
    let poll: Value = ctx.server.post("/agent-provision/poll").json(&json!({ "code": code })).await.json();
    assert_eq!(poll["status"], "completed", "{poll}");
    DeviceCert::parse(poll["credential"]["device_cert"].as_str().unwrap()).unwrap()
}

/// A session of `level` on the owner's account that proved `proved`.
fn session(ctx: &TestContext, level: SessionLevel, proved: &[&str]) -> String {
    let user = ctx.user_store.get_user_by_email(OWNER).unwrap().unwrap();
    ctx.session_store
        .create(user.id, level, proved.iter().map(|s| s.to_string()).collect())
        .unwrap()
        .id
        .0
}

#[tokio::test]
async fn an_identity_session_that_did_not_prove_the_parent_is_not_admitted() {
    let c = ctx();
    let _full = create_user(&c.server, &c.email_sender, OWNER, PASSWORD).await;
    let stranger = session(&c, SessionLevel::Lightweight, &[]);
    let code = file(&c, None).await;
    let r = approve(&c, &stranger, &code, OWNER, "self", None).await;
    assert_eq!(r.status_code(), 403, "{}", r.text());
    assert_eq!(r.json::<Value>()["reason"], "not_admitted");
}

#[tokio::test]
async fn an_e3_parent_needs_a_password_session_for_self_and_handle_agents() {
    let c = ctx();
    let _full = create_user(&c.server, &c.email_sender, OWNER, PASSWORD).await;
    // Proved the parent (an emailed-code login), but no password: the
    // broker-vouched identity does not mint, as at /device/issue.
    let light = session(&c, SessionLevel::Lightweight, &[OWNER]);
    let code = file(&c, None).await;
    let r = approve(&c, &light, &code, OWNER, "self", None).await;
    assert_eq!(r.status_code(), 401, "{}", r.text());
    assert_eq!(r.json::<Value>()["reason"], "password required");
    // A named agent: the agent rule, applied from the parent's record.
    let code = file(&c, Some("owner+bot")).await;
    let r = approve(&c, &light, &code, OWNER, "handle", Some("owner+bot")).await;
    assert_eq!(r.status_code(), 401, "{}", r.text());
    assert_eq!(r.json::<Value>()["reason"], "password required");
    // The password session signs both, for the broker's own TTL.
    let full = session(&c, SessionLevel::Full, &[OWNER]);
    let r = approve(&c, &full, &code, OWNER, "handle", Some("owner+bot")).await;
    assert_eq!(r.status_code(), 200, "{}", r.text());
    let cert = issued_cert(&c, &code).await;
    assert_eq!(cert.claims().identities, vec!["owner+bot@example.com".to_string()]);
    assert_eq!(cert.claims().exp - cert.claims().iat, 90 * 86400);
}

#[tokio::test]
async fn an_e3_parent_with_a_stale_mailbox_proof_must_reverify() {
    let c = ctx();
    let full = create_user(&c.server, &c.email_sender, OWNER, PASSWORD).await;
    c.user_store.set_email_verified_at(OWNER, Utc::now() - Duration::days(120)).unwrap();
    let code = file(&c, None).await;
    let r = approve(&c, &full, &code, OWNER, "self", None).await;
    assert_eq!(r.status_code(), 403, "{}", r.text());
    assert!(r.text().contains("verification expired"), "{}", r.text());
}

#[tokio::test]
async fn an_as_you_agent_for_a_bridged_parent_redeems_a_bridge_grant() {
    let c = ctx();
    let full = create_user(&c.server, &c.email_sender, OWNER, PASSWORD).await;
    let user = c.user_store.get_user_by_email(OWNER).unwrap().unwrap();
    let bridged = "owner@gmail.example";
    c.user_store.add_email_with_type(user.id, bridged, true, EmailType::Secondary).unwrap();
    c.user_store.set_email_proof(bridged, ProofMethod::Oidc, Some("sub-1")).unwrap();

    // The admitted password session alone never mints a bridged address.
    let code = file(&c, None).await;
    let r = approve(&c, &full, &code, bridged, "self", None).await;
    assert_eq!(r.status_code(), 403, "{}", r.text());
    assert!(r.text().contains("bridge proof"), "{}", r.text());

    // The bridge ran (as /oidc/claim records): the grant is redeemed once,
    // and the cert takes the bridge's TTL.
    c.state.record_bridge_grant(user.id, bridged, Duration::days(7));
    let r = approve(&c, &full, &code, bridged, "self", None).await;
    assert_eq!(r.status_code(), 200, "{}", r.text());
    let cert = issued_cert(&c, &code).await;
    assert_eq!(cert.claims().identities, vec![bridged.to_string()]);
    assert_eq!(cert.claims().exp - cert.claims().iat, 7 * 86400, "the bridge's TTL");

    // Consumed: the next approval needs a new proof.
    let code = file(&c, None).await;
    let r = approve(&c, &full, &code, bridged, "self", None).await;
    assert_eq!(r.status_code(), 403, "grant reused: {}", r.text());
}
