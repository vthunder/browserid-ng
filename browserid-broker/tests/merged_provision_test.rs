//! Merged one-approval agent provisioning (agent/D phase), end to end over
//! HTTP: the agent's `/agent-provision/request` carries its pubkey + handle +
//! namespace hint + warrant grant(s); the approval page calls
//! `/agent-provision/prepare` (broker assigns the holder + status indices),
//! signs the warrant(s) client-side with the user's config cert, and approves
//! via `/agent-provision/complete`; one `/agent-provision/poll` returns BOTH
//! the agent device cert and the `warrant~config_cert` grants, ready to
//! assemble a verifying 4-object presentation.

mod common;

use std::sync::Arc;

use axum_test::TestServer;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::device::{
    AccessPresentation, AccessRequest, DeviceCert, Holder, HolderMatcher, Purpose, Warrant,
};
use browserid_core::{Assertion, KeyPair, StatusRef};
use chrono::Duration;
use common::{create_user, MockEmailSender};
use serde_json::{json, Value};

const DOMAIN: &str = "localhost:3000";
const DELEGATOR: &str = "alice@example.com";
const AGENT: &str = "alice+poster@example.com";
const AUDIENCE: &str = "sbo+raw://avail:turing:506/";

fn make_server() -> (TestServer, MockEmailSender, KeyPair) {
    let keypair = KeyPair::generate();
    let email_sender = Arc::new(MockEmailSender::new());
    let mut state = AppState::new_with_arcs(
        keypair.clone(),
        DOMAIN.to_string(),
        Arc::new(InMemoryUserStore::new()),
        Arc::new(InMemorySessionStore::new()),
        email_sender.clone(),
    );
    state.agent_provisioning_enabled = true;
    let server = TestServer::new(routes::create_router(Arc::new(state))).unwrap();
    (server, MockEmailSender { sent: email_sender.sent.clone() }, keypair)
}

async fn csrf(server: &TestServer, session: &str) -> String {
    server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .await
        .json::<Value>()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn merged_request_prepare_approve_single_pickup() {
    let (server, sender, idp_kp) = make_server();
    let session = create_user(&server, &sender, DELEGATOR, "testpassword").await;

    // The browser's config cert covering the delegator's `+` namespace (what
    // login issuance deposits in the keystore).
    let config_kp = KeyPair::generate();
    let config_cert = DeviceCert::create(
        DOMAIN, &config_kp.public_key(), Purpose::Authorization, Holder::new("br.main").unwrap(),
        vec![DELEGATOR.to_string(), "alice+*@example.com".to_string()],
        Duration::days(90), &idp_kp, None,
    )
    .unwrap();

    // 1. The service starts pairing: pubkey + handle + namespace hint + grant.
    let device_kp = KeyPair::generate();
    let r = server
        .post("/agent-provision/request")
        .json(&json!({
            "provisioning_pubkey": { "algorithm": "Ed25519", "publicKey": device_kp.public_key().to_base64() },
            "requested_handles": { "names": ["alice+poster"] },
            "namespace": "services",
            "grants": [{ "audience": AUDIENCE, "scopes": ["action:post"] }],
            "label": "mingo poster",
        }))
        .await;
    assert_eq!(r.status_code(), 200, "request: {:?}", r.text());
    let code = r.json::<Value>()["code"].as_str().unwrap().to_string();

    // 2. The approval page's display info carries the grants + namespace.
    let info: Value = server
        .post("/agent-provision/info")
        .json(&json!({ "code": code }))
        .await
        .json();
    assert_eq!(info["namespace"], "services");
    assert_eq!(info["grants"][0]["audience"], AUDIENCE);

    // 3. Approving with grants but without `prepare` is refused: the page must
    //    sign matchers against the broker-assigned holder.
    let c = csrf(&server, &session).await;
    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "identity_email": DELEGATOR }))
        .await;
    assert_ne!(r.status_code(), 200, "complete without prepare must be refused");

    // 4. Prepare: the broker assigns the holder + allocates status indices.
    let prep: Value = server
        .post("/agent-provision/prepare")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "identity_email": DELEGATOR }))
        .await
        .json();
    assert_eq!(prep["success"], true, "prepare: {prep}");
    assert_eq!(prep["agent_email"], AGENT);
    let holder = prep["holder"].as_str().unwrap().to_string();
    assert!(holder.contains('.'), "holder is `<ns-prefix>.<rand>`: {holder}");
    let status_uri = prep["status_uri"].as_str().unwrap().to_string();
    let status_idx = prep["grants"][0]["status_idx"].as_u64().expect("status idx allocated");

    // Re-prepare is idempotent for the same identity: same holder.
    let prep2: Value = server
        .post("/agent-provision/prepare")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "identity_email": DELEGATOR }))
        .await
        .json();
    assert_eq!(prep2["holder"], holder);

    // 5. A warrant with a matcher that doesn't cover the assigned holder is
    //    refused all-or-nothing at complete.
    let foreign = Warrant::create(
        AGENT, HolderMatcher::new("zz.other").unwrap(), AUDIENCE, vec!["action:post".into()],
        Duration::days(90), &config_kp,
        Some(StatusRef { uri: status_uri.clone(), idx: status_idx }),
    )
    .unwrap();
    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "identity_email": DELEGATOR,
            "warrants": [foreign.encoded()], "config_cert": config_cert.encoded() }))
        .await;
    assert_ne!(r.status_code(), 200, "foreign holder matcher must be refused");

    // 6. The page signs the warrant against the assigned holder and approves.
    let warrant = Warrant::create(
        AGENT, HolderMatcher::new(&holder).unwrap(), AUDIENCE, vec!["action:post".into()],
        Duration::days(90), &config_kp,
        Some(StatusRef { uri: status_uri.clone(), idx: status_idx }),
    )
    .unwrap();
    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "identity_email": DELEGATOR,
            "warrants": [warrant.encoded()], "config_cert": config_cert.encoded() }))
        .await;
    assert_eq!(r.status_code(), 200, "complete: {:?}", r.text());

    // 7. ONE poll returns both the device cert and the warrant.
    let poll: Value = server
        .post("/agent-provision/poll")
        .json(&json!({ "code": code }))
        .await
        .json();
    assert_eq!(poll["status"], "completed", "{poll}");
    assert_eq!(poll["credential"]["identity"], AGENT);
    let device_cert_jws = poll["credential"]["device_cert"].as_str().unwrap().to_string();
    let tail = poll["grants"][0]["warrant"].as_str().unwrap().to_string();
    assert_eq!(tail, format!("{}~{}", warrant.encoded(), config_cert.encoded()));

    // The issued device cert carries the SAME holder the warrant binds to.
    let device_cert = DeviceCert::parse(&device_cert_jws).unwrap();
    assert_eq!(device_cert.holder().as_str(), holder);
    assert_eq!(device_cert.purpose(), Purpose::Authentication);

    // 8. The grant landed in the delegator's warrant registry.
    let warrants: Value = server
        .get("/wsapi/warrants")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let w = &warrants["warrants"][0];
    assert_eq!(w["agent_email"], AGENT);
    assert_eq!(w["holder"], holder);

    // 9. Full presentation: mint an access cert with the agent device key,
    //    splice the delivered tail, verify the join.
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(
        DOMAIN, AGENT, Holder::new(holder.clone()).unwrap(), &access_kp.public_key(), "jti-m1", &device_kp,
    )
    .unwrap();
    let minted: Value = server
        .post("/access/mint")
        .json(&json!({ "device_cert": device_cert_jws, "access_request": areq.encoded() }))
        .await
        .json();
    assert_eq!(minted["success"], true, "mint: {minted}");
    let assertion = Assertion::create(AUDIENCE, Duration::minutes(5), &access_kp).unwrap();
    let presentation = format!(
        "{}~{}~{}",
        minted["access_cert"].as_str().unwrap(),
        assertion.encoded(),
        tail
    );
    let verified = AccessPresentation::parse(&presentation)
        .unwrap()
        .verify(AUDIENCE, |_| Ok(idp_kp.public_key()))
        .expect("merged-provisioned service presentation verifies");
    assert_eq!(verified.email, AGENT);
    assert_eq!(verified.holder.as_str(), holder);
    assert_eq!(verified.scopes, vec!["action:post".to_string()]);
}

/// A grant-less request keeps today's shape: no prepare needed, `complete`
/// assigns the holder itself, poll delivers just the credential.
#[tokio::test]
async fn grantless_request_still_completes_without_prepare() {
    let (server, sender, _idp_kp) = make_server();
    let session = create_user(&server, &sender, DELEGATOR, "testpassword").await;

    let device_kp = KeyPair::generate();
    let r = server
        .post("/agent-provision/request")
        .json(&json!({
            "provisioning_pubkey": { "algorithm": "Ed25519", "publicKey": device_kp.public_key().to_base64() },
            "requested_handles": { "names": ["alice+bot"] },
        }))
        .await;
    assert_eq!(r.status_code(), 200, "request: {:?}", r.text());
    let code = r.json::<Value>()["code"].as_str().unwrap().to_string();

    let c = csrf(&server, &session).await;
    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "identity_email": DELEGATOR }))
        .await;
    assert_eq!(r.status_code(), 200, "complete: {:?}", r.text());

    let poll: Value = server
        .post("/agent-provision/poll")
        .json(&json!({ "code": code }))
        .await
        .json();
    assert_eq!(poll["status"], "completed", "{poll}");
    assert_eq!(poll["grants"].as_array().map(|g| g.len()), Some(0));
    let device_cert = DeviceCert::parse(poll["credential"]["device_cert"].as_str().unwrap()).unwrap();
    // Default namespace: the holder sits under the user's `agents` prefix.
    assert!(device_cert.holder().as_str().contains('.'));
}
