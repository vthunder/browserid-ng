//! Device-model warrant consent flow, end to end over HTTP:
//! an agent (holding an IdP-signed agent device cert) raises
//! `POST /warrant/request`; the delegator's consent surface signs the
//! device-shaped warrant with the config key and responds; the agent polls
//! `POST /warrant/poll` and receives `warrant~config_cert`; combined with a
//! minted access cert + assertion, the full 4-object presentation verifies.

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
const AGENT: &str = "alice+bot@example.com";
const AUDIENCE: &str = "https://notes.example.com";

/// A test server whose IdP keypair we keep, so the test can mint the agent's
/// device cert exactly as `/agent-provision/complete` would.
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
async fn agent_warrant_request_consent_poll_and_full_presentation() {
    let (server, sender, idp_kp) = make_server();
    let session = create_user(&server, &sender, DELEGATOR, "testpassword").await;

    // The agent's IdP-signed authentication device cert (what paired
    // provisioning issues), and the browser's config cert covering the
    // delegator's `+` namespace (what login issuance deposits).
    // The agent is an isolated holder in the `agents` namespace (`<id>` matcher);
    // the delegator's browser config cert carries its own browsers holder.
    let agent_holder = Holder::new("ag.bot").unwrap();
    let agent_kp = KeyPair::generate();
    let agent_cert = DeviceCert::create(
        DOMAIN, &agent_kp.public_key(), Purpose::Authentication, agent_holder.clone(),
        vec![AGENT.to_string()], Duration::days(90), &idp_kp, None,
    )
    .unwrap();
    let config_kp = KeyPair::generate();
    let config_cert = DeviceCert::create(
        DOMAIN, &config_kp.public_key(), Purpose::Authorization, Holder::new("br.main").unwrap(),
        vec![DELEGATOR.to_string(), "alice+*@example.com".to_string()],
        Duration::days(90), &idp_kp, None,
    )
    .unwrap();

    // 1. The agent raises a consent request.
    let r = server
        .post("/warrant/request")
        .json(&json!({
            "device_cert": agent_cert.encoded(),
            "identity": AGENT,
            "grants": [{ "audience": AUDIENCE, "scopes": ["post", "read"] }],
            "label": "test bot",
        }))
        .await;
    assert_eq!(r.status_code(), 200, "request: {:?}", r.text());
    let req_body: Value = r.json();
    let code = req_body["code"].as_str().unwrap().to_string();
    assert!(req_body["verification_uri_complete"].as_str().unwrap().contains(&code));

    // A cert from a rogue key is refused.
    let rogue = KeyPair::generate();
    let rogue_cert = DeviceCert::create(
        DOMAIN, &agent_kp.public_key(), Purpose::Authentication, agent_holder.clone(),
        vec![AGENT.to_string()], Duration::days(90), &rogue, None,
    )
    .unwrap();
    let r = server
        .post("/warrant/request")
        .json(&json!({ "device_cert": rogue_cert.encoded(), "identity": AGENT,
            "grants": [{ "audience": AUDIENCE }] }))
        .await;
    assert_ne!(r.status_code(), 200, "rogue-signed device cert must be refused");

    // 2. Poll while pending.
    let r = server.post("/warrant/poll").json(&json!({ "code": code })).await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    assert_eq!(r.json::<Value>()["status"], "pending");

    // 3. The delegator's consent page: list, then sign + respond.
    let listed: Value = server
        .get("/wsapi/warrant_requests")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let reqs = listed["requests"].as_array().unwrap();
    assert_eq!(reqs.len(), 1, "consent inbox shows the request: {listed}");
    assert_eq!(reqs[0]["agent_email"], AGENT);
    assert_eq!(reqs[0]["delegator_email"], DELEGATOR);
    let grant = &reqs[0]["grants"][0];
    assert_eq!(grant["audience"], AUDIENCE);
    let status_idx = grant["status_idx"].as_u64().expect("status idx allocated");
    let status_uri = listed["status_uri"].as_str().unwrap().to_string();

    let warrant = Warrant::create(
        AGENT, AGENT, HolderMatcher::new("ag.bot").unwrap(), AUDIENCE,
        vec!["post".into(), "read".into()], Duration::days(90), &config_kp,
        Some(StatusRef { uri: status_uri, idx: status_idx }),
    )
    .unwrap();
    let c = csrf(&server, &session).await;
    let r = server
        .post("/wsapi/warrant_respond")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "csrf": c, "code": code, "approve": true,
            "warrants": [warrant.encoded()],
            "config_cert": config_cert.encoded(),
        }))
        .await;
    assert_eq!(r.status_code(), 200, "respond: {:?}", r.text());

    // 4. The agent polls and receives warrant~config_cert (single delivery).
    let r = server.post("/warrant/poll").json(&json!({ "code": code })).await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    let poll: Value = r.json();
    assert_eq!(poll["status"], "approved", "{poll}");
    let tail = poll["grants"][0]["warrant"].as_str().unwrap().to_string();
    assert_eq!(tail, format!("{}~{}", warrant.encoded(), config_cert.encoded()));
    let r = server.post("/warrant/poll").json(&json!({ "code": code })).await;
    assert_ne!(r.status_code(), 200, "single delivery: second poll must fail");

    // 5. Registry: the grant is reviewable on the delegator's account.
    let warrants: Value = server
        .get("/wsapi/warrants")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let w = &warrants["warrants"][0];
    assert_eq!(w["agent_email"], AGENT);
    assert_eq!(w["holder"], "ag.bot");
    assert_eq!(w["config_cert"], config_cert.encoded());

    // 6. Full presentation: mint an access cert with the agent device key,
    //    sign an assertion, splice the delivered tail, verify the join.
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(
        DOMAIN, AGENT, agent_holder.clone(), &access_kp.public_key(), "jti-w1", &agent_kp,
    )
    .unwrap();
    let minted: Value = server
        .post("/access/mint")
        .json(&json!({ "device_cert": agent_cert.encoded(), "access_request": areq.encoded() }))
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
        .expect("agent presentation verifies");
    assert_eq!(verified.email, AGENT);
    assert_eq!(verified.holder, agent_holder);
    assert_eq!(verified.scopes, vec!["post".to_string(), "read".to_string()]);
}

/// The consent-side holder guard (holder-authorization model, stage 3): a signed
/// warrant whose matcher is a bare `*` or a *foreign* holder (one the agent's
/// own holder isn't covered by) must be refused by `respond`, even though the
/// warrant is validly signed for the right identifier + audience.
#[tokio::test]
async fn respond_rejects_overbroad_or_foreign_holder() {
    let (server, sender, idp_kp) = make_server();
    let session = create_user(&server, &sender, DELEGATOR, "testpassword").await;

    let agent_holder = Holder::new("ag.bot").unwrap();
    let agent_kp = KeyPair::generate();
    let agent_cert = DeviceCert::create(
        DOMAIN, &agent_kp.public_key(), Purpose::Authentication, agent_holder.clone(),
        vec![AGENT.to_string()], Duration::days(90), &idp_kp, None,
    )
    .unwrap();
    let config_kp = KeyPair::generate();
    let config_cert = DeviceCert::create(
        DOMAIN, &config_kp.public_key(), Purpose::Authorization, Holder::new("br.main").unwrap(),
        vec![DELEGATOR.to_string(), "alice+*@example.com".to_string()],
        Duration::days(90), &idp_kp, None,
    )
    .unwrap();

    // Raise a request; grab its code + status ref.
    let listed_code = {
        let r = server
            .post("/warrant/request")
            .json(&json!({ "device_cert": agent_cert.encoded(), "identity": AGENT,
                "grants": [{ "audience": AUDIENCE, "scopes": ["post"] }], "label": "bot" }))
            .await;
        assert_eq!(r.status_code(), 200, "request: {:?}", r.text());
        r.json::<Value>()["code"].as_str().unwrap().to_string()
    };
    let listed: Value = server
        .get("/wsapi/warrant_requests")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let grant = &listed["requests"][0]["grants"][0];
    let status_idx = grant["status_idx"].as_u64().unwrap();
    let status_uri = listed["status_uri"].as_str().unwrap().to_string();
    // The request surfaces the agent's holder for the consent page to bind to.
    assert_eq!(listed["requests"][0]["holder"], "ag.bot");
    let c = csrf(&server, &session).await;

    // Helper: sign a warrant with the given matcher and try to respond.
    let attempt = |matcher: &str| {
        let w = Warrant::create(
            AGENT, AGENT, HolderMatcher::new(matcher).unwrap(), AUDIENCE, vec!["post".into()],
            Duration::days(90), &config_kp,
            Some(StatusRef { uri: status_uri.clone(), idx: status_idx }),
        )
        .unwrap();
        server
            .post("/wsapi/warrant_respond")
            .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
            .json(&json!({ "csrf": c, "code": listed_code, "approve": true,
                "warrants": [w.encoded()], "config_cert": config_cert.encoded() }))
    };

    // Bare `*` — over-broad, fungible across all the user's holders.
    assert_ne!(attempt("*").await.status_code(), 200, "bare `*` matcher must be refused");
    // A foreign holder / namespace the agent isn't in.
    assert_ne!(attempt("svc.other").await.status_code(), 200, "foreign `<id>` must be refused");
    assert_ne!(attempt("zz.*").await.status_code(), 200, "foreign `<ns>.*` must be refused");
    // The correct isolated matcher (and its true namespace wildcard) are accepted.
    assert_eq!(attempt("ag.bot").await.status_code(), 200, "the agent's own `<id>` is accepted");
}
