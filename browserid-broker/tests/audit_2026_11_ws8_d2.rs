//! WS8 PoC — D2, now a regression test (bean 0fy3): consent `respond` used
//! to accept a config cert that the broker never signed. `validate_grant_warrants`
//! parsed the config cert and checked only purpose + `authorizes_identity(grantor)`
//! + that the warrant was signed by that same cert's key — never the cert
//! against the account's IdP key, that it is enrolled on the account, or its
//! status. So a fully self-minted (attacker-keyed) config cert was accepted.
//! Since the fix the shared `recorded_config_cert` bar refuses it and the
//! forged grant never reaches the filer. Full HTTP flow against an
//! in-process broker. No production host.
mod common;

use std::sync::Arc;

use axum_test::TestServer;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::device::{DeviceCert, Holder, HolderMatcher, Purpose, Warrant};
use browserid_core::{KeyPair, StatusRef};
use chrono::Duration;
use common::{create_user, MockEmailSender};
use serde_json::{json, Value};

const DOMAIN: &str = "localhost:3000";
const DELEGATOR: &str = "alice@example.com";
const AUDIENCE: &str = "https://api.bsky.example";

fn make_server() -> (TestServer, MockEmailSender, KeyPair) {
    let keypair = KeyPair::generate();
    let email_sender = Arc::new(MockEmailSender::new());
    let mut state = AppState::new_with_arcs(
        keypair.clone(), DOMAIN.to_string(),
        Arc::new(InMemoryUserStore::new()), Arc::new(InMemorySessionStore::new()),
        email_sender.clone(),
    );
    state.agent_provisioning_enabled = true;
    let server = TestServer::new(routes::create_router(Arc::new(state))).unwrap();
    (server, MockEmailSender { sent: email_sender.sent.clone() }, keypair)
}

#[tokio::test]
async fn d2_poc_respond_refuses_a_self_minted_config_cert() {
    let (server, sender, idp_kp) = make_server();
    let session = create_user(&server, &sender, DELEGATOR, "testpassword").await;
    let sess = common::registry::api_login(&server, &session, "testpassword").await;
    let agent = "alice+bot@example.com";

    // The agent's auth cert IS legitimately IdP-signed (as provisioning issues).
    let agent_kp = KeyPair::generate();
    let acert = DeviceCert::create(
        DOMAIN, &agent_kp.public_key(), Purpose::Authentication,
        Holder::new("ag.bot").unwrap(), vec![agent.to_string()],
        Duration::days(90), &idp_kp, None,
    ).unwrap();

    // File a request for a self-grant (grantor == grantee == agent).
    let r = common::registry::warrant_request(&server, DOMAIN, &agent_kp, json!({ "device_cert": acert.encoded(), "identity": agent,
            "grants": [{ "audience": AUDIENCE, "scopes": ["post"] }], "grantor": "self" }))
        .await;
    assert_eq!(r.status_code(), 200, "request: {:?}", r.text());
    let code = r.json::<Value>()["code"].as_str().unwrap().to_string();

    let listed: Value = common::registry::api_get(&server, &sess, "/api/v1/requests").await.json();
    let req = &listed["requests"][0];
    let status_idx = req["grants"][0]["status_idx"].as_u64().unwrap();
    let status_uri = listed["status_uri"].as_str().unwrap().to_string();

    // THE ATTACK: a config cert the broker NEVER signed. Signed by a key the
    // attacker generated; `iss` is just a string. It claims authority over the
    // agent identity, and signs the warrant.
    let attacker_kp = KeyPair::generate();
    let forged_config = DeviceCert::create(
        DOMAIN, &attacker_kp.public_key(), Purpose::Authorization,
        Holder::new("br.main").unwrap(), vec![agent.to_string(), "alice+*@example.com".into()],
        Duration::days(90),
        &attacker_kp,           // <-- self-signed, NOT idp_kp
        None,
    ).unwrap();
    // Sanity: this cert is NOT signed by the broker's real IdP key.
    assert!(forged_config.verify(&idp_kp.public_key()).is_err(),
        "the forged config cert is not IdP-signed");

    let warrant = Warrant::create(
        agent, agent, HolderMatcher::new("ag.bot").unwrap(), AUDIENCE, vec!["post".into()],
        Duration::days(90), &attacker_kp,
        Some(StatusRef { uri: status_uri.clone(), idx: status_idx }),
    ).unwrap();

    let r = common::registry::api_post(&server, &sess, "/api/v1/requests/respond",
        json!({ "code": code, "approve": true,
            "warrants": [warrant.encoded()], "config_cert": forged_config.encoded() }))
        .await;
    println!("[D2] respond status = {} body = {}", r.status_code(), r.text());
    assert_eq!(r.status_code(), 422, "respond accepted a config cert the broker never signed: {}", r.text());
    assert_eq!(r.json::<Value>()["reason"], "config_cert_invalid", "{}", r.text());

    // And nothing is delivered to the agent: the request is still pending.
    let poll: Value = server.post("/warrant/poll").json(&json!({ "code": code })).await.json();
    println!("[D2] poll status = {}", poll["status"]);
    assert_ne!(poll["status"], "approved", "the forged-config grant was delivered");
}
