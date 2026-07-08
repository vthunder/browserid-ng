//! End-to-end SDK test: a real broker on a real socket, driven purely over
//! HTTP by the `browserid-agent` SDK — the full l8lw loop: human session →
//! API key → headless provision → local assertion → offline chain verify.

use std::sync::Arc;

use browserid_agent::{AgentError, AgentIdentity};
use browserid_broker::{
    routes, AppState, ConsoleEmailSender, InMemorySessionStore, InMemoryUserStore,
};
use browserid_core::{BackedAssertion, KeyPair, PublicKey};
use serde_json::{json, Value};

const AUDIENCE: &str = "https://api.example.com";

/// Start a real broker on 127.0.0.1:0 with agent provisioning enabled.
/// Returns (base_url, broker public key).
async fn start_broker() -> (String, PublicKey) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let domain = format!("127.0.0.1:{}", addr.port());

    let keypair = KeyPair::generate();
    let broker_pubkey = keypair.public_key();

    let mut state = AppState::new_with_arcs(
        keypair,
        domain.clone(),
        Arc::new(InMemoryUserStore::new()),
        Arc::new(InMemorySessionStore::new()),
        Arc::new(ConsoleEmailSender::new()),
    );
    state.agent_provisioning_enabled = true;

    let app = routes::create_router(Arc::new(state));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{domain}"), broker_pubkey)
}

/// Drive the one human-in-the-loop moment over plain HTTP: create an account
/// and mint an API key. Everything after this is the SDK's headless path.
async fn mint_api_key(base: &str) -> String {
    let http = reqwest::Client::new();
    let email = "human@example.com";

    let response = http
        .post(format!("{base}/wsapi/stage_user"))
        .json(&json!({ "email": email, "pass": "testpassword" }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    let code = http
        .get(format!("{base}/wsapi/test/pending_verification?email={email}"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["code"]
        .as_str()
        .unwrap()
        .to_string();

    let response = http
        .post(format!("{base}/wsapi/complete_user_creation"))
        .json(&json!({ "token": code }))
        .send()
        .await
        .unwrap();
    let session_cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let csrf = http
        .get(format!("{base}/wsapi/session_context"))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string();

    let body = http
        .post(format!("{base}/wsapi/create_agent_key"))
        .header("cookie", &session_cookie)
        .json(&json!({ "csrf": csrf, "name": "sdk-test", "parent_email": email }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(body["success"], true, "key mint failed: {body}");
    body["api_key"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn sdk_provision_assert_verify_persist_revoke() {
    let (base, broker_pubkey) = start_broker().await;
    let api_key = mint_api_key(&base).await;

    // Provision: the SDK generates and keeps the keypair, the IdP certifies it
    let mut agent = AgentIdentity::provision(&base, &api_key, Some("attestor"))
        .await
        .unwrap();
    assert!(agent.email().starts_with("attestor@127.0.0.1:"));

    // Local assertion → offline chain verification against the broker key
    let assertion = agent.assertion_for(AUDIENCE).await.unwrap();
    let backed = BackedAssertion::parse(&assertion).unwrap();
    let verified = backed
        .verify(AUDIENCE, |_| Ok(broker_pubkey.clone()))
        .unwrap();
    assert_eq!(verified, agent.email());

    // Explicit re-mint (keypair unchanged) still verifies
    agent.remint().await.unwrap();
    let assertion = agent.assertion_for(AUDIENCE).await.unwrap();
    let verified = BackedAssertion::parse(&assertion)
        .unwrap()
        .verify(AUDIENCE, |_| Ok(broker_pubkey.clone()))
        .unwrap();
    assert_eq!(verified, agent.email());

    // Persistence round-trip: save (no API key inside), load, keep asserting
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.json");
    agent.save(&path).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(!contents.contains(&api_key), "API key must not be persisted");

    let mut restored = AgentIdentity::load(&path, &api_key).unwrap();
    assert_eq!(restored.email(), agent.email());
    let assertion = restored.assertion_for(AUDIENCE).await.unwrap();
    BackedAssertion::parse(&assertion)
        .unwrap()
        .verify(AUDIENCE, |_| Ok(broker_pubkey.clone()))
        .unwrap();

    // Revoke, then re-minting through the restored copy fails at the IdP
    agent.revoke().await.unwrap();
    match restored.remint().await {
        Err(AgentError::Idp { status: 403, .. }) => {}
        other => panic!("expected 403 after revocation, got {other:?}"),
    }
}

#[tokio::test]
async fn sdk_bad_api_key_is_rejected() {
    let (base, _) = start_broker().await;
    match AgentIdentity::provision(&base, "bidk_not-real", None).await {
        Err(AgentError::Idp { status: 401, .. }) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}
