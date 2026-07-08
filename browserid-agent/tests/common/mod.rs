//! Shared test harness: boot a real agent-enabled broker on a socket and
//! drive the one human-in-the-loop moment (account + API key) over HTTP.

#![allow(unused)]

use std::sync::Arc;

use browserid_broker::{
    routes, AppState, ConsoleEmailSender, InMemorySessionStore, InMemoryUserStore,
};
use browserid_core::{KeyPair, PublicKey};
use serde_json::{json, Value};

/// Start a real broker on 127.0.0.1:0 with agent provisioning enabled.
/// Returns (base_url, broker public key).
pub async fn start_broker() -> (String, PublicKey) {
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
pub async fn mint_api_key(base: &str) -> String {
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
