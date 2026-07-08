//! Integration tests for headless agent provisioning (l8lw):
//! browser-minted API keys → REST identity mint → local assertion signing →
//! cryptographic verification against the broker key. No browser, no SMTP.

mod common;

use std::sync::Arc;

use axum_test::TestServer;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::{Assertion, BackedAssertion, Certificate, KeyPair, PublicKey};
use chrono::Duration;
use common::{create_user, MockEmailSender};
use serde_json::{json, Value};

const AUDIENCE: &str = "https://rp.example.com";

/// Test server with agent provisioning enabled; returns the broker public key
/// so tests can verify issued cert chains offline.
fn create_agent_server(quota: usize) -> (TestServer, MockEmailSender, PublicKey) {
    let keypair = KeyPair::generate();
    let broker_pubkey = keypair.public_key();
    let email_sender = Arc::new(MockEmailSender::new());

    let mut state = AppState::new_with_arcs(
        keypair,
        "localhost:3000".to_string(),
        Arc::new(InMemoryUserStore::new()),
        Arc::new(InMemorySessionStore::new()),
        email_sender.clone(),
    );
    state.agent_provisioning_enabled = true;
    state.max_agent_identities_per_user = quota;

    let server = TestServer::new(routes::create_router(Arc::new(state))).unwrap();
    let sender = MockEmailSender { sent: email_sender.sent.clone() };
    (server, sender, broker_pubkey)
}

/// Get the session's CSRF token via /wsapi/session_context
async fn get_csrf(server: &TestServer, session: &str) -> String {
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .await;
    response.json::<Value>()["csrf_token"].as_str().unwrap().to_string()
}

/// Create a human account and mint an API key attributed to it
async fn mint_api_key(
    server: &TestServer,
    email_sender: &MockEmailSender,
    human_email: &str,
) -> String {
    let session = create_user(server, email_sender, human_email, "testpassword").await;
    let csrf = get_csrf(server, &session).await;

    let response = server
        .post("/wsapi/create_agent_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "csrf": csrf, "name": "ci-bot", "parent_email": human_email }))
        .await;
    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);
    let key = body["api_key"].as_str().unwrap().to_string();
    assert!(key.starts_with("bidk_"), "key should be prefixed: {key}");
    key
}

fn pubkey_json(kp: &KeyPair) -> Value {
    json!({ "algorithm": "Ed25519", "publicKey": kp.public_key().to_base64() })
}

/// The flagship round-trip: human session → API key → headless identity mint
/// → locally signed assertion → chain verifies against the broker key, with
/// no browser involvement past the key mint.
#[tokio::test]
async fn test_headless_mint_assert_verify_roundtrip() {
    let (server, email_sender, broker_pubkey) = create_agent_server(5);
    let api_key = mint_api_key(&server, &email_sender, "human@example.com").await;

    // Agent generates and holds its own keypair
    let agent_kp = KeyPair::generate();

    let response = server
        .post("/agent/identities")
        .add_header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "pubkey": pubkey_json(&agent_kp), "name": "attestor" }))
        .await;
    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);
    assert_eq!(body["email"], "attestor@localhost:3000");

    // Agent mints an assertion locally — pure signing, no further HTTP
    let cert = Certificate::parse(body["cert"].as_str().unwrap()).unwrap();
    let assertion = Assertion::create(AUDIENCE, Duration::minutes(5), &agent_kp).unwrap();
    let backed = BackedAssertion::new(cert, assertion);

    // An RP verifying the chain against the issuer key learns just an email
    let email = backed
        .verify(AUDIENCE, |_domain| Ok(broker_pubkey.clone()))
        .unwrap();
    assert_eq!(email, "attestor@localhost:3000");

    // Attribution is recorded issuer-side
    let response = server
        .get("/agent/identities")
        .add_header("authorization", format!("Bearer {api_key}"))
        .await;
    let body: Value = response.json();
    let identities = body["identities"].as_array().unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0]["email"], "attestor@localhost:3000");
    assert_eq!(identities[0]["parent_email"], "human@example.com");
    assert_eq!(identities[0]["active"], true);
}

/// Re-mint via /agent/cert works with a rotated keypair (the API key is the
/// root credential, not the agent keypair), and create is idempotent-ish.
#[tokio::test]
async fn test_remint_and_idempotent_create() {
    let (server, email_sender, broker_pubkey) = create_agent_server(5);
    let api_key = mint_api_key(&server, &email_sender, "human@example.com").await;

    let kp1 = KeyPair::generate();
    let response = server
        .post("/agent/identities")
        .add_header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "pubkey": pubkey_json(&kp1), "name": "bot" }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Re-mint with a fresh keypair
    let kp2 = KeyPair::generate();
    let response = server
        .post("/agent/cert")
        .add_header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "email": "bot@localhost:3000", "pubkey": pubkey_json(&kp2) }))
        .await;
    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    let cert = Certificate::parse(body["cert"].as_str().unwrap()).unwrap();
    let assertion = Assertion::create(AUDIENCE, Duration::minutes(5), &kp2).unwrap();
    let email = BackedAssertion::new(cert, assertion)
        .verify(AUDIENCE, |_| Ok(broker_pubkey.clone()))
        .unwrap();
    assert_eq!(email, "bot@localhost:3000");

    // POSTing the same name again re-provisions instead of erroring
    let response = server
        .post("/agent/identities")
        .add_header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "pubkey": pubkey_json(&kp2), "name": "bot" }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Still one identity, not two
    let response = server
        .get("/agent/identities")
        .add_header("authorization", format!("Bearer {api_key}"))
        .await;
    assert_eq!(response.json::<Value>()["identities"].as_array().unwrap().len(), 1);
}

/// Quota bounds active identities (the sybil limit)
#[tokio::test]
async fn test_quota_enforced() {
    let (server, email_sender, _) = create_agent_server(2);
    let api_key = mint_api_key(&server, &email_sender, "human@example.com").await;

    for name in ["one", "two"] {
        let response = server
            .post("/agent/identities")
            .add_header("authorization", format!("Bearer {api_key}"))
            .json(&json!({ "pubkey": pubkey_json(&KeyPair::generate()), "name": name }))
            .await;
        assert_eq!(response.status_code(), 200);
    }

    let response = server
        .post("/agent/identities")
        .add_header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "pubkey": pubkey_json(&KeyPair::generate()), "name": "three" }))
        .await;
    assert_eq!(response.status_code(), 429);
}

/// Bearer auth: missing, malformed, and revoked keys are all rejected
#[tokio::test]
async fn test_api_key_auth_rejections() {
    let (server, email_sender, _) = create_agent_server(5);
    let human = "human@example.com";
    let session = create_user(&server, &email_sender, human, "testpassword").await;
    let csrf = get_csrf(&server, &session).await;

    let response = server
        .post("/wsapi/create_agent_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": csrf, "name": "ci-bot", "parent_email": human }))
        .await;
    let body: Value = response.json();
    let api_key = body["api_key"].as_str().unwrap().to_string();
    let key_id = body["id"].as_u64().unwrap();

    let mint = |key: String| {
        server
            .post("/agent/identities")
            .add_header("authorization", format!("Bearer {key}"))
            .json(&json!({ "pubkey": pubkey_json(&KeyPair::generate()) }))
    };

    // No auth header at all
    let response = server
        .post("/agent/identities")
        .json(&json!({ "pubkey": pubkey_json(&KeyPair::generate()) }))
        .await;
    assert_eq!(response.status_code(), 401);

    // Wrong secret
    assert_eq!(mint("bidk_not-a-real-key".to_string()).await.status_code(), 401);

    // Works before revocation…
    assert_eq!(mint(api_key.clone()).await.status_code(), 200);

    // …and is dead after
    let csrf = get_csrf(&server, &session).await;
    let response = server
        .post("/wsapi/revoke_agent_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "csrf": csrf, "id": key_id }))
        .await;
    assert_eq!(response.status_code(), 200);
    assert_eq!(mint(api_key).await.status_code(), 401);
}

/// Revoking an identity stops re-mints, and revocation sticks even through
/// the idempotent create path
#[tokio::test]
async fn test_identity_revocation_sticks() {
    let (server, email_sender, _) = create_agent_server(5);
    let api_key = mint_api_key(&server, &email_sender, "human@example.com").await;
    let kp = KeyPair::generate();

    let response = server
        .post("/agent/identities")
        .add_header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "pubkey": pubkey_json(&kp), "name": "doomed" }))
        .await;
    assert_eq!(response.status_code(), 200);

    let response = server
        .post("/agent/identities/revoke")
        .add_header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "email": "doomed@localhost:3000" }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Re-mint fails
    let response = server
        .post("/agent/cert")
        .add_header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "email": "doomed@localhost:3000", "pubkey": pubkey_json(&kp) }))
        .await;
    assert_eq!(response.status_code(), 403);

    // Re-create of the same name fails too — no silent revival
    let response = server
        .post("/agent/identities")
        .add_header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "pubkey": pubkey_json(&kp), "name": "doomed" }))
        .await;
    assert_eq!(response.status_code(), 403);

    // Listed as inactive
    let response = server
        .get("/agent/identities")
        .add_header("authorization", format!("Bearer {api_key}"))
        .await;
    let body: Value = response.json();
    assert_eq!(body["identities"][0]["active"], false);
}

/// The API key must never act on the human's own (non-agent) identities
#[tokio::test]
async fn test_api_key_cannot_touch_human_emails() {
    let (server, email_sender, _) = create_agent_server(5);
    let human = "human@example.com";
    let api_key = mint_api_key(&server, &email_sender, human).await;

    // Certs for the human email via the agent path: invisible → 404
    let response = server
        .post("/agent/cert")
        .add_header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "email": human, "pubkey": pubkey_json(&KeyPair::generate()) }))
        .await;
    assert_eq!(response.status_code(), 404);

    // Same for revocation
    let response = server
        .post("/agent/identities/revoke")
        .add_header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "email": human }))
        .await;
    assert_eq!(response.status_code(), 404);
}

/// Key management requires a session and a matching CSRF token
#[tokio::test]
async fn test_key_management_session_and_csrf() {
    let (server, email_sender, _) = create_agent_server(5);
    let human = "human@example.com";

    // No session
    let response = server
        .post("/wsapi/create_agent_key")
        .json(&json!({ "csrf": "x", "name": "k", "parent_email": human }))
        .await;
    assert_eq!(response.status_code(), 401);

    let session = create_user(&server, &email_sender, human, "testpassword").await;

    // Wrong CSRF
    let response = server
        .post("/wsapi/create_agent_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": "wrong", "name": "k", "parent_email": human }))
        .await;
    assert_eq!(response.status_code(), 403);

    // Parent email not on the account
    let csrf = get_csrf(&server, &session).await;
    let response = server
        .post("/wsapi/create_agent_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": csrf, "name": "k", "parent_email": "other@example.com" }))
        .await;
    assert_eq!(response.status_code(), 404);

    // Happy path, then the key shows in the list without its secret
    let csrf = get_csrf(&server, &session).await;
    let response = server
        .post("/wsapi/create_agent_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": csrf, "name": "k", "parent_email": human }))
        .await;
    assert_eq!(response.status_code(), 200);

    let response = server
        .get("/wsapi/agent_keys")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .await;
    let body: Value = response.json();
    let keys = body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["name"], "k");
    assert_eq!(keys[0]["revoked"], false);
    assert!(keys[0].get("api_key").is_none(), "secret must never be listed");
}

/// An agent identity cannot be the attribution root for another key —
/// attribution must chain to a human identity
#[tokio::test]
async fn test_agent_identity_cannot_parent_a_key() {
    let (server, email_sender, _) = create_agent_server(5);
    let human = "human@example.com";
    let session = create_user(&server, &email_sender, human, "testpassword").await;
    let csrf = get_csrf(&server, &session).await;

    let response = server
        .post("/wsapi/create_agent_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": csrf, "name": "k1", "parent_email": human }))
        .await;
    let api_key = response.json::<Value>()["api_key"].as_str().unwrap().to_string();

    let response = server
        .post("/agent/identities")
        .add_header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "pubkey": pubkey_json(&KeyPair::generate()), "name": "bot" }))
        .await;
    assert_eq!(response.status_code(), 200);

    let csrf = get_csrf(&server, &session).await;
    let response = server
        .post("/wsapi/create_agent_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "csrf": csrf, "name": "k2", "parent_email": "bot@localhost:3000" }))
        .await;
    assert_eq!(response.status_code(), 400);
}

/// With provisioning disabled (the default), every agent surface 404s
#[tokio::test]
async fn test_disabled_by_default() {
    let (server, email_sender) = common::create_test_server();
    let human = "human@example.com";
    let session = create_user(&server, &email_sender, human, "testpassword").await;
    let csrf = get_csrf(&server, &session).await;

    let response = server
        .post("/wsapi/create_agent_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "csrf": csrf, "name": "k", "parent_email": human }))
        .await;
    assert_eq!(response.status_code(), 404);

    let response = server
        .post("/agent/identities")
        .add_header("authorization", "Bearer bidk_whatever")
        .json(&json!({ "pubkey": { "algorithm": "Ed25519", "publicKey": "x" } }))
        .await;
    assert_eq!(response.status_code(), 404);
}

/// Bad desired names are rejected; omitted name gets a generated one
#[tokio::test]
async fn test_name_validation_and_generation() {
    let (server, email_sender, _) = create_agent_server(5);
    let api_key = mint_api_key(&server, &email_sender, "human@example.com").await;

    // (uppercase is normalized to lowercase rather than rejected)
    for bad in ["-bad", "bad-", "has space", "x@y"] {
        let response = server
            .post("/agent/identities")
            .add_header("authorization", format!("Bearer {api_key}"))
            .json(&json!({ "pubkey": pubkey_json(&KeyPair::generate()), "name": bad }))
            .await;
        assert_eq!(response.status_code(), 400, "name {bad:?} should be rejected");
    }

    let response = server
        .post("/agent/identities")
        .add_header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "pubkey": pubkey_json(&KeyPair::generate()) }))
        .await;
    assert_eq!(response.status_code(), 200);
    let email = response.json::<Value>()["email"].as_str().unwrap().to_string();
    assert!(
        email.starts_with("agent-") && email.ends_with("@localhost:3000"),
        "generated identity: {email}"
    );
}
