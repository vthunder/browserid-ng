//! End-to-end SDK test: a real broker on a real socket, driven purely over
//! HTTP by the `browserid-agent` SDK — the full l8lw loop: human session →
//! API key → headless provision → local assertion → offline chain verify.

mod common;

use browserid_agent::{AgentError, AgentIdentity};
use browserid_core::BackedAssertion;
use common::{mint_api_key, start_broker};
use serde_json::{json, Value};

const AUDIENCE: &str = "https://api.example.com";

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
