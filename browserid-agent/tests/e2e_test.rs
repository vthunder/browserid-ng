//! End-to-end SDK test (tdxf): a real broker on a socket, driven over HTTP by
//! the `browserid-agent` SDK — the full delegation-chain loop: browser
//! registers a provisioning cert → agent endorses + mints → local assertion →
//! offline chain verify → persist → revoke.

mod common;

use browserid_agent::{AgentError, AgentIdentity};
use browserid_core::{BackedAssertion, Certificate, Warrant};
use chrono::Duration;
use common::{make_credential, start_broker};

const AUDIENCE: &str = "https://api.example.com";

#[tokio::test]
async fn sdk_provision_assert_verify_persist_revoke() {
    let (base, broker_pubkey) = start_broker().await;
    let (credential, user_kp, _session) = make_credential(&base).await;

    // Provision: SDK generates+keeps the agent keypair; endorse→mint yields a cert.
    let mut agent = AgentIdentity::provision(&credential, Some("attestor")).await.unwrap();
    assert!(agent.email().starts_with("attestor@127.0.0.1:"));

    // v0.4: an agent cert only presents with a user-signed warrant (§5.3).
    // Un-warranted audiences fail closed at the SDK.
    match agent.assertion_for(AUDIENCE).await {
        Err(AgentError::NoWarrant { .. }) => {}
        other => panic!("expected NoWarrant before a warrant is added, got {other:?}"),
    }
    let (u, _) = credential.delegation.split_once('~').unwrap();
    let parent_cert = Certificate::parse(u).unwrap();
    let warrant = Warrant::create(
        &parent_cert,
        agent.email(),
        AUDIENCE,
        Some(vec!["post".into()]),
        Duration::days(30),
        &user_kp,
    )
    .unwrap();
    agent.add_warrant(warrant.encoded()).unwrap();

    // Local assertion → offline chain verification against the broker key.
    let assertion = agent.assertion_for(AUDIENCE).await.unwrap();
    let verified = BackedAssertion::parse(&assertion)
        .unwrap()
        .verify(AUDIENCE, |_| Ok(broker_pubkey.clone()))
        .unwrap();
    assert_eq!(verified.email, agent.email());
    let attribution = verified.agent.expect("agent attribution");
    assert_eq!(attribution.parent, "human@example.com");
    assert_eq!(attribution.scopes, vec!["post"]);

    // Explicit re-mint (endorse→mint again, keypair unchanged) still verifies.
    agent.remint().await.unwrap();
    let assertion = agent.assertion_for(AUDIENCE).await.unwrap();
    BackedAssertion::parse(&assertion)
        .unwrap()
        .verify(AUDIENCE, |_| Ok(broker_pubkey.clone()))
        .unwrap();

    // Persistence: save (no credential inside), load, keep asserting.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.json");
    agent.save(&path).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(!contents.contains(&credential.secret_key), "credential must not be persisted");

    let mut restored = AgentIdentity::load(&path, &credential).unwrap();
    assert_eq!(restored.email(), agent.email());
    let assertion = restored.assertion_for(AUDIENCE).await.unwrap();
    BackedAssertion::parse(&assertion)
        .unwrap()
        .verify(AUDIENCE, |_| Ok(broker_pubkey.clone()))
        .unwrap();

    // Revoke, then re-minting through the restored copy fails at the IdP.
    agent.revoke().await.unwrap();
    match restored.remint().await {
        Err(AgentError::Idp { status: 403, .. }) => {}
        other => panic!("expected 403 after revocation, got {other:?}"),
    }
}

#[tokio::test]
async fn sdk_unregistered_credential_is_rejected() {
    let (base, _) = start_broker().await;
    // A credential the broker never registered: build it against a made-up
    // delegation. The broker refuses to endorse (404), surfaced as an Endorse
    // error.
    let (other_base, _) = start_broker().await;
    let (credential, _, _) = make_credential(&other_base).await; // registered at a DIFFERENT broker
    let credential = browserid_agent::AgentCredential {
        broker: base.clone(), // point endorsement at a broker that doesn't know it
        idp: base,
        ..credential
    };
    match AgentIdentity::provision(&credential, Some("x")).await {
        Err(AgentError::Endorse { status: 404, .. }) => {}
        other => panic!("expected 404 endorse refusal, got {other:?}"),
    }
}
