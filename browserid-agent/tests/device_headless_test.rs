//! DC Phase 7 — the HEADLESS device-cert agent roundtrip.
//!
//! Stands up a real broker (the mock IdP) with a known signing key, has the IdP
//! issue an AGENT DEVICE CERT (purpose=authentication, subject=agent), then
//! drives the SDK's headless path end to end:
//!
//!   agent device cert → signed access request → broker `/access/mint`
//!   → access cert → present `access_cert~assertion~warrant~config_cert`
//!
//! and checks that `browserid_core::device::AccessPresentation::verify` accepts
//! the bundle, with a warrant signed by the user's CONFIG cert.

use std::sync::Arc;

use base64::Engine;
use browserid_agent::{DeviceAgent, DeviceCredential};
use browserid_broker::{
    routes, AppState, ConsoleEmailSender, InMemorySessionStore, InMemoryUserStore,
};
use browserid_core::device::{
    AccessPresentation, DeviceCert, Holder, HolderMatcher, Purpose, Warrant, DEVICE_CERT_VALIDITY_DAYS,
    WARRANT_VALIDITY_DAYS,
};
use browserid_core::{KeyPair, PublicKey};
use chrono::Duration;

/// Boot a broker on a fresh socket and hand back its base URL + signing keypair
/// (the mock IdP key) so the test can mint an agent device cert with it.
async fn start_idp() -> (String, KeyPair, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let domain = format!("127.0.0.1:{}", addr.port());

    let keypair = KeyPair::generate();
    let idp_key = KeyPair::from_seed(&keypair.secret_bytes()[..]).unwrap();

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

    (format!("http://{domain}"), idp_key, domain)
}

fn seed_b64(kp: &KeyPair) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(kp.secret_bytes())
}

#[tokio::test]
async fn headless_device_cert_roundtrip() {
    let (base, idp_key, domain) = start_idp().await;
    let idp_pub: PublicKey = idp_key.public_key();
    let agent_email = "agent@127.0.0.1".to_string(); // subject=agent identity
    let audience = "https://api.example.com";

    // --- IdP issues the agent device cert (what the registrar device-cert
    // approval does after the user authorizes the pairing). ---
    let device_key = KeyPair::generate();
    let agent_device_cert = DeviceCert::create(
        &domain,
        &device_key.public_key(),
        Purpose::Authentication,
        Holder::new("svc.agent").unwrap(),
        vec![agent_email.clone()],
        Duration::days(DEVICE_CERT_VALIDITY_DAYS),
        &idp_key,
        None,
    )
    .unwrap();

    let credential = DeviceCredential {
        device_key: seed_b64(&device_key),
        agent_device_cert: agent_device_cert.encoded().to_string(),
        idp: base.clone(),
    };

    // --- Headless: build the agent, mint an access cert via the broker. ---
    let mut agent = DeviceAgent::new(credential).unwrap();
    assert_eq!(agent.email(), agent_email);
    agent.mint().await.expect("headless mint at /access/mint");

    // --- The user's CONFIG cert (authorization) + a warrant it signs. This is
    // what the warrant consent flow yields: a config-cert-signed device-model
    // warrant + the config cert per audience. ---
    let config_key = KeyPair::generate();
    let config_cert = DeviceCert::create(
        &domain,
        &config_key.public_key(),
        Purpose::Authorization,
        Holder::new("svc.agent").unwrap(),
        vec![agent_email.clone()],
        Duration::days(DEVICE_CERT_VALIDITY_DAYS),
        &idp_key, // config cert MUST be issued by the identity's own IdP
        None,
    )
    .unwrap();
    let warrant = Warrant::create(
        &agent_email,
        HolderMatcher::new("svc.agent").unwrap(),
        audience,
        vec!["post".into(), "read".into()],
        Duration::days(WARRANT_VALIDITY_DAYS),
        &config_key,
        None,
    )
    .unwrap();

    let covered = agent
        .add_grant(warrant.encoded(), config_cert.encoded())
        .unwrap();
    assert_eq!(covered, audience);
    assert_eq!(agent.warranted_audiences(), vec![audience]);

    // --- Present a bundle and verify it with the core verifier. ---
    let bundle = agent.assertion_for(audience).await.unwrap();
    let pres = AccessPresentation::parse(&bundle).unwrap();
    let verified = pres
        .verify(audience, |iss| {
            assert_eq!(iss, domain);
            Ok(idp_pub.clone())
        })
        .expect("core verify accepts the headless bundle");

    assert_eq!(verified.email, agent_email);
    assert_eq!(verified.holder.as_str(), "svc.agent");
    assert_eq!(verified.scopes, vec!["post".to_string(), "read".to_string()]);
    assert_eq!(verified.issuer, domain);
}

#[tokio::test]
async fn assertion_without_warrant_is_refused() {
    let (base, idp_key, domain) = start_idp().await;
    let device_key = KeyPair::generate();
    let agent_device_cert = DeviceCert::create(
        &domain,
        &device_key.public_key(),
        Purpose::Authentication,
        Holder::new("svc.agent").unwrap(),
        vec!["agent@127.0.0.1".into()],
        Duration::days(DEVICE_CERT_VALIDITY_DAYS),
        &idp_key,
        None,
    )
    .unwrap();
    let mut agent = DeviceAgent::new(DeviceCredential {
        device_key: seed_b64(&device_key),
        agent_device_cert: agent_device_cert.encoded().to_string(),
        idp: base,
    })
    .unwrap();
    // No held warrant → assertion_for must refuse (it still minted an access cert).
    assert!(agent.assertion_for("https://api.example.com").await.is_err());
}
