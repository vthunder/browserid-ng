//! Shared test harness: boot a real agent-enabled broker on a socket, and
//! drive the browser-side "create agent key" ceremony to produce an
//! `AgentCredential` — the one human-in-the-loop moment. Everything after is
//! the SDK's headless path.

#![allow(unused)]

use std::sync::Arc;

use browserid_agent::AgentCredential;
use browserid_broker::{
    routes, AppState, ConsoleEmailSender, InMemorySessionStore, InMemoryUserStore,
};
use browserid_core::provisioning::ProvisioningCert;
use browserid_core::{Certificate, KeyPair, PublicKey};
use chrono::Duration;
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

/// Create an account + verified email, get a broker U_cert for a fresh
/// identity key, sign a P_cert delegating to a new provisioning key, and
/// register it — returning an `AgentCredential` where broker == idp (the
/// fallback / broker-rooted case), plus the user identity keypair (the
/// "browser side" that signs warrants) and the session cookie (for tests
/// that drive session-authenticated surfaces like the consent API). This
/// mirrors exactly what the browser key-management page does.
pub async fn make_credential(base: &str) -> (AgentCredential, KeyPair, String) {
    make_credential_email(base, "human@example.com").await
}

/// Like [`make_credential`] but with an explicit human email. Pass a *primary*
/// email (domain == the broker's issuer domain) when the test needs OFFLINE
/// verification (rp::Verifier / core), which is primary-only; the default
/// `human@example.com` exercises the fallback / broker-rooted case (agents are
/// then sub-addressed and verify only via the DNS-aware hosted verifier).
pub async fn make_credential_email(base: &str, email: &str) -> (AgentCredential, KeyPair, String) {
    let http = reqwest::Client::new();

    // Account creation (stage → verify → complete).
    assert!(http
        .post(format!("{base}/wsapi/stage_user"))
        .json(&json!({ "email": email, "pass": "testpassword" }))
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
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
    let complete = http
        .post(format!("{base}/wsapi/complete_user_creation"))
        .json(&json!({ "token": code }))
        .send()
        .await
        .unwrap();
    let session_cookie = complete
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

    // U_cert for a fresh identity key (cert_key, session-authorized).
    let user_kp = KeyPair::generate();
    let cert_body: Value = http
        .post(format!("{base}/wsapi/cert_key"))
        .header("cookie", &session_cookie)
        .json(&json!({
            "csrf": csrf,
            "email": email,
            "pubkey": { "algorithm": "Ed25519", "publicKey": user_kp.public_key().to_base64() },
            "ephemeral": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_cert = Certificate::parse(cert_body["cert"].as_str().unwrap()).unwrap();

    // Delegate to a fresh provisioning key. Constraint covers the fixed names
    // the tests mint plus an `svc+*` pattern for the generated-name path.
    let provisioning_kp = KeyPair::generate();
    let constraint = browserid_core::Constraint {
        names: ["attestor", "worker", "bot"].iter().map(|s| s.to_string()).collect(),
        patterns: vec!["svc+*".into()],
    };
    let p_cert = ProvisioningCert::create(
        email,
        &provisioning_kp.public_key(),
        constraint,
        Duration::days(90),
        &user_kp,
    )
    .unwrap();
    let delegation = format!("{}~{}", user_cert.encoded(), p_cert.encoded());

    let reg: Value = http
        .post(format!("{base}/wsapi/register_provisioning_cert"))
        .header("cookie", &session_cookie)
        .json(&json!({ "csrf": csrf, "label": "sdk-test", "bundle": delegation }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reg["success"], true, "register failed: {reg}");

    (
        AgentCredential {
            secret_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(provisioning_kp.secret_bytes()),
            delegation,
            broker: base.to_string(),
            idp: base.to_string(),
        },
        user_kp,
        session_cookie,
    )
}

use base64::Engine as _;
