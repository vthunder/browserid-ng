//! Merged one-approval provisioning, driven by the SDK end to end over HTTP:
//! `request_provision` (pubkey + handle + namespace + grants) → the approval
//! page (simulated here: session + `prepare` + client-signed warrant +
//! `complete`) → `wait()` returns the device credential AND the warrant in one
//! pickup → `into_agent()` yields a `DeviceAgent` whose 4-object presentation
//! verifies.

use std::sync::{Arc, RwLock};

use browserid_agent::{request_provision, GrantRequest};
use browserid_broker::{
    routes, AppState, EmailSender, InMemorySessionStore, InMemoryUserStore,
};
use browserid_core::device::{
    AccessPresentation, DeviceCert, Holder, HolderMatcher, Purpose, Warrant,
};
use browserid_core::{KeyPair, StatusRef};
use chrono::Duration;
use serde_json::{json, Value};

const DELEGATOR: &str = "alice@example.com";
const AGENT: &str = "alice+poster@example.com";
const AUDIENCE: &str = "sbo+raw://avail:turing:506/";

/// Captures verification codes so the test can complete user creation.
#[derive(Default)]
struct MockEmailSender {
    sent: RwLock<Vec<(String, String)>>,
}
impl EmailSender for MockEmailSender {
    fn send_verification(&self, email: &str, code: &str) -> Result<(), String> {
        self.sent.write().unwrap().push((email.to_string(), code.to_string()));
        Ok(())
    }
    fn send_password_reset(&self, email: &str, code: &str) -> Result<(), String> {
        self.sent.write().unwrap().push((email.to_string(), code.to_string()));
        Ok(())
    }
}

async fn start_broker() -> (String, KeyPair, Arc<MockEmailSender>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let domain = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let keypair = KeyPair::generate();
    let idp_key = KeyPair::from_seed(&keypair.secret_bytes()[..]).unwrap();
    let sender = Arc::new(MockEmailSender::default());
    let mut state = AppState::new_with_arcs(
        keypair,
        domain.clone(),
        Arc::new(InMemoryUserStore::new()),
        Arc::new(InMemorySessionStore::new()),
        sender.clone(),
    );
    state.agent_provisioning_enabled = true;
    let app = routes::create_router(Arc::new(state));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{domain}"), idp_key, sender)
}

/// The signed-in browser: create the account via the unified sign-in code
/// lane (stage_user retired in 8gqm), then authenticate — completion mints
/// no session, the password login does.
async fn create_user(base: &str, sender: &MockEmailSender, http: &reqwest::Client) -> String {
    let r = http
        .post(format!("{base}/wsapi/stage_signin_code"))
        .json(&json!({ "email": DELEGATOR, "pass": "testpassword" }))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "stage_signin_code: {}", r.status());
    let code = sender
        .sent
        .read()
        .unwrap()
        .iter()
        .rev()
        .find(|(e, _)| e == DELEGATOR)
        .map(|(_, c)| c.clone())
        .expect("verification code sent");
    let r = http
        .post(format!("{base}/wsapi/complete_signin_code"))
        .json(&json!({ "email": DELEGATOR, "token": code }))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "complete_signin_code: {}", r.status());
    let r = http
        .post(format!("{base}/wsapi/authenticate_user"))
        .json(&json!({ "email": DELEGATOR, "pass": "testpassword" }))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "authenticate_user: {}", r.status());
    // (reqwest's cookie feature is off — read the Set-Cookie header directly)
    r.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| {
            v.strip_prefix("browserid_session=")
                .map(|rest| rest.split(';').next().unwrap_or(rest).to_string())
        })
        .expect("session cookie")
}

#[tokio::test]
async fn sdk_merged_provision_roundtrip() {
    let (base, idp_key, sender) = start_broker().await;
    let http = reqwest::Client::new();
    let session = create_user(&base, &sender, &http).await;
    let cookie = format!("browserid_session={session}");

    // 1. The service (SDK side) starts pairing with a bundled grant.
    let pending = request_provision(
        &base,
        Some("alice+poster"),
        Some("services"),
        &[GrantRequest { audience: AUDIENCE.into(), scopes: vec!["action:post".into()] }],
        Some("mingo poster"),
        None,
        None,
    )
    .await
    .expect("request_provision");
    assert!(pending.verification_uri_complete.contains(&pending.code));

    // 2. The approval page (simulated): csrf → prepare → sign → complete.
    let csrf = http
        .get(format!("{base}/wsapi/session_context"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string();
    let prep: Value = http
        .post(format!("{base}/agent-provision/prepare"))
        .header("cookie", &cookie)
        .json(&json!({ "csrf": csrf, "code": pending.code, "identity_email": DELEGATOR }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prep["success"], true, "prepare: {prep}");
    assert_eq!(prep["agent_email"], AGENT);
    let holder = prep["holder"].as_str().unwrap().to_string();
    let status_uri = prep["status_uri"].as_str().unwrap().to_string();
    let status_idx = prep["grants"][0]["status_idx"].as_u64().unwrap();

    // The browser's config cert (deposited at login) signs the warrant.
    let config_kp = KeyPair::generate();
    let config_cert = DeviceCert::create(
        &base.trim_start_matches("http://"), &config_kp.public_key(), Purpose::Authorization,
        Holder::new("br.main").unwrap(),
        vec![DELEGATOR.to_string(), "alice+*@example.com".to_string()],
        Duration::days(90), &idp_key, None,
    )
    .unwrap();
    // The page signs grantor = the APPROVING identity, grantee = the agent —
    // a named agent acts ON BEHALF OF the human who approved it. (It used to
    // sign AGENT for both, which made the on-behalf shape unreachable; the
    // registrar now rejects that mismatch. Bean browserid-ng-8v6c.)
    let warrant = Warrant::create(
        DELEGATOR, AGENT, HolderMatcher::new(&holder).unwrap(), AUDIENCE, vec!["action:post".into()],
        Duration::days(90), &config_kp,
        Some(StatusRef { uri: status_uri, idx: status_idx }),
    )
    .unwrap();
    let r: Value = http
        .post(format!("{base}/agent-provision/complete"))
        .header("cookie", &cookie)
        .json(&json!({
            "csrf": csrf, "code": pending.code, "approve": true,
            "identity_email": DELEGATOR,
            "warrants": [warrant.encoded()], "config_cert": config_cert.encoded(),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["success"], true, "complete: {r}");

    // 3. One pickup: credential + grant; the agent presents end to end.
    let provisioned = pending.wait().await.expect("wait");
    assert_eq!(provisioned.grants.len(), 1);
    assert_eq!(provisioned.grants[0].0, AUDIENCE);
    let mut agent = provisioned.into_agent().expect("into_agent");
    assert_eq!(agent.email(), AGENT);
    let bundle = agent.assertion_for(AUDIENCE).await.expect("assertion_for");
    let verified = AccessPresentation::parse(&bundle)
        .unwrap()
        .verify(AUDIENCE, |_| Ok(idp_key.public_key()))
        .expect("presentation verifies");
    // The two roles the core has always modelled, now actually distinct: the
    // write is ATTRIBUTED to the human who approved, and the ACTOR of record is
    // the agent that signed.
    assert_eq!(verified.email, DELEGATOR, "attributed to the approving identity");
    assert_eq!(verified.grantee, AGENT, "acted by the agent");
    assert_eq!(verified.holder.as_str(), holder);
    assert_eq!(verified.scopes, vec!["action:post".to_string()]);
}
