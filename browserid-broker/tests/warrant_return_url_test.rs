//! The consent flow's `return_url` (MCP gateway M1, bean b6pp): a warrant
//! request may carry where the consent page should bounce the browser after
//! resolution. The registrar ORIGIN-VALIDATES it up front — the URL must
//! belong to the requesting service (its identity's domain, or a requested
//! grant audience's origin) or the whole request is refused — persists it on
//! the pending request, and echoes it back on `/wsapi/warrant_respond` so the
//! page only ever navigates somewhere server-validated.

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
const AGENT: &str = "alice+gate@example.com";
const AUDIENCE: &str = "https://mcp.example.com";
const RETURN_URL: &str = "https://mcp.example.com/authorize/return?st=abc123";

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

/// The agent's IdP-signed authentication cert + the browser's config cert,
/// as `agent_warrant_request_consent_poll_and_full_presentation` builds them.
fn certs(idp_kp: &KeyPair) -> (DeviceCert, KeyPair, DeviceCert, KeyPair) {
    let agent_kp = KeyPair::generate();
    let agent_cert = DeviceCert::create(
        DOMAIN, &agent_kp.public_key(), Purpose::Authentication, Holder::new("ag.gate").unwrap(),
        vec![AGENT.to_string()], Duration::days(90), idp_kp, None,
    )
    .unwrap();
    let config_kp = KeyPair::generate();
    let config_cert = DeviceCert::create(
        DOMAIN, &config_kp.public_key(), Purpose::Authorization, Holder::new("br.main").unwrap(),
        vec![DELEGATOR.to_string(), "alice+*@example.com".to_string()],
        Duration::days(90), idp_kp, None,
    )
    .unwrap();
    (agent_cert, agent_kp, config_cert, config_kp)
}

/// Raise a warrant request; returns the HTTP response.
async fn raise(server: &TestServer, agent_cert: &DeviceCert, return_url: Option<&str>) -> axum_test::TestResponse {
    let mut body = json!({
        "device_cert": agent_cert.encoded(),
        "identity": AGENT,
        "grants": [{ "audience": AUDIENCE, "scopes": ["tool:read_file"] }],
        "label": "gateway",
    });
    if let Some(u) = return_url {
        body["return_url"] = json!(u);
    }
    server.post("/warrant/request").json(&body).await
}

/// Approve the (single) pending request as the delegator; returns the
/// respond-response JSON.
async fn approve(
    server: &TestServer,
    session: &str,
    code: &str,
    config_kp: &KeyPair,
    config_cert: &DeviceCert,
) -> Value {
    let listed: Value = server
        .get("/wsapi/warrant_requests")
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .await
        .json();
    let req0 = listed["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["code"] == code)
        .expect("request listed")
        .clone();
    let status_idx = req0["grants"][0]["status_idx"].as_u64().unwrap();
    let status_uri = listed["status_uri"].as_str().unwrap().to_string();
    let warrant = Warrant::create(
        AGENT, AGENT, HolderMatcher::new("ag.gate").unwrap(), AUDIENCE,
        vec!["tool:read_file".into()], Duration::days(90), config_kp,
        Some(StatusRef { uri: status_uri, idx: status_idx }),
    )
    .unwrap();
    let c = csrf(server, session).await;
    let r = server
        .post("/wsapi/warrant_respond")
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .json(&json!({
            "csrf": c, "code": code, "approve": true,
            "warrants": [warrant.encoded()],
            "config_cert": config_cert.encoded(),
        }))
        .await;
    assert_eq!(r.status_code(), 200, "respond: {:?}", r.text());
    r.json()
}

/// Happy path: a return_url whose origin matches the requested audience is
/// accepted, persisted, and echoed on approval — and the warrant still
/// delivers over the normal poll.
#[tokio::test]
async fn return_url_persisted_and_echoed_on_approval() {
    let (server, sender, idp_kp) = make_server();
    let session = create_user(&server, &sender, DELEGATOR, "testpassword").await;
    let (agent_cert, _agent_kp, config_cert, config_kp) = certs(&idp_kp);

    let r = raise(&server, &agent_cert, Some(RETURN_URL)).await;
    assert_eq!(r.status_code(), 200, "request: {:?}", r.text());
    let code = r.json::<Value>()["code"].as_str().unwrap().to_string();

    let resolved = approve(&server, &session, &code, &config_kp, &config_cert).await;
    assert_eq!(resolved["success"], true);
    assert_eq!(
        resolved["return_url"].as_str(),
        Some(RETURN_URL),
        "respond echoes the validated return_url: {resolved}"
    );

    // The warrant still delivers to the agent (the return_url changes nothing
    // on the poll side).
    let poll: Value = server.post("/warrant/poll").json(&json!({ "code": code })).await.json();
    assert_eq!(poll["status"], "approved", "{poll}");
    assert!(poll["grants"][0]["warrant"].as_str().unwrap().contains('~'));
}

/// A request without a return_url responds without one (no field at all).
#[tokio::test]
async fn no_return_url_means_none_echoed() {
    let (server, sender, idp_kp) = make_server();
    let session = create_user(&server, &sender, DELEGATOR, "testpassword").await;
    let (agent_cert, _agent_kp, config_cert, config_kp) = certs(&idp_kp);

    let r = raise(&server, &agent_cert, None).await;
    assert_eq!(r.status_code(), 200, "request: {:?}", r.text());
    let code = r.json::<Value>()["code"].as_str().unwrap().to_string();

    let resolved = approve(&server, &session, &code, &config_kp, &config_cert).await;
    assert_eq!(resolved["success"], true);
    assert!(resolved.get("return_url").is_none(), "{resolved}");
}

/// The open-redirect guard: a return_url on a foreign origin — neither the
/// requesting identity's domain nor a requested audience's origin — refuses
/// the whole request up front.
#[tokio::test]
async fn foreign_return_url_is_refused() {
    let (server, sender, idp_kp) = make_server();
    let _session = create_user(&server, &sender, DELEGATOR, "testpassword").await;
    let (agent_cert, _agent_kp, _config_cert, _config_kp) = certs(&idp_kp);

    for bad in [
        "https://evil.example/phish",
        // Host-suffix spoof of the audience.
        "https://mcp.example.com.evil.example/x",
        // Userinfo spoof.
        "https://mcp.example.com@evil.example/x",
        // Scheme downgrade of the audience origin (non-localhost http).
        "http://mcp.example.com/authorize/return",
        // Not a web URL at all.
        "javascript:alert(1)",
    ] {
        let r = raise(&server, &agent_cert, Some(bad)).await;
        assert_ne!(r.status_code(), 200, "return_url {bad} must be refused");
    }
}

/// The identity-domain rule: a return_url on the requesting identity's own
/// domain is accepted even when no audience matches (§6.6 foreign-service
/// shape).
#[tokio::test]
async fn identity_domain_return_url_is_accepted() {
    let (server, sender, idp_kp) = make_server();
    let _session = create_user(&server, &sender, DELEGATOR, "testpassword").await;
    let (agent_cert, _agent_kp, _config_cert, _config_kp) = certs(&idp_kp);

    // AGENT is alice+gate@example.com — example.com is the identity domain.
    let r = raise(&server, &agent_cert, Some("https://example.com/agents/return")).await;
    assert_eq!(r.status_code(), 200, "identity-domain return_url: {:?}", r.text());
}

/// A denial echoes the validated return_url too (the page offers a manual
/// return link; it never auto-navigates on deny).
#[tokio::test]
async fn denial_echoes_return_url() {
    let (server, sender, idp_kp) = make_server();
    let session = create_user(&server, &sender, DELEGATOR, "testpassword").await;
    let (agent_cert, _agent_kp, _config_cert, _config_kp) = certs(&idp_kp);

    let r = raise(&server, &agent_cert, Some(RETURN_URL)).await;
    assert_eq!(r.status_code(), 200, "request: {:?}", r.text());
    let code = r.json::<Value>()["code"].as_str().unwrap().to_string();

    let c = csrf(&server, &session).await;
    let r = server
        .post("/wsapi/warrant_respond")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": false }))
        .await;
    assert_eq!(r.status_code(), 200, "deny: {:?}", r.text());
    let resolved: Value = r.json();
    assert_eq!(resolved["return_url"].as_str(), Some(RETURN_URL), "{resolved}");

    let poll: Value = server.post("/warrant/poll").json(&json!({ "code": code })).await.json();
    assert_eq!(poll["status"], "denied", "{poll}");
}
