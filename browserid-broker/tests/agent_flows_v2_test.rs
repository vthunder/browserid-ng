//! Agent flows v2 (beans t1jp + eywc), end to end over HTTP:
//!
//! 1. The grantor pin on `/warrant/request`: `self` normalizes to the agent
//!    identity, an unsatisfiable pin fails the request immediately, and
//!    `respond` refuses a substituted grantor.
//! 2. An UNKNOWN agent's denial carries the `unknown_agent` machine reason.
//! 3. The two-stage provisioning approval: identity stage mints the cert
//!    (with the user-chosen display name), the grants stage signs the
//!    warrants under the dropdown's grantor, and one poll delivers both.
//!    A later `/warrant/request` from that agent then lists as KNOWN, with
//!    the display name and created date every P card opens with.
//! 4. Declining the grants stage still delivers the credential, with no
//!    grants and a `grants_denied` reason.

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

fn config_cert_for_alice(idp_kp: &KeyPair) -> (KeyPair, DeviceCert) {
    let config_kp = KeyPair::generate();
    let cert = DeviceCert::create(
        DOMAIN, &config_kp.public_key(), Purpose::Authorization, Holder::new("br.main").unwrap(),
        vec![DELEGATOR.to_string(), "alice+*@example.com".to_string()],
        Duration::days(90), idp_kp, None,
    )
    .unwrap();
    (config_kp, cert)
}

/// An IdP-signed agent authentication cert, as paired provisioning issues.
fn agent_cert(idp_kp: &KeyPair, agent: &str, holder: &str) -> (KeyPair, DeviceCert) {
    let kp = KeyPair::generate();
    let cert = DeviceCert::create(
        DOMAIN, &kp.public_key(), Purpose::Authentication, Holder::new(holder).unwrap(),
        vec![agent.to_string()], Duration::days(90), idp_kp, None,
    )
    .unwrap();
    (kp, cert)
}

#[tokio::test]
async fn warrant_request_grantor_pin_and_unknown_agent_reason() {
    let (server, sender, idp_kp) = make_server();
    let session = create_user(&server, &sender, DELEGATOR, "testpassword").await;
    let agent = "alice+bot@example.com";
    let (_akp, acert) = agent_cert(&idp_kp, agent, "ag.bot");
    let (config_kp, config_cert) = config_cert_for_alice(&idp_kp);

    // An unsatisfiable grantor pin fails the REQUEST, not the approval.
    let r = server
        .post("/warrant/request")
        .json(&json!({ "device_cert": acert.encoded(), "identity": agent,
            "grants": [{ "audience": AUDIENCE, "scopes": ["post"] }],
            "grantor": "bob@example.com" }))
        .await;
    assert_ne!(r.status_code(), 200, "unsatisfiable pin must fail immediately");
    assert!(r.text().contains("unsatisfiable grantor pin"), "{}", r.text());

    // `self` normalizes to the agent identity and is exposed to the page.
    let r = server
        .post("/warrant/request")
        .json(&json!({ "device_cert": acert.encoded(), "identity": agent,
            "grants": [{ "audience": AUDIENCE, "scopes": ["post"] }],
            "grantor": "self", "message": "I post your daily summary." }))
        .await;
    assert_eq!(r.status_code(), 200, "request: {:?}", r.text());
    let code = r.json::<Value>()["code"].as_str().unwrap().to_string();

    let listed: Value = server
        .get("/wsapi/warrant_requests")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let req = &listed["requests"][0];
    assert_eq!(req["grantor"], agent, "self pin normalizes to the agent identity");
    assert_eq!(req["message"], "I post your daily summary.");
    assert_eq!(req["known"], false, "this account never met the agent");
    let status_idx = req["grants"][0]["status_idx"].as_u64().unwrap();
    let status_uri = listed["status_uri"].as_str().unwrap().to_string();
    let c = csrf(&server, &session).await;

    // A substituted grantor (on-behalf where the pin demands self) is refused.
    let onbehalf = Warrant::create(
        DELEGATOR, agent, HolderMatcher::new("ag.bot").unwrap(), AUDIENCE, vec!["post".into()],
        Duration::days(90), &config_kp,
        Some(StatusRef { uri: status_uri.clone(), idx: status_idx }),
    )
    .unwrap();
    let r = server
        .post("/wsapi/warrant_respond")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true,
            "warrants": [onbehalf.encoded()], "config_cert": config_cert.encoded(),
            "grantor": DELEGATOR }))
        .await;
    assert_ne!(r.status_code(), 200, "pin substitution must be refused");
    assert!(r.text().contains("pins the grantor"), "{}", r.text());

    // Honoring the pin (grantor == grantee == the agent) approves.
    let selfw = Warrant::create(
        agent, agent, HolderMatcher::new("ag.bot").unwrap(), AUDIENCE, vec!["post".into()],
        Duration::days(90), &config_kp,
        Some(StatusRef { uri: status_uri.clone(), idx: status_idx }),
    )
    .unwrap();
    let r = server
        .post("/wsapi/warrant_respond")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true,
            "warrants": [selfw.encoded()], "config_cert": config_cert.encoded() }))
        .await;
    assert_eq!(r.status_code(), 200, "pin-honoring approval: {:?}", r.text());

    // A denied request from an UNMET agent tells the requester why.
    let r = server
        .post("/warrant/request")
        .json(&json!({ "device_cert": acert.encoded(), "identity": agent,
            "grants": [{ "audience": "https://other.example" }] }))
        .await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    let code2 = r.json::<Value>()["code"].as_str().unwrap().to_string();
    let c = csrf(&server, &session).await;
    let r = server
        .post("/wsapi/warrant_respond")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code2, "approve": false }))
        .await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    let poll: Value = server.post("/warrant/poll").json(&json!({ "code": code2 })).await.json();
    assert_eq!(poll["status"], "denied");
    assert!(
        poll["reason"].as_str().unwrap_or("").contains("unknown_agent"),
        "denied poll carries the unknown-agent reason: {poll}"
    );
}

/// The v2 serial flow under ONE code: identity stage (Flow I) mints the cert
/// with the user-chosen name, the grants stage (Flow P) signs the warrants,
/// the poll delivers both — and the agent is then KNOWN to the account.
#[tokio::test]
async fn two_stage_provision_then_known_agent() {
    let (server, sender, idp_kp) = make_server();
    let session = create_user(&server, &sender, DELEGATOR, "testpassword").await;
    let (config_kp, config_cert) = config_cert_for_alice(&idp_kp);

    // 1. The agent's bundled request: identity + one grant, name + message.
    let device_kp = KeyPair::generate();
    let r = server
        .post("/agent-provision/request")
        .json(&json!({
            "provisioning_pubkey": { "algorithm": "Ed25519",
                "publicKey": device_kp.public_key().to_base64() },
            "requested_handles": { "names": ["alice+bsky"] },
            "grants": [{ "audience": AUDIENCE, "scopes": ["post"] }],
            "label": "Bluesky poster",
            "message": "I'll post your daily summary thread each morning.",
        }))
        .await;
    assert_eq!(r.status_code(), 200, "request: {:?}", r.text());
    let code = r.json::<Value>()["code"].as_str().unwrap().to_string();

    // Info renders the message and the pending stage.
    let info: Value = server.post("/agent-provision/info").json(&json!({ "code": code })).await.json();
    assert_eq!(info["stage"], "pending");
    assert_eq!(info["message"], "I'll post your daily summary thread each morning.");

    // 2. Identity stage: prepare, then complete stage=identity with the name.
    let c = csrf(&server, &session).await;
    let prep: Value = server
        .post("/agent-provision/prepare")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "identity_email": DELEGATOR }))
        .await
        .json();
    assert_eq!(prep["success"], true, "prepare: {prep}");
    let agent_email = prep["agent_email"].as_str().unwrap().to_string();
    let holder = prep["holder"].as_str().unwrap().to_string();
    let status_uri = prep["status_uri"].as_str().unwrap().to_string();
    let status_idx = prep["grants"][0]["status_idx"].as_u64().unwrap();

    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "stage": "identity",
            "identity_email": DELEGATOR, "identity_mode": "handle", "handle": "alice+bsky",
            "display_name": "Bluesky poster", "public_name": "Sky Scribe" }))
        .await;
    assert_eq!(r.status_code(), 200, "identity stage: {:?}", r.text());

    // The agent still waits — the permission screen is with the human.
    let poll: Value = server.post("/agent-provision/poll").json(&json!({ "code": code })).await.json();
    assert_eq!(poll["status"], "pending", "poll stays pending mid-flow: {poll}");

    // A reloaded page resumes: info now names the issued identity + holder.
    let info: Value = server.post("/agent-provision/info").json(&json!({ "code": code })).await.json();
    assert_eq!(info["stage"], "identity_issued");
    assert_eq!(info["agent_email"], agent_email);
    assert_eq!(info["holder"], holder);

    // 3. Grants stage: the dropdown chose on-behalf of the delegator.
    let warrant = Warrant::create(
        DELEGATOR, &agent_email, HolderMatcher::new(&holder).unwrap(), AUDIENCE,
        vec!["post".into()], Duration::days(90), &config_kp,
        Some(StatusRef { uri: status_uri, idx: status_idx }),
    )
    .unwrap();
    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "stage": "grants",
            "grantor": DELEGATOR,
            "warrants": [warrant.encoded()], "config_cert": config_cert.encoded() }))
        .await;
    assert_eq!(r.status_code(), 200, "grants stage: {:?}", r.text());

    // 4. One pickup: credential + grants together.
    let poll: Value = server.post("/agent-provision/poll").json(&json!({ "code": code })).await.json();
    assert_eq!(poll["status"], "completed", "{poll}");
    assert_eq!(poll["credential"]["identity"], agent_email);
    assert!(poll["credential"]["device_cert"].as_str().is_some());
    assert_eq!(poll["grants"][0]["audience"], AUDIENCE);
    assert!(poll.get("grants_denied").is_none());

    // 5. The agent is now KNOWN: a later warrant request opens with the
    //    user-chosen name and the created date (the P card's "who").
    let device_cert = poll["credential"]["device_cert"].as_str().unwrap().to_string();
    let r = server
        .post("/warrant/request")
        .json(&json!({ "device_cert": device_cert, "identity": agent_email,
            "grants": [{ "audience": "https://more.example" }] }))
        .await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    let listed: Value = server
        .get("/wsapi/warrant_requests")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let req = &listed["requests"][0];
    assert_eq!(req["known"], true, "{listed}");
    assert_eq!(req["display_name"], "Bluesky poster");
    assert!(req["agent_created_at"].as_str().is_some(), "{listed}");

    // 6. The PUBLIC byline (bean tmk8): set at approval, served by the open
    //    /public-name lookup, editable via /wsapi/set_public_name, and the
    //    internal display_name never leaks through the public endpoint.
    // `+` is significant in agent subaddresses — percent-encode it, as any
    // URL-building client (encodeURIComponent) would.
    let enc = agent_email.replace('+', "%2B");
    let pn: Value = server.get(&format!("/public-name?identity={enc}")).await.json();
    assert_eq!(pn["public_name"], "Sky Scribe", "{pn}");

    let listed: Value = server
        .get("/wsapi/list_emails")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let names = listed["public_names"].as_array().unwrap();
    assert!(
        names.iter().any(|p| p["email"] == *agent_email && p["public_name"] == "Sky Scribe"),
        "{listed}"
    );

    // Clearing falls back to the email local-part — NOT display_name.
    let r = server
        .post("/wsapi/set_public_name")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "email": agent_email, "public_name": "" }))
        .await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    let pn: Value = server.get(&format!("/public-name?identity={enc}")).await.json();
    let local = agent_email.split('@').next().unwrap();
    assert_eq!(pn["public_name"], local, "cleared byline must fall back to local-part, not display_name: {pn}");

    // An identity nobody registered gets the same shape — no registration oracle.
    let pn: Value = server.get("/public-name?identity=stranger@nowhere.test").await.json();
    assert_eq!(pn["public_name"], "stranger");
}

/// Declining the permission screen after the identity stage: the identity is
/// real and delivered; the grants are not, and the agent is told why.
#[tokio::test]
async fn grants_stage_decline_still_delivers_the_credential() {
    let (server, sender, _idp_kp) = make_server();
    let session = create_user(&server, &sender, DELEGATOR, "testpassword").await;

    let device_kp = KeyPair::generate();
    let r = server
        .post("/agent-provision/request")
        .json(&json!({
            "provisioning_pubkey": { "algorithm": "Ed25519",
                "publicKey": device_kp.public_key().to_base64() },
            "requested_handles": { "names": ["alice+quiet"] },
            "grants": [{ "audience": AUDIENCE, "scopes": ["post"] }],
        }))
        .await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    let code = r.json::<Value>()["code"].as_str().unwrap().to_string();

    let c = csrf(&server, &session).await;
    let prep: Value = server
        .post("/agent-provision/prepare")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "identity_email": DELEGATOR }))
        .await
        .json();
    assert_eq!(prep["success"], true, "{prep}");
    let agent_email = prep["agent_email"].as_str().unwrap().to_string();

    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "stage": "identity",
            "identity_email": DELEGATOR, "identity_mode": "handle", "handle": "alice+quiet" }))
        .await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());

    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": false, "stage": "grants" }))
        .await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());

    let poll: Value = server.post("/agent-provision/poll").json(&json!({ "code": code })).await.json();
    assert_eq!(poll["status"], "completed", "{poll}");
    assert_eq!(poll["credential"]["identity"], agent_email);
    assert!(poll["credential"]["device_cert"].as_str().is_some());
    assert_eq!(poll["grants"].as_array().map(Vec::len), Some(0), "{poll}");
    assert!(
        poll["grants_denied"].as_str().unwrap_or("").contains("declined"),
        "the agent learns the grants were declined: {poll}"
    );
}
