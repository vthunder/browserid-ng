//! Integration tests for external warrant requests (agent spec §6.6, the
//! mingo-poster shape): a service agent certified by a *foreign* IdP posts
//! `agent_cert~R` to `/warrant/request` at the delegator's registrar; the
//! delegator approves on the redirect-tied `/consent/<code>` page; the
//! service polls the signed warrant. Discovery of the foreign issuer's key
//! is injected via `issuer_resolver_override`.

mod common;

use std::sync::Arc;

use axum_test::TestServer;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::provisioning::{ProvisioningRequest, WarrantGrant};
use browserid_core::{Certificate, KeyPair, PublicKey, Warrant};
use chrono::Duration;
use common::{create_user, MockEmailSender};
use serde_json::{json, Value};

const DOMAIN: &str = "localhost:3000";
const SERVICE_IDP: &str = "mingo.place";
const AGENT_EMAIL: &str = "mingo-poster@mingo.place";
const DELEGATOR: &str = "dan@example.com";
const AUDIENCE: &str = "sbo://mingo";

/// Test resolver: "discovery" that hands back the fixed foreign-IdP key.
struct FixedResolver(PublicKey);

impl browserid_registrar::IssuerKeyResolver for FixedResolver {
    fn resolve_issuer_key<'a>(
        &'a self,
        _domain: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<PublicKey, browserid_registrar::RegistrarError>,
                > + Send
                + 'a,
        >,
    > {
        let key = self.0.clone();
        Box::pin(async move { Ok(key) })
    }
}

fn create_server(service_idp_pub: &PublicKey) -> (TestServer, MockEmailSender) {
    let email_sender = Arc::new(MockEmailSender::new());
    let mut state = AppState::new_with_arcs(
        KeyPair::generate(),
        DOMAIN.to_string(),
        Arc::new(InMemoryUserStore::new()),
        Arc::new(InMemorySessionStore::new()),
        email_sender.clone(),
    );
    state.agent_provisioning_enabled = true;
    state.issuer_resolver_override = Some(Arc::new(FixedResolver(service_idp_pub.clone())));
    let server = TestServer::new(routes::create_router(Arc::new(state))).unwrap();
    (server, MockEmailSender { sent: email_sender.sent.clone() })
}

/// The service side: mint a per-delegator agent cert with the foreign IdP
/// key and sign the external request with the agent identity key.
fn external_bundle(
    service_idp: &KeyPair,
    agent_kp: &KeyPair,
    delegator: &str,
    grants: Vec<WarrantGrant>,
) -> String {
    let agent_cert = Certificate::create_agent(
        SERVICE_IDP,
        AGENT_EMAIL,
        delegator,
        &agent_kp.public_key(),
        Duration::hours(24),
        service_idp,
        Some(format!("http://{DOMAIN}")),
    )
    .unwrap();
    let request = ProvisioningRequest::warrant_external(DOMAIN, delegator, grants, agent_kp).unwrap();
    browserid_core::ExternalWarrantRequest::new(agent_cert, request)
        .encoded()
        .to_string()
}

fn post_grant() -> Vec<WarrantGrant> {
    vec![WarrantGrant { aud: AUDIENCE.into(), scopes: Some(vec!["post".into()]) }]
}

async fn get_csrf(server: &TestServer, session: &str) -> String {
    server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .await
        .json::<Value>()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The delegator's broker-issued U_cert for a fresh identity key — what the
/// consent page holds in-origin and signs warrants with.
async fn issue_user_cert(
    server: &TestServer,
    session: &str,
    email: &str,
    user_kp: &KeyPair,
) -> Certificate {
    let csrf = get_csrf(server, session).await;
    let body: Value = server
        .post("/wsapi/cert_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .json(&json!({
            "csrf": csrf,
            "email": email,
            "pubkey": { "algorithm": "Ed25519", "publicKey": user_kp.public_key().to_base64() },
            "ephemeral": false
        }))
        .await
        .json();
    assert_eq!(body["success"], true, "cert_key failed: {body}");
    Certificate::parse(body["cert"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn external_request_full_roundtrip() {
    let service_idp = KeyPair::generate();
    let agent_kp = KeyPair::generate();
    let (server, email_sender) = create_server(&service_idp.public_key());
    let session = create_user(&server, &email_sender, DELEGATOR, "testpassword").await;

    // Service raises the request (no session — it's a foreign server).
    let bundle = external_bundle(&service_idp, &agent_kp, DELEGATOR, post_grant());
    let body: Value = server
        .post("/warrant/request")
        .json(&json!({ "request_bundle": bundle }))
        .await
        .json();
    assert_eq!(body["success"], true, "external request failed: {body}");
    let code = body["code"].as_str().unwrap().to_string();
    assert!(body["verification_uri"]
        .as_str()
        .unwrap()
        .ends_with(&format!("/consent/{code}")));

    // Redirect-tied: the pending inbox does NOT list it…
    let listed: Value = server
        .get("/wsapi/warrant_requests")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    assert_eq!(listed["requests"].as_array().unwrap().len(), 0);

    // …but the deep-linked code fetch does.
    let linked: Value = server
        .get(&format!("/wsapi/warrant_requests?code={code}"))
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let reqs = linked["requests"].as_array().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0]["agent_email"], AGENT_EMAIL);
    assert_eq!(reqs[0]["delegator_email"], DELEGATOR);
    assert_eq!(reqs[0]["label"], SERVICE_IDP);
    assert_eq!(reqs[0]["external"], true);
    assert_eq!(reqs[0]["grants"][0]["audience"], AUDIENCE);
    let status_idx = reqs[0]["grants"][0]["status_idx"].as_u64();
    assert!(status_idx.is_some(), "grant should carry a status index");

    // The delegator approves: sign the warrant with the in-origin identity
    // key (what consent.html does client-side).
    let user_kp = KeyPair::generate();
    let user_cert = issue_user_cert(&server, &session, DELEGATOR, &user_kp).await;
    let warrant = Warrant::create(
        &user_cert,
        AGENT_EMAIL,
        AUDIENCE,
        Some(vec!["post".into()]),
        Duration::days(90),
        &user_kp,
    )
    .unwrap();
    let csrf = get_csrf(&server, &session).await;
    let resp: Value = server
        .post("/wsapi/warrant_respond")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "csrf": csrf,
            "code": code,
            "approve": true,
            "warrants": [warrant.encoded()],
        }))
        .await
        .json();
    assert_eq!(resp["success"], true, "respond failed: {resp}");

    // The service polls its warrant.
    let polled: Value = server
        .post("/warrant/poll")
        .json(&json!({ "code": code }))
        .await
        .json();
    assert_eq!(polled["status"], "approved");
    let handed = polled["warrants"][0].as_str().unwrap();
    assert_eq!(handed, warrant.encoded());

    // And the grant is on the delegator's own record (account page source).
    let registry: Value = server
        .get("/wsapi/warrants")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let entries = registry["warrants"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["agent_email"], AGENT_EMAIL);
    assert_eq!(entries[0]["audience"], AUDIENCE);
    assert_eq!(entries[0]["revoked"], false);
}

#[tokio::test]
async fn external_request_rejects_unknown_delegator_and_bad_signature() {
    let service_idp = KeyPair::generate();
    let agent_kp = KeyPair::generate();
    let (server, email_sender) = create_server(&service_idp.public_key());
    let _session = create_user(&server, &email_sender, DELEGATOR, "testpassword").await;

    // Unknown delegator → refused (no row parked).
    let bundle = external_bundle(&service_idp, &agent_kp, "nobody@example.com", post_grant());
    let resp = server
        .post("/warrant/request")
        .json(&json!({ "request_bundle": bundle }))
        .await;
    assert_eq!(resp.status_code(), 403, "{}", resp.text());

    // R signed by a rogue key (not the certified agent key) → refused.
    let rogue = KeyPair::generate();
    let agent_cert = Certificate::create_agent(
        SERVICE_IDP,
        AGENT_EMAIL,
        DELEGATOR,
        &agent_kp.public_key(),
        Duration::hours(24),
        &service_idp,
        None,
    )
    .unwrap();
    let request =
        ProvisioningRequest::warrant_external(DOMAIN, DELEGATOR, post_grant(), &rogue).unwrap();
    let resp = server
        .post("/warrant/request")
        .json(&json!({ "request_bundle": format!("{}~{}", agent_cert.encoded(), request.encoded()) }))
        .await;
    assert_eq!(resp.status_code(), 400, "{}", resp.text());

    // Agent cert not signed by the (discovered) issuer key → refused.
    let impostor_idp = KeyPair::generate();
    let bundle = {
        let cert = Certificate::create_agent(
            SERVICE_IDP,
            AGENT_EMAIL,
            DELEGATOR,
            &agent_kp.public_key(),
            Duration::hours(24),
            &impostor_idp,
            None,
        )
        .unwrap();
        let request =
            ProvisioningRequest::warrant_external(DOMAIN, DELEGATOR, post_grant(), &agent_kp)
                .unwrap();
        format!("{}~{}", cert.encoded(), request.encoded())
    };
    let resp = server
        .post("/warrant/request")
        .json(&json!({ "request_bundle": bundle }))
        .await;
    assert_eq!(resp.status_code(), 400, "{}", resp.text());
}

#[tokio::test]
async fn external_requests_rate_limited_per_delegator() {
    let service_idp = KeyPair::generate();
    let agent_kp = KeyPair::generate();
    let (server, email_sender) = create_server(&service_idp.public_key());
    let _session = create_user(&server, &email_sender, DELEGATOR, "testpassword").await;

    // The cap is 5 pending external rows per delegator.
    for i in 0..5 {
        let bundle = external_bundle(&service_idp, &agent_kp, DELEGATOR, post_grant());
        let resp = server
            .post("/warrant/request")
            .json(&json!({ "request_bundle": bundle }))
            .await;
        assert_eq!(resp.status_code(), 200, "request {i} failed: {}", resp.text());
    }
    let bundle = external_bundle(&service_idp, &agent_kp, DELEGATOR, post_grant());
    let resp = server
        .post("/warrant/request")
        .json(&json!({ "request_bundle": bundle }))
        .await;
    assert_eq!(resp.status_code(), 403, "{}", resp.text());
    assert!(resp.text().contains("too many pending external requests"));
}
