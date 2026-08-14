//! Admission-record flows end to end (spec §7.5): a resource raises a
//! connection grant request (audience-authenticated by the published proof),
//! the signed-in user's consent page claims it, signs the v2 connection
//! record client-side, and the resource polls the `warrant~config_cert` pair
//! it will hold. Plus the grantor-initiated authoring ceremony, and the
//! fail-closed proof gate.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum_test::TestServer;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::device::{Binding, ConnectionProtocol, DeviceCert, Holder, Purpose, Warrant};
use browserid_core::{KeyPair, RecordBundle, StatusRef};
use chrono::Duration;
use common::{create_user, MockEmailSender};
use serde_json::{json, Value};

const DOMAIN: &str = "localhost:3000";
const USER: &str = "alice@example.com";

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

/// A tiny "resource": serves audience-proof documents from a shared map at
/// `/.well-known/browserid-audience-proof/<request_id>`.
async fn spawn_resource() -> (String, Arc<RwLock<HashMap<String, String>>>) {
    let proofs: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let p = proofs.clone();
    use axum::extract::Path;
    use axum::routing::get;
    let app = axum::Router::new().route(
        "/.well-known/browserid-audience-proof/:id",
        get(move |Path(id): Path<String>| {
            let p = p.clone();
            async move {
                match p.read().unwrap().get(&id) {
                    Some(body) => (axum::http::StatusCode::OK, body.clone()),
                    None => (axum::http::StatusCode::NOT_FOUND, String::new()),
                }
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (origin, proofs)
}

/// Fetch the claimed request off the consent surface (proof-gated).
async fn fetch_claimed(server: &TestServer, session: &str, request_id: &str) -> Value {
    let resp = server
        .get(&format!("/wsapi/warrant_requests?code={request_id}"))
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .await;
    resp.json::<Value>()
}

fn config_material(identity: &str, idp: &KeyPair) -> (KeyPair, DeviceCert) {
    let config_key = KeyPair::generate();
    let cert = DeviceCert::create(
        DOMAIN,
        &config_key.public_key(),
        Purpose::Authorization,
        Holder::new("br1a2b.main").unwrap(),
        vec![identity.to_string()],
        Duration::days(90),
        idp,
        None,
    )
    .unwrap();
    (config_key, cert)
}

#[tokio::test]
async fn connection_grant_request_end_to_end() {
    let (server, sender, idp) = make_server();
    let session = create_user(&server, &sender, USER, "testpassword").await;
    let (origin, proofs) = spawn_resource().await;
    let audience = format!("{origin}/mcp");

    // 1. The resource raises the request.
    let resp = server
        .post("/warrant/record-request")
        .json(&json!({
            "type": "connection",
            "audience": audience,
            "scopes": ["tool:read_file", "tool:search_files"],
            "client": { "client_host": "claude.ai", "client_name": "Claude" },
            "return_url": format!("{origin}/authorize/return?st=x"),
        }))
        .await;
    resp.assert_status_ok();
    let body = resp.json::<Value>();
    let request_id = body["request_id"].as_str().unwrap().to_string();
    let challenge = body["challenge"].as_str().unwrap().to_string();
    assert!(body["consent_uri"].as_str().unwrap().ends_with(&format!("/consent/{request_id}")));

    // 2. Consent render is proof-gated: before the proof is published, the
    //    deep-linked fetch fails (fail-closed) …
    let gated = fetch_claimed(&server, &session, &request_id).await;
    assert_ne!(gated["success"], json!(true), "must not surface before the proof verifies: {gated}");

    //    … after publishing (with trailing whitespace, which strips), it
    //    surfaces claimed: bound to the account, status index allocated,
    //    binding.id + client descriptor attached.
    proofs.write().unwrap().insert(request_id.clone(), format!("{challenge}\n"));
    let claimed = fetch_claimed(&server, &session, &request_id).await;
    assert_eq!(claimed["success"], json!(true), "{claimed}");
    let req = &claimed["requests"][0];
    assert_eq!(req["kind"], "connection");
    assert_eq!(req["client_host"], "claude.ai");
    assert_eq!(req["client_name"], "Claude");
    let binding_id = req["binding_id"].as_str().unwrap().to_string();
    assert!(binding_id.starts_with("cn_"));
    let status_idx = req["grants"][0]["status_idx"].as_u64().unwrap();
    let status_uri = claimed["status_uri"].as_str().unwrap().to_string();

    // 3. The page signs the v2 self-grant record with the config key.
    let (config_key, config_cert) = config_material(USER, &idp);
    let record = Warrant::create_v2(
        USER,
        USER,
        Binding::Connection {
            protocol: ConnectionProtocol::Oauth,
            id: binding_id.clone(),
            client_host: "claude.ai".into(),
            client_name: "Claude".into(),
        },
        &audience,
        vec!["tool:read_file".into(), "tool:search_files".into()],
        Duration::days(90),
        &config_key,
        StatusRef { uri: status_uri, idx: status_idx },
    )
    .unwrap();
    let csrf_token = csrf(&server, &session).await;
    let resp = server
        .post("/wsapi/warrant_respond")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "csrf": csrf_token,
            "code": request_id,
            "approve": true,
            "warrants": [record.encoded()],
            "config_cert": config_cert.encoded(),
            "grantor": USER,
        }))
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<Value>()["success"], json!(true));

    // 4. The resource polls with {request_id} and receives warrant~config_cert.
    let resp = server
        .post("/warrant/poll")
        .json(&json!({ "request_id": request_id }))
        .await;
    resp.assert_status_ok();
    let poll = resp.json::<Value>();
    assert_eq!(poll["status"], "approved", "{poll}");
    let delivered = poll["grants"][0]["warrant"].as_str().unwrap();
    let bundle = RecordBundle::parse(delivered).unwrap();
    match bundle.warrant.claims().binding() {
        Binding::Connection { id, client_host, .. } => {
            assert_eq!(id, binding_id);
            assert_eq!(client_host, "claude.ai");
        }
        other => panic!("expected connection binding, got {other:?}"),
    }

    // 5. The registry shows it as a host↔service connection.
    let resp = server
        .get("/wsapi/warrants")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await;
    let warrants = resp.json::<Value>();
    let row = warrants["warrants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["binding_id"] == json!(binding_id))
        .expect("connection row in registry");
    assert_eq!(row["client_host"], "claude.ai");
    assert_eq!(row["client_name"], "Claude");
}

#[tokio::test]
async fn connection_respond_rejects_wrong_binding_id() {
    let (server, sender, idp) = make_server();
    let session = create_user(&server, &sender, USER, "testpassword").await;
    let (origin, proofs) = spawn_resource().await;
    let audience = format!("{origin}/mcp");

    let body = server
        .post("/warrant/record-request")
        .json(&json!({
            "type": "connection",
            "audience": audience,
            "scopes": ["tool:read_file"],
            "client": { "client_host": "claude.ai", "client_name": "Claude" },
        }))
        .await
        .json::<Value>();
    let request_id = body["request_id"].as_str().unwrap().to_string();
    proofs
        .write()
        .unwrap()
        .insert(request_id.clone(), body["challenge"].as_str().unwrap().to_string());
    let claimed = fetch_claimed(&server, &session, &request_id).await;
    let status_idx = claimed["requests"][0]["grants"][0]["status_idx"].as_u64().unwrap();
    let status_uri = claimed["status_uri"].as_str().unwrap().to_string();

    // A record carrying a DIFFERENT binding.id than the broker minted (§6.6
    // invariant 5) must be refused.
    let (config_key, config_cert) = config_material(USER, &idp);
    let record = Warrant::create_v2(
        USER,
        USER,
        Binding::Connection {
            protocol: ConnectionProtocol::Oauth,
            id: "cn_someone_elses".into(),
            client_host: "claude.ai".into(),
            client_name: "Claude".into(),
        },
        &audience,
        vec!["tool:read_file".into()],
        Duration::days(90),
        &config_key,
        StatusRef { uri: status_uri, idx: status_idx },
    )
    .unwrap();
    let csrf_token = csrf(&server, &session).await;
    let resp = server
        .post("/wsapi/warrant_respond")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "csrf": csrf_token,
            "code": request_id,
            "approve": true,
            "warrants": [record.encoded()],
            "config_cert": config_cert.encoded(),
            "grantor": USER,
        }))
        .await;
    assert_ne!(resp.status_code(), 200, "wrong binding.id must be refused");
}

#[tokio::test]
async fn proof_mismatch_never_surfaces_the_request() {
    let (server, sender, _idp) = make_server();
    let session = create_user(&server, &sender, USER, "testpassword").await;
    let (origin, proofs) = spawn_resource().await;
    let audience = format!("{origin}/mcp");

    let body = server
        .post("/warrant/record-request")
        .json(&json!({
            "type": "connection",
            "audience": audience,
            "scopes": ["tool:read_file"],
            "client": { "client_host": "claude.ai" },
        }))
        .await
        .json::<Value>();
    let request_id = body["request_id"].as_str().unwrap().to_string();

    // Wrong nonce published → the consent surface refuses to render it.
    proofs.write().unwrap().insert(request_id.clone(), "not-the-challenge".into());
    let gated = fetch_claimed(&server, &session, &request_id).await;
    assert_ne!(gated["success"], json!(true), "{gated}");
}

#[tokio::test]
async fn authoring_ceremony_end_to_end() {
    let (server, sender, idp) = make_server();
    let session = create_user(&server, &sender, USER, "testpassword").await;
    let (origin, proofs) = spawn_resource().await;
    let audience = format!("{origin}/notes");

    // The resource compiles its policy into flat grants (one per grantee).
    let resp = server
        .post("/warrant/record-request")
        .json(&json!({
            "type": "authoring",
            "grants": [
                { "grantee": "erin@example.com", "audience": audience, "scopes": ["tool:read_file"] },
                { "grantee": "*@example.com", "audience": format!("{origin}/wiki"), "scopes": [] },
            ],
        }))
        .await;
    resp.assert_status_ok();
    let body = resp.json::<Value>();
    let request_id = body["request_id"].as_str().unwrap().to_string();
    proofs
        .write()
        .unwrap()
        .insert(request_id.clone(), body["challenge"].as_str().unwrap().to_string());

    let claimed = fetch_claimed(&server, &session, &request_id).await;
    assert_eq!(claimed["success"], json!(true), "{claimed}");
    let req = &claimed["requests"][0];
    assert_eq!(req["kind"], "authoring");
    let status_uri = claimed["status_uri"].as_str().unwrap().to_string();

    // The grantor signs one v2 policy record per row (holder-`*` binding).
    let (config_key, config_cert) = config_material(USER, &idp);
    let mut signed = Vec::new();
    for g in req["grants"].as_array().unwrap() {
        let record = Warrant::create_v2(
            USER,
            g["grantee"].as_str().unwrap(),
            Binding::Holder { matcher: browserid_core::HolderMatcher::new("*").unwrap() },
            g["audience"].as_str().unwrap(),
            g["scopes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect(),
            Duration::days(90),
            &config_key,
            StatusRef { uri: status_uri.clone(), idx: g["status_idx"].as_u64().unwrap() },
        )
        .unwrap();
        signed.push(record.encoded().to_string());
    }
    let csrf_token = csrf(&server, &session).await;
    let resp = server
        .post("/wsapi/warrant_respond")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "csrf": csrf_token,
            "code": request_id,
            "approve": true,
            "warrants": signed,
            "config_cert": config_cert.encoded(),
            "grantor": USER,
        }))
        .await;
    resp.assert_status_ok();

    // Delivery: both records arrive as warrant~config_cert pairs, and the
    // matcher-grantee row admits domain subjects (subdomains excluded).
    let poll = server
        .post("/warrant/poll")
        .json(&json!({ "request_id": request_id }))
        .await
        .json::<Value>();
    assert_eq!(poll["status"], "approved", "{poll}");
    let grants = poll["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 2);
    let bundle = RecordBundle::parse(grants[1]["warrant"].as_str().unwrap()).unwrap();
    assert_eq!(bundle.warrant.claims().grantee, "*@example.com");
}

#[tokio::test]
async fn support_document_advertises_record_grants() {
    let (server, _sender, _idp) = make_server();
    let doc = server.get("/.well-known/browserid").await.json::<Value>();
    assert_eq!(doc["record-grants"], "/warrant/record-request");
}
