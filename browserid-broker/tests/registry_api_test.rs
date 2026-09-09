//! Registry API v1 (docs/specs/registry-api-v1.md, bean 0c49): sessions of
//! possession proofs, attach and the guard, and every §5 endpoint under
//! `Authorization: Bearer` + a `Proof` signed by a session member.
//!
//! The full-verification tests run against a REAL listener on an ephemeral
//! port: `verify_access_with_dns` discovers the broker's own key by fetching
//! its `/.well-known/browserid` over HTTP (the localhost dev lane), which an
//! in-process axum_test harness cannot serve.
//!
//! The identity vehicle is a broker-rooted (fallback-issued) email: the
//! broker is both issuer and registry, so the guard's password kind can be
//! exercised end to end.

mod common;

use std::sync::Arc;

use browserid_broker::store::UserStore;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::device::{AccessRequest, HolderMatcher, Warrant};
use browserid_core::{Assertion, KeyPair};
use chrono::Duration;
use common::MockEmailSender;
use serde_json::{json, Value};

struct Live {
    /// `http://localhost:{port}` — also the broker audience.
    base: String,
    /// `localhost:{port}` — the broker's domain.
    domain: String,
    client: reqwest::Client,
    email_sender: MockEmailSender,
    user_store: Arc<InMemoryUserStore>,
}

async fn live_broker() -> Live {
    let keypair = KeyPair::generate();
    // 127.0.0.1 (not "localhost") end to end, so the server's own well-known
    // self-discovery and the test client can never split across v4/v6.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let domain = format!("127.0.0.1:{port}");
    let email_sender = Arc::new(MockEmailSender::new());
    let user_store = Arc::new(InMemoryUserStore::new());
    let session_store = Arc::new(InMemorySessionStore::new());
    let mut state = AppState::new_with_arcs(
        keypair,
        domain.clone(),
        user_store.clone(),
        session_store,
        email_sender.clone(),
    );
    state.agent_provisioning_enabled = true;
    let app = routes::create_router(Arc::new(state));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Live {
        base: format!("http://127.0.0.1:{port}"),
        domain,
        client: reqwest::Client::new(),
        email_sender: MockEmailSender { sent: email_sender.sent.clone() },
        user_store,
    }
}

fn set_cookie(resp: &reqwest::Response, name: &str) -> String {
    resp.headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|s| s.strip_prefix(&format!("{name}=")).map(|r| r.split(';').next().unwrap()))
        .unwrap_or_else(|| panic!("no {name} cookie set"))
        .to_string()
}

/// Account signup + SMTP dance + device-cert issuance + access-cert mint,
/// then a presentation for the BROKER's own audience carrying `scopes`.
/// Returns (presentation, config_kp, device_cert_jws, config_cert_jws).
async fn broker_presentation(
    l: &Live,
    email: &str,
    scopes: Vec<String>,
) -> (String, KeyPair, String, String) {
    let post = |path: &str, body: Value| l.client.post(format!("{}{path}", l.base)).json(&body);

    // Account with a password → FULL session.
    let r = post("/wsapi/stage_signin_code", json!({"email": email, "pass": "password123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "stage: {:?}", r.text().await);
    let code = l.email_sender.get_code(email).expect("signup code emailed");
    let r = post("/wsapi/complete_signin_code", json!({"email": email, "token": code}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = post("/wsapi/authenticate_user", json!({"email": email, "pass": "password123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let session = set_cookie(&r, "browserid_session");

    // Device + config certs through the one issuance core (/device/issue;
    // the /auth/device_cert cookie lane retired with bean 2jfh).
    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let r = device_issue(l, &session, email, &device_kp, &config_kp).await;
    assert_eq!(r.status(), 200, "device/issue");
    let certs: Value = r.json().await.unwrap();
    let device_cert = certs["device_cert"].as_str().unwrap().to_string();
    let config_cert = certs["config_cert"].as_str().unwrap().to_string();
    let holder =
        browserid_core::device::DeviceCert::parse(&device_cert).unwrap().holder().clone();

    // Access cert for a fresh key.
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(
        &l.domain,
        email,
        holder.clone(),
        &access_kp.public_key(),
        &format!("jti-{}", rand_suffix()),
        &device_kp,
    )
    .unwrap();
    let r = post("/access/mint", json!({"device_cert": device_cert, "access_request": areq.encoded()}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "mint");
    let access_cert =
        r.json::<Value>().await.unwrap()["access_cert"].as_str().unwrap().to_string();

    // Self-signed warrant + assertion for the broker's own audience.
    let warrant = Warrant::create(
        email,
        email,
        HolderMatcher::new(holder.as_str()).unwrap(),
        &l.base,
        scopes,
        Duration::days(90),
        &config_kp,
        None,
    )
    .unwrap();
    let assertion = Assertion::create(&l.base, Duration::minutes(5), &access_kp).unwrap();
    let presentation =
        format!("{}~{}~{}~{}", access_cert, assertion.encoded(), warrant.encoded(), config_cert);
    (presentation, config_kp, device_cert, config_cert)
}

fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!("{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())
}

/// Session-authed batch issuance through the /device/issue core: fetch the
/// session's CSRF token, then mint a device + config pair for `email`.
async fn device_issue(
    l: &Live,
    session: &str,
    email: &str,
    device_kp: &KeyPair,
    config_kp: &KeyPair,
) -> reqwest::Response {
    device_issue_on(l, session, email, device_kp, config_kp, None).await
}

async fn device_issue_on(
    l: &Live,
    session: &str,
    email: &str,
    device_kp: &KeyPair,
    config_kp: &KeyPair,
    holder: Option<&str>,
) -> reqwest::Response {
    let ctx: Value = l
        .client
        .get(format!("{}/wsapi/session_context", l.base))
        .header("cookie", format!("browserid_session={session}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let csrf = ctx["csrf_token"].as_str().expect("csrf token").to_string();
    let mut body = json!({
        "csrf": csrf,
        "email": email,
        "device_pubkey": device_kp.public_key().to_base64(),
        "config_pubkey": config_kp.public_key().to_base64(),
    });
    if let Some(h) = holder { body["holder"] = json!(h); }
    l.client
        .post(format!("{}/device/issue", l.base))
        .header("cookie", format!("browserid_session={session}"))
        .json(&body)
        .send()
        .await
        .unwrap()
}



/// registry-api-v1 §5.3 `notice` items (bean 0c49 step 1): an identity
/// leaving the account files one; it lists with the notice shape and no
/// grants, and cannot be answered.
#[tokio::test]
async fn notices_list_in_the_inbox_and_cannot_be_answered() {
    let l = live_broker().await;
    let email = format!("notice-{}@example.com", rand_suffix());
    let (_pres, config_kp, _dc, config_cert) =
        broker_presentation(&l, &email, vec!["login".into(), "registry".into()]).await;
    let (token, _account, login_kp) = login_session(&l, &email, &config_kp, &config_cert).await;

    // A second identity on the account leaves it (the cascade is a pure
    // store operation; the HTTP triggers are the cookie lane + attach).
    let user_id = l.user_store.get_email(&email).unwrap().unwrap().user_id;
    l.user_store.add_email(user_id, "gone@example.com", true).unwrap();
    browserid_broker::membership::detach(l.user_store.as_ref(), user_id, "gone@example.com").unwrap();

    let (status, body, _) = session_call(&l, &login_kp, &token, "GET", "/api/v1/requests", None).await;
    assert_eq!(status, 200, "{body}");
    let items = body["requests"].as_array().unwrap();
    let notice = items.iter().find(|i| i["kind"] == "notice").expect("a notice item");
    assert_eq!(notice["notice"]["identity"], "gone@example.com");
    assert_eq!(notice["notice"]["reason"], "left");
    assert!(notice["notice"]["at"].is_string());
    assert!(notice["code"].is_string());
    assert!(notice["expires_at"].is_string());
    assert!(notice.get("grants").map_or(true, |g| g.as_array().map_or(true, |a| a.is_empty())));
    let code = notice["code"].as_str().unwrap().to_string();

    // Nothing to answer: respond is a 404, claim is a 404.
    let (status, body, _) = session_call(&l, &login_kp, &token, "POST", "/api/v1/requests/respond",
        Some(json!({"code": code, "approve": false}))).await;
    assert_eq!(status, 404, "{body}");
    let (status, body, _) = session_call(&l, &login_kp, &token, "POST", "/api/v1/requests/claim",
        Some(json!({"code": code}))).await;
    assert_eq!(status, 404, "{body}");
}

/// A §4.4 call under a session: `Authorization: Bearer` + `Proof` (with
/// `bh` on POSTs), signed by `kp`.
async fn session_call(
    l: &Live,
    kp: &KeyPair,
    token: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (reqwest::StatusCode, Value, reqwest::header::HeaderMap) {
    let htu = format!("{}{path}", l.base);
    let bytes = body.as_ref().map(|b| b.to_string().into_bytes());
    let proof = browserid_registrar::session::build_proof_now(method, &htu, bytes.as_deref(), kp);
    let req = if method == "GET" { l.client.get(&htu) } else { l.client.post(&htu) };
    let req = req.header("authorization", format!("Bearer {token}")).header("proof", proof);
    let req = match bytes {
        Some(b) => req.header("content-type", "application/json").body(b),
        None => req,
    };
    let r = req.send().await.unwrap();
    let status = r.status();
    let headers = r.headers().clone();
    let body = if status == reqwest::StatusCode::NO_CONTENT { json!(null) } else { r.json().await.unwrap_or(json!(null)) };
    (status, body, headers)
}

/// Issue a fresh device + config pair for `email` with known keys.
async fn issue_keys(l: &Live, email: &str) -> (String, String, KeyPair, KeyPair) {
    issue_keys_on(l, email, None).await
}

/// The same, on a holder of the caller's choosing (within the account's
/// browsers namespace) — a browser that ended up with a sibling holder.
async fn issue_keys_on(l: &Live, email: &str, holder: Option<&str>) -> (String, String, KeyPair, KeyPair) {
    let post = |path: &str, body: Value| l.client.post(format!("{}{path}", l.base)).json(&body);
    let r = post("/wsapi/authenticate_user", json!({"email": email, "pass": "password123"})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let session = set_cookie(&r, "browserid_session");
    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let r = device_issue_on(l, &session, email, &device_kp, &config_kp, holder).await;
    assert_eq!(r.status(), 200, "device/issue");
    let certs: Value = r.json().await.unwrap();
    (
        certs["device_cert"].as_str().unwrap().to_string(),
        certs["config_cert"].as_str().unwrap().to_string(),
        device_kp,
        config_kp,
    )
}

/// registry-api-v1 §5.1, §5.4–§5.6 over a session (bean 0c49 steps 6–11):
/// allocate → sign → register with the exact ref; list, revoke, a
/// fresh index after revoke; certs with kids; the three fixed namespaces;
/// discovery's `endpoint`.
#[tokio::test]
async fn warrants_certs_holders_and_discovery_over_sessions() {
    let l = live_broker().await;
    let email = "registry-owner@gmail.com";
    let (_pres, config_kp, _dc, config_cert) = broker_presentation(&l, email, vec!["registry".into()]).await;
    let (token, _account, login_kp) = login_session(&l, email, &config_kp, &config_cert).await;
    let holder = browserid_core::device::DeviceCert::parse(&config_cert).unwrap().holder().clone();
    let audience = "https://site.example";

    // Allocate, sign with that ref, register.
    let (status, alloc, _) = session_call(&l, &login_kp, &token, "POST", "/api/v1/warrants/allocate_status",
        Some(json!({"grantee": email, "audience": audience, "scopes": ["login"]}))).await;
    assert_eq!(status, 200, "{alloc}");
    let uri = alloc["uri"].as_str().unwrap().to_string();
    let idx = alloc["idx"].as_u64().unwrap();
    let sign = |status: Option<browserid_core::StatusRef>| {
        Warrant::create(email, email, HolderMatcher::new(holder.as_str()).unwrap(), audience,
            vec!["login".into()], Duration::days(30), &config_kp, status).unwrap().encoded().to_string()
    };
    let (status, body, _) = session_call(&l, &login_kp, &token, "POST", "/api/v1/warrants/register",
        Some(json!({"warrant": sign(None), "config_cert": config_cert}))).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["reason"], "status_ref_missing");
    let wrong = browserid_core::StatusRef { uri: uri.clone(), idx: idx + 1000 };
    let (status, body, _) = session_call(&l, &login_kp, &token, "POST", "/api/v1/warrants/register",
        Some(json!({"warrant": sign(Some(wrong)), "config_cert": config_cert}))).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["reason"], "status_ref_mismatch");
    let right = browserid_core::StatusRef { uri: uri.clone(), idx };
    let (status, body, _) = session_call(&l, &login_kp, &token, "POST", "/api/v1/warrants/register",
        Some(json!({"warrant": sign(Some(right.clone())), "config_cert": config_cert}))).await;
    assert_eq!(status, 200, "{body}");
    let id = body["id"].as_u64().unwrap();

    // List.
    let (status, body, _) = session_call(&l, &login_kp, &token, "GET", "/api/v1/warrants", None).await;
    assert_eq!(status, 200, "{body}");
    let item = body["warrants"].as_array().unwrap().iter().find(|w| w["id"] == id).unwrap();
    assert_eq!(item["grantor"], email);
    assert_eq!(item["grantee"], email);
    assert_eq!(item["status"]["idx"], idx);
    assert_eq!(item["revoked"], false);
    assert_eq!(item["holder"], holder.as_str());
    assert_eq!(item["audience"], audience);

    // Revoke: sticky, listed as revoked, and the next allocation is fresh.
    let (status, _, _) = session_call(&l, &login_kp, &token, "POST", "/api/v1/warrants/revoke", Some(json!({"id": id}))).await;
    assert_eq!(status, 204);
    let (status, _, _) = session_call(&l, &login_kp, &token, "POST", "/api/v1/warrants/revoke", Some(json!({"id": id}))).await;
    assert_eq!(status, 204, "a second revoke is a 204");
    let (_, body, _) = session_call(&l, &login_kp, &token, "GET", "/api/v1/warrants", None).await;
    assert_eq!(body["warrants"].as_array().unwrap().iter().find(|w| w["id"] == id).unwrap()["revoked"], true);
    let (_, alloc2, _) = session_call(&l, &login_kp, &token, "POST", "/api/v1/warrants/allocate_status",
        Some(json!({"grantee": email, "audience": audience, "scopes": ["login"]}))).await;
    assert_ne!(alloc2["idx"].as_u64().unwrap(), idx, "a revoked record's key allocates a fresh index");
    // Registering with the OLD ref is now a mismatch.
    let (status, body, _) = session_call(&l, &login_kp, &token, "POST", "/api/v1/warrants/register",
        Some(json!({"warrant": sign(Some(right)), "config_cert": config_cert}))).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["reason"], "status_ref_mismatch");

    // Holders: the three fixed namespaces.
    let (status, body, _) = session_call(&l, &login_kp, &token, "GET", "/api/v1/holders", None).await;
    assert_eq!(status, 200, "{body}");
    let names: Vec<&str> = body["namespaces"].as_array().unwrap().iter().map(|n| n["name"].as_str().unwrap()).collect();
    for n in ["browsers", "agents", "services"] {
        assert!(names.contains(&n), "{names:?}");
    }

    // Discovery.
    let doc: Value = l.client.get(format!("{}/.well-known/browserid", l.base)).send().await.unwrap().json().await.unwrap();
    assert_eq!(doc["registry"]["endpoint"], format!("{}/api/v1", l.base));

    // Certs: listed with kids; revoking by kid retires it, and the session
    // (bound to the login key, not the cert) carries on.
    let (status, body, _) = session_call(&l, &login_kp, &token, "GET", "/api/v1/certs", None).await;
    assert_eq!(status, 200, "{body}");
    let kid = config_kp.public_key().kid();
    let mine = body["certs"].as_array().unwrap().iter().find(|c| c["kid"] == kid).expect("own cert listed");
    assert_eq!(mine["purpose"], "authorization");
    assert_eq!(mine["revoked"], false);
    let (status, body, _) = session_call(&l, &login_kp, &token, "POST", "/api/v1/certs/revoke", Some(json!({"kid": kid}))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["revoked"], true, "this registry is the issuer");
    let (status, body, _) = session_call(&l, &login_kp, &token, "GET", "/api/v1/certs", None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["certs"].as_array().unwrap().iter().find(|c| c["kid"] == kid).unwrap()["revoked"], true);
}

/// registry-api-v1 §5.3 over a session: the inbox lists a request an agent
/// raised, `respond` is a signing ceremony (the client-signed warrant must
/// embed exactly the allocated ref), the requester's poll picks it up, a
/// deny is a `{}`, and an unknown code is an owner-scoped 404.
#[tokio::test]
async fn respond_over_sessions_is_a_signing_ceremony() {
    use browserid_core::StatusRef;
    let l = live_broker().await;
    let email = "approver@gmail.com";
    let (_pres, config_kp, device_cert, config_cert) =
        broker_presentation(&l, email, vec!["registry".into()]).await;
    let (token, _account, login_kp) = login_session(&l, email, &config_kp, &config_cert).await;
    let respond = |body: Value| session_call(&l, &login_kp, &token, "POST", "/api/v1/requests/respond", Some(body));

    // The device cert raises a consent request for the account's own email.
    let r = l.client.post(format!("{}/warrant/request", l.base))
        .json(&json!({
            "device_cert": device_cert, "identity": email,
            "grants": [ { "audience": "https://rp.example.com", "scopes": ["events:read"] } ],
        }))
        .send().await.unwrap();
    assert_eq!(r.status(), 200);
    let code = r.json::<Value>().await.unwrap()["code"].as_str().unwrap().to_string();

    let (status, inbox, _) = session_call(&l, &login_kp, &token, "GET", "/api/v1/requests", None).await;
    assert_eq!(status, 200, "{inbox}");
    let req0 = inbox["requests"].as_array().unwrap().iter().find(|r| r["code"] == code.as_str()).expect("listed");
    assert_eq!(req0["grantee"], req0["agent_email"]);
    let holder = req0["holder"].as_str().unwrap().to_string();
    let status_uri = inbox["status_uri"].as_str().unwrap().to_string();
    let idx = req0["grants"][0]["status_idx"].as_u64().unwrap();

    let sign = |status: Option<StatusRef>| Warrant::create(email, email, HolderMatcher::new(&holder).unwrap(),
        "https://rp.example.com", vec!["events:read".into()], Duration::days(30), &config_kp, status).unwrap().encoded().to_string();
    let (status, body, _) = respond(json!({"code": code, "approve": true, "warrants": [sign(None)], "config_cert": config_cert})).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["reason"], "status_ref_missing");
    let signed = sign(Some(StatusRef { uri: status_uri, idx }));
    let (status, body, _) = respond(json!({"code": code, "approve": true, "warrants": [signed.clone()], "config_cert": config_cert})).await;
    assert_eq!(status, 200, "approve: {body}");
    assert_eq!(body, json!({}));

    let poll: Value = l.client.post(format!("{}/warrant/poll", l.base)).json(&json!({ "code": code })).send().await.unwrap().json().await.unwrap();
    assert_eq!(poll["status"], "approved", "{poll}");
    assert!(poll["grants"][0]["warrant"].as_str().unwrap().starts_with(&format!("{signed}~")));

    let r = l.client.post(format!("{}/warrant/request", l.base))
        .json(&json!({ "device_cert": device_cert, "identity": email, "grants": [ { "audience": "https://rp2.example.com" } ] }))
        .send().await.unwrap();
    let code2 = r.json::<Value>().await.unwrap()["code"].as_str().unwrap().to_string();
    let (status, body, _) = respond(json!({ "code": code2, "approve": false })).await;
    assert_eq!(status, 200, "deny: {body}");
    assert_eq!(body, json!({}));
    let poll: Value = l.client.post(format!("{}/warrant/poll", l.base)).json(&json!({ "code": code2 })).send().await.unwrap().json().await.unwrap();
    assert_eq!(poll["status"], "denied");
    let (status, body, _) = respond(json!({ "code": "no-such-code", "approve": false })).await;
    assert_eq!(status, 404, "{body}");
}

/// registry-api-v1 §5.5–§5.6 over a session: the holders view, rename with
/// the §7 taxonomy, namespace relabel, honest cert revocation (own list
/// flips the bit; a foreign issuer's cert only retires here), and forget
/// surfacing the issuers it could not revoke at.
#[tokio::test]
async fn holders_and_certs_over_sessions() {
    use browserid_broker::store::DeviceCertRecord;
    let l = live_broker().await;
    let email = "holders-owner@gmail.com";
    let (_pres, config_kp, _dc, config_cert) = broker_presentation(&l, email, vec!["registry".into()]).await;
    let (token, _account, login_kp) = login_session(&l, email, &config_kp, &config_cert).await;
    let call = |method: &'static str, path: &'static str, body: Option<Value>| session_call(&l, &login_kp, &token, method, path, body);
    let my_holder = browserid_core::device::DeviceCert::parse(&config_cert).unwrap().holder().as_str().to_string();

    let (status, view, _) = call("GET", "/api/v1/holders", None).await;
    assert_eq!(status, 200, "{view}");
    let find_holder = |view: &Value| view["namespaces"].as_array().unwrap().iter()
        .flat_map(|n| n["holders"].as_array().unwrap().clone()).find(|h| h["holder_id"] == my_holder.as_str());
    let hv = find_holder(&view).expect("our holder listed");
    assert_eq!(hv["trust"], "trusted");
    assert_eq!(hv["external"], false);

    let (status, _, _) = call("POST", "/api/v1/holders/rename", Some(json!({"holder_id": my_holder, "label": "  My Wallet  "}))).await;
    assert_eq!(status, 204);
    let (_, view, _) = call("GET", "/api/v1/holders", None).await;
    assert_eq!(find_holder(&view).unwrap()["label"], "My Wallet");
    let (status, body, _) = call("POST", "/api/v1/holders/rename", Some(json!({"holder_id": my_holder, "label": ""}))).await;
    assert_eq!(status, 400, "{body}");
    let (status, body, _) = call("POST", "/api/v1/holders/rename", Some(json!({"holder_id": "nope.nope", "label": "x"}))).await;
    assert_eq!(status, 404, "{body}");
    let (status, _, _) = call("POST", "/api/v1/namespaces/rename", Some(json!({"name": "agents", "label": "Bots"}))).await;
    assert_eq!(status, 204);
    let (status, body, _) = call("POST", "/api/v1/namespaces/rename", Some(json!({"name": "nope", "label": "x"}))).await;
    assert_eq!(status, 404, "{body}");

    // Seed a bot holder with an own-list ref and a foreign-issued cert.
    let user_id = l.user_store.get_email(email).unwrap().unwrap().user_id;
    let agents_prefix = l.user_store.get_or_create_namespace(user_id, "agents").unwrap();
    let bot_holder = format!("{agents_prefix}.botbot23");
    let bot_idx = l.user_store.get_or_allocate_status("device", "bot-pubkey").unwrap();
    let now = chrono::Utc::now();
    let mk = |holder: &str, pubkey: &str, iss: &str, uri: Option<String>, idx: Option<u64>| DeviceCertRecord {
        id: 0, user_id, identities: vec![email.to_string()], purpose: "authentication".into(),
        holder: holder.to_string(), pubkey: pubkey.to_string(), iss: iss.to_string(),
        issued_at: now, expires_at: now + Duration::days(90), revoked_at: None, status_uri: uri, status_idx: idx, prov: "smtp".into(), login_key_id: None,
    };
    let bot_id = l.user_store.insert_device_cert(mk(&bot_holder, "bot-pubkey", &l.domain,
        Some(format!("{}/.well-known/browserid-status", l.base)), Some(bot_idx))).unwrap();
    let foreign_holder = format!("{agents_prefix}.forgn234");
    let foreign_id = l.user_store.insert_device_cert(mk(&foreign_holder, "foreign-pubkey", "idp.partner.example",
        Some("https://idp.partner.example/.well-known/browserid-status".into()), Some(987_654))).unwrap();

    let (status, body, _) = call("POST", "/api/v1/certs/revoke", Some(json!({"id": bot_id}))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["revoked"], true, "own list: the bit is ours to flip");
    assert!(l.user_store.is_status_revoked_idx(bot_idx).unwrap());
    let (status, body, _) = call("POST", "/api/v1/certs/revoke", Some(json!({"id": foreign_id}))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["revoked"], false, "foreign issuer: not ours to revoke");
    let (status, body, _) = call("POST", "/api/v1/certs/revoke", Some(json!({"id": 999999}))).await;
    assert_eq!(status, 404, "{body}");
    let (_, certs, _) = call("GET", "/api/v1/certs", None).await;
    assert!(certs["certs"].as_array().unwrap().iter().any(|c| c["id"] == bot_id && c["revoked"] == true), "retired rows stay listed: {certs}");

    let (status, body, _) = call("POST", "/api/v1/holders/forget", Some(json!({"holder_id": bot_holder}))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["unrevocable"], json!([]));
    let (status, body, _) = call("POST", "/api/v1/holders/forget", Some(json!({"holder_id": foreign_holder}))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["unrevocable"], json!(["idp.partner.example"]));
    let (status, certs, _) = call("GET", "/api/v1/certs", None).await;
    assert_eq!(status, 200, "our own cert never touched: {certs}");
    assert!(!certs["certs"].as_array().unwrap().iter().any(|c| c["holder"] == bot_holder.as_str() || c["holder"] == foreign_holder.as_str()));
}

/// registry-api-v1 §5.1: the support document's `registry` object.
#[tokio::test]
async fn support_document_advertises_the_registry() {
    let ctx = common::create_test_context_customized(|s| s.agent_provisioning_enabled = true);
    let doc: Value = ctx.server.get("/.well-known/browserid").await.json();
    let reg = &doc["registry"];
    assert_eq!(reg["version"], 1);
    assert_eq!(reg["endpoint"], "http://localhost:3000/api/v1");
    assert_eq!(reg["status_list"], "http://localhost:3000/.well-known/browserid-status");
    assert!(reg["browser"]["account"].is_string());
    assert!(reg["browser"]["login"].as_str().unwrap().ends_with("/registry-login"));
    assert_eq!(reg["login_methods"], json!(["login_page", "stored_key"]));
    assert!(reg.get("token_endpoint").is_none());
    assert!(reg.get("guard_kinds").is_none());

    // With the consent surface off, the origin serves no registry key.
    let (server, _mail) = common::create_test_server();
    let doc: Value = server.get("/.well-known/browserid").await.json();
    assert!(doc.get("registry").is_none());
}

// --- §5.2.1 / §4.2 client helpers ------------------------------------------

/// Header proof by `signer` over `body`, one possession proof per cert.
fn proofs_for(htu: &str, certs: &[(&str, &KeyPair)], signer: &KeyPair, body_fn: impl Fn(Vec<Value>) -> Value) -> (Vec<u8>, String) {
    let jti = rand_suffix();
    let now = chrono::Utc::now().timestamp();
    let entries: Vec<Value> = certs
        .iter()
        .map(|(c, k)| json!({ "cert": c, "proof": browserid_registrar::session::build_proof("POST", htu, None, k, now, &jti) }))
        .collect();
    let bytes = body_fn(entries).to_string().into_bytes();
    let header = browserid_registrar::session::build_proof("POST", htu, Some(&bytes), signer, now, &jti);
    (bytes, header)
}

async fn post_proven(l: &Live, path: &str, bytes: Vec<u8>, header: String, bearer: Option<&str>) -> (reqwest::StatusCode, Value) {
    let mut req = l.client.post(format!("{}{path}", l.base)).header("proof", header).header("content-type", "application/json");
    if let Some(t) = bearer { req = req.header("authorization", format!("Bearer {t}")); }
    let r = req.body(bytes).send().await.unwrap();
    let status = r.status();
    (status, r.json().await.unwrap_or(json!(null)))
}

/// The `login_key` argument of `accounts` / `login_page` (§4.2): the key,
/// a label, and its possession proof sharing `jti`.
fn login_key_arg(htu: &str, login_kp: &KeyPair, now: i64, jti: &str) -> Value {
    json!({
        "pubkey": login_kp.public_key().to_base64(),
        "label": "test wallet",
        "proof": browserid_registrar::session::build_proof("POST", htu, None, login_kp, now, jti),
    })
}

/// A session-opening call: certs' possession proofs + the login key's, the
/// header proof by the login key.
fn opening_proofs(htu: &str, certs: &[(&str, &KeyPair)], login_kp: &KeyPair, body_fn: impl Fn(Vec<Value>, Value) -> Value) -> (Vec<u8>, String) {
    let jti = rand_suffix();
    let now = chrono::Utc::now().timestamp();
    let entries: Vec<Value> = certs
        .iter()
        .map(|(c, k)| json!({ "cert": c, "proof": browserid_registrar::session::build_proof("POST", htu, None, k, now, &jti) }))
        .collect();
    let bytes = body_fn(entries, login_key_arg(htu, login_kp, now, &jti)).to_string().into_bytes();
    let header = browserid_registrar::session::build_proof("POST", htu, Some(&bytes), login_kp, now, &jti);
    (bytes, header)
}

/// `POST /api/v1/accounts` (§5.2.1) with the device's login key.
async fn accounts_create(l: &Live, certs: &[(&str, &KeyPair)], login_kp: &KeyPair, identity: &str, confirm: bool) -> (reqwest::StatusCode, Value) {
    let path = "/api/v1/accounts";
    let htu = format!("{}{path}", l.base);
    let (bytes, header) = opening_proofs(&htu, certs, login_kp, |entries, key| {
        let mut b = json!({ "identity": identity, "certs": entries, "login_key": key });
        if confirm { b["confirm_takeover"] = json!(true); }
        b
    });
    post_proven(l, path, bytes, header, None).await
}

/// `POST /api/v1/accounts/lookup` (§5.2.1).
async fn lookup(l: &Live, certs: &[(&str, &KeyPair)], identity: &str) -> (reqwest::StatusCode, Value) {
    let path = "/api/v1/accounts/lookup";
    let htu = format!("{}{path}", l.base);
    let (bytes, header) = proofs_for(&htu, certs, certs[0].1, |entries| json!({ "identity": identity, "certs": entries }));
    post_proven(l, path, bytes, header, None).await
}

/// The broker's login page backend: the account password → one-time token.
async fn login_token(l: &Live, account: &str, password: &str) -> (reqwest::StatusCode, Value) {
    let r = l.client.post(format!("{}/wsapi/registry_login", l.base))
        .json(&json!({ "account": account, "password": password })).send().await.unwrap();
    let status = r.status();
    (status, r.json().await.unwrap_or(json!(null)))
}

/// `POST /api/v1/login` by `login_page` (§4.2): without a token, the bare
/// ask; with one, the login key comes along and the header proof is by it.
async fn login_page(l: &Live, account: &str, token: Option<&str>, login_kp: Option<&KeyPair>) -> (reqwest::StatusCode, Value) {
    let path = "/api/v1/login";
    let Some(t) = token else {
        let r = l.client.post(format!("{}{path}", l.base)).json(&json!({ "account": account, "method": "login_page" })).send().await.unwrap();
        let status = r.status();
        return (status, r.json().await.unwrap_or(json!(null)));
    };
    let kp = login_kp.expect("a login key comes with the token");
    let htu = format!("{}{path}", l.base);
    let (bytes, header) = opening_proofs(&htu, &[], kp, |_, key| json!({ "account": account, "method": "login_page", "token": t, "login_key": key }));
    post_proven(l, path, bytes, header, None).await
}

/// `POST /api/v1/login` by `stored_key` (§4.2): header + possession proofs
/// by the login key.
async fn login_stored(l: &Live, account: &str, login_kp: &KeyPair) -> (reqwest::StatusCode, Value) {
    let path = "/api/v1/login";
    let htu = format!("{}{path}", l.base);
    let jti = rand_suffix();
    let now = chrono::Utc::now().timestamp();
    let pp = browserid_registrar::session::build_proof("POST", &htu, None, login_kp, now, &jti);
    let bytes = json!({ "account": account, "method": "stored_key", "proof": pp }).to_string().into_bytes();
    let header = browserid_registrar::session::build_proof("POST", &htu, Some(&bytes), login_kp, now, &jti);
    post_proven(l, path, bytes, header, None).await
}

/// `POST /api/v1/account/attach` under a session bound to `login_kp`.
async fn attach_call(l: &Live, login_kp: &KeyPair, token: &str, certs: &[(&str, &KeyPair)], identity: &str, confirm: bool) -> (reqwest::StatusCode, Value) {
    let path = "/api/v1/account/attach";
    let htu = format!("{}{path}", l.base);
    let (bytes, header) = proofs_for(&htu, certs, login_kp, |entries| {
        let mut b = json!({ "identity": identity, "certs": entries });
        if confirm { b["confirm_takeover"] = json!(true); }
        b
    });
    post_proven(l, path, bytes, header, Some(token)).await
}

/// The new-device flow (§1): lookup → login page (password) → login with
/// a fresh login key → attach the config cert. Returns the session token,
/// the account, and the login key every call under it is signed with.
async fn login_session(l: &Live, email: &str, config_kp: &KeyPair, config_cert: &str) -> (String, String, KeyPair) {
    let (status, body) = lookup(l, &[(config_cert, config_kp)], email).await;
    assert_eq!(status, 200, "lookup: {body}");
    let account = body["account"].as_str().unwrap().to_string();
    let login_kp = KeyPair::generate();
    let token = page_login(l, &account, &login_kp).await;
    let (status, body) = attach_call(l, &login_kp, &token, &[(config_cert, config_kp)], email, false).await;
    assert_eq!(status, 200, "attach: {body}");
    (token, account, login_kp)
}

/// A page login for `account` with `login_kp`: the session token.
async fn page_login(l: &Live, account: &str, login_kp: &KeyPair) -> String {
    let (status, body) = login_token(l, account, "password123").await;
    assert_eq!(status, 200, "login token: {body}");
    let (status, body) = login_page(l, account, body["login"].as_str(), Some(login_kp)).await;
    assert_eq!(status, 200, "login: {body}");
    body["token"].as_str().unwrap().to_string()
}

/// registry-api-v1 §4.2–§4.5: the two login methods, the session bound to
/// the key it brought, attach leaving the session alone, revocation of a
/// key (its sessions end, the page restores it), forget logging a device
/// out, and a keyless device.
#[tokio::test]
async fn login_methods_login_certs_and_session_authority() {
    let l = live_broker().await;
    let email = "login-owner@gmail.com";
    let (_pres, config_kp, _dc, config_cert) = broker_presentation(&l, email, vec!["registry".into()]).await;

    // Lookup: the sign-up created the account.
    let (status, body) = lookup(&l, &[(&config_cert, &config_kp)], email).await;
    assert_eq!(status, 200, "{body}");
    let account = body["account"].as_str().unwrap().to_string();
    let (status, _) = lookup(&l, &[(&config_cert, &config_kp)], "nobody@gmail.com").await;
    assert_eq!(status, 422, "a cert not naming the identity");

    // login_page: without a token, the page URL; the page refuses a wrong
    // password and an unknown account alike; a bad token is rejected.
    let (status, body) = login_page(&l, &account, None, None).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["reason"], "login_required");
    assert!(body["url"].as_str().unwrap().ends_with("/registry-login"));
    let (status, _) = login_token(&l, &account, "nope").await;
    assert_eq!(status, 403);
    let (status, _) = login_token(&l, "no-such-account", "password123").await;
    assert_eq!(status, 403);
    let login_kp = KeyPair::generate();
    let (status, body) = login_page(&l, &account, Some("bogus"), Some(&login_kp)).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["reason"], "login_rejected");
    let (_, t) = login_token(&l, &account, "password123").await;
    let tok = t["login"].as_str().unwrap().to_string();
    let (status, body) = login_page(&l, &account, Some(&tok), Some(&login_kp)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["account"], account);
    assert_eq!(body["key"]["kid"], login_kp.public_key().kid(), "the session is bound to the key it brought");
    assert_eq!(body["key"]["label"], "test wallet");
    assert_eq!(body["roster"], json!([{ "identity": email, "state": "active" }]));
    let token = body["token"].as_str().unwrap().to_string();
    let (status, body) = login_page(&l, &account, Some(&tok), Some(&login_kp)).await;
    assert_eq!(status, 403, "a token is one-time: {body}");
    assert_eq!(body["reason"], "login_rejected");

    // The session signs with its key and manages the account before any
    // cert is recorded (§4.3); a cert cannot sign for it.
    let alloc = json!({"grantee": email, "audience": "https://rp.example", "scopes": ["login"]});
    let (status, body, _) = session_call(&l, &login_kp, &token, "POST", "/api/v1/warrants/allocate_status", Some(alloc.clone())).await;
    assert_eq!(status, 200, "{body}");
    let (status, body, _) = session_call(&l, &config_kp, &token, "GET", "/api/v1/requests", None).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "invalid_session");

    // Signing calls are judged by the cert they carry, not the session.
    let (_pres2, stranger_kp, _dc2, stranger_cert) = broker_presentation(&l, "login-stranger@gmail.com", vec!["registry".into()]).await;
    let stranger_holder = browserid_core::device::DeviceCert::parse(&stranger_cert).unwrap().holder().clone();
    let w = Warrant::create(email, email, HolderMatcher::new(stranger_holder.as_str()).unwrap(), "https://rp.example",
        vec!["login".into()], Duration::days(30), &stranger_kp, None).unwrap().encoded().to_string();
    let (status, body, _) = session_call(&l, &login_kp, &token, "POST", "/api/v1/warrants/register",
        Some(json!({"warrant": w, "config_cert": stranger_cert}))).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["reason"], "config_cert_not_recorded", "{body}");

    // attach records certs, leaves the session alone, and gives the key its
    // device's holder.
    let (status, body) = attach_call(&l, &login_kp, &token, &[(&config_cert, &config_kp)], email, false).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["recorded"].as_array().unwrap().len(), 1, "{body}");
    let holder = browserid_core::device::DeviceCert::parse(&config_cert).unwrap().holder().as_str().to_string();
    let (status, body, _) = session_call(&l, &login_kp, &token, "GET", "/api/v1/login-keys", None).await;
    assert_eq!(status, 200, "{body}");
    let mine = body["login_keys"].as_array().unwrap().iter().find(|k| k["kid"] == login_kp.public_key().kid()).unwrap();
    assert_eq!(mine["holder"], holder.as_str());
    assert_eq!(mine["current"], true);
    assert_eq!(mine["revoked"], false);
    // A second pair on a SIBLING holder (a browser that lost its holder
    // cache) attached under the same key is the same device.
    let prefix = holder.split('.').next().unwrap().to_string();
    let sibling = format!("{prefix}.sibling001");
    let (dc_s, cc_s, dkp_s, ckp_s) = issue_keys_on(&l, email, Some(&sibling)).await;
    let (status, body) = attach_call(&l, &login_kp, &token, &[(&dc_s, &dkp_s), (&cc_s, &ckp_s)], email, false).await;
    assert_eq!(status, 200, "{body}");
    let (_, certs, _) = session_call(&l, &login_kp, &token, "GET", "/api/v1/certs", None).await;
    let key_id = mine["id"].as_u64().unwrap();
    for kid in [config_kp.public_key().kid(), ckp_s.public_key().kid()] {
        let c = certs["certs"].as_array().unwrap().iter().find(|c| c["kid"] == kid).unwrap();
        assert_eq!(c["login_key"], key_id, "attached under the key: {c}");
    }
    assert_eq!(certs["certs"].as_array().unwrap().iter().find(|c| c["kid"] == ckp_s.public_key().kid()).unwrap()["holder"], sibling.as_str());

    // stored_key: headless from now on. A stranger's key, or none, is sent
    // to the page — never told whether the account exists.
    let (status, body) = login_stored(&l, &account, &login_kp).await;
    assert_eq!(status, 200, "{body}");
    let stored = body["token"].as_str().unwrap().to_string();
    assert_eq!(body["key"]["kid"], login_kp.public_key().kid());
    let (status, body) = login_stored(&l, &account, &KeyPair::generate()).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["reason"], "login_required");
    assert!(body["url"].as_str().unwrap().ends_with("/registry-login"));
    let (status, body) = login_stored(&l, "no-such-account", &login_kp).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["reason"], "login_required");

    // A keyless device (the account page): the same flow with no certs.
    let page_kp = KeyPair::generate();
    let page_token = page_login(&l, &account, &page_kp).await;
    let (status, body, _) = session_call(&l, &page_kp, &page_token, "GET", "/api/v1/login-keys", None).await;
    assert_eq!(status, 200, "{body}");
    let page_key = body["login_keys"].as_array().unwrap().iter().find(|k| k["kid"] == page_kp.public_key().kid()).unwrap();
    assert!(page_key["holder"].is_null(), "no certs, no holder: {page_key}");
    let (status, _) = login_stored(&l, &account, &page_kp).await;
    assert_eq!(status, 200);

    // Revoking a key ends its sessions; the device is sent to the page and
    // may come back with the same key, its record restored.
    let (status, body, _) = session_call(&l, &page_kp, &page_token, "POST", "/api/v1/login-keys/revoke", Some(json!({"kid": login_kp.public_key().kid()}))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["unrevocable"], json!([]));
    let (status, body, _) = session_call(&l, &login_kp, &stored, "GET", "/api/v1/requests", None).await;
    assert_eq!(status, 401, "{body}");
    // Signing a device out retires every cert attached under its key — both
    // holders — so it can no longer sign in anywhere with them.
    let (_, certs, _) = session_call(&l, &page_kp, &page_token, "GET", "/api/v1/certs", None).await;
    for kid in [config_kp.public_key().kid(), ckp_s.public_key().kid()] {
        let c = certs["certs"].as_array().unwrap().iter().find(|c| c["kid"] == kid).unwrap();
        assert_eq!(c["revoked"], true, "{c}");
        assert!(l.user_store.is_status_revoked_idx(c["status"]["idx"].as_u64().unwrap()).unwrap(), "the bit on our list");
    }
    let (status, _, _) = session_call(&l, &login_kp, &token, "GET", "/api/v1/requests", None).await;
    assert_eq!(status, 401, "every session on the key");
    let (status, body) = login_stored(&l, &account, &login_kp).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["reason"], "login_required");
    let (_, body, _) = session_call(&l, &page_kp, &page_token, "GET", "/api/v1/login-keys", None).await;
    assert_eq!(body["login_keys"].as_array().unwrap().iter().find(|k| k["kid"] == login_kp.public_key().kid()).unwrap()["revoked"], true);
    let again = page_login(&l, &account, &login_kp).await;
    let (status, body, _) = session_call(&l, &login_kp, &again, "GET", "/api/v1/login-keys", None).await;
    assert_eq!(status, 200, "{body}");
    let mine = body["login_keys"].as_array().unwrap().iter().find(|k| k["kid"] == login_kp.public_key().kid()).unwrap();
    assert_eq!(mine["revoked"], false, "re-enrolled through the page");
    assert_eq!(mine["holder"], holder.as_str(), "holder kept");

    // Forgetting the device revokes its login key with its certs.
    let (status, body, _) = session_call(&l, &page_kp, &page_token, "POST", "/api/v1/holders/forget", Some(json!({"holder_id": holder}))).await;
    assert_eq!(status, 200, "{body}");
    let (status, _, _) = session_call(&l, &login_kp, &again, "GET", "/api/v1/requests", None).await;
    assert_eq!(status, 401, "the device is logged out");
    let (status, body) = login_stored(&l, &account, &login_kp).await;
    assert_eq!(status, 403, "{body}");
    // Revoking the page's own key (no holder) is a plain logout.
    let (status, body, _) = session_call(&l, &page_kp, &page_token, "POST", "/api/v1/login-keys/revoke", Some(json!({"kid": page_kp.public_key().kid()}))).await;
    assert_eq!(status, 200, "{body}");
    let page_token = page_login(&l, &account, &page_kp).await;

    // Ending a session.
    let (status, _, _) = session_call(&l, &page_kp, &page_token, "POST", "/api/v1/session/end", Some(json!({}))).await;
    assert_eq!(status, 204);
    let (status, _, _) = session_call(&l, &page_kp, &page_token, "GET", "/api/v1/requests", None).await;
    assert_eq!(status, 401);
    let (status, _) = login_stored(&l, &account, &page_kp).await;
    assert_eq!(status, 200, "the key survives its session");
}

/// registry-api-v1 §5.2.1, §5.2.4–§5.2.6: creation refuses a held identity
/// until confirmed (takeover into a new account, the old one on hold),
/// attach's cases under a session, detach and delete.
#[tokio::test]
async fn accounts_attach_takeover_detach_and_delete() {
    use browserid_broker::store::UserStore;
    let l = live_broker().await;
    let email = "attach-owner@gmail.com";
    let (_pres, config_kp, _dc, config_cert) = broker_presentation(&l, email, vec!["registry".into()]).await;

    // The sign-up made an account: creating another around the identity is
    // refused until the user confirms a takeover.
    let (status, body) = accounts_create(&l, &[(&config_cert, &config_kp)], &KeyPair::generate(), email, false).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["reason"], "identity_held");

    // The normal new-device path: lookup, log in, attach.
    let (token, account, login_kp) = login_session(&l, email, &config_kp, &config_cert).await;
    let (status, body) = attach_call(&l, &login_kp, &token, &[(&config_cert, &config_kp)], email, false).await;
    assert_eq!(status, 200, "idempotent on pubkey: {body}");
    let (dc2, cc2, dkp2, ckp2) = issue_keys(&l, email).await;
    let (status, body) = attach_call(&l, &login_kp, &token, &[(&dc2, &dkp2), (&cc2, &ckp2)], email, false).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["recorded"].as_array().unwrap().len(), 2, "{body}");
    let (status, certs, _) = session_call(&l, &login_kp, &token, "GET", "/api/v1/certs", None).await;
    assert_eq!(status, 200);
    assert!(certs["certs"].as_array().unwrap().iter().any(|c| c["kid"] == ckp2.public_key().kid()));

    // Takeover: fresh certs and a new device's key create a NEW account
    // around the identity; the old account keeps it on hold and its certs
    // for it die at the issuer.
    let (dc3, cc3, dkp3, ckp3) = issue_keys(&l, email).await;
    let login_kp3 = KeyPair::generate();
    let (status, body) = accounts_create(&l, &[(&dc3, &dkp3), (&cc3, &ckp3)], &login_kp3, email, true).await;
    assert_eq!(status, 200, "{body}");
    let account3 = body["account"].as_str().unwrap().to_string();
    assert_ne!(account3, account);
    assert_eq!(body["key"]["kid"], login_kp3.public_key().kid());
    assert_eq!(body["roster"], json!([{ "identity": email, "state": "active" }]));
    let token3 = body["token"].as_str().unwrap().to_string();
    let old_user = l.user_store.user_for_public_id(&account).unwrap().unwrap();
    assert_eq!(l.user_store.get_suspended_identity(old_user, email).unwrap().unwrap().reason, "taken_over");
    // The old device keeps its login key and session (the account itself is
    // untouched) and sees the identity suspended and its certs revoked.
    let (status, certs, _) = session_call(&l, &login_kp, &token, "GET", "/api/v1/certs", None).await;
    assert_eq!(status, 200, "{certs}");
    assert!(certs["certs"].as_array().unwrap().iter().all(|c| c["revoked"] == true), "revoked by the issuer: {certs}");
    let (_, body) = login_stored(&l, &account, &login_kp).await;
    assert_eq!(body["roster"], json!([{ "identity": email, "state": "suspended" }]), "{body}");
    // The new account's key holds the new device's holder.
    let (_, keys, _) = session_call(&l, &login_kp3, &token3, "GET", "/api/v1/login-keys", None).await;
    let holder3 = browserid_core::device::DeviceCert::parse(&cc3).unwrap().holder().as_str().to_string();
    assert_eq!(keys["login_keys"][0]["holder"], holder3.as_str(), "{keys}");

    // Detach and delete on the new account.
    let new_user = l.user_store.user_for_public_id(&account3).unwrap().unwrap();
    let (status, body, _) = session_call(&l, &login_kp3, &token3, "POST", "/api/v1/account/detach", Some(json!({"identity": email}))).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["reason"], "last_identity");
    l.user_store.add_email(new_user, "second@example.org", true).unwrap();
    let (status, body, _) = session_call(&l, &login_kp3, &token3, "POST", "/api/v1/account/detach", Some(json!({"identity": "second@example.org"}))).await;
    assert_eq!(status, 204, "{body}");
    assert!(l.user_store.get_email("second@example.org").unwrap().is_none());
    let (status, body, _) = session_call(&l, &login_kp3, &token3, "POST", "/api/v1/account/detach", Some(json!({"identity": "stranger@example.org"}))).await;
    assert_eq!(status, 404, "{body}");
    let (status, body, _) = session_call(&l, &login_kp3, &token3, "POST", "/api/v1/account/delete", Some(json!({}))).await;
    assert_eq!(status, 204, "{body}");
    assert!(l.user_store.get_email(email).unwrap().is_none(), "every identity left");
    assert_eq!(l.user_store.get_suspended_identity(new_user, email).unwrap().unwrap().reason, "deleted");
    let (status, _, _) = session_call(&l, &login_kp3, &token3, "GET", "/api/v1/requests", None).await;
    assert_eq!(status, 401);
}
