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
    l.client
        .post(format!("{}/device/issue", l.base))
        .header("cookie", format!("browserid_session={session}"))
        .json(&json!({
            "csrf": csrf,
            "email": email,
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": config_kp.public_key().to_base64(),
        }))
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
    let (_, g) = guard_token(&l, &email, &[&config_cert], Some("password123")).await;
    let (status, body) = attach_call(&l, &[(&config_cert, &config_kp)], &email, None, g["guard"].as_str(), false, None).await;
    assert_eq!(status, 200, "{body}");
    let token = body["token"].as_str().unwrap().to_string();

    // A second identity on the account leaves it (the cascade is a pure
    // store operation; the HTTP triggers are the cookie lane + attach).
    let user_id = l.user_store.get_email(&email).unwrap().unwrap().user_id;
    l.user_store.add_email(user_id, "gone@example.com", true).unwrap();
    browserid_broker::membership::detach(l.user_store.as_ref(), user_id, "gone@example.com").unwrap();

    let (status, body, _) = session_call(&l, &config_kp, &token, "GET", "/api/v1/requests", None).await;
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
    let (status, body, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/requests/respond",
        Some(json!({"code": code, "approve": false}))).await;
    assert_eq!(status, 404, "{body}");
    let (status, body, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/requests/claim",
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

/// Open a §4.5 session with possession proofs by `keys`, the header proof
/// signed by the first.
async fn open_session(l: &Live, account: &str, keys: &[&KeyPair]) -> (reqwest::StatusCode, Value) {
    let htu = format!("{}/api/v1/session", l.base);
    let jti = rand_suffix();
    let now = chrono::Utc::now().timestamp();
    let proofs: Vec<String> = keys
        .iter()
        .map(|k| browserid_registrar::session::build_proof("POST", &htu, None, k, now, &jti))
        .collect();
    let body = json!({ "account": account, "proofs": proofs }).to_string().into_bytes();
    let header = browserid_registrar::session::build_proof("POST", &htu, Some(&body), keys[0], now, &jti);
    let r = l
        .client
        .post(&htu)
        .header("proof", header)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = r.status();
    (status, r.json().await.unwrap_or(json!(null)))
}

/// registry-api-v1 §4.4–§4.5 (bean 0c49 steps 2+3): a session is a set of
/// recorded certs proven by possession; every call is proven by a member;
/// POST bodies are bound; members are re-checked; the config-cert rule
/// gates mutations; retiring the last member ends the session.
#[tokio::test]
async fn sessions_of_proofs_and_the_config_cert_rule() {
    use browserid_broker::store::{DeviceCertRecord, UserStore};
    let l = live_broker().await;
    let email = "session-owner@gmail.com";
    let (_pres, config_kp, _device_cert, config_cert) =
        broker_presentation(&l, email, vec!["registry".into()]).await;
    // Record the config cert through attach (the password guard).
    let (_, g) = guard_token(&l, email, &[&config_cert], Some("password123")).await;
    let (status, body) = attach_call(&l, &[(&config_cert, &config_kp)], email, None, g["guard"].as_str(), false, None).await;
    assert_eq!(status, 200, "{body}");
    let user_id = l.user_store.get_email(email).unwrap().unwrap().user_id;
    let account = l.user_store.account_public_id(user_id).unwrap();

    // Unknown account, or a key not recorded there: 401 invalid_cert/unknown_key.
    let (status, body) = open_session(&l, "nope", &[&config_kp]).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["reason"], "unknown_key");
    let stranger = KeyPair::generate();
    let (status, body) = open_session(&l, &account, &[&stranger]).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["reason"], "unknown_key");

    // A config-cert session.
    let (status, body) = open_session(&l, &account, &[&config_kp]).await;
    assert_eq!(status, 200, "{body}");
    let token = body["token"].as_str().unwrap().to_string();
    assert_eq!(body["account"], account);
    assert_eq!(body["members"][0]["purpose"], "authorization");
    assert_eq!(body["members"][0]["kid"], config_kp.public_key().kid());
    assert!(body["roster"].as_array().unwrap().iter().any(|r| r["identity"] == email && r["state"] == "active"), "{body}");

    // GET under it; a POST with its body bound; the config rule satisfied.
    let (status, body, _) = session_call(&l, &config_kp, &token, "GET", "/api/v1/requests", None).await;
    assert_eq!(status, 200, "{body}");
    let alloc = json!({"grantee": email, "audience": "https://rp.example", "scopes": ["login"]});
    let (status, body, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/warrants/allocate_status", Some(alloc.clone())).await;
    assert_eq!(status, 200, "{body}");

    // A POST whose proof binds a different body: 401 invalid_proof.
    let htu = format!("{}/api/v1/warrants/allocate_status", l.base);
    let proof = browserid_registrar::session::build_proof_now("POST", &htu, Some(b"{}"), &config_kp);
    let r = l.client.post(&htu).header("authorization", format!("Bearer {token}")).header("proof", proof)
        .header("content-type", "application/json").body(alloc.to_string()).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["error"], "invalid_proof", "{body}");

    // A stranger's key is not a member: 401 invalid_session, Bearer challenge.
    let (status, body, headers) = session_call(&l, &stranger, &token, "GET", "/api/v1/requests", None).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "invalid_session");
    assert_eq!(headers.get("www-authenticate").unwrap(), "Bearer");

    // An auth-only session: reads, cannot mutate, may revoke its own cert —
    // which ends it.
    let auth_kp = KeyPair::generate();
    let auth_id = l
        .user_store
        .insert_device_cert(DeviceCertRecord {
            id: 0,
            user_id,
            identities: vec![email.into()],
            purpose: "authentication".into(),
            holder: "browsers.test".into(),
            pubkey: auth_kp.public_key().to_base64(),
            iss: l.domain.clone(),
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + Duration::days(30),
            revoked_at: None,
            status_uri: None,
            status_idx: None,
            prov: "smtp".into(),
        })
        .unwrap();
    let (status, body) = open_session(&l, &account, &[&auth_kp]).await;
    assert_eq!(status, 200, "{body}");
    let auth_token = body["token"].as_str().unwrap().to_string();
    assert_eq!(body["members"][0]["purpose"], "authentication");
    let (status, body, _) = session_call(&l, &auth_kp, &auth_token, "GET", "/api/v1/warrants", None).await;
    assert_eq!(status, 200, "{body}");
    let (status, body, _) = session_call(&l, &auth_kp, &auth_token, "POST", "/api/v1/warrants/allocate_status", Some(alloc.clone())).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "forbidden");
    assert_eq!(body["reason"], "config_cert_required");
    let (status, body, _) = session_call(&l, &auth_kp, &auth_token, "POST", "/api/v1/certs/revoke", Some(json!({"id": auth_id}))).await;
    assert_eq!(status, 200, "{body}");
    let (status, body, _) = session_call(&l, &auth_kp, &auth_token, "GET", "/api/v1/warrants", None).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "invalid_session");

    // Ending the config session.
    let (status, body, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/session/end", Some(json!({}))).await;
    assert_eq!(status, 204, "{body}");
    let (status, body, _) = session_call(&l, &config_kp, &token, "GET", "/api/v1/requests", None).await;
    assert_eq!(status, 401, "{body}");
}

/// Issue a fresh device + config pair for `email` with known keys.
async fn issue_keys(l: &Live, email: &str) -> (String, String, KeyPair, KeyPair) {
    let post = |path: &str, body: Value| l.client.post(format!("{}{path}", l.base)).json(&body);
    let r = post("/wsapi/authenticate_user", json!({"email": email, "pass": "password123"})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let session = set_cookie(&r, "browserid_session");
    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let r = device_issue(l, &session, email, &device_kp, &config_kp).await;
    assert_eq!(r.status(), 200, "device/issue");
    let certs: Value = r.json().await.unwrap();
    (
        certs["device_cert"].as_str().unwrap().to_string(),
        certs["config_cert"].as_str().unwrap().to_string(),
        device_kp,
        config_kp,
    )
}

/// `POST /api/v1/account/attach` (§5.2.1): header proof by the first cert's
/// key, one possession proof per cert, same jti.
async fn attach_call(
    l: &Live,
    certs: &[(&str, &KeyPair)],
    identity: &str,
    account: Option<&str>,
    guard: Option<&str>,
    confirm_takeover: bool,
    bearer: Option<&str>,
) -> (reqwest::StatusCode, Value) {
    let htu = format!("{}/api/v1/account/attach", l.base);
    let jti = rand_suffix();
    let now = chrono::Utc::now().timestamp();
    let entries: Vec<Value> = certs
        .iter()
        .map(|(c, k)| json!({ "cert": c, "proof": browserid_registrar::session::build_proof("POST", &htu, None, k, now, &jti) }))
        .collect();
    let mut body = json!({ "identity": identity, "certs": entries });
    if let Some(a) = account { body["account"] = json!(a); }
    if let Some(g) = guard { body["guard"] = json!(g); }
    if confirm_takeover { body["confirm_takeover"] = json!(true); }
    let bytes = body.to_string().into_bytes();
    let header = browserid_registrar::session::build_proof("POST", &htu, Some(&bytes), certs[0].1, now, &jti);
    let mut req = l.client.post(&htu).header("proof", header).header("content-type", "application/json");
    if let Some(t) = bearer { req = req.header("authorization", format!("Bearer {t}")); }
    let r = req.body(bytes).send().await.unwrap();
    let status = r.status();
    (status, r.json().await.unwrap_or(json!(null)))
}

async fn guard_token(l: &Live, identity: &str, certs: &[&str], password: Option<&str>) -> (reqwest::StatusCode, Value) {
    let mut body = json!({ "identity": identity, "certs": certs });
    if let Some(p) = password { body["password"] = json!(p); }
    let r = l.client.post(format!("{}/wsapi/guard", l.base)).json(&body).send().await.unwrap();
    let status = r.status();
    (status, r.json().await.unwrap_or(json!(null)))
}

/// registry-api-v1 §5.2 + §4.2 (bean 0c49 steps 4+5): attach's case list,
/// the guard page's token, takeover with the hold, detach and delete.
#[tokio::test]
async fn attach_cases_the_guard_takeover_detach_and_delete() {
    use browserid_broker::store::UserStore;
    let l = live_broker().await;
    let email = "attach-owner@gmail.com";
    let (_pres, config_kp, _dc, config_cert) = broker_presentation(&l, email, vec!["registry".into()]).await;

    // Held by an account (the signup made one), no guard: 403 guard_required
    // naming the page.
    let (status, body) = attach_call(&l, &[(&config_cert, &config_kp)], email, None, None, false, None).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "forbidden");
    assert_eq!(body["reason"], "guard_required");
    assert_eq!(body["guard_kinds"][0]["kind"], "page");
    assert!(body["guard_kinds"][0]["url"].as_str().unwrap().ends_with("/guard"), "{body}");

    // The guard page mints a token for these certs: wrong password refused,
    // unknown identity indistinguishable from it.
    let (status, body) = guard_token(&l, email, &[&config_cert], Some("nope")).await;
    assert_eq!(status, 403, "{body}");
    let (status, _) = guard_token(&l, "nobody@gmail.com", &[&config_cert], Some("password123")).await;
    assert_eq!(status, 403);
    let (status, body) = guard_token(&l, email, &[&config_cert], Some("password123")).await;
    assert_eq!(status, 200, "{body}");
    let guard = body["guard"].as_str().unwrap().to_string();

    // Past the guard: recorded, a session on the account.
    let (status, body) = attach_call(&l, &[(&config_cert, &config_kp)], email, None, Some(&guard), false, None).await;
    assert_eq!(status, 200, "{body}");
    let token = body["token"].as_str().unwrap().to_string();
    let account = body["account"].as_str().unwrap().to_string();
    assert_eq!(body["members"].as_array().unwrap().len(), 1);
    assert_eq!(body["members"][0]["purpose"], "authorization");
    assert_eq!(body["roster"], json!([{ "identity": email, "state": "active" }]));
    // The token is spent.
    let (status, body) = attach_call(&l, &[(&config_cert, &config_kp)], email, None, Some(&guard), false, None).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["reason"], "guard_rejected");
    // Re-attaching under the session is idempotent on pubkey.
    let (status, body) = attach_call(&l, &[(&config_cert, &config_kp)], email, Some(&account), None, false, Some(&token)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["members"].as_array().unwrap().len(), 1);

    // A second device: both certs, guard bound to the pair.
    let (dc2, cc2, dkp2, ckp2) = issue_keys(&l, email).await;
    let (status, body) = attach_call(&l, &[(&dc2, &dkp2), (&cc2, &ckp2)], email, None, None, false, None).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["reason"], "guard_required");
    let (_, g1) = guard_token(&l, email, &[&cc2], Some("password123")).await;
    let (status, body) = attach_call(&l, &[(&dc2, &dkp2), (&cc2, &ckp2)], email, None, g1["guard"].as_str(), false, None).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["reason"], "guard_rejected", "a token for other certs");
    let (_, g2) = guard_token(&l, email, &[&dc2, &cc2], Some("password123")).await;
    let (status, body) = attach_call(&l, &[(&dc2, &dkp2), (&cc2, &ckp2)], email, None, g2["guard"].as_str(), false, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["account"], account);
    assert_eq!(body["members"].as_array().unwrap().len(), 2);
    let token2 = body["token"].as_str().unwrap().to_string();

    // Takeover: fresh certs, the user's explicit choice, no guard. The
    // identity leaves into a new account; the old account keeps it on hold
    // and its certs for it die at the issuer (this broker).
    let (dc3, cc3, dkp3, ckp3) = issue_keys(&l, email).await;
    let (status, body) = attach_call(&l, &[(&dc3, &dkp3), (&cc3, &ckp3)], email, None, None, true, None).await;
    assert_eq!(status, 200, "{body}");
    let account3 = body["account"].as_str().unwrap().to_string();
    assert_ne!(account3, account);
    assert_eq!(body["roster"], json!([{ "identity": email, "state": "active" }]));
    let token3 = body["token"].as_str().unwrap().to_string();
    let old_user = l.user_store.user_for_public_id(&account).unwrap().unwrap();
    assert_eq!(l.user_store.get_suspended_identity(old_user, email).unwrap().unwrap().reason, "taken_over");
    let old_roster = browserid_broker::membership::roster(l.user_store.as_ref(), old_user).unwrap();
    assert_eq!(old_roster, vec![(email.to_string(), "suspended")]);
    let (status, body, _) = session_call(&l, &ckp2, &token2, "GET", "/api/v1/requests", None).await;
    assert_eq!(status, 401, "the old device's cert was revoked by the issuer: {body}");

    // Detach and delete on the new account.
    let new_user = l.user_store.user_for_public_id(&account3).unwrap().unwrap();
    let (status, body, _) = session_call(&l, &ckp3, &token3, "POST", "/api/v1/account/detach", Some(json!({"identity": email}))).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["reason"], "last_identity");
    l.user_store.add_email(new_user, "second@example.org", true).unwrap();
    let (status, body, _) = session_call(&l, &ckp3, &token3, "POST", "/api/v1/account/detach", Some(json!({"identity": "second@example.org"}))).await;
    assert_eq!(status, 204, "{body}");
    assert!(l.user_store.get_email("second@example.org").unwrap().is_none());
    assert!(l.user_store.get_suspended_identity(new_user, "second@example.org").unwrap().is_some());
    let (status, body, _) = session_call(&l, &ckp3, &token3, "POST", "/api/v1/account/detach", Some(json!({"identity": "stranger@example.org"}))).await;
    assert_eq!(status, 404, "{body}");
    let (status, body, _) = session_call(&l, &ckp3, &token3, "POST", "/api/v1/account/delete", Some(json!({}))).await;
    assert_eq!(status, 204, "{body}");
    assert!(l.user_store.get_email(email).unwrap().is_none(), "every identity left");
    assert_eq!(l.user_store.get_suspended_identity(new_user, email).unwrap().unwrap().reason, "deleted");
    let (status, _, _) = session_call(&l, &ckp3, &token3, "GET", "/api/v1/requests", None).await;
    assert_eq!(status, 401);

    // Discovery advertises the guard.
    let doc: Value = l.client.get(format!("{}/.well-known/browserid", l.base)).send().await.unwrap().json().await.unwrap();
    assert_eq!(doc["registry"]["guard_kinds"][0]["kind"], "page");
    assert!(doc["registry"]["browser"]["guard"].as_str().unwrap().ends_with("/guard"));
}

/// registry-api-v1 §5.1, §5.4–§5.6 over a session (bean 0c49 steps 6–11):
/// allocate → sign → register with the exact ref; list, lookup, revoke, a
/// fresh index after revoke; certs with kids; the three fixed namespaces;
/// discovery's `endpoint`.
#[tokio::test]
async fn warrants_certs_holders_and_discovery_over_sessions() {
    let l = live_broker().await;
    let email = "registry-owner@gmail.com";
    let (_pres, config_kp, _dc, config_cert) = broker_presentation(&l, email, vec!["registry".into()]).await;
    let (_, g) = guard_token(&l, email, &[&config_cert], Some("password123")).await;
    let (status, body) = attach_call(&l, &[(&config_cert, &config_kp)], email, None, g["guard"].as_str(), false, None).await;
    assert_eq!(status, 200, "{body}");
    let token = body["token"].as_str().unwrap().to_string();
    let holder = browserid_core::device::DeviceCert::parse(&config_cert).unwrap().holder().clone();
    let audience = "https://site.example";

    // Allocate, sign with that ref, register.
    let (status, alloc, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/warrants/allocate_status",
        Some(json!({"grantee": email, "audience": audience, "scopes": ["login"]}))).await;
    assert_eq!(status, 200, "{alloc}");
    let uri = alloc["uri"].as_str().unwrap().to_string();
    let idx = alloc["idx"].as_u64().unwrap();
    let sign = |status: Option<browserid_core::StatusRef>| {
        Warrant::create(email, email, HolderMatcher::new(holder.as_str()).unwrap(), audience,
            vec!["login".into()], Duration::days(30), &config_kp, status).unwrap().encoded().to_string()
    };
    let (status, body, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/warrants/register",
        Some(json!({"warrant": sign(None), "config_cert": config_cert}))).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["reason"], "status_ref_missing");
    let wrong = browserid_core::StatusRef { uri: uri.clone(), idx: idx + 1000 };
    let (status, body, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/warrants/register",
        Some(json!({"warrant": sign(Some(wrong)), "config_cert": config_cert}))).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["reason"], "status_ref_mismatch");
    let right = browserid_core::StatusRef { uri: uri.clone(), idx };
    let (status, body, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/warrants/register",
        Some(json!({"warrant": sign(Some(right.clone())), "config_cert": config_cert}))).await;
    assert_eq!(status, 200, "{body}");
    let id = body["id"].as_u64().unwrap();

    // List and lookup.
    let (status, body, _) = session_call(&l, &config_kp, &token, "GET", "/api/v1/warrants", None).await;
    assert_eq!(status, 200, "{body}");
    let item = body["warrants"].as_array().unwrap().iter().find(|w| w["id"] == id).unwrap();
    assert_eq!(item["grantor"], email);
    assert_eq!(item["grantee"], email);
    assert_eq!(item["status"]["idx"], idx);
    assert_eq!(item["revoked"], false);
    let (status, body, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/warrants/lookup", Some(json!({"audience": audience}))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["warrants"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["warrants"][0]["status"]["idx"], idx);
    assert_eq!(body["warrants"][0]["holder"], holder.as_str());
    let (status, body, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/warrants/lookup", Some(json!({"audience": "https://other.example"}))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["warrants"].as_array().unwrap().len(), 0);

    // Revoke: sticky, gone from lookup, and the next allocation is fresh.
    let (status, _, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/warrants/revoke", Some(json!({"id": id}))).await;
    assert_eq!(status, 204);
    let (status, _, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/warrants/revoke", Some(json!({"id": id}))).await;
    assert_eq!(status, 204, "a second revoke is a 204");
    let (_, body, _) = session_call(&l, &config_kp, &token, "GET", "/api/v1/warrants", None).await;
    assert_eq!(body["warrants"].as_array().unwrap().iter().find(|w| w["id"] == id).unwrap()["revoked"], true);
    let (_, body, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/warrants/lookup", Some(json!({"audience": audience}))).await;
    assert_eq!(body["warrants"].as_array().unwrap().len(), 0);
    let (_, alloc2, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/warrants/allocate_status",
        Some(json!({"grantee": email, "audience": audience, "scopes": ["login"]}))).await;
    assert_ne!(alloc2["idx"].as_u64().unwrap(), idx, "a revoked record's key allocates a fresh index");
    // Registering with the OLD ref is now a mismatch.
    let (status, body, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/warrants/register",
        Some(json!({"warrant": sign(Some(right)), "config_cert": config_cert}))).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["reason"], "status_ref_mismatch");

    // Holders: the three fixed namespaces.
    let (status, body, _) = session_call(&l, &config_kp, &token, "GET", "/api/v1/holders", None).await;
    assert_eq!(status, 200, "{body}");
    let names: Vec<&str> = body["namespaces"].as_array().unwrap().iter().map(|n| n["name"].as_str().unwrap()).collect();
    for n in ["browsers", "agents", "services"] {
        assert!(names.contains(&n), "{names:?}");
    }

    // Discovery.
    let doc: Value = l.client.get(format!("{}/.well-known/browserid", l.base)).send().await.unwrap().json().await.unwrap();
    assert_eq!(doc["registry"]["endpoint"], format!("{}/api/v1", l.base));

    // Certs: listed with kids; revoking by kid the session's own cert ends it.
    let (status, body, _) = session_call(&l, &config_kp, &token, "GET", "/api/v1/certs", None).await;
    assert_eq!(status, 200, "{body}");
    let kid = config_kp.public_key().kid();
    let mine = body["certs"].as_array().unwrap().iter().find(|c| c["kid"] == kid).expect("own cert listed");
    assert_eq!(mine["purpose"], "authorization");
    assert_eq!(mine["revoked"], false);
    let (status, body, _) = session_call(&l, &config_kp, &token, "POST", "/api/v1/certs/revoke", Some(json!({"kid": kid}))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["revoked"], true, "this registry is the issuer");
    let (status, _, _) = session_call(&l, &config_kp, &token, "GET", "/api/v1/certs", None).await;
    assert_eq!(status, 401);
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
    let (_, g) = guard_token(&l, email, &[&config_cert], Some("password123")).await;
    let (status, body) = attach_call(&l, &[(&config_cert, &config_kp)], email, None, g["guard"].as_str(), false, None).await;
    assert_eq!(status, 200, "{body}");
    let token = body["token"].as_str().unwrap().to_string();
    let respond = |body: Value| session_call(&l, &config_kp, &token, "POST", "/api/v1/requests/respond", Some(body));

    // The device cert raises a consent request for the account's own email.
    let r = l.client.post(format!("{}/warrant/request", l.base))
        .json(&json!({
            "device_cert": device_cert, "identity": email,
            "grants": [ { "audience": "https://rp.example.com", "scopes": ["events:read"] } ],
        }))
        .send().await.unwrap();
    assert_eq!(r.status(), 200);
    let code = r.json::<Value>().await.unwrap()["code"].as_str().unwrap().to_string();

    let (status, inbox, _) = session_call(&l, &config_kp, &token, "GET", "/api/v1/requests", None).await;
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
    let (_, g) = guard_token(&l, email, &[&config_cert], Some("password123")).await;
    let (status, body) = attach_call(&l, &[(&config_cert, &config_kp)], email, None, g["guard"].as_str(), false, None).await;
    assert_eq!(status, 200, "{body}");
    let token = body["token"].as_str().unwrap().to_string();
    let call = |method: &'static str, path: &'static str, body: Option<Value>| session_call(&l, &config_kp, &token, method, path, body);
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
        issued_at: now, expires_at: now + Duration::days(90), revoked_at: None, status_uri: uri, status_idx: idx, prov: "smtp".into(),
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
    assert!(reg["browser"]["guard"].is_string());
    assert_eq!(reg["guard_kinds"][0]["kind"], "page");
    assert!(reg.get("token_endpoint").is_none());

    // With the consent surface off, the origin serves no registry key.
    let (server, _mail) = common::create_test_server();
    let doc: Value = server.get("/.well-known/browserid").await.json();
    assert!(doc.get("registry").is_none());
}
