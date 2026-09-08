//! Registry API v1 token lane (docs/specs/registry-api-v1.md, bean bw9q):
//! `POST /api/v1/token` exchanges a presentation for the broker's own
//! audience into a sender-constrained token, and every authed endpoint
//! demands a DPoP-style proof signed by the bound config-cert key.
//!
//! The full-verification tests run against a REAL listener on an ephemeral
//! port: `verify_access_with_dns` discovers the broker's own key by fetching
//! its `/.well-known/browserid` over HTTP (the localhost dev lane), which an
//! in-process axum_test harness cannot serve.
//!
//! The identity vehicle is a broker-rooted (fallback-issued) email —
//! deliberately: self-issued presentations are ACCEPTED at the exchange
//! (§10 decision 7) even though the cookie sibling rejects them, so the
//! same certs that fail `auth_with_presentation` must succeed here.

mod common;

use std::sync::Arc;

use browserid_broker::store::UserStore;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::device::{AccessRequest, HolderMatcher, Warrant};
use browserid_core::{Assertion, KeyPair};
use browserid_registrar::api::{build_proof, build_proof_at};
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

async fn exchange(l: &Live, body: Value) -> (reqwest::StatusCode, Value) {
    let r = l.client.post(format!("{}/api/v1/token", l.base)).json(&body).send().await.unwrap();
    let status = r.status();
    (status, r.json().await.unwrap())
}

async fn get_inbox(l: &Live, token: &str, proof: &str) -> (reqwest::StatusCode, Value) {
    let r = l
        .client
        .get(format!("{}/api/v1/requests", l.base))
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", proof)
        .send()
        .await
        .unwrap();
    let status = r.status();
    (status, r.json().await.unwrap())
}

#[tokio::test]
async fn token_exchange_mints_and_the_proof_gates_the_inbox() {
    let l = live_broker().await;
    let email = "wallet-owner@gmail.com";
    let (presentation, config_kp, device_cert, _config_cert) =
        broker_presentation(&l, email, vec!["login".into(), "registry".into()]).await;

    // The exchange accepts the self-issued presentation (§10 decision 7) —
    // the exact credential the cookie lane refuses.
    let (status, body) = exchange(&l, json!({ "presentation": presentation })).await;
    assert_eq!(status, 200, "exchange: {body}");
    let token = body["access_token"].as_str().unwrap().to_string();
    assert_eq!(body["token_type"], "DPoP");
    assert_eq!(body["scope"], "registry");
    let expires_in = body["expires_in"].as_i64().unwrap();
    assert!(expires_in > 0 && expires_in <= 3600, "expires_in = {expires_in}");
    assert!(body.get("success").is_none(), "legacy envelope must not appear here");

    let htu = format!("{}/api/v1/requests", l.base);

    // No proof → 401 invalid_proof, with the DPoP challenge.
    let r = l
        .client
        .get(htu.clone())
        .header("authorization", format!("DPoP {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["www-authenticate"], "DPoP");
    assert_eq!(r.json::<Value>().await.unwrap()["error"], "invalid_proof");

    // Garbage token → 401 invalid_token.
    let (status, body) =
        get_inbox(&l, "not-a-token", &build_proof("GET", &htu, "not-a-token", &config_kp)).await;
    assert_eq!(status, 401);
    assert_eq!(body["error"], "invalid_token");

    // Proof signed by the WRONG key → 401 invalid_proof.
    let mallory = KeyPair::generate();
    let (status, body) = get_inbox(&l, &token, &build_proof("GET", &htu, &token, &mallory)).await;
    assert_eq!(status, 401);
    assert_eq!(body["error"], "invalid_proof");

    // Wrong htm / wrong htu / stale iat / wrong ath all reject.
    let (status, _) = get_inbox(&l, &token, &build_proof("POST", &htu, &token, &config_kp)).await;
    assert_eq!(status, 401, "htm mismatch must reject");
    let wrong_htu = format!("{}/api/v1/other", l.base);
    let (status, _) =
        get_inbox(&l, &token, &build_proof("GET", &wrong_htu, &token, &config_kp)).await;
    assert_eq!(status, 401, "htu mismatch must reject");
    let stale = chrono::Utc::now().timestamp() - 3600;
    let (status, _) = get_inbox(
        &l,
        &token,
        &build_proof_at("GET", &htu, &token, &config_kp, stale, "jti-stale"),
    )
    .await;
    assert_eq!(status, 401, "stale iat must reject");
    let (status, _) =
        get_inbox(&l, &token, &build_proof("GET", &htu, "other-token", &config_kp)).await;
    assert_eq!(status, 401, "ath mismatch must reject");

    // A correct proof → 200 with the (empty) inbox + our status list URI.
    let (status, inbox) = get_inbox(&l, &token, &build_proof("GET", &htu, &token, &config_kp)).await;
    assert_eq!(status, 200, "authed inbox: {inbox}");
    assert_eq!(inbox["status_uri"], format!("{}/.well-known/browserid-status", l.base));
    assert_eq!(inbox["requests"].as_array().unwrap().len(), 0);

    // jti replay: the SAME proof again is rejected.
    let jti = format!("jti-{}", rand_suffix());
    let replayed =
        build_proof_at("GET", &htu, &token, &config_kp, chrono::Utc::now().timestamp(), &jti);
    let (status, _) = get_inbox(&l, &token, &replayed).await;
    assert_eq!(status, 200);
    let (status, body) = get_inbox(&l, &token, &replayed).await;
    assert_eq!(status, 401, "replayed jti must reject");
    assert_eq!(body["error"], "invalid_proof");

    // A pending consent request shows up in the token-lane inbox: the
    // device (authentication) cert raises one for the account's own email.
    let r = l
        .client
        .post(format!("{}/warrant/request", l.base))
        .json(&json!({
            "device_cert": device_cert,
            "identity": email,
            "grants": [ { "audience": "https://rp.example.com", "scopes": ["events:read"] } ],
            "label": "Wallet test"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "warrant_request");
    let code = r.json::<Value>().await.unwrap()["code"].as_str().unwrap().to_string();

    let (status, inbox) = get_inbox(&l, &token, &build_proof("GET", &htu, &token, &config_kp)).await;
    assert_eq!(status, 200);
    let reqs = inbox["requests"].as_array().unwrap();
    assert_eq!(reqs.len(), 1, "the raised request is in the inbox: {inbox}");
    assert_eq!(reqs[0]["code"], code.as_str());
    assert_eq!(reqs[0]["kind"], "agent");
    assert_eq!(reqs[0]["grants"][0]["audience"], "https://rp.example.com");
}

#[tokio::test]
async fn exchange_requires_the_registry_scope_on_the_warrant() {
    let l = live_broker().await;
    // A plain login warrant — no `registry` scope — authenticates the cookie
    // lane but must NOT mint a registry-management token (§3.1).
    let (presentation, ..) =
        broker_presentation(&l, "scopeless@gmail.com", vec!["login".into()]).await;
    let (status, body) = exchange(&l, json!({ "presentation": presentation })).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["reason"], "scope_missing");
}

#[tokio::test]
async fn exchange_is_single_use_per_assertion() {
    let l = live_broker().await;
    let (presentation, ..) =
        broker_presentation(&l, "replay@gmail.com", vec!["registry".into()]).await;

    let (status, body) = exchange(&l, json!({ "presentation": presentation })).await;
    assert_eq!(status, 200, "first exchange: {body}");
    let (status, body) = exchange(&l, json!({ "presentation": presentation })).await;
    assert_eq!(status, 400, "same assertion again must be refused: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn revoking_the_bound_cert_kills_the_token_fail_closed() {
    let l = live_broker().await;
    let (presentation, config_kp, _device_cert, config_cert) =
        broker_presentation(&l, "revoked@gmail.com", vec!["registry".into()]).await;

    let (status, body) = exchange(&l, json!({ "presentation": presentation })).await;
    assert_eq!(status, 200, "{body}");
    let token = body["access_token"].as_str().unwrap().to_string();
    let htu = format!("{}/api/v1/requests", l.base);

    // Live token works…
    let (status, _) = get_inbox(&l, &token, &build_proof("GET", &htu, &token, &config_kp)).await;
    assert_eq!(status, 200);

    // …until the bound config cert's status bit flips: revocation follows
    // the cert with no token-level bookkeeping (§3.1).
    let cc = browserid_core::device::DeviceCert::parse(&config_cert).unwrap();
    let idx = cc.claims().status.as_ref().expect("config cert has a status ref").idx;
    l.user_store.set_status_revoked_idx(idx).unwrap();

    let (status, body) = get_inbox(&l, &token, &build_proof("GET", &htu, &token, &config_kp)).await;
    assert_eq!(status, 401, "revoked cert must kill the token: {body}");
    assert_eq!(body["error"], "invalid_token");
}

/// Consent is API-complete (§5.1): approval over the token lane carries the
/// same client-signed warrants as the browser page, validated to the same
/// bar (shared core), and the requester's poll delivers the result.
#[tokio::test]
async fn respond_over_the_token_lane_is_a_signing_ceremony() {
    use browserid_core::StatusRef;
    let l = live_broker().await;
    let email = "approver@gmail.com";
    let (presentation, config_kp, device_cert, config_cert) =
        broker_presentation(&l, email, vec!["registry".into()]).await;
    let (status, body) = exchange(&l, json!({ "presentation": presentation })).await;
    assert_eq!(status, 200, "{body}");
    let token = body["access_token"].as_str().unwrap().to_string();
    let htu_inbox = format!("{}/api/v1/requests", l.base);
    let htu_respond = format!("{}/api/v1/requests/respond", l.base);
    let respond = |body: Value, proof: String| {
        let l = &l;
        let token = token.clone();
        async move {
            let r = l
                .client
                .post(format!("{}/api/v1/requests/respond", l.base))
                .header("authorization", format!("DPoP {token}"))
                .header("dpop", proof)
                .json(&body)
                .send()
                .await
                .unwrap();
            let status = r.status();
            (status, r.json::<Value>().await.unwrap())
        }
    };

    // The device cert raises a consent request for the account's own email.
    let r = l
        .client
        .post(format!("{}/warrant/request", l.base))
        .json(&json!({
            "device_cert": device_cert,
            "identity": email,
            "grants": [ { "audience": "https://rp.example.com", "scopes": ["events:read"] } ],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let code = r.json::<Value>().await.unwrap()["code"].as_str().unwrap().to_string();

    // Read the pending request from the token-lane inbox: holder + the
    // allocated status ref the signed warrant must embed.
    let (status, inbox) =
        get_inbox(&l, &token, &build_proof("GET", &htu_inbox, &token, &config_kp)).await;
    assert_eq!(status, 200);
    let req0 = &inbox["requests"][0];
    assert_eq!(req0["code"], code.as_str());
    let holder = req0["holder"].as_str().unwrap().to_string();
    let status_uri = inbox["status_uri"].as_str().unwrap().to_string();
    let idx = req0["grants"][0]["status_idx"].as_u64().unwrap();

    // A warrant missing its allocated ref fails the bar: 422 + machine reason.
    let refless = Warrant::create(
        email,
        email,
        HolderMatcher::new(&holder).unwrap(),
        "https://rp.example.com",
        vec!["events:read".into()],
        Duration::days(30),
        &config_kp,
        None,
    )
    .unwrap();
    let (status, body) = respond(
        json!({
            "code": code, "approve": true,
            "warrants": [refless.encoded()], "config_cert": config_cert,
        }),
        build_proof("POST", &htu_respond, &token, &config_kp),
    )
    .await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["error"], "invalid_warrant");
    assert_eq!(body["reason"], "status_ref_missing");

    // The real approval: the client-signed warrant embeds exactly the
    // allocated {uri, idx}. Response is 200 {} (no return_url on request).
    let warrant = Warrant::create(
        email,
        email,
        HolderMatcher::new(&holder).unwrap(),
        "https://rp.example.com",
        vec!["events:read".into()],
        Duration::days(30),
        &config_kp,
        Some(StatusRef { uri: status_uri, idx }),
    )
    .unwrap();
    let (status, body) = respond(
        json!({
            "code": code, "approve": true,
            "warrants": [warrant.encoded()], "config_cert": config_cert,
        }),
        build_proof("POST", &htu_respond, &token, &config_kp),
    )
    .await;
    assert_eq!(status, 200, "approve: {body}");
    assert_eq!(body, json!({}));

    // The requester's poll picks up `warrant~config_cert` (single delivery).
    let r = l
        .client
        .post(format!("{}/warrant/poll", l.base))
        .json(&json!({ "code": code }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let poll: Value = r.json().await.unwrap();
    assert_eq!(poll["status"], "approved", "{poll}");
    let delivered = poll["grants"][0]["warrant"].as_str().unwrap();
    assert!(delivered.starts_with(&format!("{}~", warrant.encoded())));

    // Deny lane: a second request, denied over the API → the poll learns it.
    let r = l
        .client
        .post(format!("{}/warrant/request", l.base))
        .json(&json!({
            "device_cert": device_cert,
            "identity": email,
            "grants": [ { "audience": "https://rp2.example.com" } ],
        }))
        .send()
        .await
        .unwrap();
    let code2 = r.json::<Value>().await.unwrap()["code"].as_str().unwrap().to_string();
    let (status, body) = respond(
        json!({ "code": code2, "approve": false }),
        build_proof("POST", &htu_respond, &token, &config_kp),
    )
    .await;
    assert_eq!(status, 200, "deny: {body}");
    assert_eq!(body, json!({}), "deny never carries a return_url (§5.1)");
    let r = l
        .client
        .post(format!("{}/warrant/poll", l.base))
        .json(&json!({ "code": code2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.json::<Value>().await.unwrap()["status"], "denied");

    // An unknown (or another account's) code is an owner-scoped 404.
    let (status, body) = respond(
        json!({ "code": "no-such-code", "approve": false }),
        build_proof("POST", &htu_respond, &token, &config_kp),
    )
    .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error"], "not_found");
}

/// The §5.2 warrant registry over the token lane: allocate a status ref,
/// sign + register a warrant embedding it, list, revoke (bit flips), forget.
#[tokio::test]
async fn warrant_registry_over_the_token_lane() {
    use browserid_core::StatusRef;
    let l = live_broker().await;
    let email = "registrar-user@gmail.com";
    let (presentation, config_kp, _device_cert, config_cert) =
        broker_presentation(&l, email, vec!["registry".into()]).await;
    let (status, body) = exchange(&l, json!({ "presentation": presentation })).await;
    assert_eq!(status, 200, "{body}");
    let token = body["access_token"].as_str().unwrap().to_string();

    let call = |method: &'static str, path: String, body: Option<Value>| {
        let l = &l;
        let token = token.clone();
        let config_kp = &config_kp;
        async move {
            let url = format!("{}{path}", l.base);
            let htu = url.clone();
            let proof = build_proof(method, &htu, &token, config_kp);
            let req = match method {
                "GET" => l.client.get(&url),
                _ => {
                    let r = l.client.post(&url);
                    match body {
                        Some(b) => r.json(&b),
                        None => r,
                    }
                }
            };
            req.header("authorization", format!("DPoP {token}"))
                .header("dpop", proof)
                .send()
                .await
                .unwrap()
        }
    };

    // Allocate the stable ref for a login grant (idempotent).
    let r = call(
        "POST",
        "/api/v1/warrants/allocate_status".into(),
        Some(json!({ "agent_email": email, "audience": "https://site.example", "scopes": ["login"] })),
    )
    .await;
    assert_eq!(r.status(), 200, "allocate");
    let alloc: Value = r.json().await.unwrap();
    let uri = alloc["uri"].as_str().unwrap().to_string();
    let idx = alloc["idx"].as_u64().unwrap();
    assert_eq!(uri, format!("{}/.well-known/browserid-status", l.base));
    let r = call(
        "POST",
        "/api/v1/warrants/allocate_status".into(),
        Some(json!({ "agent_email": email, "audience": "https://site.example", "scopes": ["login"] })),
    )
    .await;
    assert_eq!(r.json::<Value>().await.unwrap()["idx"].as_u64().unwrap(), idx, "stable per grant");

    // Sign a login warrant embedding the ref and register it.
    let warrant = Warrant::create(
        email,
        email,
        HolderMatcher::new("browsers.*").unwrap(),
        "https://site.example",
        vec!["login".into()],
        Duration::days(90),
        &config_kp,
        Some(StatusRef { uri: uri.clone(), idx }),
    )
    .unwrap();
    let r = call(
        "POST",
        "/api/v1/warrants/register".into(),
        Some(json!({ "warrant": warrant.encoded(), "config_cert": config_cert })),
    )
    .await;
    assert_eq!(r.status(), 200, "register");

    // Listed, unrevoked, carrying the allocated index.
    let r = call("GET", "/api/v1/warrants".into(), None).await;
    assert_eq!(r.status(), 200);
    let list: Value = r.json().await.unwrap();
    let row = list["warrants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["audience"] == "https://site.example")
        .expect("registered warrant listed")
        .clone();
    assert_eq!(row["status_idx"].as_u64(), Some(idx));
    assert_eq!(row["revoked"], false);
    let id = row["id"].as_u64().unwrap();

    // Revoke flips the bit (visible in the next list).
    let r = call("POST", "/api/v1/warrants/revoke".into(), Some(json!({ "id": id }))).await;
    assert_eq!(r.status(), 204, "revoke");
    let r = call("GET", "/api/v1/warrants".into(), None).await;
    let list: Value = r.json().await.unwrap();
    let row = list["warrants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["id"].as_u64() == Some(id))
        .unwrap()
        .clone();
    assert_eq!(row["revoked"], true);

    // A REFLESS warrant is refused (§5.4: every record carries a ref this
    // registry allocated).
    let refless = Warrant::create(
        email,
        email,
        HolderMatcher::new("browsers.*").unwrap(),
        "https://other.example",
        vec!["login".into()],
        Duration::days(90),
        &config_kp,
        None,
    )
    .unwrap();
    let r = call(
        "POST",
        "/api/v1/warrants/register".into(),
        Some(json!({ "warrant": refless.encoded(), "config_cert": config_cert })),
    )
    .await;
    assert_eq!(r.status(), 422);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["reason"], "status_ref_missing");

    // Forget drops the row without touching bits.
    let r = call("POST", "/api/v1/warrants/forget".into(), Some(json!({ "id": id }))).await;
    assert_eq!(r.status(), 204, "forget {id}");
    let r = call("GET", "/api/v1/warrants".into(), None).await;
    let list: Value = r.json().await.unwrap();
    assert!(
        !list["warrants"].as_array().unwrap().iter().any(|w| w["id"].as_u64() == Some(id)),
        "forgotten row gone"
    );
}

/// One token-authed API call; `htu` in the proof excludes any query string
/// (§3.2 — the server compares against the path only). 204 → null body.
async fn api_call(
    l: &Live,
    kp: &KeyPair,
    token: &str,
    method: &str,
    path: &str,
    query: Option<&str>,
    body: Option<Value>,
) -> (reqwest::StatusCode, Value) {
    let htu = format!("{}{path}", l.base);
    let url = match query {
        Some(q) => format!("{htu}?{q}"),
        None => htu.clone(),
    };
    let proof = build_proof(method, &htu, token, kp);
    let req = if method == "GET" {
        l.client.get(&url)
    } else {
        let r = l.client.post(&url);
        match body {
            Some(b) => r.json(&b),
            None => r,
        }
    };
    let r = req
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", proof)
        .send()
        .await
        .unwrap();
    let status = r.status();
    let body = if status == reqwest::StatusCode::NO_CONTENT {
        json!(null)
    } else {
        r.json().await.unwrap_or(json!(null))
    };
    (status, body)
}

/// §5.3 devices + §5.4 holders/namespaces over the token lane: list, rename,
/// revoke (authority-honest), status, move (redirect recorded), forget
/// (revoke-then-delete with unrevocable surfaced), namespace lifecycle with
/// the machine-reason taxonomy.
#[tokio::test]
async fn devices_and_holders_over_the_token_lane() {
    use browserid_broker::store::DeviceCertRecord;
    let l = live_broker().await;
    let email = "wallet-owner@gmail.com";
    let (presentation, config_kp, device_cert, _config_cert) =
        broker_presentation(&l, email, vec!["registry".into()]).await;
    let (status, body) = exchange(&l, json!({ "presentation": presentation })).await;
    assert_eq!(status, 200, "{body}");
    let token = body["access_token"].as_str().unwrap().to_string();
    let holder =
        browserid_core::device::DeviceCert::parse(&device_cert).unwrap().holder().as_str().to_string();
    let call = |method: &'static str, path: &'static str, query: Option<&'static str>, body: Option<Value>| {
        api_call(&l, &config_kp, &token, method, path, query, body)
    };

    // §5.3 list: the bootstrap certs are listed under our holder, unrevoked.
    let (status, devices) = call("GET", "/api/v1/devices", None, None).await;
    assert_eq!(status, 200, "{devices}");
    let ours: Vec<&Value> =
        devices["certs"].as_array().unwrap().iter().filter(|c| c["holder"] == holder).collect();
    assert!(!ours.is_empty(), "bootstrap certs listed: {devices}");
    assert!(ours.iter().all(|c| c["revoked"] == false && c["iss"] == l.domain.as_str()));

    // §5.4 view: the holder sits in the browsers namespace, trusted (it holds
    // a config cert), not external.
    let (status, view) = call("GET", "/api/v1/holders", None, None).await;
    assert_eq!(status, 200, "{view}");
    let browsers = view["namespaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == "browsers")
        .expect("browsers namespace");
    let hv = browsers["holders"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["holder_id"] == holder)
        .expect("our holder in browsers");
    assert_eq!(hv["trust"], "trusted");
    assert_eq!(hv["external"], false);

    // Rename the holder; the label shows in the next view. Grammar violations
    // and owner-scoped misses use the §7 taxonomy.
    let (status, _) = call(
        "POST",
        "/api/v1/holders/rename",
        None,
        Some(json!({ "holder_id": holder, "label": "  My Wallet " })),
    )
    .await;
    assert_eq!(status, 204);
    let (_, view) = call("GET", "/api/v1/holders", None, None).await;
    let hv = view["namespaces"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|n| n["holders"].as_array().unwrap())
        .find(|h| h["holder_id"] == holder)
        .unwrap();
    assert_eq!(hv["label"], "My Wallet", "trimmed label applied");
    let (status, body) = call(
        "POST",
        "/api/v1/holders/rename",
        None,
        Some(json!({ "holder_id": holder, "label": "a\nb" })),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_request");
    let (status, body) = call(
        "POST",
        "/api/v1/holders/rename",
        None,
        Some(json!({ "holder_id": "nope.zzzz", "label": "X" })),
    )
    .await;
    assert_eq!(status, 404, "owner-scoped miss: {body}");
    assert_eq!(body["error"], "not_found");

    // Namespace lifecycle: grammar → create → rename → delete; deleting an
    // occupied namespace is a 409 with the §7.1 reason.
    let (status, body) =
        call("POST", "/api/v1/namespaces/create", None, Some(json!({ "name": "Not Valid!" }))).await;
    assert_eq!(status, 400, "{body}");
    let (status, _) =
        call("POST", "/api/v1/namespaces/create", None, Some(json!({ "name": "work" }))).await;
    assert_eq!(status, 204);
    let (status, _) = call(
        "POST",
        "/api/v1/namespaces/rename",
        None,
        Some(json!({ "name": "work", "label": "Work" })),
    )
    .await;
    assert_eq!(status, 204);
    let (_, view) = call("GET", "/api/v1/holders", None, None).await;
    let work =
        view["namespaces"].as_array().unwrap().iter().find(|n| n["name"] == "work").unwrap();
    assert_eq!(work["label"], "Work");
    assert_eq!(work["holders"].as_array().unwrap().len(), 0);
    let (status, body) = call(
        "POST",
        "/api/v1/namespaces/rename",
        None,
        Some(json!({ "name": "gone", "label": "X" })),
    )
    .await;
    assert_eq!(status, 404, "{body}");
    let (status, _) =
        call("POST", "/api/v1/namespaces/delete", None, Some(json!({ "name": "work" }))).await;
    assert_eq!(status, 204);
    let (status, body) =
        call("POST", "/api/v1/namespaces/delete", None, Some(json!({ "name": "browsers" }))).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["reason"], "namespace_not_empty");

    // Seed a second holder ("the bot") under agents, with an own-list status
    // ref, plus a foreign-issued cert — so revoke/move/forget can be
    // exercised without killing the cert our token is bound to.
    let user_id = l.user_store.get_email(email).unwrap().unwrap().user_id;
    let agents_prefix = l.user_store.get_or_create_namespace(user_id, "agents").unwrap();
    let bot_holder = format!("{agents_prefix}.botbot23");
    let bot_idx = l.user_store.get_or_allocate_status("device", "bot-pubkey").unwrap();
    let now = chrono::Utc::now();
    let own_status_uri = format!("{}/.well-known/browserid-status", l.base);
    let mk_cert = |holder: &str, pubkey: &str, iss: &str, uri: Option<String>, idx: Option<u64>| {
        DeviceCertRecord {
            id: 0,
            user_id,
            identities: vec![email.to_string()],
            purpose: "authentication".into(),
            holder: holder.to_string(),
            pubkey: pubkey.to_string(),
            iss: iss.to_string(),
            issued_at: now,
            expires_at: now + Duration::days(90),
            revoked_at: None,
            status_uri: uri,
            status_idx: idx,
            prov: "smtp".into(),
        }
    };
    l.user_store
        .insert_device_cert(mk_cert(
            &bot_holder,
            "bot-pubkey",
            &l.domain,
            Some(own_status_uri.clone()),
            Some(bot_idx),
        ))
        .unwrap();
    let foreign_holder = format!("{agents_prefix}.forgn234");
    l.user_store
        .insert_device_cert(mk_cert(
            &foreign_holder,
            "foreign-pubkey",
            "idp.partner.example",
            Some("https://idp.partner.example/.well-known/browserid-status".into()),
            Some(987_654),
        ))
        .unwrap();

    // §5.3 revoke: own-list authority → the bit flips and the API says so.
    let (_, devices) = call("GET", "/api/v1/devices", None, None).await;
    let bot_id = devices["certs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["holder"] == bot_holder)
        .unwrap()["id"]
        .as_u64()
        .unwrap();
    let (status, body) =
        call("POST", "/api/v1/devices/revoke", None, Some(json!({ "id": bot_id }))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["revoked"], true, "own list: the bit is ours to flip");
    assert!(l.user_store.is_status_revoked_idx(bot_idx).unwrap(), "bit actually flipped");
    let q = format!("id={bot_id}");
    let q: &'static str = Box::leak(q.into_boxed_str());
    let (status, body) = call("GET", "/api/v1/devices/status", Some(q), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "revoked");

    // A foreign-issued cert: the row hides, but the API MUST NOT claim the
    // cert is dead — its bit numbers the ISSUER's list (ft55).
    let (_, devices) = call("GET", "/api/v1/devices", None, None).await;
    let foreign_id = devices["certs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["holder"] == foreign_holder)
        .unwrap()["id"]
        .as_u64()
        .unwrap();
    let (status, body) =
        call("POST", "/api/v1/devices/revoke", None, Some(json!({ "id": foreign_id }))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["revoked"], false, "foreign issuer: not ours to revoke");
    assert!(
        !l.user_store.is_status_revoked_idx(987_654).unwrap(),
        "own-list idx NOT collaterally flipped for a foreign ref (ft55)"
    );
    let (status, body) =
        call("POST", "/api/v1/devices/revoke", None, Some(json!({ "id": 999999 }))).await;
    assert_eq!(status, 404, "owner-scoped miss: {body}");

    // §5.4 move: the bot moves to services — permanent redirect recorded,
    // and the view buckets it under the TARGET with the moving badge.
    let (status, body) = call(
        "POST",
        "/api/v1/holders/move",
        None,
        Some(json!({ "holder_id": bot_holder, "namespace": "services" })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let new_holder = body["new_holder"].as_str().unwrap().to_string();
    let services_prefix = l.user_store.get_or_create_namespace(user_id, "services").unwrap();
    assert!(new_holder.starts_with(&format!("{services_prefix}.")), "{new_holder}");
    let q = format!("holder={bot_holder}");
    let q: &'static str = Box::leak(q.into_boxed_str());
    let (status, body) = call("GET", "/api/v1/holders/assignment", Some(q), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "moved");
    assert_eq!(body["new_holder"], new_holder.as_str());
    let (_, view) = call("GET", "/api/v1/holders", None, None).await;
    let services = view["namespaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == "services")
        .unwrap();
    let moved = services["holders"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["holder_id"] == bot_holder)
        .expect("pending-moved holder files under its target");
    assert!(moved["moving_to"].is_string());

    // Our own holder is current, and moving it into the namespace it already
    // lives in is the §7.1 conflict — checked BEFORE anything is revoked.
    let q = format!("holder={holder}");
    let q: &'static str = Box::leak(q.into_boxed_str());
    let (_, body) = call("GET", "/api/v1/holders/assignment", Some(q), None).await;
    assert_eq!(body["status"], "current");
    let (status, body) = call(
        "POST",
        "/api/v1/holders/move",
        None,
        Some(json!({ "holder_id": holder, "namespace": "browsers" })),
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["reason"], "already_in_namespace");
    let (_, devices) = call("GET", "/api/v1/devices", None, None).await;
    assert!(
        devices["certs"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["holder"] == holder)
            .all(|c| c["revoked"] == false),
        "a refused move must not have revoked anything"
    );

    // §5.4 forget: revoke-then-delete. The bot (own issuer, has a ref) leaves
    // nothing unrevocable; the foreign holder surfaces its issuer.
    let (status, body) =
        call("POST", "/api/v1/holders/forget", None, Some(json!({ "holder_id": bot_holder }))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["unrevocable"], json!([]));
    let (status, body) = call(
        "POST",
        "/api/v1/holders/forget",
        None,
        Some(json!({ "holder_id": foreign_holder })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["unrevocable"], json!(["idp.partner.example"]));
    let (_, devices) = call("GET", "/api/v1/devices", None, None).await;
    assert!(
        !devices["certs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["holder"] == bot_holder || c["holder"] == foreign_holder),
        "forgotten holders' rows are gone"
    );

    // Through it all the token stayed alive: its own bound cert was never
    // touched.
    let (status, _) = call("GET", "/api/v1/devices", None, None).await;
    assert_eq!(status, 200);
}

// --- Shape-level checks that need no verification stack (axum_test) ---

#[tokio::test]
async fn exchange_rejects_unknown_scopes_and_bad_bodies() {
    let ctx = common::create_test_context_customized(|s| s.agent_provisioning_enabled = true);

    // Unknown requested scope → invalid_scope (checked before verification).
    let r = ctx
        .server
        .post("/api/v1/token")
        .json(&json!({ "presentation": "x~y~z~w", "scope": "registry admin" }))
        .await;
    assert_eq!(r.status_code(), 400);
    assert_eq!(r.json::<Value>()["error"], "invalid_scope");

    // Unknown FIELD → invalid_request (§4: unknown request fields rejected).
    let r = ctx
        .server
        .post("/api/v1/token")
        .json(&json!({ "presentation": "x~y~z~w", "csrf": "nope" }))
        .await;
    assert_eq!(r.status_code(), 400);
    assert_eq!(r.json::<Value>()["error"], "invalid_request");

    // Garbage presentation → invalid_grant / verification_failed, with no
    // finer detail (verification-oracle rule).
    let r = ctx
        .server
        .post("/api/v1/token")
        .json(&json!({ "presentation": "not~a~real~bundle" }))
        .await;
    assert_eq!(r.status_code(), 400);
    let body: Value = r.json();
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["reason"], "verification_failed");
}

#[tokio::test]
async fn support_document_advertises_the_registry() {
    let ctx = common::create_test_context_customized(|s| s.agent_provisioning_enabled = true);
    let doc: Value = ctx.server.get("/.well-known/browserid").await.json();
    let reg = &doc["registry"];
    assert_eq!(reg["version"], "v1");
    assert_eq!(reg["token_endpoint"], "http://localhost:3000/api/v1/token");
    assert_eq!(reg["status_list"], "http://localhost:3000/.well-known/browserid-status");
    assert!(reg["browser"].is_object(), "browser key is REQUIRED (may be empty)");

    // With the consent surface off, the origin serves no registry key.
    let (server, _mail) = common::create_test_server();
    let doc: Value = server.get("/.well-known/browserid").await.json();
    assert!(doc.get("registry").is_none());
}

/// The api_tokens table on the REAL sqlite schema — memory-store tests can't
/// see sqlite constraints (the 2026-08-14 FK-500 lesson), so round-trip the
/// record shapes against SqliteStore directly.
#[tokio::test]
async fn api_tokens_round_trip_on_sqlite() {
    use browserid_broker::store::{ApiTokenRecord, SqliteStore, UserId};
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(dir.path().join("t.db").to_str().unwrap()).unwrap();

    let now = chrono::Utc::now();
    let rec = ApiTokenRecord {
        token_hash: "hash-1".into(),
        user_id: UserId(42),
        proof_key: "pk-b64".into(),
        cert_status_uri: Some("http://localhost:3000/.well-known/browserid-status".into()),
        cert_status_idx: Some(7),
        scope: "registry".into(),
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
    };
    store.create_api_token(rec.clone()).unwrap();
    // Optional fields absent (a refless v1-warrant cert) round-trip too.
    store
        .create_api_token(ApiTokenRecord {
            token_hash: "hash-2".into(),
            cert_status_uri: None,
            cert_status_idx: None,
            expires_at: now - chrono::Duration::seconds(5), // already expired
            ..rec.clone()
        })
        .unwrap();

    let got = store.get_api_token("hash-1").unwrap().expect("row exists");
    assert_eq!(got.user_id, UserId(42));
    assert_eq!(got.proof_key, "pk-b64");
    assert_eq!(got.cert_status_idx, Some(7));
    assert_eq!(got.scope, "registry");
    assert!((got.expires_at - rec.expires_at).num_seconds().abs() <= 1);
    let got2 = store.get_api_token("hash-2").unwrap().expect("row exists");
    assert_eq!(got2.cert_status_uri, None);
    assert_eq!(got2.cert_status_idx, None);

    // Re-minting under the same hash upserts rather than erroring (PK).
    store.create_api_token(rec.clone()).unwrap();

    // Cleanup removes only the expired row.
    let removed = store.cleanup_expired_api_tokens().unwrap();
    assert_eq!(removed, 1);
    assert!(store.get_api_token("hash-1").unwrap().is_some());
    assert!(store.get_api_token("hash-2").unwrap().is_none());
}

// ===========================================================================
// §5.3 devices/register (fallback-idp-api-v1 §4: wallet-driven registration)
// ===========================================================================

/// A fresh device+config pair for an EXISTING account — the wallet's
/// re-issuance lane: password auth + the /device/issue core.
async fn issue_pair(l: &Live, email: &str) -> (String, String) {
    let post = |path: &str, body: Value| l.client.post(format!("{}{path}", l.base)).json(&body);
    let r = post("/wsapi/authenticate_user", json!({"email": email, "pass": "password123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let session = set_cookie(&r, "browserid_session");
    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let r = device_issue(l, &session, email, &device_kp, &config_kp).await;
    assert_eq!(r.status(), 200, "second device/issue");
    let certs: Value = r.json().await.unwrap();
    (
        certs["device_cert"].as_str().unwrap().to_string(),
        certs["config_cert"].as_str().unwrap().to_string(),
    )
}

/// POST /api/v1/devices/register with an optional User-Agent.
async fn register_call(
    l: &Live,
    kp: &KeyPair,
    token: &str,
    body: Value,
    ua: Option<&str>,
) -> (reqwest::StatusCode, Value) {
    let htu = format!("{}/api/v1/devices/register", l.base);
    let mut req = l
        .client
        .post(&htu)
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", build_proof("POST", &htu, token, kp))
        .json(&body);
    if let Some(ua) = ua {
        req = req.header("user-agent", ua);
    }
    let r = req.send().await.unwrap();
    let status = r.status();
    let body = if status == reqwest::StatusCode::NO_CONTENT {
        json!(null)
    } else {
        r.json().await.unwrap_or(json!(null))
    };
    (status, body)
}

/// §5.3 devices/register: verified pair recording, idempotency, the §7.1
/// invalid_cert taxonomy, the holder-move guard, and the UA label hook —
/// registration must work with NO issuer-side convenience rows present
/// (fallback-idp-api-v1 §4: wallets must not rely on issuer recording).
#[tokio::test]
async fn devices_register_over_the_token_lane() {
    let l = live_broker().await;
    let email = "wallet-register@gmail.com";
    let (presentation, config_kp, device_cert, config_cert) =
        broker_presentation(&l, email, vec!["registry".into()]).await;
    let (status, body) = exchange(&l, json!({ "presentation": presentation })).await;
    assert_eq!(status, 200, "{body}");
    let token = body["access_token"].as_str().unwrap().to_string();
    let holder = browserid_core::device::DeviceCert::parse(&device_cert)
        .unwrap()
        .holder()
        .as_str()
        .to_string();
    let user_id = l.user_store.get_email(email).unwrap().unwrap().user_id;

    // Wipe the issuer-side convenience rows: registration alone must record.
    UserStore::forget_holder(&*l.user_store, user_id, &holder).unwrap();
    let call = |method: &'static str, path: &'static str, query: Option<&'static str>, body: Option<Value>| {
        api_call(&l, &config_kp, &token, method, path, query, body)
    };
    let (_, devices) = call("GET", "/api/v1/devices", None, None).await;
    assert!(
        !devices["certs"].as_array().unwrap().iter().any(|c| c["holder"] == holder.as_str()),
        "precondition: no issuer-side rows remain"
    );

    // Register the pair (product-token UA → default holder label).
    let (status, body) = register_call(
        &l,
        &config_kp,
        &token,
        json!({ "device_cert": device_cert, "config_cert": config_cert }),
        Some("BrowserID-Wallet/0.1"),
    )
    .await;
    assert_eq!(status, 204, "register: {body}");
    let (_, devices) = call("GET", "/api/v1/devices", None, None).await;
    let ours: Vec<_> = devices["certs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["holder"] == holder.as_str())
        .collect();
    assert_eq!(ours.len(), 2, "both certs recorded: {devices}");
    let purposes: Vec<_> = ours.iter().map(|c| c["purpose"].as_str().unwrap()).collect();
    assert!(purposes.contains(&"authentication") && purposes.contains(&"authorization"));
    assert!(ours.iter().all(|c| c["revoked"] == false && c["iss"] == l.domain.as_str()));
    let labels = UserStore::get_holder_labels(&*l.user_store, user_id).unwrap();
    assert_eq!(labels.get(&holder).map(String::as_str), Some("BrowserID-Wallet"));

    // Idempotent: same pair again is a no-op success, and no duplicate rows.
    let (status, _) = register_call(
        &l,
        &config_kp,
        &token,
        json!({ "device_cert": device_cert, "config_cert": config_cert }),
        None,
    )
    .await;
    assert_eq!(status, 204, "re-register is idempotent");
    let (_, devices) = call("GET", "/api/v1/devices", None, None).await;
    let n = devices["certs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["holder"] == holder.as_str())
        .count();
    assert_eq!(n, 2, "no duplicate rows on re-register");

    // Swapped fields → wrong_purpose (the pair's roles are checked).
    let (status, body) = register_call(
        &l,
        &config_kp,
        &token,
        json!({ "device_cert": config_cert, "config_cert": device_cert }),
        None,
    )
    .await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["error"], "invalid_cert");
    assert_eq!(body["reason"], "wrong_purpose");

    // Unknown fields are rejected (§4).
    let (status, body) = register_call(
        &l,
        &config_kp,
        &token,
        json!({ "device_cert": device_cert, "config_cert": config_cert, "extra": 1 }),
        None,
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_request");

    // A second pair for the SAME account: internally consistent, but its
    // config cert is not the one this token is bound to.
    let (device2, config2) = issue_pair(&l, email).await;
    let (status, body) = register_call(
        &l,
        &config_kp,
        &token,
        json!({ "device_cert": device2, "config_cert": config2 }),
        None,
    )
    .await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["reason"], "config_cert_not_bound");

    // Mixing the pairs: different holders → holder_mismatch (checked before
    // the binding).
    let (status, body) = register_call(
        &l,
        &config_kp,
        &token,
        json!({ "device_cert": device2, "config_cert": config_cert }),
        None,
    )
    .await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["reason"], "holder_mismatch");

    // Another ACCOUNT's pair under our token → identity_not_owned.
    let other = "other-wallet@gmail.com";
    let (_, _, other_device, other_config) =
        broker_presentation(&l, other, vec!["registry".into()]).await;
    let (status, body) = register_call(
        &l,
        &config_kp,
        &token,
        json!({ "device_cert": other_device, "config_cert": other_config }),
        None,
    )
    .await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["reason"], "identity_not_owned");

    // A moved holder must not resurrect its old row: 409 holder_moved.
    UserStore::set_holder_move(&*l.user_store, user_id, &holder, "browsers.fresh12345").unwrap();
    let (status, body) = register_call(
        &l,
        &config_kp,
        &token,
        json!({ "device_cert": device_cert, "config_cert": config_cert }),
        None,
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"], "conflict");
    assert_eq!(body["reason"], "holder_moved");
}

/// registry-api-v1 §5.3 `notice` items (bean 0c49 step 1): an identity
/// leaving the account files one; it lists with the notice shape and no
/// grants, and cannot be answered.
#[tokio::test]
async fn notices_list_in_the_inbox_and_cannot_be_answered() {
    let l = live_broker().await;
    let email = format!("notice-{}@example.com", rand_suffix());
    let (presentation, config_kp, _dc, _cc) =
        broker_presentation(&l, &email, vec!["login".into(), "registry".into()]).await;
    let (status, body) = exchange(&l, json!({"presentation": presentation})).await;
    assert_eq!(status, 200, "{body}");
    let token = body["access_token"].as_str().unwrap().to_string();

    // A second identity on the account leaves it (the cascade is a pure
    // store operation; the HTTP triggers are the cookie lane + attach).
    let user_id = l.user_store.get_email(&email).unwrap().unwrap().user_id;
    l.user_store.add_email(user_id, "gone@example.com", true).unwrap();
    browserid_broker::membership::detach(l.user_store.as_ref(), user_id, "gone@example.com").unwrap();

    let (status, body) = api_call(&l, &config_kp, &token, "GET", "/api/v1/requests", None, None).await;
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
    let (status, body) = api_call(
        &l, &config_kp, &token, "POST", "/api/v1/requests/respond", None,
        Some(json!({"code": code, "approve": false})),
    )
    .await;
    assert_eq!(status, 404, "{body}");
    let (status, body) = api_call(
        &l, &config_kp, &token, "POST", "/api/v1/requests/claim", None,
        Some(json!({"code": code})),
    )
    .await;
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
    let (presentation, config_kp, device_cert, config_cert) =
        broker_presentation(&l, email, vec!["registry".into()]).await;
    // Record the pair (attach replaces this in step 4).
    let (status, body) = exchange(&l, json!({ "presentation": presentation })).await;
    assert_eq!(status, 200, "{body}");
    let legacy = body["access_token"].as_str().unwrap().to_string();
    let (status, body) = register_call(&l, &config_kp, &legacy, json!({"device_cert": device_cert, "config_cert": config_cert}), None).await;
    assert_eq!(status, 204, "{body}");
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
    let alloc = json!({"agent_email": email, "audience": "https://rp.example", "scopes": ["login"]});
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
    let (status, body, _) = session_call(&l, &auth_kp, &auth_token, "POST", "/api/v1/devices/revoke", Some(json!({"id": auth_id}))).await;
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
