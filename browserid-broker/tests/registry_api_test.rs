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

    // SMTP-fresh email cookie.
    let r = post("/auth/send", json!({"email": email})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let code = l.email_sender.get_code(email).expect("auth code emailed");
    let r = post("/auth/verify", json!({"email": email, "code": code})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let fb = set_cookie(&r, "fb_email");

    // Device + config certs.
    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let r = l
        .client
        .post(format!("{}/auth/device_cert", l.base))
        .header("cookie", format!("browserid_session={session}; fb_email={fb}"))
        .json(&json!({
            "email": email,
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": config_kp.public_key().to_base64(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "device_cert");
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
