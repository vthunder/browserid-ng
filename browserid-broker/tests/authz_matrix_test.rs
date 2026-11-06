// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Security audit 2026-11, WS5: the broker HTTP surface's authorization
//! matrix (threat model I15–I28, `docs/design/threat-model.md`).
//!
//! Every route is driven by the principals that can reach it — anonymous,
//! an account holder, a *different* account holder, a tenant admin — and
//! the expected status is asserted. The matrix is the durable regression
//! guard; the `#[ignore]` tests at the bottom encode findings that fail
//! today (`// AUDIT-2026-11 Dx: fails today`). Un-ignore one when its fix
//! lands; it then becomes a regression test.
//!
//! Report: `docs/security-audit-2026-11-ws5-http-surface.md`.

mod common;

use std::sync::Arc;

use axum_test::{TestResponse, TestServer};
use browserid_broker::store::{DeviceCertRecord, SqliteStore, UserStore};
use browserid_broker::tenant_keys::KeystoreKey;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::device::{DeviceCert, Holder, HolderMatcher, Purpose, Warrant};
use browserid_core::{KeyPair, StatusRef};
use chrono::{Duration, Utc};
use common::registry::{api_get, api_post, ApiSession};
use common::{create_user, get_csrf, MockEmailSender};
use serde_json::{json, Value};

const DOMAIN: &str = "localhost:3000";
const IDP_HOST: &str = "idp.localhost:3000";
const ALICE: &str = "alice@example.com";
const ALICE_BOT: &str = "alice+bot@example.com";
const BOB: &str = "bob@example.com";
const PASSWORD: &str = "correct horse battery";
const AUDIENCE: &str = "https://notes.example.com";
const TENANT: &str = "tenant.example";

struct Rig {
    server: TestServer,
    sender: MockEmailSender,
    idp: KeyPair,
    store: Arc<InMemoryUserStore>,
}

fn rig() -> Rig {
    let idp = KeyPair::generate();
    let sender = Arc::new(MockEmailSender::new());
    let store = Arc::new(InMemoryUserStore::new());
    let mut state = AppState::new_with_arcs(
        idp.clone(),
        DOMAIN.to_string(),
        store.clone(),
        Arc::new(InMemorySessionStore::new()),
        sender.clone(),
    );
    state.agent_provisioning_enabled = true;
    state.idp_host = IDP_HOST.to_string();
    state.tenant_keystore = Some(KeystoreKey::from_env_value(&"ab".repeat(32)).unwrap());
    let server = TestServer::new(routes::create_router(Arc::new(state))).unwrap();
    Rig { server, sender: MockEmailSender { sent: sender.sent.clone() }, idp, store }
}

/// A cookie-surface call: optional session cookie, JSON body.
async fn cookie_call(
    server: &TestServer,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> TestResponse {
    let mut req = match method {
        "GET" => server.get(path),
        "POST" => server.post(path),
        "PUT" => server.put(path),
        m => panic!("method {m}"),
    };
    if let Some(c) = cookie {
        req = req.add_cookie(cookie::Cookie::new("browserid_session", c.to_string()));
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    req.await
}

/// A `/api/v1` call with no Authorization and no Proof header at all.
async fn api_anon(server: &TestServer, method: &str, path: &str, body: Value) -> TestResponse {
    let bytes = body.to_string().into_bytes();
    let req = match method {
        "GET" => server.get(path),
        "POST" => server.post(path),
        "PUT" => server.put(path),
        m => panic!("method {m}"),
    };
    if method == "GET" {
        req.await
    } else {
        req.add_header("content-type", "application/json").bytes(bytes.into()).await
    }
}

async fn api_put(server: &TestServer, sess: &ApiSession, path: &str, body: Value) -> TestResponse {
    let origin = browserid_registrar::consent::public_origin(DOMAIN);
    let bytes = body.to_string().into_bytes();
    let proof = browserid_registrar::session::build_proof_now("PUT", &format!("{origin}{path}"), Some(&bytes), &sess.key);
    server
        .put(path)
        .add_header("authorization", format!("Bearer {}", sess.token))
        .add_header("proof", proof)
        .add_header("content-type", "application/json")
        .bytes(bytes.into())
        .await
}

fn agent_cert(idp: &KeyPair, agent_kp: &KeyPair, holder: &str) -> DeviceCert {
    DeviceCert::create(
        DOMAIN,
        &agent_kp.public_key(),
        Purpose::Authentication,
        Holder::new(holder).unwrap(),
        vec![ALICE_BOT.to_string()],
        Duration::days(90),
        idp,
        None,
    )
    .unwrap()
}

/// File a JIT consent request for Alice's agent; returns the code.
async fn file_agent_request(r: &Rig, agent_kp: &KeyPair) -> String {
    let cert = agent_cert(&r.idp, agent_kp, "ag.bot");
    let resp = common::registry::warrant_request(&r.server, DOMAIN, agent_kp, json!({
            "device_cert": cert.encoded(),
            "identity": ALICE_BOT,
            "grants": [{ "audience": AUDIENCE, "scopes": ["post"] }],
            "label": "matrix bot",
        }))
        .await;
    assert_eq!(resp.status_code(), 200, "warrant/request: {}", resp.text());
    resp.json::<Value>()["code"].as_str().unwrap().to_string()
}

/// The grant's allocated status index and the registry's status URI, read
/// from the approver's inbox.
async fn grant_status(server: &TestServer, sess: &ApiSession) -> (u64, String) {
    let inbox: Value = api_get(server, sess, "/api/v1/requests").await.json();
    let grant = &inbox["requests"][0]["grants"][0];
    (
        grant["status_idx"].as_u64().expect("status idx"),
        inbox["status_uri"].as_str().unwrap().to_string(),
    )
}

fn signed_warrant(config_kp: &KeyPair, status: StatusRef) -> Warrant {
    Warrant::create(
        ALICE_BOT,
        ALICE_BOT,
        HolderMatcher::new("ag.bot").unwrap(),
        AUDIENCE,
        vec!["post".into()],
        Duration::days(90),
        config_kp,
        Some(status),
    )
    .unwrap()
}

fn is_2xx(r: &TestResponse) -> bool {
    r.status_code().is_success()
}

// ===========================================================================
// 1. Anonymous principal
// ===========================================================================

/// Every cookie-session route refuses an anonymous caller (I27 / B7). Where
/// the body is parsed before the session is read, a well-formed body is sent
/// so the refusal we see is the auth one, not a 4xx from the extractor.
#[tokio::test]
async fn anon_is_refused_on_every_cookie_session_route() {
    let r = rig();
    let pub1 = KeyPair::generate().public_key().to_base64();
    let pub2 = KeyPair::generate().public_key().to_base64();
    let roster_path = format!("/wsapi/tenant/roster?domain={TENANT}&csrf=");
    // (method, path, body, expected statuses)
    let rows: Vec<(&str, &str, Option<Value>, &[u16])> = vec![
        ("GET", "/wsapi/list_emails", None, &[401]),
        ("POST", "/wsapi/update_password", Some(json!({"oldpass": "a", "newpass": "bbbbbbbbbb", "csrf": ""})), &[401]),
        ("POST", "/wsapi/set_password", Some(json!({"pass": "bbbbbbbbbb", "csrf": ""})), &[401, 422]),
        ("POST", "/wsapi/stage_email", Some(json!({"email": BOB, "csrf": ""})), &[401]),
        ("POST", "/wsapi/complete_email_addition", Some(json!({"token": "x", "csrf": ""})), &[401, 422]),
        ("POST", "/wsapi/remove_email", Some(json!({"email": BOB, "csrf": ""})), &[401]),
        ("GET", "/wsapi/parent_of?email=alice%2Bbot%40example.com", None, &[401]),
        ("POST", "/wsapi/set_parent", Some(json!({"email": ALICE_BOT, "parent": ALICE, "csrf": ""})), &[401, 422]),
        ("POST", "/wsapi/set_public_name", Some(json!({"email": ALICE, "public_name": "x", "csrf": ""})), &[401, 422]),
        ("POST", "/device/issue", Some(json!({"email": ALICE, "device_pubkey": pub1, "config_pubkey": pub2})), &[401]),
        ("GET", "/wsapi/issuer_revoke_url?iss=example.org", None, &[401]),
        ("GET", "/wsapi/browser_holder", None, &[401]),
        ("POST", "/wsapi/account_cancel", Some(json!({"password": PASSWORD, "csrf": ""})), &[401, 422]),
        ("POST", "/wsapi/session_admit", Some(json!({})), &[401]),
        ("GET", "/wsapi/tenant/list", None, &[401]),
        ("POST", "/wsapi/tenant/create", Some(json!({"csrf": "", "domain": TENANT, "admin_email": ALICE})), &[401]),
        ("GET", roster_path.as_str(), None, &[401]),
        ("POST", "/wsapi/tenant/check", Some(json!({"csrf": "", "domain": TENANT})), &[401]),
        ("POST", "/wsapi/tenant/delete", Some(json!({"csrf": "", "domain": TENANT, "confirm": TENANT})), &[401]),
        ("POST", "/wsapi/tenant/revoke_all", Some(json!({"csrf": "", "domain": TENANT})), &[401]),
        ("POST", "/agent-provision/prepare", Some(json!({"code": "apr_x", "csrf": ""})), &[401, 403, 422]),
        ("POST", "/agent-provision/complete", Some(json!({"code": "apr_x", "csrf": ""})), &[401, 403, 422]),
        ("POST", "/wsapi/auth_with_presentation", Some(json!({"presentation": "a~b~c~d"})), &[401, 400]),
    ];
    let mut failures = Vec::new();
    for (method, path, body, expected) in rows {
        let resp = cookie_call(&r.server, method, path, None, body).await;
        let status = resp.status_code().as_u16();
        if is_2xx(&resp) || !expected.contains(&status) {
            failures.push(format!("{method} {path}: got {status}, expected one of {expected:?}: {}", resp.text()));
        }
    }
    assert!(failures.is_empty(), "anonymous refusals:\n{}", failures.join("\n"));
}

/// Every `/api/v1` route behind `ApiUser` (I22) answers 401 to a caller with
/// no session and no proof. The handful that are anonymous by design are
/// pinned to their documented status so a change there is noticed.
#[tokio::test]
async fn anon_is_refused_on_every_api_v1_session_route() {
    let r = rig();
    let session_routes: Vec<(&str, &str)> = vec![
        ("GET", "/api/v1/login-keys"),
        ("POST", "/api/v1/login-keys/revoke"),
        ("POST", "/api/v1/login-keys/rename"),
        ("POST", "/api/v1/session/end"),
        ("POST", "/api/v1/account/attach"),
        ("POST", "/api/v1/account/detach"),
        ("POST", "/api/v1/account/delete"),
        ("GET", "/api/v1/account/policy"),
        ("PUT", "/api/v1/account/policy"),
        ("GET", "/api/v1/approvals"),
        ("POST", "/api/v1/approvals/approve"),
        ("POST", "/api/v1/approvals/deny"),
        ("GET", "/api/v1/requests"),
        ("POST", "/api/v1/requests/claim"),
        ("POST", "/api/v1/requests/respond"),
        ("GET", "/api/v1/warrants"),
        ("POST", "/api/v1/warrants/register"),
        ("POST", "/api/v1/warrants/revoke"),
        ("POST", "/api/v1/warrants/allocate_status"),
        ("GET", "/api/v1/certs"),
        ("POST", "/api/v1/certs/revoke"),
        ("GET", "/api/v1/holders"),
        ("POST", "/api/v1/holders/rename"),
        ("POST", "/api/v1/holders/forget"),
        ("POST", "/api/v1/namespaces/rename"),
        // Proof-bearing but sessionless lanes: a missing Proof header is
        // the same 401 (invalid_proof).
        ("POST", "/api/v1/accounts"),
        ("POST", "/api/v1/accounts/lookup"),
        ("POST", "/api/v1/login"),
    ];
    // `login` parses its body before reading the Proof header, so give it a
    // well-formed one; the missing header proof is still the refusal.
    let lk = KeyPair::generate();
    let origin = browserid_registrar::consent::public_origin(DOMAIN);
    let login_body = json!({"account": "acct_x", "method": "login_page", "token": "t",
        "login_key": {"pubkey": lk.public_key().to_base64(), "label": "x",
            "proof": browserid_registrar::session::build_proof_now("POST", &format!("{origin}/api/v1/login"), None, &lk)}});
    let mut failures = Vec::new();
    for (method, path) in session_routes {
        let body = if path == "/api/v1/login" { login_body.clone() } else { json!({}) };
        let resp = api_anon(&r.server, method, path, body).await;
        if resp.status_code() != 401 {
            failures.push(format!("{method} {path}: got {}: {}", resp.status_code(), resp.text()));
        }
    }
    assert!(failures.is_empty(), "api/v1 anonymous refusals:\n{}", failures.join("\n"));

    // Anonymous by design (documented in the WS5 report):
    //  - the filer's poll by secret code → an unknown code falls through to
    //    the provisioning lane, where unknown == expired (410)
    //  - the approval opener's poll by secret id → "pending" for unknown
    //  - opening an approval for any account id (enumeration-safe shape)
    let resp = api_anon(&r.server, "GET", "/api/v1/requests/no-such-code", json!({})).await;
    assert_eq!(resp.status_code(), 410, "poll unknown code: {}", resp.text());
    let resp = api_anon(&r.server, "GET", "/api/v1/approvals/no-such-id", json!({})).await;
    assert_eq!(resp.status_code(), 200);
    assert_eq!(resp.json::<Value>()["status"], "pending");
    let resp = api_anon(&r.server, "POST", "/api/v1/approvals", json!({"account": "acct_nobody"})).await;
    assert_eq!(resp.status_code(), 200, "open approval for unknown account: {}", resp.text());
    assert!(resp.json::<Value>()["code"].is_string());
}

/// A bearer token alone, without a Proof signed by the session's login key,
/// is not a session (I22): both a missing and a foreign-key proof refuse.
#[tokio::test]
async fn api_v1_session_needs_the_login_key_proof() {
    let r = rig();
    let cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let sess = common::registry::api_login(&r.server, &cookie, PASSWORD).await;
    // Bearer only.
    let resp = r
        .server
        .get("/api/v1/login-keys")
        .add_header("authorization", format!("Bearer {}", sess.token))
        .await;
    assert_eq!(resp.status_code(), 401, "{}", resp.text());
    // Bearer + proof by a key that is not the session's.
    let stranger = KeyPair::generate();
    let origin = browserid_registrar::consent::public_origin(DOMAIN);
    let proof = browserid_registrar::session::build_proof_now("GET", &format!("{origin}/api/v1/login-keys"), None, &stranger);
    let resp = r
        .server
        .get("/api/v1/login-keys")
        .add_header("authorization", format!("Bearer {}", sess.token))
        .add_header("proof", proof)
        .await;
    assert_eq!(resp.status_code(), 401, "{}", resp.text());
    // The real thing works.
    assert_eq!(api_get(&r.server, &sess, "/api/v1/login-keys").await.status_code(), 200);
}

// ===========================================================================
// 2. CSRF on the cookie surface
// ===========================================================================

/// Every state-changing cookie route refuses a session whose CSRF token is
/// missing or wrong (403), so a cross-site page holding the user's cookie
/// cannot drive it.
#[tokio::test]
async fn cookie_mutations_require_the_session_csrf_token() {
    let r = rig();
    let cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let pub1 = KeyPair::generate().public_key().to_base64();
    let pub2 = KeyPair::generate().public_key().to_base64();
    let rows: Vec<(&str, Value)> = vec![
        ("/wsapi/update_password", json!({"oldpass": PASSWORD, "newpass": "another long one", "csrf": "wrong"})),
        ("/wsapi/stage_email", json!({"email": "alice2@example.com", "csrf": "wrong"})),
        ("/wsapi/remove_email", json!({"email": ALICE, "csrf": "wrong"})),
        ("/device/issue", json!({"email": ALICE, "device_pubkey": pub1, "config_pubkey": pub2, "csrf": "wrong"})),
        ("/wsapi/tenant/create", json!({"csrf": "wrong", "domain": TENANT, "admin_email": ALICE})),
        ("/wsapi/tenant/check", json!({"csrf": "wrong", "domain": TENANT})),
    ];
    let mut failures = Vec::new();
    for (path, body) in rows {
        let resp = cookie_call(&r.server, "POST", path, Some(&cookie), Some(body)).await;
        if resp.status_code() != 403 {
            failures.push(format!("POST {path}: got {}: {}", resp.status_code(), resp.text()));
        }
    }
    assert!(failures.is_empty(), "csrf refusals:\n{}", failures.join("\n"));
    // Alice's account is intact: the password still works.
    let resp = r
        .server
        .post("/wsapi/authenticate_user")
        .json(&json!({"email": ALICE, "pass": PASSWORD}))
        .await;
    assert_eq!(resp.status_code(), 200);
}

// ===========================================================================
// 3. Another account holder
// ===========================================================================

/// Bob, with a full registry session of his own, cannot see or act on
/// Alice's objects: her consent request, her approval, her login key, her
/// certs, her holder, her identity. Every refusal is the unknown-object
/// shape (404) so existence does not leak across accounts (I25).
#[tokio::test]
async fn other_account_cannot_reach_a_users_objects() {
    let r = rig();
    let alice_cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let alice = common::registry::api_login(&r.server, &alice_cookie, PASSWORD).await;
    let bob_cookie = create_user(&r.server, &r.sender, BOB, PASSWORD).await;
    let bob = common::registry::api_login(&r.server, &bob_cookie, PASSWORD).await;

    // Alice gets a pending consent request, an approval, a login key, certs.
    let agent_kp = KeyPair::generate();
    let code = file_agent_request(&r, &agent_kp).await;
    let opened: Value = api_anon(&r.server, "POST", "/api/v1/approvals", json!({"account": alice.account})).await.json();
    let approval_id = opened["id"].as_str().unwrap().to_string();
    let approval_code = opened["code"].as_str().unwrap().to_string();
    let alice_keys: Value = api_get(&r.server, &alice, "/api/v1/login-keys").await.json();
    let alice_key_id = alice_keys["keys"][0]["id"].as_u64().or_else(|| alice_keys["login_keys"][0]["id"].as_u64());
    let alice_certs: Value = api_get(&r.server, &alice, "/api/v1/certs").await.json();
    let alice_cert_id = alice_certs["certs"][0]["id"].as_u64();
    let alice_holders: Value = api_get(&r.server, &alice, "/api/v1/holders").await.json();
    let alice_holder = alice_holders["holders"][0]["holder"].as_str()
        .or_else(|| alice_holders["holders"][0]["id"].as_str())
        .map(str::to_string);

    // Bob's inbox does not contain Alice's request.
    let inbox: Value = api_get(&r.server, &bob, "/api/v1/requests").await.json();
    assert_eq!(inbox["requests"].as_array().map(Vec::len), Some(0), "{inbox}");

    let mut rows: Vec<(&str, Value)> = vec![
        ("/api/v1/requests/respond", json!({"code": code, "approve": false})),
        ("/api/v1/requests/claim", json!({"code": code})),
        ("/api/v1/approvals/approve", json!({"id": approval_id, "code": approval_code})),
        ("/api/v1/approvals/deny", json!({"id": approval_id})),
        ("/api/v1/account/detach", json!({"identity": ALICE})),
    ];
    if let Some(id) = alice_key_id {
        rows.push(("/api/v1/login-keys/revoke", json!({"id": id})));
        rows.push(("/api/v1/login-keys/rename", json!({"id": id, "label": "pwned"})));
    }
    if let Some(id) = alice_cert_id {
        rows.push(("/api/v1/certs/revoke", json!({"id": id})));
    }
    if let Some(h) = alice_holder.clone() {
        rows.push(("/api/v1/holders/rename", json!({"holder_id": h, "label": "pwned"})));
        rows.push(("/api/v1/holders/forget", json!({"holder_id": h})));
    }
    let mut failures = Vec::new();
    for (path, body) in rows {
        let resp = api_post(&r.server, &bob, path, body).await;
        if resp.status_code() != 404 {
            failures.push(format!("POST {path} as bob: got {}: {}", resp.status_code(), resp.text()));
        }
    }
    assert!(failures.is_empty(), "cross-account refusals:\n{}", failures.join("\n"));

    // Alice is untouched: her session, request and approval still live.
    assert_eq!(api_get(&r.server, &alice, "/api/v1/login-keys").await.status_code(), 200);
    let inbox: Value = api_get(&r.server, &alice, "/api/v1/requests").await.json();
    assert_eq!(inbox["requests"].as_array().map(Vec::len), Some(1), "{inbox}");
    let poll: Value = api_anon(&r.server, "GET", &format!("/api/v1/approvals/{approval_id}"), json!({})).await.json();
    assert_eq!(poll["status"], "pending");
}

/// The cookie surface: Bob's session cannot issue certs for Alice's address
/// or remove it (admitted session, correct CSRF, foreign identity).
#[tokio::test]
async fn other_account_cannot_issue_or_remove_a_foreign_identity() {
    let r = rig();
    let _alice = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let bob = create_user(&r.server, &r.sender, BOB, PASSWORD).await;
    let csrf = get_csrf(&r.server, &bob).await;
    let resp = cookie_call(
        &r.server,
        "POST",
        "/device/issue",
        Some(&bob),
        Some(json!({
            "email": ALICE,
            "device_pubkey": KeyPair::generate().public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
            "csrf": csrf,
        })),
    )
    .await;
    assert!(!is_2xx(&resp), "bob issued for alice: {}", resp.text());
    let resp = cookie_call(&r.server, "POST", "/wsapi/remove_email", Some(&bob), Some(json!({"email": ALICE, "csrf": csrf}))).await;
    assert!(!is_2xx(&resp), "bob removed alice's email: {}", resp.text());
    assert!(r.store.get_email(ALICE).unwrap().is_some(), "alice's email survived");
}

// ===========================================================================
// 4. Tenant admin
// ===========================================================================

/// Tenant management (`/wsapi/tenant/*`) is reachable only by the tenant's
/// admin or owner: anonymous → 401, a stranger with a session → 403,
/// the owner → 200.
#[tokio::test]
async fn tenant_routes_admit_only_the_tenants_admin() {
    let r = rig();
    let alice_cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let bob_cookie = create_user(&r.server, &r.sender, BOB, PASSWORD).await;
    let alice_id = r.store.get_email(ALICE).unwrap().unwrap().user_id;
    let ks = KeystoreKey::from_env_value(&"ab".repeat(32)).unwrap();
    let (public_key, sealed) = ks.generate_sealed(TENANT).unwrap();
    r.store.create_tenant(TENANT, &public_key, &sealed, Some(alice_id), ALICE).unwrap();

    let alice_csrf = get_csrf(&r.server, &alice_cookie).await;
    let bob_csrf = get_csrf(&r.server, &bob_cookie).await;

    let resp = cookie_call(&r.server, "GET", &format!("/wsapi/tenant/roster?domain={TENANT}&csrf={alice_csrf}"), Some(&alice_cookie), None).await;
    assert_eq!(resp.status_code(), 200, "owner roster: {}", resp.text());
    let resp = cookie_call(&r.server, "GET", &format!("/wsapi/tenant/roster?domain={TENANT}&csrf={bob_csrf}"), Some(&bob_cookie), None).await;
    assert_eq!(resp.status_code(), 403, "stranger roster: {}", resp.text());
    let resp = cookie_call(&r.server, "GET", &format!("/wsapi/tenant/roster?domain={TENANT}&csrf="), None, None).await;
    assert_eq!(resp.status_code(), 401, "anon roster: {}", resp.text());

    // Mutations as a stranger (correct CSRF for HIS session) are refused and
    // leave the tenant standing.
    let rows: Vec<(&str, Value)> = vec![
        ("/wsapi/tenant/roster", json!({"csrf": bob_csrf, "domain": TENANT, "local": "mallory", "password": "hunter2hunter2"})),
        ("/wsapi/tenant/admins", json!({"csrf": bob_csrf, "domain": TENANT, "email": BOB})),
        ("/wsapi/tenant/revoke_all", json!({"csrf": bob_csrf, "domain": TENANT})),
        ("/wsapi/tenant/delete", json!({"csrf": bob_csrf, "domain": TENANT})),
        ("/wsapi/tenant/management", json!({"csrf": bob_csrf, "domain": TENANT, "managed": true})),
    ];
    let mut failures = Vec::new();
    for (path, body) in rows {
        let resp = cookie_call(&r.server, "POST", path, Some(&bob_cookie), Some(body)).await;
        if is_2xx(&resp) {
            failures.push(format!("POST {path} as stranger: got {}: {}", resp.status_code(), resp.text()));
        }
    }
    assert!(failures.is_empty(), "tenant stranger refusals:\n{}", failures.join("\n"));
    assert!(r.store.get_tenant(TENANT).unwrap().is_some(), "tenant survived");
}

// ===========================================================================
// 5. Return-origin gating (I15, fb §3.1) and proof replay (I22)
// ===========================================================================

/// The cookie lane of `/device/issue` refuses a `return_origin` outside the
/// accepted set at the endpoint, not just on the page. An absent
/// `return_origin` is the broker's own dialog (same-origin, CSRF-bound) and
/// is allowed: the certs then go back to the caller's own storage, never to
/// a return_url. (WS1 appendix question; see report.)
#[tokio::test]
async fn device_issue_checks_return_origin_at_the_endpoint() {
    let r = rig();
    let cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let csrf = get_csrf(&r.server, &cookie).await;
    let body = |ro: Option<&str>| {
        let mut b = json!({
            "email": ALICE,
            "device_pubkey": KeyPair::generate().public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
            "csrf": csrf,
        });
        if let Some(ro) = ro {
            b["return_origin"] = json!(ro);
        }
        b
    };
    let resp = cookie_call(&r.server, "POST", "/device/issue", Some(&cookie), Some(body(Some("https://evil.example")))).await;
    assert_eq!(resp.status_code(), 403, "foreign return_origin: {}", resp.text());
    let resp = cookie_call(&r.server, "POST", "/device/issue", Some(&cookie), Some(body(Some("http://127.0.0.1:4321")))).await;
    assert_eq!(resp.status_code(), 200, "loopback return_origin: {}", resp.text());
    let resp = cookie_call(&r.server, "POST", "/device/issue", Some(&cookie), Some(body(None))).await;
    assert_eq!(resp.status_code(), 200, "absent return_origin (own dialog): {}", resp.text());
}

/// D10 refuted: a proof's `jti` is single-use per key, and a possession
/// proof must share the header proof's `jti`, so a captured proof cannot be
/// replayed in another request.
#[tokio::test]
async fn proof_jti_replay_is_rejected() {
    let r = rig();
    let cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let sess = common::registry::api_login(&r.server, &cookie, PASSWORD).await;
    let origin = browserid_registrar::consent::public_origin(DOMAIN);
    let path = "/api/v1/login-keys";
    let proof = browserid_registrar::session::build_proof_now("GET", &format!("{origin}{path}"), None, &sess.key);
    let call = |p: String| {
        r.server
            .get(path)
            .add_header("authorization", format!("Bearer {}", sess.token))
            .add_header("proof", p)
    };
    assert_eq!(call(proof.clone()).await.status_code(), 200);
    let replay = call(proof).await;
    assert_eq!(replay.status_code(), 401, "replayed jti: {}", replay.text());
    assert_eq!(replay.json::<Value>()["error"], "invalid_proof");
}

// ===========================================================================
// 6. Findings that fail today (AUDIT-2026-11). Un-ignore when fixed.
// ===========================================================================

/// D2 (audit 2026-11, fixed in bean 0fy3): `respond` refuses a "config
/// cert" no issuer signed. It used to check purpose, expiry, identity and
/// that the warrant was signed by the cert's key, but never the issuer
/// signature, nor that the key is a recorded, unretired cert of the
/// account (I20, B4) — and the approval was delivered to the filer.
#[tokio::test]
async fn respond_refuses_a_config_cert_the_issuer_never_signed() {
    let r = rig();
    let cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let sess = common::registry::api_login(&r.server, &cookie, PASSWORD).await;
    let agent_kp = KeyPair::generate();
    let code = file_agent_request(&r, &agent_kp).await;
    let (idx, uri) = grant_status(&r.server, &sess).await;

    // A self-minted config cert: signed by a key nobody published.
    let rogue_issuer = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let fake_config = DeviceCert::create(
        DOMAIN,
        &config_kp.public_key(),
        Purpose::Authorization,
        Holder::new("br.fake").unwrap(),
        vec![ALICE_BOT.to_string()],
        Duration::days(90),
        &rogue_issuer,
        None,
    )
    .unwrap();
    let warrant = signed_warrant(&config_kp, StatusRef { uri, idx });
    let resp = api_post(
        &r.server,
        &sess,
        "/api/v1/requests/respond",
        json!({ "code": code, "approve": true, "warrants": [warrant.encoded()], "config_cert": fake_config.encoded() }),
    )
    .await;
    assert_ne!(resp.status_code(), 200, "unsigned config cert accepted: {}", resp.text());
    let poll: Value = r.server.post("/warrant/poll").json(&json!({"code": code})).await.json();
    assert_ne!(poll["status"], "approved", "forged approval delivered: {poll}");
}

/// D2 variant (fixed in bean 0fy3): a config cert the issuer DID sign but
/// which this registry has never recorded under the account — or has
/// retired — is refused `config_cert_not_recorded`. Here: a cert minted for
/// a different holder than any the account has, never attached.
#[tokio::test]
async fn respond_refuses_a_config_cert_not_recorded_on_the_account() {
    let r = rig();
    let cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let sess = common::registry::api_login(&r.server, &cookie, PASSWORD).await;
    let agent_kp = KeyPair::generate();
    let code = file_agent_request(&r, &agent_kp).await;
    let (idx, uri) = grant_status(&r.server, &sess).await;
    let config_kp = KeyPair::generate();
    let unrecorded = DeviceCert::create(
        DOMAIN,
        &config_kp.public_key(),
        Purpose::Authorization,
        Holder::new("zz.elsewhere").unwrap(),
        vec![ALICE.to_string(), "alice+*@example.com".to_string()],
        Duration::days(90),
        &r.idp,
        None,
    )
    .unwrap();
    assert!(r.store.get_device_cert_by_pubkey(&config_kp.public_key().to_base64()).unwrap().is_none());
    let warrant = signed_warrant(&config_kp, StatusRef { uri, idx });
    let resp = api_post(
        &r.server,
        &sess,
        "/api/v1/requests/respond",
        json!({ "code": code, "approve": true, "warrants": [warrant.encoded()], "config_cert": unrecorded.encoded() }),
    )
    .await;
    assert_ne!(resp.status_code(), 200, "unrecorded config cert accepted: {}", resp.text());
    assert_eq!(resp.json::<Value>()["reason"], "config_cert_not_recorded", "{}", resp.text());
}

/// D4 (audit 2026-11, fixed in bean jvfr): `/warrant/request` used to take
/// the agent's PUBLIC device cert and nothing signed by the agent's key, so
/// anyone who had seen the cert (every audience it presented to) could
/// file consent requests in the agent's name (§7.5 step 1). A filing now
/// carries a `Proof` header the device key signs over the body: none, one
/// by another key, one over different bytes, and a replayed one are all
/// refused; the party below never touches `agent_kp`'s private half.
#[tokio::test]
async fn warrant_request_needs_a_signature_by_the_agent_key() {
    let r = rig();
    let _cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let agent_kp = KeyPair::generate();
    let cert = agent_cert(&r.idp, &agent_kp, "ag.bot");
    let body = json!({
        "device_cert": cert.encoded(),
        "identity": ALICE_BOT,
        "grants": [{ "audience": AUDIENCE, "scopes": ["post"] }],
    });
    // No proof at all.
    let resp = r.server.post("/warrant/request").json(&body).await;
    assert_ne!(resp.status_code(), 200, "unsigned filing accepted: {}", resp.text());
    // A proof by a key that is not the cert's.
    let resp = common::registry::warrant_request(&r.server, DOMAIN, &KeyPair::generate(), body.clone()).await;
    assert_ne!(resp.status_code(), 200, "foreign-key proof accepted: {}", resp.text());
    // The right key over the wrong bytes (bh binds the body).
    let htu = format!("{}/warrant/request", browserid_registrar::consent::public_origin(DOMAIN));
    let other = json!({"x": 1}).to_string().into_bytes();
    let header = browserid_registrar::session::build_proof_now("POST", &htu, Some(&other), &agent_kp);
    let resp = r
        .server
        .post("/warrant/request")
        .add_header("proof", header)
        .add_header("content-type", "application/json")
        .bytes(body.to_string().into_bytes().into())
        .await;
    assert_ne!(resp.status_code(), 200, "proof over other bytes accepted: {}", resp.text());
    // The genuine filing, and its replay (same jti) refused.
    let bytes = body.to_string().into_bytes();
    let header = browserid_registrar::session::build_proof_now("POST", &htu, Some(&bytes), &agent_kp);
    let send = |h: String| {
        r.server
            .post("/warrant/request")
            .add_header("proof", h)
            .add_header("content-type", "application/json")
            .bytes(bytes.clone().into())
    };
    let first = send(header.clone()).await;
    assert_eq!(first.status_code(), 200, "{}", first.text());
    let replay = send(header).await;
    assert_ne!(replay.status_code(), 200, "replayed proof accepted: {}", replay.text());
    drop(agent_kp);
}

/// AUDIT-2026-11 D8: thirty wrong `login_page` tokens against one account
/// from one IP trip the registry's failures-only login bucket (reg §3:
/// `429 slow_down`; the token is high-entropy, so this is amplification
/// and policy, not takeover — see report).
#[tokio::test]
async fn api_v1_login_guessing_is_throttled() {
    let r = rig();
    let cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let sess = common::registry::api_login(&r.server, &cookie, PASSWORD).await;
    let origin = browserid_registrar::consent::public_origin(DOMAIN);
    let path = "/api/v1/login";
    let htu = format!("{origin}{path}");
    let mut saw_429 = false;
    for i in 0..30 {
        let key = KeyPair::generate();
        let now = Utc::now().timestamp();
        let jti = format!("guess-{i}");
        let body = json!({
            "account": sess.account, "method": "login_page", "token": format!("not-the-token-{i}"),
            "login_key": { "pubkey": key.public_key().to_base64(), "label": "x",
                "proof": browserid_registrar::session::build_proof("POST", &htu, None, &key, now, &jti) },
        })
        .to_string()
        .into_bytes();
        let header = browserid_registrar::session::build_proof("POST", &htu, Some(&body), &key, now, &jti);
        let resp = r
            .server
            .post(path)
            .add_header("proof", header)
            .add_header("content-type", "application/json")
            .add_header("x-forwarded-for", "203.0.113.7")
            .bytes(body.into())
            .await;
        assert_ne!(resp.status_code(), 200, "a guessed token logged in");
        if resp.status_code() == 429 {
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "30 bad login tokens from one IP were never rate-limited");
}

/// The `403 login_required` answer is the first step of every page login
/// (registry-api-v1 §4.2), not a failed guess: it must never feed the
/// per-source failure bucket, or one shared address locks out after
/// twenty sign-ins (regression found by e2e on 2026-11-06, bean 4r2j).
#[tokio::test]
async fn api_v1_login_required_is_not_a_failure() {
    let r = rig();
    let cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let sess = common::registry::api_login(&r.server, &cookie, PASSWORD).await;
    for _ in 0..40 {
        let resp = r
            .server
            .post("/api/v1/login")
            .add_header("content-type", "application/json")
            .add_header("x-forwarded-for", "203.0.113.8")
            .json(&json!({ "account": sess.account, "method": "login_page" }))
            .await;
        assert_eq!(resp.status_code(), 403, "no token: expected login_required");
        assert_eq!(resp.json::<serde_json::Value>()["reason"], "login_required");
    }
}

/// D9 (audit 2026-11, fixed in bean cd6r): `accounts/lookup` checks the
/// possession proof under the cert's own key — and its claims and replay —
/// before any issuer discovery, so a garbage proof with a foreign-issuer
/// cert is `invalid_proof` with no network touched (I2).
#[tokio::test]
async fn lookup_checks_the_possession_proof_before_any_fetch() {
    let r = rig();
    let _cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let foreign_idp = KeyPair::generate();
    let device_kp = KeyPair::generate();
    let cert = DeviceCert::create(
        "nonexistent-idp.invalid",
        &device_kp.public_key(),
        Purpose::Authentication,
        Holder::new("xx.dev").unwrap(),
        vec!["alice@nonexistent-idp.invalid".to_string()],
        Duration::days(1),
        &foreign_idp,
        None,
    )
    .unwrap();
    let origin = browserid_registrar::consent::public_origin(DOMAIN);
    let path = "/api/v1/accounts/lookup";
    let htu = format!("{origin}{path}");
    let now = Utc::now().timestamp();
    let signer = KeyPair::generate(); // NOT the device key: the proof must fail locally
    let body = json!({
        "identity": "alice@nonexistent-idp.invalid",
        "certs": [{ "cert": cert.encoded(), "proof": browserid_registrar::session::build_proof("POST", &htu, None, &signer, now, "j1") }],
    })
    .to_string()
    .into_bytes();
    let header = browserid_registrar::session::build_proof("POST", &htu, Some(&body), &device_kp, now, "j1");
    let resp = r
        .server
        .post(path)
        .add_header("proof", header)
        .add_header("content-type", "application/json")
        .bytes(body.into())
        .await;
    let v: Value = resp.json();
    assert_eq!(v["error"], "invalid_proof", "expected the local proof check first, got {v}");
}

/// D11 (audit 2026-11, fixed in bean uphh): the SQLite upsert on `pubkey`
/// used to rewrite identities, holder and login key but keep the OLD
/// `user_id`, so a key already active on account A, recorded from account
/// B, left a row that belonged to A yet named B's identity, holder and
/// login key. Both stores now move the whole row (and the registrar only
/// records a foreign active key when its identity moves with it). Runs on
/// SqliteStore because the memory store never had the bug.
#[test]
fn sqlite_upsert_of_a_key_active_on_another_account_keeps_the_row_coherent() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = SqliteStore::open(dir.path().join("t.db").to_str().unwrap()).unwrap();
    let a = store.create_user("h").unwrap();
    let b = store.create_user("h").unwrap();
    let now = Utc::now();
    let row = |user, identity: &str, holder: &str| DeviceCertRecord {
        id: 0,
        user_id: user,
        identities: vec![identity.to_string()],
        purpose: "authentication".into(),
        holder: holder.into(),
        pubkey: "SHARED_PUBKEY".into(),
        iss: DOMAIN.into(),
        issued_at: now,
        expires_at: now + Duration::days(90),
        revoked_at: None,
        status_uri: None,
        status_idx: None,
        prov: "smtp".into(),
        login_key_id: None,
    };
    store.insert_device_cert(row(a, ALICE, "aa.one")).unwrap();
    store.insert_device_cert(row(b, BOB, "bb.two")).unwrap();
    let got = store.get_device_cert_by_pubkey("SHARED_PUBKEY").unwrap().unwrap();
    let coherent = (got.user_id == b && got.holder == "bb.two" && got.identities == vec![BOB.to_string()])
        || (got.user_id == a && got.holder == "aa.one" && got.identities == vec![ALICE.to_string()]);
    assert!(
        coherent,
        "row straddles two accounts: user_id={:?} holder={} identities={:?} (a={:?}, b={:?})",
        got.user_id, got.holder, got.identities, a, b
    );
}

/// D18 (audit 2026-11, fixed in bean jvfr): the JIT lane takes at most 8
/// grants (request-kinds/warrant) and refuses duplicate audiences in one
/// request.
#[tokio::test]
async fn warrant_request_caps_grants_at_eight_and_rejects_duplicate_audiences() {
    let r = rig();
    let _cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let agent_kp = KeyPair::generate();
    let cert = agent_cert(&r.idp, &agent_kp, "ag.bot");
    let nine: Vec<Value> = (0..9).map(|i| json!({"audience": format!("https://a{i}.example.com"), "scopes": ["post"]})).collect();
    let resp = common::registry::warrant_request(&r.server, DOMAIN, &agent_kp, json!({"device_cert": cert.encoded(), "identity": ALICE_BOT, "grants": nine})).await;
    assert_ne!(resp.status_code(), 200, "nine grants accepted: {}", resp.text());
    let eight: Vec<Value> = (0..8).map(|i| json!({"audience": format!("https://a{i}.example.com"), "scopes": ["post"]})).collect();
    let resp = common::registry::warrant_request(&r.server, DOMAIN, &agent_kp, json!({"device_cert": cert.encoded(), "identity": ALICE_BOT, "grants": eight})).await;
    assert_eq!(resp.status_code(), 200, "eight grants refused: {}", resp.text());
    let dup = vec![
        json!({"audience": AUDIENCE, "scopes": ["post"]}),
        json!({"audience": AUDIENCE, "scopes": ["read"]}),
    ];
    let resp = common::registry::warrant_request(&r.server, DOMAIN, &agent_kp, json!({"device_cert": cert.encoded(), "identity": ALICE_BOT, "grants": dup})).await;
    assert_ne!(resp.status_code(), 200, "duplicate audiences accepted: {}", resp.text());
}

/// AUDIT-2026-11 W5-1 (I18): a poll faster than `interval` gets 429
/// (`RegistrarError::PollTooFast`), not 400 `slow_down`. The registrar
/// change lands with bean 0fy3 (fix-registrar's branch); this goes green
/// once the two branches merge.
#[tokio::test]
async fn poll_too_fast_is_429() {
    let r = rig();
    let _cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let agent_kp = KeyPair::generate();
    let code = file_agent_request(&r, &agent_kp).await;
    let first = api_anon(&r.server, "GET", &format!("/api/v1/requests/{code}"), json!({})).await;
    assert_eq!(first.status_code(), 200, "{}", first.text());
    let second = api_anon(&r.server, "GET", &format!("/api/v1/requests/{code}"), json!({})).await;
    assert_eq!(second.status_code(), 429, "fast poll: {} {}", second.status_code(), second.text());
}

/// AUDIT-2026-11 W5-2: the hosted-primary password endpoint `/idp/login`
/// is throttled per client IP like the broker login (July M6).
#[tokio::test]
async fn idp_login_is_throttled() {
    let r = rig();
    let ks = KeystoreKey::from_env_value(&"ab".repeat(32)).unwrap();
    let (public_key, sealed) = ks.generate_sealed(TENANT).unwrap();
    r.store.create_tenant(TENANT, &public_key, &sealed, None, "admin@example.org").unwrap();
    r.store.set_tenant_status(TENANT, browserid_broker::store::TenantStatus::Active).unwrap();
    let tenant = r.store.get_tenant(TENANT).unwrap().unwrap();
    r.store.create_roster_entry(tenant.id, "carol", &bcrypt::hash("right one", 4).unwrap(), false, "admin@example.org").unwrap();
    let mut saw_429 = false;
    for i in 0..25 {
        let resp = r
            .server
            .post("/idp/login")
            .add_header("x-forwarded-for", "203.0.113.9")
            .json(&json!({"email": format!("carol@{TENANT}"), "password": format!("wrong-{i}")}))
            .await;
        assert_ne!(resp.status_code(), 200);
        if resp.status_code() == 429 {
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "25 wrong tenant passwords from one IP were never rate-limited");
}

/// W5-3 (audit 2026-11, fixed in bean imn6): `/wsapi/record_device_cert`
/// is unauthenticated; it used to look the identity up BEFORE verifying
/// the cert's signature, so an unsigned config cert naming an address
/// answered "no account holds this identity" for strangers and something
/// else for real accounts (July M7 class). The signature is checked first
/// now and every refusal is the one generic answer.
#[tokio::test]
async fn record_device_cert_does_not_reveal_account_existence() {
    let r = rig();
    let _cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let rogue = KeyPair::generate();
    let mk = |who: &str| {
        DeviceCert::create(
            "example.com",
            &KeyPair::generate().public_key(),
            Purpose::Authorization,
            Holder::new("xx.dev").unwrap(),
            vec![who.to_string()],
            Duration::days(1),
            &rogue,
            None,
        )
        .unwrap()
        .encoded()
        .to_string()
    };
    let exists: Value = r.server.post("/wsapi/record_device_cert").json(&json!({"config_cert": mk(ALICE)})).await.json();
    let absent: Value = r.server.post("/wsapi/record_device_cert").json(&json!({"config_cert": mk("nobody@example.com")})).await.json();
    assert_eq!(exists, absent, "existence oracle: {exists} vs {absent}");
}

/// W5-4 (audit 2026-11, decision Q4 (a), fixed in bean a7mx): a password
/// change on the cookie surface ends cookie sessions (July H2) AND retires
/// every registry login key enrolled by password — with its bearer
/// sessions — except the key the changing session is bound to; keys
/// enrolled by identity proofs or approval stay. So a wallet an attacker
/// enrolled with the old password does not keep the account.
#[tokio::test]
async fn password_change_ends_registry_sessions_enrolled_by_password() {
    let r = rig();
    let cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let sess = common::registry::api_login(&r.server, &cookie, PASSWORD).await;
    assert_eq!(api_get(&r.server, &sess, "/api/v1/login-keys").await.status_code(), 200);
    // The session making the change is admitted on its own password-enrolled
    // key (create_user admits the browser): that key must survive.
    let ctx: Value = cookie_call(&r.server, "GET", "/wsapi/session_context", Some(&cookie), None).await.json();
    assert_eq!(ctx["admitted"], true, "{ctx}");
    let csrf = get_csrf(&r.server, &cookie).await;
    let resp = cookie_call(
        &r.server,
        "POST",
        "/wsapi/update_password",
        Some(&cookie),
        Some(json!({"oldpass": PASSWORD, "newpass": "a brand new long password", "csrf": csrf})),
    )
    .await;
    assert_eq!(resp.status_code(), 200, "update_password: {}", resp.text());
    // The change re-mints the caller's cookie session (July H2).
    let fresh = resp.cookie("browserid_session").value().to_string();
    let after = api_get(&r.server, &sess, "/api/v1/login-keys").await;
    assert_eq!(after.status_code(), 401, "registry session survived the password change: {}", after.text());
    // The changing browser is still admitted on its own key.
    let ctx: Value = cookie_call(&r.server, "GET", "/wsapi/session_context", Some(&fresh), None).await.json();
    assert_eq!(ctx["admitted"], true, "the changing session lost its own key: {ctx}");
    // Its key is live; the other password-enrolled key is revoked.
    let user = r.store.get_user_by_email(ALICE).unwrap().unwrap();
    let keys = r.store.list_login_certs(user.id).unwrap();
    let revoked = keys.iter().find(|k| k.kid == sess.key.public_key().kid()).expect("the wallet's key");
    assert!(revoked.revoked_at.is_some(), "the other password-enrolled key survived");
    assert!(keys.iter().any(|k| k.revoked_at.is_none() && k.enrolled_by == "password"), "the changing session's own key was retired");
}

/// Policy PUT is session-bound like every other mutation (I22) and only
/// tightens (I25): a stranger's PUT is 401, the owner's loosening attempt is
/// refused. Runs today; here so the matrix covers the one PUT route.
#[tokio::test]
async fn policy_put_is_owner_only_and_only_tightens() {
    let r = rig();
    let cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let sess = common::registry::api_login(&r.server, &cookie, PASSWORD).await;
    let resp = api_anon(&r.server, "PUT", "/api/v1/account/policy", json!({"proofs": 1})).await;
    assert_eq!(resp.status_code(), 401);
    let current: Value = api_get(&r.server, &sess, "/api/v1/account/policy").await.json();
    assert!(current.is_object(), "{current}");
    // Looser than the floor: zero proofs.
    let resp = api_put(&r.server, &sess, "/api/v1/account/policy", json!({"proofs": 0})).await;
    assert!(!is_2xx(&resp), "policy loosened below the floor: {}", resp.text());
}

// ===========================================================================
// 7. Divergences from the spec as amended by WS1 (commit d221cb3)
// ===========================================================================

/// AUDIT-2026-11 W5-10: fails today. Reg §4.2 (amended): the login-page
/// token is delivered only to an accepted return origin, and "the check
/// lives in the handler that mints the token" (reg §4.2, fb §3.1).
#[tokio::test]
async fn registry_login_token_minting_checks_the_return_origin() {
    let r = rig();
    let cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let ctx: Value = cookie_call(&r.server, "GET", "/wsapi/session_context", Some(&cookie), None).await.json();
    let account = ctx["account"].as_str().unwrap().to_string();
    let resp = r
        .server
        .post("/wsapi/registry_login")
        .json(&json!({"account": account, "password": PASSWORD, "return_origin": "https://evil.example", "return_url": "https://evil.example/steal"}))
        .await;
    assert_ne!(resp.status_code(), 200, "token minted for a foreign return origin: {}", resp.text());
}

/// W5-11 (audit 2026-11, fixed in bean lu7i): reg §3 names one scope
/// grammar `^[a-z0-9_:.\-/*@+]{1,128}$`; `validate_grant_shape` applies
/// `browserid_core::validate_scope_string`, so spaces, uppercase,
/// punctuation, non-ASCII and the empty string are refused at filing.
#[tokio::test]
async fn filed_scopes_must_match_the_one_scope_grammar() {
    let r = rig();
    let _cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let agent_kp = KeyPair::generate();
    let cert = agent_cert(&r.idp, &agent_kp, "ag.bot");
    for bad in ["Post", "read write", "x;y", "émoji", ""] {
        let resp = common::registry::warrant_request(&r.server, DOMAIN, &agent_kp, json!({"device_cert": cert.encoded(), "identity": ALICE_BOT,
                "grants": [{"audience": AUDIENCE, "scopes": [bad]}]})).await;
        assert_ne!(resp.status_code(), 200, "scope {bad:?} accepted: {}", resp.text());
    }
    let resp = common::registry::warrant_request(&r.server, DOMAIN, &agent_kp, json!({"device_cert": cert.encoded(), "identity": ALICE_BOT,
            "grants": [{"audience": AUDIENCE, "scopes": ["tool:read_file", "as:alice@example.com", "path:/notes/*"]}]})).await;
    assert_eq!(resp.status_code(), 200, "in-grammar scopes refused: {}", resp.text());
}

/// S11 (audit 2026-11, bean imn6): enrolling a login key that is live on
/// another account answers exactly what a bad login-page token answers —
/// `403 login_rejected`, same body — not "this key is a login key on
/// another account".
#[tokio::test]
async fn foreign_login_key_is_refused_like_a_bad_token() {
    let r = rig();
    let alice = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let bob = create_user(&r.server, &r.sender, BOB, PASSWORD).await;
    let shared = KeyPair::generate();
    let _alice_sess = common::registry::api_login_with_key(&r.server, &alice, PASSWORD, shared.clone()).await.expect("alice enrols the key");
    let foreign = match common::registry::api_login_with_key(&r.server, &bob, PASSWORD, shared).await {
        Ok(_) => panic!("bob enrolled alice's live login key"),
        Err(e) => e,
    };
    // The reference refusal: a bad token on bob's own account.
    let ctx: Value = cookie_call(&r.server, "GET", "/wsapi/session_context", Some(&bob), None).await.json();
    let account = ctx["account"].as_str().unwrap();
    let origin = browserid_registrar::consent::public_origin(DOMAIN);
    let htu = format!("{origin}/api/v1/login");
    let key = KeyPair::generate();
    let now = Utc::now().timestamp();
    let body = json!({ "account": account, "method": "login_page", "token": "not-a-token",
        "login_key": { "pubkey": key.public_key().to_base64(), "label": "x",
            "proof": browserid_registrar::session::build_proof("POST", &htu, None, &key, now, "j-bad") } })
        .to_string().into_bytes();
    let header = browserid_registrar::session::build_proof("POST", &htu, Some(&body), &key, now, "j-bad");
    let bad = r.server.post("/api/v1/login").add_header("proof", header).add_header("content-type", "application/json").bytes(body.into()).await;
    assert_eq!(foreign.0, bad.status_code().as_u16(), "{:?} vs {}", foreign, bad.text());
    assert_eq!(foreign.1, bad.json::<Value>(), "the two refusals must be indistinguishable");
}

/// W5-12 (audit 2026-11, fixed in bean imn6): reg §5.2.8 — an account at
/// its cap of open approvals answers the same 200 as an unknown account
/// (a code nothing will approve), not a `403` that told the caller both
/// that the account exists and that it is busy.
#[tokio::test]
async fn approvals_at_the_cap_answer_like_an_unknown_account() {
    let r = rig();
    let cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let sess = common::registry::api_login(&r.server, &cookie, PASSWORD).await;
    for _ in 0..5 {
        let resp = api_anon(&r.server, "POST", "/api/v1/approvals", json!({"account": sess.account})).await;
        assert_eq!(resp.status_code(), 200, "{}", resp.text());
    }
    let sixth = api_anon(&r.server, "POST", "/api/v1/approvals", json!({"account": sess.account})).await;
    assert_eq!(sixth.status_code(), 200, "cap leaks existence: {} {}", sixth.status_code(), sixth.text());
    assert!(sixth.json::<Value>()["code"].is_string());
}

/// W5-13 (audit 2026-11, fixed in bean 1dy0): reg §5.3 — `claim` claims a
/// pending agent request too (it is bound to the delegator's account at
/// filing; the claim re-states that and answers the item with its
/// allocated indices). Another account's claim is a 404.
#[tokio::test]
async fn claim_accepts_a_pending_agent_request() {
    let r = rig();
    let cookie = create_user(&r.server, &r.sender, ALICE, PASSWORD).await;
    let sess = common::registry::api_login(&r.server, &cookie, PASSWORD).await;
    let agent_kp = KeyPair::generate();
    let code = file_agent_request(&r, &agent_kp).await;
    let resp = api_post(&r.server, &sess, "/api/v1/requests/claim", json!({"code": code})).await;
    assert_eq!(resp.status_code(), 200, "claim of an agent code: {} {}", resp.status_code(), resp.text());
    let item: Value = resp.json();
    assert_eq!(item["code"], code, "{item}");
    assert_eq!(item["kind"], "agent", "{item}");
    assert!(item["grants"][0]["status_idx"].is_u64(), "indices allocated: {item}");
    // Idempotent for the same account.
    let again = api_post(&r.server, &sess, "/api/v1/requests/claim", json!({"code": code})).await;
    assert_eq!(again.status_code(), 200, "{}", again.text());
    // Not for another account.
    let bob = create_user(&r.server, &r.sender, BOB, PASSWORD).await;
    let bob_sess = common::registry::api_login(&r.server, &bob, PASSWORD).await;
    let other = api_post(&r.server, &bob_sess, "/api/v1/requests/claim", json!({"code": code})).await;
    assert_eq!(other.status_code(), 404, "{}", other.text());
}
