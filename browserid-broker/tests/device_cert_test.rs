//! HTTP integration test for DC Phase 2 endpoints: /device/issue + /access/mint.
//! (/verify conformance is covered in verifier_test.rs.)

mod common;

use std::sync::Arc;

use axum_test::TestServer;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::device::{AccessRequest, DeviceCert, Holder, Purpose};
use browserid_core::KeyPair;
use common::{create_user, MockEmailSender};
use serde_json::{json, Value};

const DOMAIN: &str = "localhost:3000";

fn make_server() -> (TestServer, MockEmailSender) {
    let (server, sender, _store) = make_server_with_store();
    (server, sender)
}

fn make_server_with_store() -> (TestServer, MockEmailSender, Arc<InMemoryUserStore>) {
    let keypair = KeyPair::generate();
    let email_sender = Arc::new(MockEmailSender::new());
    let store = Arc::new(InMemoryUserStore::new());
    let state = AppState::new_with_arcs(
        keypair,
        DOMAIN.to_string(),
        store.clone(),
        Arc::new(InMemorySessionStore::new()),
        email_sender.clone(),
    );
    let server = TestServer::new(routes::create_router(Arc::new(state))).unwrap();
    (server, MockEmailSender { sent: email_sender.sent.clone() }, store)
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

#[tokio::test]
async fn device_issue_then_access_mint() {
    let (server, sender) = make_server();
    let email = "human@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
    let _sess = common::registry::api_login(&server, &session, "testpassword").await;
    let c = csrf(&server, &session).await;

    // 1. Batch-issue a user device cert + a config cert.
    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let body: Value = server
        .post("/device/issue")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "csrf": c, "email": email,
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": config_kp.public_key().to_base64(),
        }))
        .await
        .json();
    assert_eq!(body["success"], true, "device/issue: {body}");
    let device_cert = DeviceCert::parse(body["device_cert"].as_str().unwrap()).unwrap();
    let config_cert = DeviceCert::parse(body["config_cert"].as_str().unwrap()).unwrap();
    assert_eq!(device_cert.purpose(), Purpose::Authentication);
    assert_eq!(config_cert.purpose(), Purpose::Authorization);
    assert!(device_cert.authorizes_identity(email));
    // Per-device status refs allocated + distinct.
    assert!(device_cert.claims().status.is_some() && config_cert.claims().status.is_some());
    assert_ne!(device_cert.claims().status, config_cert.claims().status);

    // 2. Mint a fresh-key access cert with the device key.
    let access_kp = KeyPair::generate();
    // The mint copies the device cert's holder; the request must carry the same.
    let areq = AccessRequest::create(
        DOMAIN, email, device_cert.holder().clone(), &access_kp.public_key(), "nonce-1", &device_kp,
    ).unwrap();
    let body: Value = server
        .post("/access/mint")
        .json(&json!({ "device_cert": body["device_cert"], "access_request": areq.encoded() }))
        .await
        .json();
    assert_eq!(body["success"], true, "access/mint: {body}");
    assert_eq!(body["email"], email);
    // Access cert inherits the device's status index (B3: revoke-device kills access certs).
    let access_body = body.clone();
    let ac = browserid_core::device::AccessCert::parse(access_body["access_cert"].as_str().unwrap()).unwrap();
    assert_eq!(ac.claims().status, device_cert.claims().status);
}

#[tokio::test]
async fn device_issue_accepts_client_browser_holder_and_rejects_foreign() {
    let (server, sender) = make_server();
    let email = "human2@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
    let _sess = common::registry::api_login(&server, &session, "testpassword").await;
    let c = csrf(&server, &session).await;

    // The account's browsers-namespace prefix (client broker fetches this).
    let prefix: String = server
        .get("/wsapi/browser_holder")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json::<Value>()["prefix"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!prefix.is_empty());
    let holder = format!("{prefix}.mainlaptop");

    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let issue = |h: Value| {
        server
            .post("/device/issue")
            .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
            .json(&json!({
                "csrf": c, "email": email,
                "device_pubkey": device_kp.public_key().to_base64(),
                "config_pubkey": config_kp.public_key().to_base64(),
                "holder": h,
            }))
    };

    // Client-supplied holder in the account's browsers namespace → used verbatim
    // on BOTH certs.
    let body: Value = issue(json!(holder)).await.json();
    assert_eq!(body["success"], true, "device/issue with holder: {body}");
    let dc = DeviceCert::parse(body["device_cert"].as_str().unwrap()).unwrap();
    let cc = DeviceCert::parse(body["config_cert"].as_str().unwrap()).unwrap();
    assert_eq!(dc.holder().as_str(), holder);
    assert_eq!(cc.holder().as_str(), holder);

    // A holder outside this account's browsers namespace is refused.
    let resp = issue(json!("br-someoneelse.evil")).await;
    assert_ne!(resp.status_code(), 200, "foreign-namespace holder must be rejected");
}

#[tokio::test]
async fn access_mint_rejects_request_not_signed_by_device_key() {
    let (server, sender) = make_server();
    let email = "human@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
    let _sess = common::registry::api_login(&server, &session, "testpassword").await;
    let c = csrf(&server, &session).await;
    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let body: Value = server
        .post("/device/issue")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "email": email, "device_pubkey": device_kp.public_key().to_base64(), "config_pubkey": config_kp.public_key().to_base64() }))
        .await
        .json();
    let device_cert = body["device_cert"].clone();

    // Access request signed by a DIFFERENT key than the device cert certifies.
    let attacker = KeyPair::generate();
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(DOMAIN, email, Holder::new("br.x").unwrap(), &access_kp.public_key(), "nonce-2", &attacker).unwrap();
    let resp = server
        .post("/access/mint")
        .json(&json!({ "device_cert": device_cert, "access_request": areq.encoded() }))
        .await;
    assert_ne!(resp.status_code(), 200, "must reject a request not signed by the device key");
}

// --- DC Phase 8: device-cert list + owner-scoped, sticky revoke -------------

async fn issue_pair(server: &TestServer, session: &str, email: &str) {
    let c = csrf(server, session).await;
    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let body: Value = server
        .post("/device/issue")
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .json(&json!({ "csrf": c, "email": email,
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": config_kp.public_key().to_base64() }))
        .await
        .json();
    assert_eq!(body["success"], true, "device/issue: {body}");
}

#[tokio::test]
async fn device_certs_list_and_revoke() {
    let (server, sender) = make_server();
    let email = "human@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
    let sess = common::registry::api_login(&server, &session, "testpassword").await;

    // Issue a device+config pair, then list them.
    issue_pair(&server, &session, email).await;
    let listed: Value = common::registry::api_get(&server, &sess, "/api/v1/certs")
        .await
        .json();
    let certs = listed["certs"].as_array().unwrap();
    assert_eq!(certs.len(), 2, "one authentication + one authorization cert");
    let purposes: Vec<&str> = certs.iter().map(|c| c["purpose"].as_str().unwrap()).collect();
    assert!(purposes.contains(&"authentication"));
    assert!(purposes.contains(&"authorization"));
    assert!(certs.iter().all(|c| c["revoked"] == false));

    // Revoke the authentication cert (owner-scoped).
    let auth = certs.iter().find(|c| c["purpose"] == "authentication").unwrap();
    let id = auth["id"].as_u64().unwrap();
    let _c = csrf(&server, &session).await;
    let body: Value = common::registry::api_post(&server, &sess, "/api/v1/certs/revoke", json!({ "id": id }))
        .await
        .json();
    assert_eq!(body["revoked"], true, "revoke: {body}");

    // Sticky: it now reads back revoked, and a second revoke still succeeds.
    let listed2: Value = common::registry::api_get(&server, &sess, "/api/v1/certs")
        .await
        .json();
    let after = listed2["certs"].as_array().unwrap();
    let auth2 = after.iter().find(|c| c["id"].as_u64() == Some(id)).unwrap();
    assert_eq!(auth2["revoked"], true, "cert should be sticky-revoked");
    let _c = csrf(&server, &session).await;
    let again = common::registry::api_post(&server, &sess, "/api/v1/certs/revoke", json!({ "id": id }))
        .await;
    assert_eq!(again.status_code(), 200, "re-revoke stays green (idempotent/sticky)");
}

#[tokio::test]
async fn revoke_device_cert_is_owner_scoped() {
    let (server, sender) = make_server();
    let owner = "owner@localhost:3000";
    let owner_session = create_user(&server, &sender, owner, "testpassword").await;
    let owner_sess = common::registry::api_login(&server, &owner_session, "testpassword").await;
    issue_pair(&server, &owner_session, owner).await;
    let owner_certs: Value = common::registry::api_get(&server, &owner_sess, "/api/v1/certs")
        .await
        .json();
    let victim_id = owner_certs["certs"][0]["id"].as_u64().unwrap();

    // A different account cannot revoke the owner's cert.
    let attacker = "attacker@localhost:3000";
    let attacker_session = create_user(&server, &sender, attacker, "testpassword").await;
    let attacker_sess = common::registry::api_login(&server, &attacker_session, "testpassword").await;
    let _c = csrf(&server, &attacker_session).await;
    let resp = common::registry::api_post(&server, &attacker_sess, "/api/v1/certs/revoke", json!({ "id": victim_id }))
        .await;
    assert_ne!(resp.status_code(), 200, "cross-account revoke must fail");

    // The owner's cert is untouched.
    let still: Value = common::registry::api_get(&server, &owner_sess, "/api/v1/certs")
        .await
        .json();
    let rec = still["certs"].as_array().unwrap().iter()
        .find(|c| c["id"].as_u64() == Some(victim_id)).unwrap();
    assert_eq!(rec["revoked"], false, "owner cert must survive an attacker's revoke");
}

/// Removing a holder (forget_holder): every cert carrying it is revoked
/// (status bits flipped, fail-closed at verifiers) and its rows leave the
/// account view — the "get rid of this device" action. Owner-scoped; a
/// foreign holder id is refused.
#[tokio::test]
async fn forget_holder_revokes_and_removes_all_of_its_certs() {
    let (server, sender) = make_server();
    let email = "human@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
    let sess = common::registry::api_login(&server, &session, "testpassword").await;
    issue_pair(&server, &session, email).await;

    let listed: Value = common::registry::api_get(&server, &sess, "/api/v1/certs")
        .await
        .json();
    let certs = listed["certs"].as_array().unwrap();
    assert_eq!(certs.len(), 2);
    let holder = certs[0]["holder"].as_str().unwrap().to_string();
    assert!(certs.iter().all(|c| c["holder"] == holder.as_str()), "one pair, one holder");

    // A holder that isn't the user's is refused.
    let _c = csrf(&server, &session).await;
    let r = common::registry::api_post(&server, &sess, "/api/v1/holders/forget", json!({ "holder_id": "zz.notmine" }))
        .await;
    assert_ne!(r.status_code(), 200, "foreign holder must be refused");

    // Forget the real one: rows gone from the list.
    let r = common::registry::api_post(&server, &sess, "/api/v1/holders/forget", json!({ "holder_id": holder }))
        .await;
    assert_eq!(r.status_code(), 200, "forget: {:?}", r.text());
    let after: Value = common::registry::api_get(&server, &sess, "/api/v1/certs")
        .await
        .json();
    assert_eq!(after["certs"].as_array().unwrap().len(), 0, "all rows removed: {after}");

    // The certs' status bits were flipped before deletion: the published
    // status list carries revoked indices.
    let status_jws = server.get("/.well-known/browserid-status").await.text();
    assert!(!status_jws.is_empty(), "status list still published");
}

/// browserid-ng-ft55 regression: revoking a FOREIGN-issued device cert from
/// /account must not flip the broker's own status list — the record's
/// status_idx numbers the ISSUER's list, and flipping the same index here
/// would (a) not revoke the cert anywhere a verifier looks and (b) could
/// collaterally revoke an unrelated broker-issued cert at that index.
#[tokio::test]
async fn foreign_issued_cert_revocation_never_touches_the_broker_status_list() {
    use browserid_broker::store::{DeviceCertRecord, UserStore};
    use common::{create_test_context_customized, create_user as mk_user, get_csrf};

    let ctx = create_test_context_customized(|_| {});
    let session = mk_user(&ctx.server, &ctx.email_sender, "me@mail.test", "password123").await;
    let sess = common::registry::api_login(&ctx.server, &session, "password123").await;
    let _csrf = get_csrf(&ctx.server, &session).await;
    let user_id = ctx.user_store.get_user_by_email("me@mail.test").unwrap().unwrap().id;

    // A broker-owned status slot, as issuance would allocate it…
    let own_idx = ctx.user_store.get_or_allocate_status("device", "own-key").unwrap();
    // …and a foreign cert whose ISSUER-side index happens to collide with it.
    let mk = |iss: &str, idx: u64, holder: &str| DeviceCertRecord {
        id: 0,
        user_id,
        identities: vec![format!("dan@{iss}")],
        purpose: "authorization".into(),
        holder: holder.into(),
        pubkey: format!("pk-{holder}"),
        iss: iss.into(),
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::days(90),
        revoked_at: None,
        status_uri: None,
        status_idx: Some(idx),
        prov: "smtp".to_string(),
        login_key_id: None,
    };
    ctx.user_store.insert_device_cert(mk("localhost:3000", own_idx, "br1.own")).unwrap();
    ctx.user_store.insert_device_cert(mk("mingo.place", own_idx, "br2.foreign")).unwrap();

    let ids: Vec<(u64, String)> = ctx
        .user_store
        .list_device_certs(user_id)
        .unwrap()
        .into_iter()
        .map(|r| (r.id, r.iss))
        .collect();
    let foreign_id = ids.iter().find(|(_, i)| i == "mingo.place").unwrap().0;
    let own_id = ids.iter().find(|(_, i)| i == "localhost:3000").unwrap().0;

    // Revoking the FOREIGN cert soft-hides it but leaves our list alone.
    let resp = common::registry::api_post(&ctx.server, &sess, "/api/v1/certs/revoke", json!({ "id": foreign_id }))
        .await;
    resp.assert_status_ok();
    assert!(
        !ctx.user_store.is_status_revoked_idx(own_idx).unwrap(),
        "foreign revoke must not flip the broker's bit at the colliding index"
    );

    // Revoking the OWN cert still flips our bit.
    let resp = common::registry::api_post(&ctx.server, &sess, "/api/v1/certs/revoke", json!({ "id": own_id }))
        .await;
    resp.assert_status_ok();
    assert!(ctx.user_store.is_status_revoked_idx(own_idx).unwrap());
}

/// Revocation answers from the authority (browserid-ng-ft55 follow-up): the
/// certs list reads `revoked` from our store for own-issued certs; a cert
/// from a foreign issuer with no recorded ref is only retired here —
/// `certs/revoke` says so with `revoked: false`, never a false claim.
#[tokio::test]
async fn cert_revocation_answers_from_the_authority() {
    use browserid_broker::store::{DeviceCertRecord, UserStore};
    use common::{create_test_context_customized, create_user as mk_user};

    let ctx = create_test_context_customized(|_| {});
    let session = mk_user(&ctx.server, &ctx.email_sender, "me@mail.test", "password123").await;
    let sess = common::registry::api_login(&ctx.server, &session, "password123").await;
    let user_id = ctx.user_store.get_user_by_email("me@mail.test").unwrap().unwrap().id;

    let own_idx = ctx.user_store.get_or_allocate_status("device", "own-key-2").unwrap();
    let mk = |iss: &str, idx: Option<u64>, holder: &str| DeviceCertRecord {
        id: 0,
        user_id,
        identities: vec![format!("dan@{iss}")],
        purpose: "authorization".into(),
        holder: holder.into(),
        pubkey: format!("pk-{holder}"),
        iss: iss.into(),
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::days(90),
        revoked_at: None,
        status_uri: None,
        status_idx: idx,
        prov: "smtp".to_string(),
        login_key_id: None,
    };
    ctx.user_store.insert_device_cert(mk("localhost:3000", Some(own_idx), "br3.own")).unwrap();
    ctx.user_store.insert_device_cert(mk("mingo.place", None, "br4.norf")).unwrap();
    let ids: Vec<(u64, String)> = ctx
        .user_store
        .list_device_certs(user_id)
        .unwrap()
        .into_iter()
        .map(|r| (r.id, r.holder))
        .collect();
    let own_id = ids.iter().find(|(_, h)| h == "br3.own").unwrap().0;
    let norf_id = ids.iter().find(|(_, h)| h == "br4.norf").unwrap().0;

    let srv = &ctx.server;
    let sref = &sess;
    let listed = |id: u64| async move {
        let v: Value = common::registry::api_get(srv, sref, "/api/v1/certs").await.json();
        v["certs"].as_array().unwrap().iter().find(|c| c["id"] == id).cloned().unwrap()
    };
    // Own cert, bit not flipped → not revoked.
    assert_eq!(listed(own_id).await["revoked"], false);
    // Revoke it (own-issued: flips our bit) → revoked, and the call says so.
    let r: Value = common::registry::api_post(&ctx.server, &sess, "/api/v1/certs/revoke", json!({ "id": own_id })).await.json();
    assert_eq!(r["revoked"], true, "{r}");
    assert_eq!(listed(own_id).await["revoked"], true);
    assert!(ctx.user_store.is_status_revoked_idx(own_idx).unwrap());
    // Foreign cert with no recorded ref: retired here, honestly not revoked
    // anywhere a verifier looks.
    let r: Value = common::registry::api_post(&ctx.server, &sess, "/api/v1/certs/revoke", json!({ "id": norf_id })).await.json();
    assert_eq!(r["revoked"], false, "{r}");
}

// A revoked device cert must mint NOTHING new (audit M1 / bean mmnp):
// fail-closed revocation gate at /access/mint.
#[tokio::test]
async fn revoked_device_cert_cannot_mint() {
    let (server, sender) = make_server();
    let email = "revoke-me@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
    let sess = common::registry::api_login(&server, &session, "testpassword").await;
    let c = csrf(&server, &session).await;

    // Issue + persist the device/config certs under the account.
    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let issued: Value = server
        .post("/device/issue")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "csrf": c, "email": email,
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": config_kp.public_key().to_base64(),
        }))
        .await
        .json();
    assert_eq!(issued["success"], true, "issue: {issued}");

    // Minting works before revocation.
    let access_kp = KeyPair::generate();
    let dc = DeviceCert::parse(issued["device_cert"].as_str().unwrap()).unwrap();
    let areq = AccessRequest::create(
        DOMAIN, email, dc.holder().clone(), &access_kp.public_key(), "nonce-pre", &device_kp,
    ).unwrap();
    let pre: Value = server
        .post("/access/mint")
        .json(&json!({ "device_cert": issued["device_cert"], "access_request": areq.encoded() }))
        .await
        .json();
    assert_eq!(pre["success"], true, "pre-revoke mint should work: {pre}");

    // Find the authentication device cert's id and revoke it.
    let certs: Value = common::registry::api_get(&server, &sess, "/api/v1/certs")
        .await
        .json();
    let id = certs["certs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["purpose"] == "authentication")
        .and_then(|c| c["id"].as_u64())
        .expect("authentication cert id");
    let revoked: Value = common::registry::api_post(&server, &sess, "/api/v1/certs/revoke", json!({ "id": id }))
        .await
        .json();
    assert_eq!(revoked["revoked"], true, "revoke: {revoked}");

    // Now the mint must refuse even a nominally-valid request.
    let areq2 = AccessRequest::create(
        DOMAIN, email, dc.holder().clone(), &access_kp.public_key(), "nonce-post", &device_kp,
    ).unwrap();
    let post = server
        .post("/access/mint")
        .json(&json!({ "device_cert": issued["device_cert"], "access_request": areq2.encoded() }))
        .await;
    assert_eq!(post.status_code(), 403, "revoked device cert must not mint");
}

// --- Accepted return origins (fallback-idp-api-v1 §3.1, bean qze7) ---------

async fn issue_with_origin(server: &TestServer, session: &str, email: &str, origin: &str) -> (u16, Value) {
    let c = csrf(server, session).await;
    let r = server
        .post("/device/issue")
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .json(&json!({
            "csrf": c, "email": email,
            "device_pubkey": KeyPair::generate().public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
            "return_origin": origin,
        }))
        .await;
    (r.status_code().as_u16(), r.json::<Value>())
}

#[tokio::test]
async fn device_issue_refuses_untrusted_web_return_origin() {
    let (server, sender) = make_server();
    let email = "human@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
    let _sess = common::registry::api_login(&server, &session, "testpassword").await;

    let (status, body) = issue_with_origin(&server, &session, email, "https://evil.example").await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["reason"], "return_origin_not_allowed");
    assert!(body.get("device_cert").is_none());

    // Lookalikes of the default trusted wallet.
    for o in ["https://browserid.me.evil.example", "https://evil.example/https://browserid.me"] {
        let (status, body) = issue_with_origin(&server, &session, email, o).await;
        assert_eq!(status, 403, "{o}: {body}");
    }
}

#[tokio::test]
async fn device_issue_accepts_native_trusted_and_own_origins() {
    let (server, sender) = make_server();
    let email = "human@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
    let _sess = common::registry::api_login(&server, &session, "testpassword").await;

    for o in [
        "http://127.0.0.1:4321",   // loopback
        "http://[::1]:9",          // loopback v6
        "mingo://wallet",          // custom scheme
        "https://browserid.me",    // default trusted list
        "http://localhost:3000",   // own origin
    ] {
        let (status, body) = issue_with_origin(&server, &session, email, o).await;
        assert_eq!(status, 200, "{o}: {body}");
        assert!(body["device_cert"].as_str().is_some(), "{o}");
    }
}

#[tokio::test]
async fn support_document_advertises_wallet_origins() {
    let (server, _) = make_server();
    let doc = server.get("/.well-known/browserid").await.json::<Value>();
    let list = doc["wallet-origins"].as_array().expect("wallet-origins").clone();
    assert!(list.iter().any(|o| o == "http://localhost:3000"), "{list:?}");
    assert!(list.iter().any(|o| o == "https://browserid.me"), "{list:?}");
}

/// a93p, closed by the hold model (bean 0c49 step 1): after the parent
/// identity leaves the account, the old account cannot mint fresh certs
/// for the derived agent it left behind — the agent row is suspended.
#[tokio::test]
async fn suspended_agent_cannot_mint_on_the_old_account() {
    use browserid_broker::membership::{identity_leaves, LeaveReason};
    use browserid_broker::store::{EmailType, UserStore};
    let (server, sender, store) = make_server_with_store();
    let email = "parent@localhost:3000";
    let agent = "parent+cal@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
    let _sess = common::registry::api_login(&server, &session, "testpassword").await;
    let user_id = store.get_email(email).unwrap().unwrap().user_id;
    store.add_email_with_type(user_id, agent, true, EmailType::Agent).unwrap();
    store.set_parent_email(agent, Some(email)).unwrap();

    // Before: the agent mints.
    let (status, body) = issue_with_origin(&server, &session, agent, "http://localhost:3000").await;
    assert_eq!(status, 200, "{body}");

    // The parent leaves. The agent row stays on the account, suspended.
    identity_leaves(store.as_ref(), user_id, email, LeaveReason::Detached).unwrap();
    let (status, body) = issue_with_origin(&server, &session, agent, "http://localhost:3000").await;
    assert_eq!(status, 403, "{body}");
    assert!(body["reason"].as_str().unwrap_or("").contains("suspended"), "{body}");
}
