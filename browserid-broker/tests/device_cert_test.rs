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
    let keypair = KeyPair::generate();
    let email_sender = Arc::new(MockEmailSender::new());
    let state = AppState::new_with_arcs(
        keypair,
        DOMAIN.to_string(),
        Arc::new(InMemoryUserStore::new()),
        Arc::new(InMemorySessionStore::new()),
        email_sender.clone(),
    );
    let server = TestServer::new(routes::create_router(Arc::new(state))).unwrap();
    (server, MockEmailSender { sent: email_sender.sent.clone() })
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

    // Issue a device+config pair, then list them.
    issue_pair(&server, &session, email).await;
    let listed: Value = server
        .get("/wsapi/device_certs")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    assert_eq!(listed["success"], true, "list: {listed}");
    let certs = listed["certs"].as_array().unwrap();
    assert_eq!(certs.len(), 2, "one authentication + one authorization cert");
    let purposes: Vec<&str> = certs.iter().map(|c| c["purpose"].as_str().unwrap()).collect();
    assert!(purposes.contains(&"authentication"));
    assert!(purposes.contains(&"authorization"));
    assert!(certs.iter().all(|c| c["revoked"] == false));

    // Revoke the authentication cert (owner-scoped).
    let auth = certs.iter().find(|c| c["purpose"] == "authentication").unwrap();
    let id = auth["id"].as_u64().unwrap();
    let c = csrf(&server, &session).await;
    let body: Value = server
        .post("/wsapi/revoke_device_cert")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "id": id }))
        .await
        .json();
    assert_eq!(body["success"], true, "revoke: {body}");

    // Sticky: it now reads back revoked, and a second revoke still succeeds.
    let listed2: Value = server
        .get("/wsapi/device_certs")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let after = listed2["certs"].as_array().unwrap();
    let auth2 = after.iter().find(|c| c["id"].as_u64() == Some(id)).unwrap();
    assert_eq!(auth2["revoked"], true, "cert should be sticky-revoked");
    let c = csrf(&server, &session).await;
    let again = server
        .post("/wsapi/revoke_device_cert")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "id": id }))
        .await;
    assert_eq!(again.status_code(), 200, "re-revoke stays green (idempotent/sticky)");
}

#[tokio::test]
async fn revoke_device_cert_is_owner_scoped() {
    let (server, sender) = make_server();
    let owner = "owner@localhost:3000";
    let owner_session = create_user(&server, &sender, owner, "testpassword").await;
    issue_pair(&server, &owner_session, owner).await;
    let owner_certs: Value = server
        .get("/wsapi/device_certs")
        .add_cookie(cookie::Cookie::new("browserid_session", owner_session.clone()))
        .await
        .json();
    let victim_id = owner_certs["certs"][0]["id"].as_u64().unwrap();

    // A different account cannot revoke the owner's cert.
    let attacker = "attacker@localhost:3000";
    let attacker_session = create_user(&server, &sender, attacker, "testpassword").await;
    let c = csrf(&server, &attacker_session).await;
    let resp = server
        .post("/wsapi/revoke_device_cert")
        .add_cookie(cookie::Cookie::new("browserid_session", attacker_session.clone()))
        .json(&json!({ "csrf": c, "id": victim_id }))
        .await;
    assert_ne!(resp.status_code(), 200, "cross-account revoke must fail");

    // The owner's cert is untouched.
    let still: Value = server
        .get("/wsapi/device_certs")
        .add_cookie(cookie::Cookie::new("browserid_session", owner_session.clone()))
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
    issue_pair(&server, &session, email).await;

    let listed: Value = server
        .get("/wsapi/device_certs")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let certs = listed["certs"].as_array().unwrap();
    assert_eq!(certs.len(), 2);
    let holder = certs[0]["holder"].as_str().unwrap().to_string();
    assert!(certs.iter().all(|c| c["holder"] == holder.as_str()), "one pair, one holder");

    // A holder that isn't the user's is refused.
    let c = csrf(&server, &session).await;
    let r = server
        .post("/wsapi/forget_holder")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "holder_id": "zz.notmine" }))
        .await;
    assert_ne!(r.status_code(), 200, "foreign holder must be refused");

    // Forget the real one: rows gone from the list.
    let r = server
        .post("/wsapi/forget_holder")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "holder_id": holder }))
        .await;
    assert_eq!(r.status_code(), 200, "forget: {:?}", r.text());
    let after: Value = server
        .get("/wsapi/device_certs")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    assert_eq!(after["certs"].as_array().unwrap().len(), 0, "all rows removed: {after}");

    // The certs' status bits were flipped before deletion: the published
    // status list carries revoked indices.
    let status_jws = server.get("/.well-known/browserid-status").await.text();
    assert!(!status_jws.is_empty(), "status list still published");
}

/// Account-driven namespace move (revoke-up-front): moving a holder revokes
/// its certs immediately, records a permanent redirect, reports the pending
/// move, silently redirects a stale client's issuance to the target, and
/// cleans up the old rows once the device re-registers.
#[tokio::test]
async fn move_holder_revokes_up_front_and_redirects_reissue() {
    let (server, sender) = make_server();
    let email = "human@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
    issue_pair(&server, &session, email).await;

    let listed: Value = server
        .get("/wsapi/device_certs")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let certs = listed["certs"].as_array().unwrap();
    let old_holder = certs[0]["holder"].as_str().unwrap().to_string();
    // Keep the device's real pubkeys: re-issue must be for the SAME keys.
    let device_pub = certs.iter().find(|c| c["purpose"] == "authentication").unwrap()["pubkey"]
        .as_str().unwrap().to_string();
    let config_pub = certs.iter().find(|c| c["purpose"] == "authorization").unwrap()["pubkey"]
        .as_str().unwrap().to_string();

    // Move to a new namespace.
    let c = csrf(&server, &session).await;
    let moved: Value = server
        .post("/wsapi/move_holder")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "holder_id": old_holder, "namespace": "laptops" }))
        .await
        .json();
    assert_eq!(moved["success"], true, "move: {moved}");
    let new_holder = moved["new_holder"].as_str().unwrap().to_string();
    assert_ne!(new_holder, old_holder);

    // Revoked UP FRONT: the old certs read back revoked immediately.
    let after: Value = server
        .get("/wsapi/device_certs")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    assert!(after["certs"].as_array().unwrap().iter().all(|c| c["revoked"] == true),
        "old certs must be revoked at move time: {after}");

    // The device's next check sees the reassignment.
    let assign: Value = server
        .get(&format!("/wsapi/holder_assignment?holder={old_holder}"))
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    assert_eq!(assign["status"], "moved", "{assign}");
    assert_eq!(assign["new_holder"], new_holder.as_str());

    // Holders view reports the pending move.
    let holders: Value = server
        .get("/wsapi/holders")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let all = holders["namespaces"].as_array().unwrap().iter()
        .flat_map(|n| n["holders"].as_array().unwrap().clone())
        .chain(holders["holders_without_namespace"].as_array().unwrap().clone())
        .collect::<Vec<_>>();
    let row = all.iter().find(|h| h["holder_id"] == old_holder.as_str()).expect("old holder listed");
    assert!(row["moving_to"].is_string(), "pending move surfaced: {row}");

    // A STALE client re-issuing with the old holder is silently redirected.
    let c = csrf(&server, &session).await;
    let reissued: Value = server
        .post("/device/issue")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "email": email,
            "device_pubkey": device_pub, "config_pubkey": config_pub,
            "holder": old_holder }))
        .await
        .json();
    assert_eq!(reissued["success"], true, "redirected reissue: {reissued}");
    let dc = DeviceCert::parse(reissued["device_cert"].as_str().unwrap()).unwrap();
    assert_eq!(dc.holder().as_str(), new_holder, "issuance lands on the move target");

    // Completion cleanup: the old holder's rows are gone; the device appears
    // exactly once, under the new holder, unrevoked.
    let after2: Value = server
        .get("/wsapi/device_certs")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let rows = after2["certs"].as_array().unwrap();
    assert!(rows.iter().all(|c| c["holder"] == new_holder.as_str()), "only the new holder remains: {after2}");
    assert!(rows.iter().all(|c| c["revoked"] == false), "fresh certs are live: {after2}");
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
    let csrf = get_csrf(&ctx.server, &session).await;
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
    let resp = ctx
        .server
        .post("/wsapi/revoke_device_cert")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "id": foreign_id, "csrf": csrf }))
        .await;
    resp.assert_status_ok();
    assert!(
        !ctx.user_store.is_status_revoked_idx(own_idx).unwrap(),
        "foreign revoke must not flip the broker's bit at the colliding index"
    );

    // Revoking the OWN cert still flips our bit.
    let resp = ctx
        .server
        .post("/wsapi/revoke_device_cert")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "id": own_id, "csrf": csrf }))
        .await;
    resp.assert_status_ok();
    assert!(ctx.user_store.is_status_revoked_idx(own_idx).unwrap());
}

/// The post-revocation confirmation (browserid-ng-ft55 follow-up): the
/// account page verifies a revocation actually landed before hiding
/// anything. Own-issued certs answer from our store; a cert with no
/// recorded status ref answers "unknown", never a false "revoked".
#[tokio::test]
async fn cert_revocation_status_answers_from_the_authority() {
    use browserid_broker::store::{DeviceCertRecord, UserStore};
    use common::{create_test_context_customized, create_user as mk_user, get_csrf};

    let ctx = create_test_context_customized(|_| {});
    let session = mk_user(&ctx.server, &ctx.email_sender, "me@mail.test", "password123").await;
    let csrf = get_csrf(&ctx.server, &session).await;
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

    let get = |id: u64| {
        ctx.server
            .get(&format!("/wsapi/cert_revocation_status?id={id}"))
            .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
    };

    // Own cert, bit not flipped → active.
    let body: Value = get(own_id).await.json();
    assert_eq!(body["state"], "active");

    // Revoke it (own-issued: flips our bit) → revoked.
    ctx.server
        .post("/wsapi/revoke_device_cert")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "id": own_id, "csrf": csrf }))
        .await
        .assert_status_ok();
    let body: Value = get(own_id).await.json();
    assert_eq!(body["state"], "revoked");

    // Foreign cert with no recorded ref → unknown, never a false claim.
    let body: Value = get(norf_id).await.json();
    assert_eq!(body["state"], "unknown");
}

// A revoked device cert must mint NOTHING new (audit M1 / bean mmnp):
// fail-closed revocation gate at /access/mint.
#[tokio::test]
async fn revoked_device_cert_cannot_mint() {
    let (server, sender) = make_server();
    let email = "revoke-me@localhost:3000";
    let session = create_user(&server, &sender, email, "testpassword").await;
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
    let certs: Value = server
        .get("/wsapi/device_certs")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let id = certs["certs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["purpose"] == "authentication")
        .and_then(|c| c["id"].as_u64())
        .expect("authentication cert id");
    let revoked: Value = server
        .post("/wsapi/revoke_device_cert")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "id": id }))
        .await
        .json();
    assert_eq!(revoked["success"], true, "revoke: {revoked}");

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
