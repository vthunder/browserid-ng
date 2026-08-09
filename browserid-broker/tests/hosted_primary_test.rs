//! Hosted-primary IdP integration (bean g5qt): the tenant issuance spine —
//! roster login → device-cert issuance (signed by the tenant key,
//! iss = tenant domain) → headless mint → tenant status list — plus the
//! forced-password-change gate and the mint's revocation/roster gates.
//!
//! Activation-by-DNS is exercised at the unit level (the checker needs a live
//! resolver); here the tenant is created + activated directly through the
//! store so the issuance and admin surfaces can be driven deterministically.

mod common;

use std::sync::Arc;

use axum_test::TestServer;
use browserid_broker::store::{TenantStatus, UserStore};
use browserid_broker::tenant_keys::KeystoreKey;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::device::{AccessCert, AccessRequest, DeviceCert, Purpose};
use browserid_core::status::StatusListToken;
use browserid_core::KeyPair;
use common::MockEmailSender;
use serde_json::{json, Value};

const BROKER: &str = "localhost:3000";
const IDP_HOST: &str = "idp.localhost:3000";
const TENANT: &str = "tenant.example";

fn make_server() -> (TestServer, Arc<InMemoryUserStore>) {
    let (server, store, _sender) = make_server_full();
    (server, store)
}

fn make_server_full() -> (TestServer, Arc<InMemoryUserStore>, MockEmailSender) {
    let user_store = Arc::new(InMemoryUserStore::new());
    let sender = MockEmailSender::new();
    let mut state = AppState::new_with_arcs(
        KeyPair::generate(),
        BROKER.to_string(),
        user_store.clone(),
        Arc::new(InMemorySessionStore::new()),
        Arc::new(MockEmailSender { sent: sender.sent.clone() }),
    );
    state.idp_host = IDP_HOST.to_string();
    state.tenant_keystore = Some(KeystoreKey::from_env_value(&"ab".repeat(32)).unwrap());
    let server = TestServer::new(routes::create_router(Arc::new(state))).unwrap();
    (server, user_store, sender)
}

/// Create + activate a tenant directly in the store, returning its public key.
fn seed_active_tenant(store: &InMemoryUserStore) -> String {
    let ks = KeystoreKey::from_env_value(&"ab".repeat(32)).unwrap();
    let (public_key, sealed) = ks.generate_sealed(TENANT).unwrap();
    store
        .create_tenant(TENANT, &public_key, &sealed, None, "admin@example.org")
        .unwrap();
    store.set_tenant_status(TENANT, TenantStatus::Active).unwrap();
    public_key
}

fn add_roster(server: &TestServer, store: &InMemoryUserStore, local: &str, password: &str) {
    let tenant = store.get_tenant(TENANT).unwrap().unwrap();
    // Use the store directly so the test owns the hash (admin-set password).
    let hash = bcrypt_hash(password);
    store
        .create_roster_entry(tenant.id, local, &hash, true, "admin@example.org")
        .unwrap();
    let _ = server; // (kept for symmetry with other helpers)
}

fn bcrypt_hash(pw: &str) -> String {
    bcrypt::hash(pw, 4).unwrap()
}

async fn idp_login(server: &TestServer, email: &str, password: &str) -> (String, Value) {
    let resp = server
        .post("/idp/login")
        .json(&json!({ "email": email, "password": password }))
        .await;
    let cookie = resp
        .maybe_cookie("idp_session")
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    (cookie, resp.json::<Value>())
}

#[tokio::test]
async fn tenant_login_issue_mint_and_status() {
    let (server, store) = make_server();
    let tenant_pub = seed_active_tenant(&store);
    add_roster(&server, &store, "alice", "hunter2secret");
    let email = format!("alice@{TENANT}");

    // The support doc served on the idp host is the tenant §7 surface.
    let doc: Value = server
        .get("/.well-known/browserid")
        .add_header("host", IDP_HOST)
        .await
        .json();
    assert_eq!(doc["device-authorization"], "/idp/device-authorize");
    assert_eq!(doc["access-cert"], "/idp/access_cert");
    assert!(doc.get("public-key").is_none(), "tenant doc carries no key");

    // A fresh roster user must change password first: login flags it, and
    // device-cert issuance is refused until it happens.
    let (cookie, login) = idp_login(&server, &email, "hunter2secret").await;
    assert_eq!(login["success"], true, "login: {login}");
    assert_eq!(login["must_change_password"], true);

    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let blocked: Value = server
        .post("/idp/device_cert")
        .add_cookie(cookie::Cookie::new("idp_session", cookie.clone()))
        .json(&json!({
            "email": email,
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": config_kp.public_key().to_base64(),
        }))
        .await
        .json();
    assert_eq!(blocked["success"], false, "must-change blocks issuance");

    // Change the password; the new session clears the flag.
    let (cookie, changed) = {
        let resp = server
            .post("/idp/password")
            .json(&json!({
                "email": email,
                "current_password": "hunter2secret",
                "new_password": "brandnewpass9",
            }))
            .await;
        let c = resp.maybe_cookie("idp_session").unwrap().value().to_string();
        (c, resp.json::<Value>())
    };
    assert_eq!(changed["success"], true, "password change: {changed}");

    // Issue the device + config certs — signed by the TENANT key, iss = tenant.
    let issued: Value = server
        .post("/idp/device_cert")
        .add_cookie(cookie::Cookie::new("idp_session", cookie.clone()))
        .json(&json!({
            "email": email,
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": config_kp.public_key().to_base64(),
        }))
        .await
        .json();
    assert_eq!(issued["success"], true, "device_cert: {issued}");
    let device_cert = DeviceCert::parse(issued["device_cert"].as_str().unwrap()).unwrap();
    assert_eq!(device_cert.iss(), TENANT);
    assert_eq!(device_cert.purpose(), Purpose::Authentication);
    assert!(device_cert.authorizes_identity(&email));
    // Verifies under the tenant's published key, not the broker's.
    let tenant_key = browserid_core::PublicKey::from_base64(&tenant_pub).unwrap();
    device_cert.verify(&tenant_key).unwrap();

    // Headless mint against /idp/access_cert (CORS; no session).
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(
        TENANT,
        &email,
        device_cert.holder().clone(),
        &access_kp.public_key(),
        "nonce-hp-1",
        &device_kp,
    )
    .unwrap();
    let minted: Value = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": issued["device_cert"], "access_request": areq.encoded() }))
        .await
        .json();
    assert_eq!(minted["success"], true, "access_cert: {minted}");
    let ac = AccessCert::parse(minted["access_cert"].as_str().unwrap()).unwrap();
    assert_eq!(ac.claims().iss, TENANT);
    ac.verify(&tenant_key).unwrap();

    // The tenant status list is signed by the tenant key, iss = tenant, and
    // served at /status/<tenant>.
    let list_body = server.get(&format!("/status/{TENANT}")).await.text();
    let token = StatusListToken::parse(list_body.trim()).unwrap();
    // public_origin() only treats a literal localhost/127.* host as http;
    // `idp.localhost` reads as a normal (https) host — same as the real
    // idp.browserid.me deployment.
    let uri = format!("https://{IDP_HOST}/status/{TENANT}");
    token.verify(&tenant_key, &uri).unwrap();
    // The freshly issued device is not revoked.
    let idx = device_cert.claims().status.as_ref().unwrap().idx;
    assert!(!token.is_revoked(idx));
}

#[tokio::test]
async fn mint_refused_after_roster_disable() {
    let (server, store) = make_server();
    seed_active_tenant(&store);
    add_roster(&server, &store, "bob", "correcthorse");
    let email = format!("bob@{TENANT}");
    let tenant = store.get_tenant(TENANT).unwrap().unwrap();
    // Clear the must-change flag so we can issue directly.
    store
        .set_roster_password(tenant.id, "bob", &bcrypt_hash("correcthorse"), false)
        .unwrap();

    let (cookie, _) = idp_login(&server, &email, "correcthorse").await;
    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let issued: Value = server
        .post("/idp/device_cert")
        .add_cookie(cookie::Cookie::new("idp_session", cookie))
        .json(&json!({
            "email": email,
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": config_kp.public_key().to_base64(),
        }))
        .await
        .json();
    assert_eq!(issued["success"], true, "{issued}");
    let device_cert = DeviceCert::parse(issued["device_cert"].as_str().unwrap()).unwrap();

    // Disable the user; the mint must now refuse even a valid device cert.
    store.set_roster_state(tenant.id, "bob", browserid_broker::store::RosterState::Disabled).unwrap();
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(
        TENANT, &email, device_cert.holder().clone(), &access_kp.public_key(), "nonce-hp-2", &device_kp,
    )
    .unwrap();
    let refused = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": issued["device_cert"], "access_request": areq.encoded() }))
        .await;
    assert_eq!(refused.status_code(), 403, "disabled user must not mint");
}

#[tokio::test]
async fn roster_user_without_forced_change_issues_directly() {
    // The onboarding path creates the first user with require_password_change
    // = false; that user logs in and issues certs with no change prompt.
    let (server, store) = make_server();
    seed_active_tenant(&store);
    let tenant = store.get_tenant(TENANT).unwrap().unwrap();
    store
        .create_roster_entry(tenant.id, "dana", &bcrypt_hash("chosenbyadmin1"), false, "admin@example.org")
        .unwrap();
    let email = format!("dana@{TENANT}");

    let (cookie, login) = idp_login(&server, &email, "chosenbyadmin1").await;
    assert_eq!(login["success"], true, "{login}");
    assert_eq!(login["must_change_password"], false, "no forced change expected");

    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let issued: Value = server
        .post("/idp/device_cert")
        .add_cookie(cookie::Cookie::new("idp_session", cookie))
        .json(&json!({
            "email": email,
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": config_kp.public_key().to_base64(),
        }))
        .await
        .json();
    assert_eq!(issued["success"], true, "issuance should not be blocked: {issued}");
}

#[tokio::test]
async fn delete_tenant_clears_rows_and_frees_the_domain() {
    let (_server, store) = make_server();
    let store = &*store;
    seed_active_tenant(store);
    let tenant = store.get_tenant(TENANT).unwrap().unwrap();
    store
        .create_roster_entry(tenant.id, "eve", &bcrypt_hash("evepassword1"), true, "admin@example.org")
        .unwrap();
    store.tenant_status_allocate(tenant.id, "somekey").unwrap();
    assert!(store.get_tenant(TENANT).unwrap().is_some());

    store.delete_tenant(TENANT).unwrap();

    // Everything scoped to the tenant is gone, and the domain can be recreated.
    assert!(store.get_tenant(TENANT).unwrap().is_none());
    assert!(store.list_tenant_admins(TENANT).unwrap().is_empty());
    let (pubkey2, sealed2) = KeystoreKey::from_env_value(&"ab".repeat(32))
        .unwrap()
        .generate_sealed(TENANT)
        .unwrap();
    store
        .create_tenant(TENANT, &pubkey2, &sealed2, None, "someone@else.org")
        .expect("domain should be free to onboard again");
    // The recreated tenant is a clean slate (no leftover roster).
    let fresh = store.get_tenant(TENANT).unwrap().unwrap();
    assert!(store.get_roster_entry(fresh.id, "eve").unwrap().is_none());
}

#[tokio::test]
async fn create_local_admin_preseeds_login_no_forced_change() {
    // Onboarding with a domain-local admin pre-creates that login (hashed at
    // create time), tied to the onboarding account as owner, with no forced
    // change. It becomes usable once the tenant is active.
    let (server, store, sender) = make_server_full();
    // A signed-in account with a verified email (the operator).
    let session = common::create_user(&server, &sender, "operator@op.example", "operatorpass1").await;
    let csrf = common::get_csrf(&server, &session).await;
    let created: Value = server
        .post("/wsapi/tenant/create")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "csrf": csrf, "domain": TENANT,
            "admin_email": format!("boss@{TENANT}"), "password": "bosspassword1",
        }))
        .await
        .json();
    assert_eq!(created["success"], true, "create: {created}");

    // Pending tenant: the login exists but can't be used yet.
    let tenant = store.get_tenant(TENANT).unwrap().unwrap();
    assert_eq!(tenant.status, TenantStatus::PendingDns);
    assert_eq!(tenant.owner_user_id.is_some(), true, "tenant is owned by the operator");
    let entry = store.get_roster_entry(tenant.id, "boss").unwrap().unwrap();
    assert_eq!(entry.must_change_password, false, "admin chose the password");

    // Activate directly (DNS is unit-tested elsewhere) and log in — no change prompt.
    store.set_tenant_status(TENANT, TenantStatus::Active).unwrap();
    let (_, login) = idp_login(&server, &format!("boss@{TENANT}"), "bosspassword1").await;
    assert_eq!(login["success"], true, "{login}");
    assert_eq!(login["must_change_password"], false);
}

#[tokio::test]
async fn activation_revokes_prior_broker_certs_for_the_domain() {
    use browserid_broker::store::DeviceCertRecord;
    use chrono::Utc;
    let (_server, store) = make_server();
    // A broker-issued (fallback) device cert for an identity at the domain,
    // with a broker status index, exists before onboarding.
    let uid = store.create_user_no_password().unwrap();
    let idx = store.get_or_allocate_status("device", "somepub").unwrap();
    store
        .insert_device_cert(DeviceCertRecord {
            id: 0,
            user_id: uid,
            identities: vec![format!("legacy@{TENANT}")],
            purpose: "authentication".into(),
            holder: "br.x".into(),
            pubkey: "somepub".into(),
            iss: BROKER.into(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(90),
            revoked_at: None,
            status_idx: Some(idx),
        })
        .unwrap();
    assert!(!store.is_status_revoked_idx(idx).unwrap());

    let n = store.revoke_domain_device_certs(TENANT).unwrap();
    assert_eq!(n, 1, "the domain's broker cert should be revoked");
    assert!(store.is_status_revoked_idx(idx).unwrap(), "status bit flipped");
    // A cert at another domain is untouched.
    assert_eq!(store.revoke_domain_device_certs("other.example").unwrap(), 0);
}

#[tokio::test]
async fn login_rejects_wrong_password_and_unknown_tenant() {
    let (server, store) = make_server();
    seed_active_tenant(&store);
    add_roster(&server, &store, "carol", "carolpassword");

    let (_, bad) = idp_login(&server, &format!("carol@{TENANT}"), "wrong").await;
    assert_eq!(bad["success"], false);

    let (_, no_tenant) = idp_login(&server, "someone@no-such-tenant.example", "whatever").await;
    assert_eq!(no_tenant["success"], false);
}
