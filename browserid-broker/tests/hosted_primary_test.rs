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

/// An agent identity is a `+tag` subaddress of a roster user (`bob+poster`
/// acts for roster user `bob`). The access mint must resolve it to its base
/// roster entry — regression for the live github-mcp demo failure where a
/// hosted-tenant agent (`danmills+claude-github@sandmill.org`) hit "roster
/// entry is not active" because the full `+tag` local part was looked up.
#[tokio::test]
async fn agent_subaddress_mints_against_its_base_roster_user() {
    let (server, store) = make_server();
    seed_active_tenant(&store);
    add_roster(&server, &store, "bob", "correcthorse");
    let email = format!("bob@{TENANT}");
    let agent = format!("bob+poster@{TENANT}");
    let tenant = store.get_tenant(TENANT).unwrap().unwrap();
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
    // The base device cert covers the agent subaddress (RFC 5233).
    assert!(device_cert.authorizes_identity(&agent));

    // Mint an access cert AS THE AGENT subaddress: the roster check resolves
    // `bob+poster` to roster user `bob`, so it succeeds.
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(
        TENANT, &agent, device_cert.holder().clone(), &access_kp.public_key(), "nonce-agent-1", &device_kp,
    )
    .unwrap();
    let minted: Value = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": issued["device_cert"], "access_request": areq.encoded() }))
        .await
        .json();
    assert_eq!(minted["success"], true, "agent subaddress must mint: {minted}");
    let ac = AccessCert::parse(minted["access_cert"].as_str().unwrap()).unwrap();
    assert_eq!(ac.claims().identity, agent, "the cert names the agent subaddress");

    // Disabling the BASE user stops the agent minting too.
    store
        .set_roster_state(tenant.id, "bob", browserid_broker::store::RosterState::Disabled)
        .unwrap();
    let areq2 = AccessRequest::create(
        TENANT, &agent, device_cert.holder().clone(), &access_kp.public_key(), "nonce-agent-2", &device_kp,
    )
    .unwrap();
    let refused = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": issued["device_cert"], "access_request": areq2.encoded() }))
        .await;
    assert_eq!(refused.status_code(), 403, "disabling the base user stops the agent");
}

/// The full managed-agent path (regression for the github-mcp demo block):
/// a managed, per-audience tenant issues a device cert to the base roster
/// user (the shape the agent-provision user-mode hop produces), and an AGENT
/// `+tag` subaddress mints a per-audience access cert against it. Proves the
/// device cert carries `managed: true` and the mint honors the audience for
/// the agent subaddress — the two things that must both hold for a hosted
/// managed tenant's agents to work.
#[tokio::test]
async fn managed_tenant_agent_subaddress_mints_per_audience() {
    use browserid_broker::store::ManagementPolicy;

    let (server, store) = make_server();
    seed_active_tenant(&store);
    let allowed = "http://localhost:3400";
    store
        .set_tenant_management(
            TENANT,
            &ManagementPolicy {
                enabled: true,
                per_audience: true,
                audiences: vec![allowed.to_string()],
                scopes: None,
                max_ttl: Some(86_400),
                device_cert_ttl: None,
                access_cert_ttl: None,
                salt: "c2FsdHktc2FsdA".into(),
            },
        )
        .unwrap();

    let tenant = store.get_tenant(TENANT).unwrap().unwrap();
    store
        .create_roster_entry(tenant.id, "dan", &bcrypt_hash("hunter2secret"), false, "admin@example.org")
        .unwrap();
    let email = format!("dan@{TENANT}");
    let agent = format!("dan+poster@{TENANT}");

    // The device cert the agent holds is issued by the user-mode hop: it
    // names the SESSION (base) identity but is over the agent's key.
    let (cookie, _) = idp_login(&server, &email, "hunter2secret").await;
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
    assert_eq!(issued["success"], true, "device_cert: {issued}");
    let device_cert = DeviceCert::parse(issued["device_cert"].as_str().unwrap()).unwrap();
    // The managed marker MUST be present — its absence is exactly what makes
    // the agent SDK skip the audience and the mint reject "audience required".
    assert_eq!(device_cert.claims().managed, Some(true), "agent device cert must be managed");
    assert!(device_cert.authorizes_identity(&agent), "base cert covers the +tag agent");

    // The agent mints a per-audience access cert (what DeviceAgent.mint does
    // for a managed identity) naming its +tag subaddress.
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create_for_audience(
        TENANT, &agent, device_cert.holder().clone(),
        &access_kp.public_key(), "nonce-ma-1", allowed, &device_kp,
    )
    .unwrap();
    let minted: Value = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": issued["device_cert"], "access_request": areq.encoded() }))
        .await
        .json();
    assert_eq!(minted["success"], true, "managed agent per-audience mint: {minted}");
    let ac = AccessCert::parse(minted["access_cert"].as_str().unwrap()).unwrap();
    assert_eq!(ac.claims().identity, agent);
    assert!(ac.claims().constraints.as_ref().and_then(|c| c.aud.as_ref()).is_some(), "aud-scoped");
}

/// A device cert issued BEFORE the domain enabled managed identities has no
/// `managed` marker, so its agent never mints per-audience and the mint would
/// otherwise reject with the opaque "audience required". The mint instead
/// tells it to re-provision — the only real recovery. Regression for the live
/// github-mcp block, where the agent held a pre-managed credential.
#[tokio::test]
async fn stale_pre_managed_credential_is_told_to_reprovision() {
    use browserid_broker::store::ManagementPolicy;

    let (server, store) = make_server();
    let tenant_pub = seed_active_tenant(&store);
    let tenant = store.get_tenant(TENANT).unwrap().unwrap();
    store
        .create_roster_entry(tenant.id, "dan", &bcrypt_hash("hunter2secret"), false, "admin@example.org")
        .unwrap();
    let email = format!("dan@{TENANT}");

    // Issue a device cert while the tenant is UNMANAGED — no managed marker.
    let (cookie, _) = idp_login(&server, &email, "hunter2secret").await;
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
    let device_cert = DeviceCert::parse(issued["device_cert"].as_str().unwrap()).unwrap();
    assert_eq!(device_cert.claims().managed, None, "pre-managed cert has no marker");
    let _ = tenant_pub;

    // NOW enable managed + per-audience.
    store
        .set_tenant_management(
            TENANT,
            &ManagementPolicy {
                enabled: true,
                per_audience: true,
                audiences: vec![],
                scopes: None,
                max_ttl: Some(86_400),
                device_cert_ttl: None,
                access_cert_ttl: None,
                salt: "c2FsdHktc2FsdA".into(),
            },
        )
        .unwrap();

    // The stale cert mints audience-free (it never learned it was managed);
    // the mint tells it to re-provision, not the opaque "audience required".
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(
        TENANT, &email, device_cert.holder().clone(),
        &access_kp.public_key(), "nonce-stale-1", &device_kp,
    )
    .unwrap();
    let refused = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": issued["device_cert"], "access_request": areq.encoded() }))
        .await;
    assert_eq!(refused.status_code(), 403);
    let body = refused.text();
    assert!(body.contains("provision the identity again"), "actionable message: {body}");
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
            status_uri: None,
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

// --- managed identities (spec §4.7; bean 4vu7) -----------------------------

/// Enable management + full spine: the device cert carries the marker, the
/// mint stamps constraints per current policy, per-audience posture requires
/// (and scopes to) the requested audience, and off-list audiences fail with a
/// comprehensible policy error at the mint — not a verifier reject.
#[tokio::test]
async fn managed_tenant_marks_certs_and_stamps_mint_policy() {
    use browserid_broker::store::ManagementPolicy;
    use browserid_core::device::AudConstraint;

    let (server, store) = make_server();
    seed_active_tenant(&store);
    let allowed = "https://app.allowed.example";
    store
        .set_tenant_management(
            TENANT,
            &ManagementPolicy {
                enabled: true,
                per_audience: true,
                audiences: vec![allowed.to_string()],
                scopes: Some(vec!["post".into()]),
                max_ttl: Some(86_400),
                device_cert_ttl: None,
                access_cert_ttl: None,
                salt: "c2FsdHktc2FsdA".into(),
            },
        )
        .unwrap();

    // Roster user without forced change so issuance flows directly.
    let tenant = store.get_tenant(TENANT).unwrap().unwrap();
    store
        .create_roster_entry(tenant.id, "bob", &bcrypt_hash("hunter2secret"), false, "admin@example.org")
        .unwrap();
    let email = format!("bob@{TENANT}");
    let (cookie, login) = idp_login(&server, &email, "hunter2secret").await;
    assert_eq!(login["success"], true, "login: {login}");

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
    assert_eq!(issued["success"], true, "device_cert: {issued}");
    let device_cert = DeviceCert::parse(issued["device_cert"].as_str().unwrap()).unwrap();
    assert_eq!(device_cert.claims().managed, Some(true), "managed marker on the device cert");
    let config_cert = DeviceCert::parse(issued["config_cert"].as_str().unwrap()).unwrap();
    assert_eq!(config_cert.claims().managed, Some(true), "marker on the config cert too");

    // Per-audience posture: an audience-free mint is refused with the
    // audience-required reason.
    let access_kp = KeyPair::generate();
    let blind = AccessRequest::create(
        TENANT, &email, device_cert.holder().clone(),
        &access_kp.public_key(), "nonce-mg-1", &device_kp,
    )
    .unwrap();
    let refused = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": issued["device_cert"], "access_request": blind.encoded() }))
        .await;
    assert_eq!(refused.status_code(), 403, "audience-free mint refused: {}", refused.text());
    assert!(refused.text().contains("audience required"), "{}", refused.text());

    // An off-list audience fails at the mint with the policy reason.
    let off = AccessRequest::create_for_audience(
        TENANT, &email, device_cert.holder().clone(),
        &access_kp.public_key(), "nonce-mg-2", "https://forbidden.example", &device_kp,
    )
    .unwrap();
    let refused = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": issued["device_cert"], "access_request": off.encoded() }))
        .await;
    assert_eq!(refused.status_code(), 403);
    assert!(refused.text().contains("not permitted"), "{}", refused.text());

    // The allowed audience mints a cert scoped to EXACTLY that audience,
    // carrying the policy's scopes + max-ttl.
    let ok = AccessRequest::create_for_audience(
        TENANT, &email, device_cert.holder().clone(),
        &access_kp.public_key(), "nonce-mg-3", allowed, &device_kp,
    )
    .unwrap();
    let minted: Value = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": issued["device_cert"], "access_request": ok.encoded() }))
        .await
        .json();
    assert_eq!(minted["success"], true, "mint: {minted}");
    let ac = AccessCert::parse(minted["access_cert"].as_str().unwrap()).unwrap();
    let cons = ac.claims().constraints.as_ref().expect("constraints stamped");
    let aud = cons.aud.as_ref().expect("aud constraint");
    assert_eq!(aud.hashes.len(), 1, "scoped to exactly the requested audience");
    assert!(aud.permits(allowed));
    assert!(!aud.permits("https://forbidden.example"));
    assert_eq!(cons.scopes.as_deref(), Some(&["post".to_string()][..]));
    assert_eq!(cons.max_ttl, Some(86_400));
}

/// Unmanaged tenants are untouched: no marker, no constraints — and an
/// `audience` in the request is IGNORED, never honored (the mint stays
/// RP-blind for unmanaged identities even against a nonconforming client).
#[tokio::test]
async fn unmanaged_tenant_ignores_audience_and_stamps_nothing() {
    let (server, store) = make_server();
    seed_active_tenant(&store);
    let tenant = store.get_tenant(TENANT).unwrap().unwrap();
    store
        .create_roster_entry(tenant.id, "carol", &bcrypt_hash("hunter2secret"), false, "admin@example.org")
        .unwrap();
    let email = format!("carol@{TENANT}");
    let (cookie, _) = idp_login(&server, &email, "hunter2secret").await;

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
    let device_cert = DeviceCert::parse(issued["device_cert"].as_str().unwrap()).unwrap();
    assert_eq!(device_cert.claims().managed, None, "no marker for an unmanaged tenant");

    let access_kp = KeyPair::generate();
    // A nonconforming client sends an audience anyway — it must be ignored.
    let areq = AccessRequest::create_for_audience(
        TENANT, &email, device_cert.holder().clone(),
        &access_kp.public_key(), "nonce-um-1", "https://spy.example", &device_kp,
    )
    .unwrap();
    let minted: Value = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": issued["device_cert"], "access_request": areq.encoded() }))
        .await
        .json();
    assert_eq!(minted["success"], true, "mint: {minted}");
    let ac = AccessCert::parse(minted["access_cert"].as_str().unwrap()).unwrap();
    assert!(ac.claims().constraints.is_none(), "no constraints on an unmanaged cert");
}

/// "Remove for good" must revoke at the cert's OWN authority (bean pbzn): a
/// tenant-issued cert's status bit lives on the TENANT's list — flipping the
/// broker's list (the old behavior) left the cert live while the account view
/// showed nothing. Foreign-issuer certs we cannot revoke are surfaced in
/// `unrevocable` instead of silently pretending.
#[tokio::test]
async fn forget_holder_revokes_at_the_tenant_authority() {
    use browserid_broker::store::DeviceCertRecord;
    use chrono::Utc;
    use common::create_user;

    let (server, store, sender) = make_server_full();
    seed_active_tenant(&store);
    let tenant = store.get_tenant(TENANT).unwrap().unwrap();

    let session = create_user(&server, &sender, "human@localhost:3000", "testpassword").await;
    let user_id = store.get_email("human@localhost:3000").unwrap().unwrap().user_id;

    // A tenant-issued config cert recorded for this account (as the dialog's
    // record path would), with its bit on the TENANT's status list.
    let idx = store.tenant_status_allocate(tenant.id, "cfg-pubkey-tenant").unwrap();
    let tenant_uri = format!("https://{IDP_HOST}/status/{TENANT}");
    let holder = "brtest.tenantdev";
    let mk = |pubkey: &str, iss: &str, uri: Option<String>, idx: Option<u64>| DeviceCertRecord {
        id: 0,
        user_id,
        identities: vec![format!("dan@{iss}")],
        purpose: "authorization".into(),
        holder: holder.into(),
        pubkey: pubkey.into(),
        iss: iss.into(),
        issued_at: Utc::now(),
        expires_at: Utc::now(),
        revoked_at: None,
        status_uri: uri,
        status_idx: idx,
    };
    store
        .insert_device_cert(mk("cfg-pubkey-tenant", TENANT, Some(tenant_uri), Some(idx)))
        .unwrap();
    // And one from a genuinely foreign issuer we are no authority for.
    store
        .insert_device_cert(mk(
            "cfg-pubkey-foreign",
            "foreign.example",
            Some("https://foreign.example/.well-known/browserid-status".into()),
            Some(9),
        ))
        .unwrap();

    let csrf: String = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json::<Value>()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = server
        .post("/wsapi/forget_holder")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "csrf": csrf, "holder_id": holder }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let body: Value = resp.json();

    // The tenant-list bit is flipped — the cert now fails the mint gate and
    // fail-closed verifiers, matching what the account claims.
    assert!(
        store.tenant_status_is_revoked(tenant.id, idx).unwrap(),
        "tenant-authority bit must be revoked"
    );
    // The foreign cert is honestly reported as beyond our reach.
    let unrevocable: Vec<String> = body["unrevocable"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(unrevocable, vec!["foreign.example".to_string()], "{body}");
}

// --- domains console redesign (bean r9gn): remove-admin, split TTLs, ---------
// --- standalone revoke-all, per-address managed flag -------------------------

/// The remove-admin endpoint enforces the one-admin floor, removes otherwise,
/// and refuses identities that aren't admins at all.
#[tokio::test]
async fn admin_remove_enforces_floor_then_removes() {
    // Owner console access with a domain-LOCAL first admin: the operator is
    // not an admin identity themself, so the last-admin floor is testable
    // independently of the self-removal rule.
    let (server, store, sender) = make_server_full();
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
    store.set_tenant_status(TENANT, TenantStatus::Active).unwrap();
    assert_eq!(store.list_tenant_admins(TENANT).unwrap(), vec![format!("boss@{TENANT}")]);

    // The floor: the sole admin cannot be removed.
    let refused = server
        .post("/wsapi/tenant/admins/remove")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({"csrf": csrf, "domain": TENANT, "identity": format!("boss@{TENANT}")}))
        .await;
    assert_eq!(refused.status_code(), 403, "{}", refused.text());
    assert!(refused.text().contains("at least one administrator"), "{}", refused.text());

    // With a second admin seated, the first becomes removable.
    let added: Value = server
        .post("/wsapi/tenant/admins")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({"csrf": csrf, "domain": TENANT, "identity": "carol@other.example"}))
        .await
        .json();
    assert_eq!(added["success"], true, "{added}");
    let removed = server
        .post("/wsapi/tenant/admins/remove")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({"csrf": csrf, "domain": TENANT, "identity": format!("boss@{TENANT}")}))
        .await;
    assert_eq!(removed.status_code(), 200, "{}", removed.text());
    assert_eq!(store.list_tenant_admins(TENANT).unwrap(), vec!["carol@other.example".to_string()]);

    // A non-admin identity is refused, not silently ignored.
    let refused = server
        .post("/wsapi/tenant/admins/remove")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({"csrf": csrf, "domain": TENANT, "identity": "nobody@x.example"}))
        .await;
    assert_eq!(refused.status_code(), 403, "{}", refused.text());
}

/// You can never remove yourself — even when another admin would remain.
#[tokio::test]
async fn admin_remove_refuses_self() {
    let (server, store, sender) = make_server_full();
    let session = common::create_user(&server, &sender, "operator@op.example", "operatorpass1").await;
    let csrf = common::get_csrf(&server, &session).await;
    // External admin-of-record = the operator's own verified identity.
    let created: Value = server
        .post("/wsapi/tenant/create")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({"csrf": csrf, "domain": TENANT, "admin_email": "operator@op.example"}))
        .await
        .json();
    assert_eq!(created["success"], true, "create: {created}");
    store.set_tenant_status(TENANT, TenantStatus::Active).unwrap();
    let added: Value = server
        .post("/wsapi/tenant/admins")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({"csrf": csrf, "domain": TENANT, "identity": "carol@other.example"}))
        .await
        .json();
    assert_eq!(added["success"], true, "{added}");

    let refused = server
        .post("/wsapi/tenant/admins/remove")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({"csrf": csrf, "domain": TENANT, "identity": "operator@op.example"}))
        .await;
    assert_eq!(refused.status_code(), 403, "{}", refused.text());
    assert!(refused.text().contains("yourself"), "{}", refused.text());
    assert_eq!(store.list_tenant_admins(TENANT).unwrap().len(), 2, "nothing removed");
}

/// The split TTL knobs bound issuance at their own sites — device_cert_ttl at
/// /idp/device_cert, access_cert_ttl at the mint — and the legacy single
/// max_ttl still bounds the access cert when the split knob is absent.
#[tokio::test]
async fn split_cert_ttls_bound_issuance_with_max_ttl_fallback() {
    use browserid_broker::store::ManagementPolicy;

    let (server, store) = make_server();
    seed_active_tenant(&store);
    let tenant = store.get_tenant(TENANT).unwrap().unwrap();
    store
        .create_roster_entry(tenant.id, "tina", &bcrypt_hash("hunter2secret"), false, "admin@example.org")
        .unwrap();
    let email = format!("tina@{TENANT}");
    store
        .set_tenant_management(
            TENANT,
            &ManagementPolicy {
                enabled: true,
                device_cert_ttl: Some(3600),
                access_cert_ttl: Some(600),
                salt: "c2FsdHktc2FsdA".into(),
                ..Default::default()
            },
        )
        .unwrap();

    let (cookie, login) = idp_login(&server, &email, "hunter2secret").await;
    assert_eq!(login["success"], true, "login: {login}");
    let device_kp = KeyPair::generate();
    let issued: Value = server
        .post("/idp/device_cert")
        .add_cookie(cookie::Cookie::new("idp_session", cookie.clone()))
        .json(&json!({
            "email": email,
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
        }))
        .await
        .json();
    assert_eq!(issued["success"], true, "device_cert: {issued}");
    let device_cert = DeviceCert::parse(issued["device_cert"].as_str().unwrap()).unwrap();
    let c = device_cert.claims();
    assert_eq!(c.exp - c.iat, 3600, "device cert bound by device_cert_ttl");

    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(
        TENANT, &email, device_cert.holder().clone(), &access_kp.public_key(), "nonce-ttl-1", &device_kp,
    )
    .unwrap();
    let minted: Value = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": issued["device_cert"], "access_request": areq.encoded() }))
        .await
        .json();
    assert_eq!(minted["success"], true, "mint: {minted}");
    let ac = AccessCert::parse(minted["access_cert"].as_str().unwrap()).unwrap();
    assert_eq!(ac.claims().exp - ac.claims().iat, 600, "access cert bound by access_cert_ttl");

    // Backward compat: a pre-split policy carrying only max_ttl bounds the
    // access cert with it; the device cert falls back to the 90-day default.
    store
        .set_tenant_management(
            TENANT,
            &ManagementPolicy {
                enabled: true,
                max_ttl: Some(7200),
                salt: "c2FsdHktc2FsdA".into(),
                ..Default::default()
            },
        )
        .unwrap();
    let device_kp2 = KeyPair::generate();
    let issued2: Value = server
        .post("/idp/device_cert")
        .add_cookie(cookie::Cookie::new("idp_session", cookie))
        .json(&json!({
            "email": email,
            "device_pubkey": device_kp2.public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
        }))
        .await
        .json();
    assert_eq!(issued2["success"], true, "device_cert: {issued2}");
    let device_cert2 = DeviceCert::parse(issued2["device_cert"].as_str().unwrap()).unwrap();
    let c2 = device_cert2.claims();
    assert_eq!(c2.exp - c2.iat, 90 * 86_400, "device cert back to the default");
    let areq2 = AccessRequest::create(
        TENANT, &email, device_cert2.holder().clone(), &access_kp.public_key(), "nonce-ttl-2", &device_kp2,
    )
    .unwrap();
    let minted2: Value = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": issued2["device_cert"], "access_request": areq2.encoded() }))
        .await
        .json();
    assert_eq!(minted2["success"], true, "mint: {minted2}");
    let ac2 = AccessCert::parse(minted2["access_cert"].as_str().unwrap()).unwrap();
    assert_eq!(ac2.claims().exp - ac2.claims().iat, 7200, "legacy max_ttl bounds the access cert");
}

/// The policy endpoints round-trip the split TTLs.
#[tokio::test]
async fn management_endpoint_roundtrips_split_ttls() {
    let (server, store, sender) = make_server_full();
    let session = common::create_user(&server, &sender, "operator@op.example", "operatorpass1").await;
    let csrf = common::get_csrf(&server, &session).await;
    let created: Value = server
        .post("/wsapi/tenant/create")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({"csrf": csrf, "domain": TENANT, "admin_email": "operator@op.example"}))
        .await
        .json();
    assert_eq!(created["success"], true, "create: {created}");
    store.set_tenant_status(TENANT, TenantStatus::Active).unwrap();

    let saved: Value = server
        .post("/wsapi/tenant/management")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "csrf": csrf, "domain": TENANT, "enabled": true,
            "device_cert_ttl": 30 * 86_400, "access_cert_ttl": 3600,
        }))
        .await
        .json();
    assert_eq!(saved["success"], true, "save: {saved}");

    let got: Value = server
        .get(&format!("/wsapi/tenant/management?domain={TENANT}&csrf={csrf}"))
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .await
        .json();
    assert_eq!(got["success"], true, "get: {got}");
    assert_eq!(got["management"]["device_cert_ttl"], 30 * 86_400, "{got}");
    assert_eq!(got["management"]["access_cert_ttl"], 3600, "{got}");
    assert_eq!(got["management"]["max_ttl"], Value::Null, "{got}");
}

/// The standalone revoke-all endpoint revokes every outstanding credential
/// (management OFF — it must not depend on the policy) and reports the count;
/// the policy endpoint's revoke_now keeps working alongside it.
#[tokio::test]
async fn revoke_all_endpoint_counts_and_kills_mints() {
    let (server, store, sender) = make_server_full();
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
    store.set_tenant_status(TENANT, TenantStatus::Active).unwrap();

    // A signed-in tenant user with outstanding device + config certs.
    let email = format!("boss@{TENANT}");
    let (cookie, login) = idp_login(&server, &email, "bosspassword1").await;
    assert_eq!(login["success"], true, "{login}");
    let device_kp = KeyPair::generate();
    let issued: Value = server
        .post("/idp/device_cert")
        .add_cookie(cookie::Cookie::new("idp_session", cookie))
        .json(&json!({
            "email": email,
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
        }))
        .await
        .json();
    assert_eq!(issued["success"], true, "{issued}");
    let device_cert = DeviceCert::parse(issued["device_cert"].as_str().unwrap()).unwrap();

    let revoked: Value = server
        .post("/wsapi/tenant/revoke_all")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({"csrf": csrf, "domain": TENANT}))
        .await
        .json();
    assert_eq!(revoked["success"], true, "revoke_all: {revoked}");
    assert!(revoked["revoked"].as_u64().unwrap() >= 2, "device + config bits: {revoked}");

    // The revoked device cert can no longer mint.
    let areq = AccessRequest::create(
        TENANT, &email, device_cert.holder().clone(),
        &KeyPair::generate().public_key(), "nonce-ra-1", &device_kp,
    )
    .unwrap();
    let refused = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": issued["device_cert"], "access_request": areq.encoded() }))
        .await;
    assert_eq!(refused.status_code(), 403, "{}", refused.text());
    assert!(refused.text().contains("revoked"), "{}", refused.text());

    // revoke_now on the policy save keeps functioning.
    let again: Value = server
        .post("/wsapi/tenant/management")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({"csrf": csrf, "domain": TENANT, "enabled": false, "revoke_now": true}))
        .await
        .json();
    assert_eq!(again["success"], true, "revoke_now: {again}");
}

/// /wsapi/list_emails flags addresses whose domain runs managed identities,
/// naming the managing domain.
#[tokio::test]
async fn list_emails_flags_managed_addresses() {
    use browserid_broker::store::ManagementPolicy;

    let (server, store, sender) = make_server_full();
    let email = format!("amira@{TENANT}");
    let session = common::create_user(&server, &sender, &email, "somepassword1").await;
    seed_active_tenant(&store);

    // Active tenant, management off: not managed.
    let resp: Value = server
        .get("/wsapi/list_emails")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    assert_eq!(resp["managed"].as_array().unwrap().len(), 0, "{resp}");

    // Enable management: the address is flagged with its managing domain.
    store
        .set_tenant_management(
            TENANT,
            &ManagementPolicy { enabled: true, salt: "c2FsdHktc2FsdA".into(), ..Default::default() },
        )
        .unwrap();
    let resp: Value = server
        .get("/wsapi/list_emails")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .await
        .json();
    let managed = resp["managed"].as_array().unwrap();
    assert_eq!(managed.len(), 1, "{resp}");
    assert_eq!(managed[0]["email"], email.as_str(), "{resp}");
    assert_eq!(managed[0]["domain"], TENANT, "{resp}");
}
