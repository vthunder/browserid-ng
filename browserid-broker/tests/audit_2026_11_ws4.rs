//! Security audit 2026-11, WS4 (bean browserid-ng-n6nn): the broker layers
//! never audited before — hosted-primary tenancy (`routes/hosted_idp.rs`,
//! `tenant_keys.rs`), the OIDC bridge (`oidc/`, `routes/oidc.rs`), cookie
//! session admission (`routes/session.rs`, bean 160l) and the FedCM mint
//! (`routes/fedcm.rs`).
//!
//! Convention (same as WS5/WS6): a test that encodes an invariant the code
//! FAILS today is `#[ignore]`d with an `AUDIT-2026-11 <id>: fails today`
//! comment and is the acceptance test for the fix; everything else passes
//! today and pins what the skeptic pass re-verified. No production code
//! changed. Run the failing set with
//! `cargo test -p browserid-broker --test audit_2026_11_ws4 -- --ignored`.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::http::{HeaderName, HeaderValue};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_test::TestServer;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use browserid_broker::authority::AuthorityChecker;
use browserid_broker::oidc::{OidcProvider, OidcRuntime, GOOGLE_ISSUER};
use browserid_broker::store::{RosterState, TenantStatus, UserStore};
use browserid_broker::tenant_keys::KeystoreKey;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::device::{AccessCert, AccessRequest, DeviceCert, Warrant};
use browserid_core::KeyPair;
use common::{create_test_context_customized, create_user, get_csrf, MockEmailSender, TestContext};
use serde_json::{json, Value};

// ===========================================================================
// Hosted-primary tenancy harness (copied from hosted_primary_test.rs)
// ===========================================================================

const BROKER: &str = "localhost:3000";
const IDP_HOST: &str = "idp.localhost:3000";
const TENANT_A: &str = "tenant-a.example";
const TENANT_B: &str = "tenant-b.example";

fn keystore() -> KeystoreKey {
    KeystoreKey::from_env_value(&"ab".repeat(32)).unwrap()
}

fn tenant_server() -> (TestServer, Arc<InMemoryUserStore>) {
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
    state.tenant_keystore = Some(keystore());
    let server = TestServer::new(routes::create_router(Arc::new(state))).unwrap();
    (server, user_store)
}

/// Create + activate a tenant directly in the store; returns its public key.
fn seed_active_tenant(store: &InMemoryUserStore, domain: &str) -> String {
    let (public_key, sealed) = keystore().generate_sealed(domain).unwrap();
    store
        .create_tenant(domain, &public_key, &sealed, None, "admin@example.org")
        .unwrap();
    store.set_tenant_status(domain, TenantStatus::Active).unwrap();
    public_key
}

/// A roster user whose must-change flag is already cleared.
fn add_roster_ready(store: &InMemoryUserStore, domain: &str, local: &str, password: &str) {
    let tenant = store.get_tenant(domain).unwrap().unwrap();
    let hash = bcrypt::hash(password, 4).unwrap();
    store
        .create_roster_entry(tenant.id, local, &hash, false, "admin@example.org")
        .unwrap();
}

async fn idp_login(server: &TestServer, email: &str, password: &str) -> String {
    let resp = server
        .post("/idp/login")
        .json(&json!({ "email": email, "password": password }))
        .await;
    let body: Value = resp.json();
    assert_eq!(body["success"], true, "idp login: {body}");
    resp.maybe_cookie("idp_session").expect("idp cookie").value().to_string()
}

async fn idp_device_cert(server: &TestServer, cookie: &str, body: Value) -> (u16, Value) {
    let r = server
        .post("/idp/device_cert")
        .add_cookie(cookie::Cookie::new("idp_session", cookie.to_string()))
        .json(&body)
        .await;
    (r.status_code().as_u16(), r.json())
}

// ---------------------------------------------------------------------------
// D3 — holder passthrough on /idp/device_cert
// ---------------------------------------------------------------------------

/// fb §3.2: "The certs bind the fragment's keys to a holder the issuer
/// assigns fresh"; B3: the requester never chooses its holder. The hosted
/// IdP copies the body's `holder` verbatim with no namespace check, so a
/// tenant user (or whoever holds the roster password) can stamp any
/// well-formed holder on its certs — including the holder of another,
/// already-approved device — and satisfy holder-pinned warrant matchers
/// meant for that device.
#[tokio::test]
async fn d3_tenant_device_cert_does_not_take_a_caller_chosen_holder() {
    let (server, store) = tenant_server();
    seed_active_tenant(&store, TENANT_A);
    add_roster_ready(&store, TENANT_A, "alice", "correcthorse");
    let email = format!("alice@{TENANT_A}");
    let cookie = idp_login(&server, &email, "correcthorse").await;

    // A holder from somebody else's namespace, well-formed.
    let foreign_holder = "zzzzzzzzzz.attacker";
    let (status, body) = idp_device_cert(
        &server,
        &cookie,
        json!({
            "email": email,
            "device_pubkey": KeyPair::generate().public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
            "holder": foreign_holder,
        }),
    )
    .await;
    if status == 200 {
        let cert = DeviceCert::parse(body["device_cert"].as_str().unwrap()).unwrap();
        assert_ne!(
            cert.holder().as_str(),
            foreign_holder,
            "the issuer must assign the holder, not copy the caller's"
        );
    } else {
        assert_eq!(status, 403, "a caller-chosen holder is refused: {body}");
    }
}

/// Pin (passes today): with no `holder` in the body the issuer self-assigns,
/// and two cold logins get two different holders.
#[tokio::test]
async fn d3_pin_tenant_device_cert_self_assigns_a_fresh_holder_when_absent() {
    let (server, store) = tenant_server();
    seed_active_tenant(&store, TENANT_A);
    add_roster_ready(&store, TENANT_A, "alice", "correcthorse");
    let email = format!("alice@{TENANT_A}");
    let cookie = idp_login(&server, &email, "correcthorse").await;
    let mut holders = Vec::new();
    for _ in 0..2 {
        let (status, body) = idp_device_cert(
            &server,
            &cookie,
            json!({
                "email": email,
                "device_pubkey": KeyPair::generate().public_key().to_base64(),
                "config_pubkey": KeyPair::generate().public_key().to_base64(),
            }),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let d = DeviceCert::parse(body["device_cert"].as_str().unwrap()).unwrap();
        let c = DeviceCert::parse(body["config_cert"].as_str().unwrap()).unwrap();
        assert_eq!(d.holder(), c.holder(), "both certs share one holder");
        holders.push(d.holder().as_str().to_string());
    }
    assert_ne!(holders[0], holders[1], "each cold issuance gets a fresh holder");
}

// ---------------------------------------------------------------------------
// Tenant isolation pins (pass today)
// ---------------------------------------------------------------------------

/// A tenant-A roster session cannot issue for a tenant-B identity: the cookie
/// email must equal the requested email, and the tenant is resolved from
/// that email's domain, never from the Host header or a body field.
#[tokio::test]
async fn pin_tenant_cookie_cannot_issue_for_another_tenant() {
    let (server, store) = tenant_server();
    seed_active_tenant(&store, TENANT_A);
    seed_active_tenant(&store, TENANT_B);
    add_roster_ready(&store, TENANT_A, "alice", "correcthorse");
    add_roster_ready(&store, TENANT_B, "alice", "otherpassword");
    let cookie = idp_login(&server, &format!("alice@{TENANT_A}"), "correcthorse").await;
    let (status, body) = idp_device_cert(
        &server,
        &cookie,
        json!({
            "email": format!("alice@{TENANT_B}"),
            "device_pubkey": KeyPair::generate().public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
        }),
    )
    .await;
    assert_eq!(status, 403, "{body}");
}

/// The headless mint routes by the device cert's `iss` and verifies the
/// signature under THAT tenant's key: a cert signed by tenant A's key but
/// claiming `iss = tenant B` is refused, and a device cert for tenant A
/// cannot mint an access request targeting tenant B.
#[tokio::test]
async fn pin_access_cert_mint_refuses_cross_tenant_certs() {
    let (server, store) = tenant_server();
    seed_active_tenant(&store, TENANT_A);
    seed_active_tenant(&store, TENANT_B);
    add_roster_ready(&store, TENANT_A, "alice", "correcthorse");
    add_roster_ready(&store, TENANT_B, "alice", "otherpassword");
    let email_a = format!("alice@{TENANT_A}");
    let cookie = idp_login(&server, &email_a, "correcthorse").await;
    let device_kp = KeyPair::generate();
    let (status, body) = idp_device_cert(
        &server,
        &cookie,
        json!({
            "email": email_a,
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
        }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let device_cert = DeviceCert::parse(body["device_cert"].as_str().unwrap()).unwrap();

    // (1) Access request targeting tenant B with tenant A's cert.
    let areq = AccessRequest::create(
        TENANT_B,
        &format!("alice@{TENANT_B}"),
        device_cert.holder().clone(),
        &KeyPair::generate().public_key(),
        "nonce-xt-1",
        &device_kp,
    )
    .unwrap();
    let r = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": body["device_cert"], "access_request": areq.encoded() }))
        .await;
    assert_ne!(r.status_code(), 200, "cross-tenant access request must not mint");

    // (2) A forged cert: tenant A's claims re-signed with a key that is not
    // tenant B's, but naming `iss = tenant B`.
    let mut claims = device_cert.claims().clone();
    claims.iss = TENANT_B.to_string();
    let forged = DeviceCert::from_claims(claims, &KeyPair::generate()).unwrap();
    let areq = AccessRequest::create(
        TENANT_B,
        &email_a,
        device_cert.holder().clone(),
        &KeyPair::generate().public_key(),
        "nonce-xt-2",
        &device_kp,
    )
    .unwrap();
    let r = server
        .post("/idp/access_cert")
        .json(&json!({ "device_cert": forged.encoded(), "access_request": areq.encoded() }))
        .await;
    assert_ne!(r.status_code(), 200, "a cert not signed by the iss tenant's key must not mint");
}

/// Sealed keys are AAD-bound to the tenant domain: a sealed blob moved onto
/// another tenant row does not unseal (pins `tenant_keys.rs` unit tests at
/// the integration boundary).
#[test]
fn pin_sealed_tenant_key_is_bound_to_its_domain() {
    let ks = keystore();
    let (_, sealed) = ks.generate_sealed(TENANT_A).unwrap();
    assert!(ks.unseal(TENANT_B, &sealed).is_err());
    assert!(ks.unseal(TENANT_A, &sealed).is_ok());
}

// ---------------------------------------------------------------------------
// W4-30 — tenant onboarding squat
// ---------------------------------------------------------------------------

/// Any broker account can open a PendingDns tenant for ANY domain, and the
/// store refuses a second attempt for that domain (`TenantExists`) with no
/// expiry on the pending row. The real domain owner can then never onboard:
/// only the squatter (owner/admin of the pending row) may run `tenant/check`
/// or `tenant/delete`. Adversary A4. Expected: a pending attempt by another
/// account must not block the domain (expire pending rows, or let a fresh
/// attempt replace a pending one and let DNS decide).
#[tokio::test]
async fn w4_30_pending_tenant_squat_does_not_block_the_domain_owner() {
    let ctx = create_test_context_customized(|state| {
        state.idp_host = IDP_HOST.to_string();
        state.tenant_keystore = Some(keystore());
    });
    let squatter = create_user(&ctx.server, &ctx.email_sender, "squatter@example.com", "password123").await;
    let owner = create_user(&ctx.server, &ctx.email_sender, "owner@example.net", "password123").await;

    let create = |cookie: String, admin: &'static str| {
        let server = &ctx.server;
        async move {
            let csrf = get_csrf(server, &cookie).await;
            let r = server
                .post("/wsapi/tenant/create")
                .add_cookie(cookie::Cookie::new("browserid_session", cookie))
                .json(&json!({
                    "csrf": csrf,
                    "domain": "victim.example",
                    "admin_email": admin,
                }))
                .await;
            (r.status_code().as_u16(), r.json::<Value>())
        }
    };
    let (s1, b1) = create(squatter, "squatter@example.com").await;
    assert_eq!(s1, 200, "squatter opens a pending attempt: {b1}");

    // The real owner's attempt must not be refused because of a pending
    // row it does not control.
    let (s2, b2) = create(owner, "owner@example.net").await;
    assert_eq!(s2, 200, "owner's onboarding is blocked by the squat: {b2}");
}

/// Pin (passes today): a pending tenant issues nothing — login, issuance and
/// the status list all refuse until DNS activates it.
#[tokio::test]
async fn pin_pending_tenant_issues_nothing() {
    let (server, store) = tenant_server();
    let (public_key, sealed) = keystore().generate_sealed(TENANT_A).unwrap();
    store
        .create_tenant(TENANT_A, &public_key, &sealed, None, "admin@example.org")
        .unwrap();
    add_roster_ready(&store, TENANT_A, "alice", "correcthorse");
    let r = server
        .post("/idp/login")
        .json(&json!({ "email": format!("alice@{TENANT_A}"), "password": "correcthorse" }))
        .await;
    assert_eq!(r.status_code(), 401);
    let r = server.get(&format!("/status/{TENANT_A}")).await;
    assert_ne!(r.status_code(), 200, "no status list for a pending tenant");
}

// ---------------------------------------------------------------------------
// W4-31 — stateless idp_session cookie ignores roster changes
// ---------------------------------------------------------------------------

/// The `/idp` cookie is stateless (`{email, exp, mc}` signed by the root
/// key, 2 h). `/idp/device_cert` reads the must-change flag from the COOKIE,
/// not the roster, so after an admin resets a user's password
/// (`roster_password` sets `must_change = true`) a session opened under the
/// old password keeps issuing 90-day certs until the cookie expires. The
/// roster's `Active` state IS re-read, so disabling works; the password
/// reset does not.
#[tokio::test]
async fn w4_31_admin_password_reset_stops_an_open_idp_session_from_issuing() {
    let (server, store) = tenant_server();
    seed_active_tenant(&store, TENANT_A);
    add_roster_ready(&store, TENANT_A, "alice", "correcthorse");
    let email = format!("alice@{TENANT_A}");
    let cookie = idp_login(&server, &email, "correcthorse").await;
    let tenant = store.get_tenant(TENANT_A).unwrap().unwrap();

    // Admin resets the password (what POST /wsapi/tenant/roster/password does).
    store
        .set_roster_password(tenant.id, "alice", &bcrypt::hash("newtemppass1", 4).unwrap(), true)
        .unwrap();

    let (status, body) = idp_device_cert(
        &server,
        &cookie,
        json!({
            "email": email,
            "device_pubkey": KeyPair::generate().public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
        }),
    )
    .await;
    assert_eq!(status, 403, "a pre-reset session must not issue: {body}");
}

/// Pin (passes today): disabling the roster user does stop issuance under an
/// open cookie — the roster state is read fresh at issuance.
#[tokio::test]
async fn pin_roster_disable_stops_an_open_idp_session_from_issuing() {
    let (server, store) = tenant_server();
    seed_active_tenant(&store, TENANT_A);
    add_roster_ready(&store, TENANT_A, "alice", "correcthorse");
    let email = format!("alice@{TENANT_A}");
    let cookie = idp_login(&server, &email, "correcthorse").await;
    let tenant = store.get_tenant(TENANT_A).unwrap().unwrap();
    store.set_roster_state(tenant.id, "alice", RosterState::Disabled).unwrap();
    let (status, _) = idp_device_cert(
        &server,
        &cookie,
        json!({
            "email": email,
            "device_pubkey": KeyPair::generate().public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
        }),
    )
    .await;
    assert_eq!(status, 403);
}

// ---------------------------------------------------------------------------
// W4-32 — idp_session cookie: root-key signature with no type tag (July L3 class)
// ---------------------------------------------------------------------------

/// July L3 was closed by deleting the `fb_email` route; the same shape
/// returned in `idp_session`: `b64(json{email,exp,mc}).b64(sig)` signed by
/// the broker ROOT key over the bare payload, no `typ`, no domain tag. Not
/// exploitable today (every other root-key signature is a JWS whose signing
/// input contains a `.`), but the latent signing-confusion the July report
/// flagged is back. Expected: a `typ` discriminator in the signed payload
/// (or an HMAC under a derived cookie key, not the issuer key).
#[tokio::test]
async fn w4_32_idp_session_cookie_payload_carries_a_type_tag() {
    let (server, store) = tenant_server();
    seed_active_tenant(&store, TENANT_A);
    add_roster_ready(&store, TENANT_A, "alice", "correcthorse");
    let cookie = idp_login(&server, &format!("alice@{TENANT_A}"), "correcthorse").await;
    let (payload, _sig) = cookie.rsplit_once('.').unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert!(
        claims.get("typ").is_some(),
        "idp cookie payload has no type discriminator: {claims}"
    );
}

/// Pin (passes today): the cookie's signature covers the payload — a
/// re-encoded payload naming another roster user is refused.
#[tokio::test]
async fn pin_idp_session_cookie_payload_is_signature_bound() {
    let (server, store) = tenant_server();
    seed_active_tenant(&store, TENANT_A);
    add_roster_ready(&store, TENANT_A, "alice", "correcthorse");
    add_roster_ready(&store, TENANT_A, "bob", "correcthorse");
    let cookie = idp_login(&server, &format!("alice@{TENANT_A}"), "correcthorse").await;
    let (payload, sig) = cookie.rsplit_once('.').unwrap();
    let mut claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    claims["email"] = json!(format!("bob@{TENANT_A}"));
    let forged = format!("{}.{sig}", URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes()));
    let who: Value = server
        .get("/idp/whoami")
        .add_cookie(cookie::Cookie::new("idp_session", forged))
        .await
        .json();
    assert!(who["email"].is_null(), "forged cookie must not authenticate: {who}");
}

// ===========================================================================
// D19 — FedCM server-side mint
// ===========================================================================

fn sec_fetch_dest() -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("sec-fetch-dest"),
        HeaderValue::from_static("webidentity"),
    )
}

async fn fedcm_token(ctx: &TestContext, session: &str, email: &str) -> String {
    let res = ctx
        .server
        .post("/fedcm/assertion")
        .add_header(
            HeaderName::from_static("origin"),
            HeaderValue::from_static("https://rp.example.com"),
        )
        .add_header(sec_fetch_dest().0, sec_fetch_dest().1)
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .form(&[("account_id", email)])
        .await;
    assert_eq!(res.status_code(), 200, "{}", res.text());
    res.json::<Value>()["token"].as_str().unwrap().to_string()
}

/// Core §6.3 / fb §3.2: per-key status refs on both certs; S3 (decided):
/// every warrant carries a status ref. The FedCM mint signs a throwaway
/// config cert and the login warrant server-side with `status: None`, and
/// registers the warrant with `status_idx: None` — so "forget this site"
/// cannot revoke it. Mitigation today: the whole presentation lives 5 min
/// (pinned below). Decision for Dan: accept as the documented FedCM
/// exception (and say so in core §6.3), or allocate refs on the broker list.
// AUDIT-2026-11 D19: fails today
#[ignore]
#[tokio::test]
async fn d19_fedcm_config_cert_and_warrant_carry_status_refs() {
    let ctx = common::create_test_context();
    let session = create_user(&ctx.server, &ctx.email_sender, "alice@example.com", "Password123!").await;
    let token = fedcm_token(&ctx, &session, "alice@example.com").await;
    let parts: Vec<&str> = token.split('~').collect();
    assert_eq!(parts.len(), 4, "access~assertion~warrant~config");
    let warrant = Warrant::parse(parts[2]).unwrap();
    let config = DeviceCert::parse(parts[3]).unwrap();
    assert!(config.claims().status.is_some(), "config cert has no status ref");
    assert!(warrant.claims().status.is_some(), "login warrant has no status ref");
}

/// Pin (passes today): the FedCM presentation is short-lived end to end —
/// every object expires within 5 minutes of issue — which bounds D19.
#[tokio::test]
async fn d19_pin_fedcm_presentation_is_bounded_to_five_minutes() {
    let ctx = common::create_test_context();
    let session = create_user(&ctx.server, &ctx.email_sender, "alice@example.com", "Password123!").await;
    let token = fedcm_token(&ctx, &session, "alice@example.com").await;
    let parts: Vec<&str> = token.split('~').collect();
    let access = AccessCert::parse(parts[0]).unwrap();
    let warrant = Warrant::parse(parts[2]).unwrap();
    let config = DeviceCert::parse(parts[3]).unwrap();
    let now = chrono::Utc::now().timestamp();
    for (what, exp) in [
        ("access cert", access.claims().exp),
        ("warrant", warrant.claims().exp),
        ("config cert", config.claims().exp),
    ] {
        assert!(exp - now <= 5 * 60 + 5, "{what} lives {}s", exp - now);
    }
}

// ===========================================================================
// OIDC bridge harness (copied from oidc_claim_test.rs)
// ===========================================================================

const TEST_KID: &str = "test-kid-1";
const TEST_N: &str = "k9MkcSs6W_CoUQbpXsP1MXq_cx_TwdP8-gnaNl4kQnMzTRK4IJdvgD2u1aAXhKdbV1MtJKU0ZqyWwFxc2mbHEkmNVMsBTPUVVk6iZGhcchTNOpPlw2wFN_NWWt_rnEpGjtzagUaFr_UF5KfkbIUa5xJZaG661P3yGmUDMQhWDBBJ0EEmtB0xbfi9Xzss0B7RCYTf_ejQzut3w_tQcP1ax378Ki3qJFqJjJqfUHAvPWSyT9QqttS89hgayCOXl8qPVb9H_R8qZdbTj1-ZnBYz2ayUmKzKYErMmFgim97Ib-Mahpjqq_SIH9LTWQTqeT1bIVYsnfeqULnzWLraags60Q";
const TEST_E: &str = "AQAB";
const TEST_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCT0yRxKzpb8KhR
Bulew/Uxer9zH9PB0/z6Cdo2XiRCczNNErggl2+APa7VoBeEp1tXUy0kpTRmrJbA
XFzaZscSSY1UywFM9RVWTqJkaFxyFM06k+XDbAU381Za3+ucSkaO3NqBRoWv9QXk
p+RshRrnEllobrrU/fIaZQMxCFYMEEnQQSa0HTFt+L1fOyzQHtEJhN/96NDO63fD
+1Bw/VrHfvwqLeokWomMmp9QcC89ZLJP1Cq21Lz2GBrII5eXyo9Vv0f9Hypl1tOP
X5mcFjPZrJSYrMpgSsyYWCKb3shv4xqGmOqr9Igf0tNZBOp5PVshViyd96pQufNY
utpqCzrRAgMBAAECggEANefAeb48PUuwbT+6eTK3JnBvARHBnARsU1elab8BtPOi
aQAjAcuHPvn/V+pVuSt4LQtpQlw2FBzqqkHkIEZrYJlOvvV6R3B18++f20KNN5Kr
VimZlx48du829dOC7Q7O1Qjna03msUgF+qBYtVQCf/HahbEfU005bHOaatZx3lrC
TGyZTPGaE2KPQNrjD/XngeZwydJo18jujcccK2UgrG41CN6qk9bnvbbVGSU20W6K
om4c5QLqj4V2OYEXm6P9d8VSTobtShJCVCrZSEC3YjpFD6BcXVHjxnkBeLLOQ+iA
3S2ahE5KgiJbKXnEqZwKVvFiZ1zQPSdFgnzjoMFY4wKBgQDHWVqObBcx5/I60J3O
kxwdFxPN8TBmQz8QrGOeqkRr7PquWY7OFN3fNCOOOe1Wk9npCLKn1WYhrK5eoa+N
zkD2lK6C9iyZyMYmoLpexlblHtpZiQC/+OJIa5EZTt/zUQBTejdBtPL3uRZVrFdR
0oQ8fnKDsTs39y6m2JXOsoxHQwKBgQC91WXCdDNc9XXpuZhRfMNhI+eeK47aG9JM
Sz5xYDdkdwv3UKCdfj+5YkbHebuVKiKuZt4pYBpmJpUzlWunqGNkK/JJs6zvB2Li
tmJfIaGCv2jeuwLFK6jXNdC8kvfpt6xTX4tRGHYukde7z6SJsB2HY4lLmtMg0OQ0
2IOhl30iWwKBgBSFFBc49SJD9+Ep/DR5XBl6eKVoQE0meuVieVapvCVH3X345gQ8
jaIeIdLQD6gry/B63rj79Gle9wvypLl6E6HOKDB+2pRx4EO1o7mBvQwUovE4cwVP
vyspN2RdhBvtqJTvLaTr1V6+hJgJB2v6uXXopiz8H1ZhcUHnZXRDWME1AoGBALZ2
9H2pFWmnofPK6eaBZobrbQjyUzfAAC5HMLjnQ7b0WnMYc5mOLRAyr1ey4aPpwTYj
OC1K63T+ZvETEUwwpYA2YYeIBZQnZFwH9Jv+BnFXLCTSWkJMydg6KO3o0hQ68I+e
yZlkSsxOcK9cUYnq1yc4fFJIeeEUCBXnevaKVsP7AoGBAKNK6JaY9cLGDtopkAC7
59Nh5WHnxjm+V/DsxjK4a/fiZ5BXZM1BBGVVP+DZ5HVJV+a3a9zqwC0a3SF7m+YA
4jGU4+EOM1K43lsOWEyvcqGHdgtQrCsrcACETFGf1VTRVPRd93xG6KkyymVwV1vI
hsJX71r6EqXNoyjpb6m9XfTc
-----END PRIVATE KEY-----";
const CLIENT_ID: &str = "test-client.apps.googleusercontent.com";

fn mint_id_token(claims: &Value) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(TEST_KID.into());
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).unwrap();
    jsonwebtoken::encode(&header, claims, &key).unwrap()
}

fn base_claims(email: &str, nonce: &str, sub: &str) -> Value {
    json!({
        "iss": GOOGLE_ISSUER,
        "aud": CLIENT_ID,
        "exp": (chrono::Utc::now().timestamp() + 300),
        "iat": chrono::Utc::now().timestamp(),
        "sub": sub,
        "email": email,
        "email_verified": true,
        "nonce": nonce,
    })
}

struct MockGoogle {
    base: String,
    next_claims: Arc<Mutex<Option<Value>>>,
}

impl MockGoogle {
    fn respond_with(&self, claims: Value) {
        *self.next_claims.lock().unwrap() = Some(claims);
    }
}

async fn start_mock_google() -> MockGoogle {
    let next_claims: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let for_token = next_claims.clone();
    let app = Router::new()
        .route(
            "/token",
            post(move || {
                let next = for_token.clone();
                async move {
                    let claims = next.lock().unwrap().clone().expect("no staged claims");
                    Json(json!({
                        "id_token": mint_id_token(&claims),
                        "access_token": "unused",
                        "token_type": "Bearer",
                    }))
                }
            }),
        )
        .route(
            "/jwks",
            get(|| async {
                Json(json!({
                    "keys": [{ "kid": TEST_KID, "kty": "RSA", "alg": "RS256",
                               "n": TEST_N, "e": TEST_E }]
                }))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    MockGoogle { base, next_claims }
}

async fn oidc_context() -> (TestContext, MockGoogle) {
    let mock = start_mock_google().await;
    let provider = OidcProvider {
        name: "google",
        issuer: GOOGLE_ISSUER.to_string(),
        auth_endpoint: format!("{}/auth", mock.base),
        token_endpoint: format!("{}/token", mock.base),
        jwks_uri: format!("{}/jwks", mock.base),
        client_id: CLIENT_ID.to_string(),
        client_secret: "sekrit".to_string(),
    };
    let ctx = create_test_context_customized(|state| {
        state.oidc = Some(OidcRuntime::new(provider));
        state.authority = AuthorityChecker::fixed_with_mx_hosts(
            HashMap::new(),
            HashMap::from([
                ("gmail.com".to_string(), Some("aspmx.l.google.com".to_string())),
                ("plain.test".to_string(), Some("mx.plain.test".to_string())),
            ]),
            None,
        );
    });
    (ctx, mock)
}

/// Begin the claim under an optional broker session cookie; returns
/// (state, nonce, flow cookie).
async fn begin_claim(
    ctx: &TestContext,
    email: &str,
    session: Option<&str>,
) -> (String, String, cookie::Cookie<'static>) {
    let mut req = ctx.server.get(&format!("/oidc/claim?email={email}"));
    if let Some(s) = session {
        req = req.add_cookie(cookie::Cookie::new("browserid_session", s.to_string()));
    }
    let resp = req.await;
    assert_eq!(resp.status_code(), 303, "claim leg redirects: {}", resp.text());
    let loc = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    let url = reqwest::Url::parse(&loc).unwrap();
    let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let flow_cookie = resp.maybe_cookie("browserid_oidc_flow").expect("flow cookie");
    (q["state"].clone(), q["nonce"].clone(), flow_cookie)
}

async fn login_again(ctx: &TestContext, email: &str, password: &str) -> String {
    let r = ctx
        .server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": email, "pass": password }))
        .await;
    assert_eq!(r.status_code(), 200);
    r.maybe_cookie("browserid_session").unwrap().value().to_string()
}

// ---------------------------------------------------------------------------
// W4-33 — OIDC flow records the starting session but attaches to whichever
// session rides the callback
// ---------------------------------------------------------------------------

/// `OidcFlows::begin` stores the broker session that began the claim
/// (`FlowState.session_id`) but `attach_verified` ignores it and reads the
/// cookie session at callback time. The double-submit flow cookie proves the
/// same BROWSER, not the same account: if the browser's broker session
/// changes between the two legs, the proven identity attaches to the new
/// session's account. Low today (no login-CSRF vector on the broker was
/// found), but the recorded binding should be enforced or removed.
#[tokio::test]
async fn w4_33_oidc_attaches_to_the_session_that_began_the_claim() {
    let (ctx, mock) = oidc_context().await;
    let first = create_user(&ctx.server, &ctx.email_sender, "first@plain.test", "password123").await;
    let second = create_user(&ctx.server, &ctx.email_sender, "second@plain.test", "password123").await;
    let first_uid = ctx.user_store.get_email("first@plain.test").unwrap().unwrap().user_id;

    let (st, nonce, flow) = begin_claim(&ctx, "dan@gmail.com", Some(&first)).await;
    mock.respond_with(base_claims("dan@gmail.com", &nonce, "google-sub-1"));
    // The callback arrives with a DIFFERENT broker session in the browser.
    let resp = ctx
        .server
        .get(&format!("/oidc/callback?code=c0de&state={st}"))
        .add_cookie(flow)
        .add_cookie(cookie::Cookie::new("browserid_session", second.clone()))
        .await;
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    if loc.contains("status=ok") {
        let rec = ctx.user_store.get_email("dan@gmail.com").unwrap().unwrap();
        assert_eq!(rec.user_id, first_uid, "identity attached to the callback-time session, not the one that began the claim");
    }
}

// ---------------------------------------------------------------------------
// W4-34 — bridge grant is per (account, email), not per session
// ---------------------------------------------------------------------------

/// `record_bridge_grant` keys the single-use grant on `(user_id, email)` and
/// `/device/issue` redeems it from ANY session of that account within 10
/// minutes. So a second browser holding a Full session on the account (say,
/// one enrolled with a leaked password) mints certs for the bridge-proofed
/// address the moment the real user re-proves it elsewhere — without the
/// Google ceremony the chokepoint demands of E2 addresses. Spec fb §3.2 says
/// "a live bridge grant"; it does not say whose. Decision: bind the grant to
/// the session that ran the ceremony (store the session id with it), or
/// accept and document that a bridge proof is account-wide for 10 minutes.
#[tokio::test]
async fn w4_34_bridge_grant_is_redeemable_only_by_the_proving_session() {
    let (ctx, mock) = oidc_context().await;
    // Browser 1: the admitted session (create_user admits it).
    let other_browser = create_user(&ctx.server, &ctx.email_sender, "owner@plain.test", "password123").await;
    // Browser 2: a second password login that runs the Google ceremony.
    let proving = login_again(&ctx, "owner@plain.test", "password123").await;

    let (st, nonce, flow) = begin_claim(&ctx, "dan@gmail.com", Some(&proving)).await;
    mock.respond_with(base_claims("dan@gmail.com", &nonce, "google-sub-1"));
    let resp = ctx
        .server
        .get(&format!("/oidc/callback?code=c0de&state={st}"))
        .add_cookie(flow)
        .add_cookie(cookie::Cookie::new("browserid_session", proving.clone()))
        .await;
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.contains("status=ok"), "{loc}");

    // Browser 1 never saw Google, yet redeems the grant.
    let csrf = get_csrf(&ctx.server, &other_browser).await;
    let r = ctx
        .server
        .post("/device/issue")
        .add_cookie(cookie::Cookie::new("browserid_session", other_browser.clone()))
        .json(&json!({
            "csrf": csrf,
            "email": "dan@gmail.com",
            "device_pubkey": KeyPair::generate().public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
        }))
        .await;
    assert_ne!(
        r.status_code(),
        200,
        "a session that did not run the bridge redeemed its grant: {}",
        r.text()
    );
}

/// Pin (passes today): the grant is single-use and only the bridge-proofed
/// address is mintable under it — a second issue for the same address is
/// refused until the bridge runs again.
#[tokio::test]
async fn pin_bridge_grant_is_single_use() {
    let (ctx, mock) = oidc_context().await;
    let session = create_user(&ctx.server, &ctx.email_sender, "owner@plain.test", "password123").await;
    let (st, nonce, flow) = begin_claim(&ctx, "dan@gmail.com", Some(&session)).await;
    mock.respond_with(base_claims("dan@gmail.com", &nonce, "google-sub-1"));
    let resp = ctx
        .server
        .get(&format!("/oidc/callback?code=c0de&state={st}"))
        .add_cookie(flow)
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await;
    assert!(resp.headers().get("location").unwrap().to_str().unwrap().contains("status=ok"));

    let issue = |n: u32| {
        let server = &ctx.server;
        let session = session.clone();
        async move {
            let csrf = get_csrf(server, &session).await;
            server
                .post("/device/issue")
                .add_cookie(cookie::Cookie::new("browserid_session", session))
                .json(&json!({
                    "csrf": csrf,
                    "email": "dan@gmail.com",
                    "device_pubkey": KeyPair::generate().public_key().to_base64(),
                    "config_pubkey": KeyPair::generate().public_key().to_base64(),
                    "nonce": n,
                }))
                .await
        }
    };
    let first = issue(1).await;
    assert_eq!(first.status_code(), 200, "{}", first.text());
    let second = issue(2).await;
    assert_ne!(second.status_code(), 200, "grant must be single-use");
}

// ---------------------------------------------------------------------------
// OIDC pins (pass today): what the skeptic re-verified
// ---------------------------------------------------------------------------

/// `alg` confusion is closed: the verifier is pinned to RS256, so an HS256
/// token "signed" with the RSA modulus bytes as the secret is refused.
#[tokio::test]
async fn pin_oidc_rejects_hs256_tokens() {
    let (ctx, _mock) = oidc_context().await;
    let (st, nonce, flow) = begin_claim(&ctx, "dan@gmail.com", None).await;
    // Stage an HS256 token directly through the mock's claims: the mock
    // always mints RS256, so instead exercise the verifier in-process.
    let jwks = browserid_broker::oidc::Jwks::parse(&json!({
        "keys": [{ "kid": TEST_KID, "kty": "RSA", "alg": "RS256", "n": TEST_N, "e": TEST_E }]
    }).to_string()).unwrap();
    let provider = OidcProvider::google(CLIENT_ID, "sekrit");
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(TEST_KID.into());
    let hs = jsonwebtoken::encode(
        &header,
        &base_claims("dan@gmail.com", &nonce, "s"),
        &jsonwebtoken::EncodingKey::from_secret(&URL_SAFE_NO_PAD.decode(TEST_N).unwrap()),
    )
    .unwrap();
    assert!(browserid_broker::oidc::verify_id_token(&hs, &jwks, &provider, &nonce, "dan@gmail.com").is_err());
    let _ = (st, flow);
}

/// A token that omits `email_verified` (deserialises as false) is refused.
#[tokio::test]
async fn pin_oidc_requires_email_verified() {
    let (ctx, mock) = oidc_context().await;
    let (st, nonce, flow) = begin_claim(&ctx, "dan@gmail.com", None).await;
    let mut claims = base_claims("dan@gmail.com", &nonce, "s");
    claims.as_object_mut().unwrap().remove("email_verified");
    mock.respond_with(claims);
    let resp = ctx
        .server
        .get(&format!("/oidc/callback?code=c0de&state={st}"))
        .add_cookie(flow)
        .await;
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.contains("oidc_error="), "{loc}");
    assert!(ctx.user_store.get_email("dan@gmail.com").unwrap().is_none());
}

/// A callback whose flow cookie belongs to a DIFFERENT flow (two tabs) is
/// refused: the cookie must equal the `state` being redeemed.
#[tokio::test]
async fn pin_oidc_flow_cookie_must_match_the_state_being_redeemed() {
    let (ctx, mock) = oidc_context().await;
    let (st1, nonce1, _flow1) = begin_claim(&ctx, "dan@gmail.com", None).await;
    let (_st2, _nonce2, flow2) = begin_claim(&ctx, "dan@gmail.com", None).await;
    mock.respond_with(base_claims("dan@gmail.com", &nonce1, "s"));
    let resp = ctx
        .server
        .get(&format!("/oidc/callback?code=c0de&state={st1}"))
        .add_cookie(flow2)
        .await;
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.contains("oidc_error="), "{loc}");
}

// ===========================================================================
// Session admission pins (pass today)
// ===========================================================================

/// A registry session on account B cannot admit a cookie session on account
/// A, and an admitted session is unbound when its login key is revoked.
#[tokio::test]
async fn pin_session_admit_requires_the_same_account_and_unbinds_on_revoke() {
    use common::registry::{admit_with, api_login};
    let ctx = common::create_test_context();
    let a = common::create_user_unadmitted(&ctx.server, &ctx.email_sender, "a@example.com", "password123").await;
    let b = common::create_user_unadmitted(&ctx.server, &ctx.email_sender, "b@example.com", "password123").await;
    let b_sess = api_login(&ctx.server, &b, "password123").await;
    let r = admit_with(&ctx.server, &a, &b_sess).await;
    assert_eq!(r.status_code(), 403, "cross-account admission: {}", r.text());

    // Admit A properly, then revoke the key through the registrar glue.
    let a_sess = common::registry::admit_session(&ctx.server, &a, "password123").await;
    let before: Value = ctx
        .server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", a.clone()))
        .await
        .json();
    assert_eq!(before["admitted"], true);
    // Revoking the login key via the registry logout lane unbinds.
    let _ = a_sess;
    let a_uid = ctx.user_store.get_email("a@example.com").unwrap().unwrap().user_id;
    let keys = ctx.session_store.clone();
    let session = browserid_broker::store::SessionStore::get(
        keys.as_ref(),
        &browserid_broker::store::SessionId(a.clone()),
    )
    .unwrap()
    .unwrap();
    let key_id = session.login_key_id.expect("admitted");
    browserid_broker::store::SessionStore::unbind_login_key(keys.as_ref(), a_uid, key_id).unwrap();
    let after: Value = ctx
        .server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", a.clone()))
        .await
        .json();
    assert_eq!(after["admitted"], false);
}
