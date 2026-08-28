//! The central mint chokepoint wired into the issuance routes
//! (browserid-ng-u4xz, epic shyj): /device/issue and /fedcm/* consult
//! authorize_mint — provenance (EmailType × ProofMethod) × session level —
//! instead of the old verified-only gate. The pure decision matrix itself is
//! unit-tested in src/mint.rs; these tests prove the ROUTES obey it.

mod common;

use axum::http::{HeaderName, HeaderValue};
use browserid_broker::store::{
    EmailType, ProofMethod, SessionLevel, SessionStore, SqliteStore, UserStore,
};
use browserid_core::KeyPair;
use common::{create_test_context, create_user, get_csrf, TestContext};
use serde_json::{json, Value};

fn issue_body(csrf: &str, email: &str) -> Value {
    json!({
        "csrf": csrf,
        "email": email,
        "device_pubkey": KeyPair::generate().public_key().to_base64(),
        "config_pubkey": KeyPair::generate().public_key().to_base64(),
    })
}

async fn device_issue(ctx: &TestContext, session: &str, email: &str) -> (u16, Value) {
    let csrf = get_csrf(&ctx.server, session).await;
    let response = ctx
        .server
        .post("/device/issue")
        .add_cookie(cookie::Cookie::new(
            "browserid_session",
            session.to_string(),
        ))
        .json(&issue_body(&csrf, email))
        .await;
    (response.status_code().as_u16(), response.json())
}

/// E3 (Secondary + Smtp): full session mints, lightweight session gets the
/// 401 password step-up — never a silent mint.
#[tokio::test]
async fn e3_mint_requires_full_session() {
    let ctx = create_test_context();
    let email = "e3@example.com";
    let full = create_user(&ctx.server, &ctx.email_sender, email, "password123").await;

    // Full session → allowed.
    let (status, body) = device_issue(&ctx, &full, email).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["success"], true);

    // Same account, lightweight session (bridge-established analogue) → 401
    // with the stable step-up reason the dialog branches on.
    let user = ctx.user_store.get_user_by_email(email).unwrap().unwrap();
    let light = ctx
        .session_store
        .create(user.id, SessionLevel::Lightweight)
        .unwrap()
        .id
        .0;
    let (status, body) = device_issue(&ctx, &light, email).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["reason"], "password required");
}

/// E2 (Secondary + Oidc/Atproto): the broker session NEVER mints — not even
/// a full one. Issuance is the bridge's (pr3a).
#[tokio::test]
async fn e2_mint_refused_even_with_full_session() {
    let ctx = create_test_context();
    let full = create_user(&ctx.server, &ctx.email_sender, "owner@example.com", "password123").await;
    let user = ctx
        .user_store
        .get_user_by_email("owner@example.com")
        .unwrap()
        .unwrap();

    for (email, proof) in [
        ("gmailish@example.com", ProofMethod::Oidc),
        ("handle@example.com", ProofMethod::Atproto),
    ] {
        ctx.user_store
            .add_email_with_type(user.id, email, true, EmailType::Secondary)
            .unwrap();
        ctx.user_store
            .set_email_proof(email, proof, Some("subject"))
            .unwrap();

        let (status, body) = device_issue(&ctx, &full, email).await;
        assert_eq!(status, 403, "{proof:?}: {body}");
    }
}

/// E1 (Primary): the broker must never sign iss=broker for a primary
/// identity; /device/issue refuses and the client uses the primary's own
/// device-cert endpoint.
#[tokio::test]
async fn primary_mint_refused() {
    let ctx = create_test_context();
    let full = create_user(&ctx.server, &ctx.email_sender, "owner@example.com", "password123").await;
    let user = ctx
        .user_store
        .get_user_by_email("owner@example.com")
        .unwrap()
        .unwrap();
    ctx.user_store
        .add_email_with_type(user.id, "me@primary-idp.example", true, EmailType::Primary)
        .unwrap();

    let (status, body) = device_issue(&ctx, &full, "me@primary-idp.example").await;
    assert_eq!(status, 403, "{body}");
}

/// Agent identities are broker-vouched (minted via the delegation chain), so
/// signing in AS one follows the E3 rule: full mints, lightweight steps up.
#[tokio::test]
async fn agent_identity_follows_password_rule() {
    let ctx = create_test_context();
    let full = create_user(&ctx.server, &ctx.email_sender, "owner@example.com", "password123").await;
    let user = ctx
        .user_store
        .get_user_by_email("owner@example.com")
        .unwrap()
        .unwrap();
    ctx.user_store
        .add_email_with_type(user.id, "owner+bot@example.com", true, EmailType::Agent)
        .unwrap();

    let (status, body) = device_issue(&ctx, &full, "owner+bot@example.com").await;
    assert_eq!(status, 200, "{body}");

    let light = ctx
        .session_store
        .create(user.id, SessionLevel::Lightweight)
        .unwrap()
        .id
        .0;
    let (status, body) = device_issue(&ctx, &light, "owner+bot@example.com").await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["reason"], "password required");
}

/// FedCM mints entirely off the session, so its accounts list and assertion
/// gate follow the chokepoint: E2 entries disappear, and a lightweight
/// session offers nothing.
#[tokio::test]
async fn fedcm_follows_the_chokepoint() {
    let ctx = create_test_context();
    let email = "alice@example.com";
    let full = create_user(&ctx.server, &ctx.email_sender, email, "password123").await;
    let user = ctx.user_store.get_user_by_email(email).unwrap().unwrap();

    // An E2 sibling address on the same account.
    ctx.user_store
        .add_email_with_type(user.id, "alice-gmail@example.com", true, EmailType::Secondary)
        .unwrap();
    ctx.user_store
        .set_email_proof("alice-gmail@example.com", ProofMethod::Oidc, Some("s"))
        .unwrap();

    let dest = (
        HeaderName::from_static("sec-fetch-dest"),
        HeaderValue::from_static("webidentity"),
    );

    // Accounts under the FULL session: E3 listed, E2 filtered out.
    let response = ctx
        .server
        .get("/fedcm/accounts")
        .add_header(dest.0.clone(), dest.1.clone())
        .add_cookie(cookie::Cookie::new("browserid_fedcm", full.clone()))
        .await;
    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    let ids: Vec<&str> = body["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![email]);

    // Assertion for the E2 address is refused even under the full session.
    let response = ctx
        .server
        .post("/fedcm/assertion")
        .add_header(
            HeaderName::from_static("origin"),
            HeaderValue::from_static("https://rp.example.com"),
        )
        .add_header(dest.0.clone(), dest.1.clone())
        .add_cookie(cookie::Cookie::new("browserid_fedcm", full.clone()))
        .form(&[("account_id", "alice-gmail@example.com")])
        .await;
    assert_eq!(response.status_code(), 403);

    // A lightweight session has nothing FedCM may mint: accounts 401s (empty
    // list) and an assertion for the E3 is refused.
    let light = ctx
        .session_store
        .create(user.id, SessionLevel::Lightweight)
        .unwrap()
        .id
        .0;
    let response = ctx
        .server
        .get("/fedcm/accounts")
        .add_header(dest.0.clone(), dest.1.clone())
        .add_cookie(cookie::Cookie::new("browserid_fedcm", light.clone()))
        .await;
    assert_eq!(response.status_code(), 401);

    let response = ctx
        .server
        .post("/fedcm/assertion")
        .add_header(
            HeaderName::from_static("origin"),
            HeaderValue::from_static("https://rp.example.com"),
        )
        .add_header(dest.0, dest.1)
        .add_cookie(cookie::Cookie::new("browserid_fedcm", light))
        .form(&[("account_id", email)])
        .await;
    assert_eq!(response.status_code(), 403);
}

/// The chokepoint's inputs (email_type, proof) round-trip through the real
/// SQLite store — memory-store coverage alone misses sqlite constraints.
#[test]
fn sqlite_provenance_feeds_the_chokepoint() {
    use browserid_broker::mint::{authorize_mint, MintDecision, Voucher};

    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("test.db");
    let store = SqliteStore::open(path.to_str().unwrap()).unwrap();
    let user_id = store.create_user("hash").unwrap();

    store
        .add_email_with_type(user_id, "e2@example.com", true, EmailType::Secondary)
        .unwrap();
    store
        .set_email_proof("e2@example.com", ProofMethod::Oidc, Some("iss#sub"))
        .unwrap();
    store.add_email(user_id, "e3@example.com", true).unwrap();

    let emails = store.list_emails(user_id).unwrap();
    let e2 = emails.iter().find(|e| e.email == "e2@example.com").unwrap();
    let e3 = emails.iter().find(|e| e.email == "e3@example.com").unwrap();

    assert_eq!(
        authorize_mint(e2, SessionLevel::Full),
        MintDecision::Delegate(Voucher::Oidc)
    );
    assert_eq!(authorize_mint(e3, SessionLevel::Full), MintDecision::Allow);
    assert_eq!(
        authorize_mint(e3, SessionLevel::Lightweight),
        MintDecision::NeedPassword
    );
}

/// Regression guard: every file that creates broker-signed certs is a
/// REGISTERED issuance surface, and the session-authed ones call
/// authorize_mint. A new `DeviceCert::create`/`AccessCert::create` call site
/// fails this test until its mint policy is decided (the epic's
/// no-silent-bypass invariant).
#[test]
fn issuance_call_sites_are_registered() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut minting_files = Vec::new();
    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                // ::create signs with the broker key; ::from_claims is the
                // raw constructor hosted_idp signs tenant-key certs with.
                if text.contains("DeviceCert::create")
                    || text.contains("AccessCert::create")
                    || text.contains("DeviceCert::from_claims")
                    || text.contains("AccessCert::from_claims")
                {
                    minting_files.push(
                        path.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/"),
                    );
                }
            }
        }
    }
    minting_files.sort();

    // The audited issuance surfaces. device.rs + fedcm.rs mint off the broker
    // session → chokepoint required. hosted_idp.rs is the tenant PRIMARY's
    // own issuance (the E1 voucher itself) — outside the broker-session
    // chokepoint by design. (fallback_idp.rs — the 7ww7 exact-only slice —
    // retired with bean 2jfh: the fallback ceremony page issues through the
    // /device/issue core in device.rs.)
    assert_eq!(
        minting_files,
        vec![
            "routes/device.rs".to_string(),
            "routes/fedcm.rs".to_string(),
            "routes/hosted_idp.rs".to_string(),
        ],
        "unaudited issuance call site — wire it through authorize_mint (u4xz) and register it here"
    );

    for file in ["routes/device.rs", "routes/fedcm.rs"] {
        let text = std::fs::read_to_string(src.join(file)).unwrap();
        assert!(
            text.contains("authorize_mint"),
            "{file} mints without consulting authorize_mint"
        );
    }
}

/// hg2j store scope: revoke_user_certs_for_email flips ONLY the (user, email)
/// pair's rows + status bits — the same user's other addresses and other
/// users' rows for the same address stay live. On the real SQLite store.
#[test]
fn sqlite_revoke_user_certs_for_email_is_precisely_scoped() {
    use browserid_broker::store::DeviceCertRecord;
    use chrono::Utc;

    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("test.db");
    let store = SqliteStore::open(path.to_str().unwrap()).unwrap();
    let alice = store.create_user("hash").unwrap();
    let bob = store.create_user("hash").unwrap();

    let mut insert = |user, email: &str, key: &str| {
        let idx = store.get_or_allocate_status("device", key).unwrap();
        store
            .insert_device_cert(DeviceCertRecord {
                id: 0,
                user_id: user,
                identities: vec![email.to_string()],
                purpose: "authentication".to_string(),
                holder: "ns.h1".to_string(),
                pubkey: key.to_string(),
                iss: "localhost:3000".to_string(),
                issued_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::days(90),
                revoked_at: None,
                status_uri: Some("uri".to_string()),
                status_idx: Some(idx),
                prov: "smtp".to_string(),
            })
            .unwrap();
        idx
    };
    let target_idx = insert(alice, "moving@example.com", "key-a1");
    let sibling_idx = insert(alice, "staying@example.com", "key-a2");
    let bobs_idx = insert(bob, "moving@example.com", "key-b1");

    assert_eq!(
        store.revoke_user_certs_for_email(alice, "Moving@Example.com").unwrap(),
        1
    );
    assert!(store.is_status_revoked_idx(target_idx).unwrap());
    assert!(!store.is_status_revoked_idx(sibling_idx).unwrap());
    assert!(!store.is_status_revoked_idx(bobs_idx).unwrap());

    let alices: Vec<_> = store.list_device_certs(alice).unwrap();
    assert!(alices.iter().any(|c| c.identities == vec!["moving@example.com"] && c.revoked_at.is_some()));
    assert!(alices.iter().any(|c| c.identities == vec!["staying@example.com"] && c.revoked_at.is_none()));
}

/// kts0, owner requirement: an E3-era cert is SWAPPED at its next use once
/// the address upgrades to E2 — never left valid until expiry, never manually
/// cleared. /access/mint refuses AND revokes the stale-class cert; the dialog
/// reacts by re-issuing through the bridge ceremony.
#[tokio::test]
async fn stale_class_cert_is_refused_and_revoked_at_next_mint() {
    use browserid_core::device::{AccessRequest, DeviceCert};

    let ctx = create_test_context();
    let email = "gmailish@example.com";
    let session = create_user(&ctx.server, &ctx.email_sender, email, "password123").await;
    let csrf = get_csrf(&ctx.server, &session).await;

    // E3-era issuance under the full session: the cert is stamped with the
    // class it was issued under.
    let device_kp = KeyPair::generate();
    let resp = ctx
        .server
        .post("/device/issue")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({
            "csrf": csrf, "email": email,
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
        }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let cert_str = resp.json::<Value>()["device_cert"].as_str().unwrap().to_string();
    let cert = DeviceCert::parse(&cert_str).unwrap();
    assert_eq!(cert.claims().prov.as_deref(), Some("smtp"), "issuance stamps the class");
    let holder = cert.holder().clone();

    let mint = |jti: &str| {
        let areq = AccessRequest::create(
            "localhost:3000", email, holder.clone(),
            &KeyPair::generate().public_key(), jti, &device_kp,
        )
        .unwrap();
        let server = &ctx.server;
        let cert_str = cert_str.clone();
        async move {
            server
                .post("/access/mint")
                .json(&json!({ "device_cert": cert_str, "access_request": areq.encoded() }))
                .await
        }
    };

    // Mints fine while the record is E3.
    assert_eq!(mint("jti-swap-1").await.status_code(), 200);

    // The address upgrades to E2 (store-direct, simulating an upgrade that
    // predates revoke-on-upgrade — e.g. legacy history or a broker-side
    // domain ceremony change with a later re-proof).
    ctx.user_store
        .set_email_proof(email, ProofMethod::Oidc, Some("s"))
        .unwrap();

    // The stale-class cert dies at its NEXT USE.
    let resp = mint("jti-swap-2").await;
    assert_eq!(resp.status_code(), 403, "{}", resp.text());
    assert!(
        resp.text().contains("revoked") && resp.text().contains("reissue"),
        "{}",
        resp.text()
    );

    // And stays dead (the status bit is flipped, sticky).
    let resp = mint("jti-swap-3").await;
    assert_eq!(resp.status_code(), 403, "{}", resp.text());
}

/// x5c3: ONE stale-class presentation revokes the WHOLE stale set — the
/// config sibling and other browsers' pairs — with registry rows stamped
/// (honest /account list), not just the presented cert's bit.
#[tokio::test]
async fn stale_class_presentation_revokes_the_whole_stale_set() {
    use browserid_core::device::{AccessRequest, DeviceCert};

    let ctx = create_test_context();
    let email = "swapall@example.com";
    let session = create_user(&ctx.server, &ctx.email_sender, email, "password123").await;
    let csrf = get_csrf(&ctx.server, &session).await;

    // Two E3-era browser pairs (4 registry rows: 2 auth + 2 config).
    let mut issue = |kp: &KeyPair| {
        let server = &ctx.server;
        let session = session.clone();
        let csrf = csrf.clone();
        let device_pub = kp.public_key().to_base64();
        async move {
            let resp = server
                .post("/device/issue")
                .add_cookie(cookie::Cookie::new("browserid_session", session))
                .json(&json!({
                    "csrf": csrf, "email": email,
                    "device_pubkey": device_pub,
                    "config_pubkey": KeyPair::generate().public_key().to_base64(),
                }))
                .await;
            assert_eq!(resp.status_code(), 200, "{}", resp.text());
            resp.json::<Value>()["device_cert"].as_str().unwrap().to_string()
        }
    };
    let kp_a = KeyPair::generate();
    let kp_b = KeyPair::generate();
    let cert_a = issue(&kp_a).await;
    let _cert_b = issue(&kp_b).await;

    // The record upgrades to E2 (store-direct; the claim paths do their own
    // revocation — this covers legacy/off-path upgrades).
    ctx.user_store
        .set_email_proof(email, ProofMethod::Oidc, Some("s"))
        .unwrap();

    // Present ONLY browser A's cert.
    let holder = DeviceCert::parse(&cert_a).unwrap().holder().clone();
    let areq = AccessRequest::create(
        "localhost:3000", email, holder,
        &KeyPair::generate().public_key(), "jti-swapall-1", &kp_a,
    )
    .unwrap();
    let resp = ctx
        .server
        .post("/access/mint")
        .json(&json!({ "device_cert": cert_a, "access_request": areq.encoded() }))
        .await;
    assert_eq!(resp.status_code(), 403, "{}", resp.text());

    // ALL FOUR stale-class rows are revoked and stamped — including browser
    // B's pair and both config certs, none of which were ever presented.
    let user = ctx.user_store.get_user_by_email(email).unwrap().unwrap();
    let rows: Vec<_> = ctx
        .user_store
        .list_device_certs(user.id)
        .unwrap()
        .into_iter()
        .filter(|r| r.identities.iter().any(|i| i == email))
        .collect();
    assert_eq!(rows.len(), 4, "expected 2 browser pairs in the registry");
    for r in &rows {
        assert!(
            r.revoked_at.is_some(),
            "row {} ({}, prov {}) must be stamped revoked",
            r.id, r.purpose, r.prov
        );
    }
}

/// x5c3 store precision on SQLite: the class revoker kills only rows whose
/// recorded class differs — current-class rows and other addresses survive.
#[test]
fn sqlite_stale_class_revoker_spares_current_class() {
    use browserid_broker::store::DeviceCertRecord;
    use chrono::Utc;

    let dir = tempfile::TempDir::new().unwrap();
    let store = SqliteStore::open(dir.path().join("t.db").to_str().unwrap()).unwrap();
    let user = store.create_user("hash").unwrap();

    let mut insert = |email: &str, key: &str, prov: &str| {
        let idx = store.get_or_allocate_status("device", key).unwrap();
        store
            .insert_device_cert(DeviceCertRecord {
                id: 0,
                user_id: user,
                identities: vec![email.to_string()],
                purpose: "authentication".to_string(),
                holder: "ns.h1".to_string(),
                pubkey: key.to_string(),
                iss: "localhost:3000".to_string(),
                issued_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::days(90),
                revoked_at: None,
                status_uri: Some("uri".to_string()),
                status_idx: Some(idx),
                prov: prov.to_string(),
            })
            .unwrap();
        idx
    };
    let stale_idx = insert("up@example.com", "k-stale", "smtp");
    let fresh_idx = insert("up@example.com", "k-fresh", "oidc");
    let other_idx = insert("other@example.com", "k-other", "smtp");

    assert_eq!(
        store
            .revoke_user_stale_class_certs(user, "Up@Example.com", "oidc")
            .unwrap(),
        1
    );
    assert!(store.is_status_revoked_idx(stale_idx).unwrap());
    assert!(!store.is_status_revoked_idx(fresh_idx).unwrap());
    assert!(!store.is_status_revoked_idx(other_idx).unwrap());
    let rows = store.list_device_certs(user).unwrap();
    assert!(rows.iter().any(|r| r.pubkey == "k-stale" && r.revoked_at.is_some()));
    assert!(rows.iter().any(|r| r.pubkey == "k-fresh" && r.revoked_at.is_none()));
}
