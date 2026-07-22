//! Merged one-approval agent provisioning (agent/D phase), end to end over
//! HTTP: the agent's `/agent-provision/request` carries its pubkey + handle +
//! namespace hint + warrant grant(s); the approval page calls
//! `/agent-provision/prepare` (broker assigns the holder + status indices),
//! signs the warrant(s) client-side with the user's config cert, and approves
//! via `/agent-provision/complete`; one `/agent-provision/poll` returns BOTH
//! the agent device cert and the `warrant~config_cert` grants, ready to
//! assemble a verifying 4-object presentation.

mod common;

use std::sync::Arc;

use axum_test::TestServer;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::device::{
    AccessCert, AccessPresentation, AccessRequest, DeviceCert, Holder, HolderMatcher, Purpose,
    Warrant,
};
use browserid_core::{Assertion, KeyPair, PublicKey, StatusRef};
use browserid_registrar::{IssuerKeyResolver, RegistrarError};
use chrono::Duration;
use common::{create_user, MockEmailSender};
use serde_json::{json, Value};

const DOMAIN: &str = "localhost:3000";
const DELEGATOR: &str = "alice@example.com";
const AGENT: &str = "alice+poster@example.com";
const AUDIENCE: &str = "sbo+raw://avail:turing:506/";

fn make_server() -> (TestServer, MockEmailSender, KeyPair) {
    let keypair = KeyPair::generate();
    let email_sender = Arc::new(MockEmailSender::new());
    let mut state = AppState::new_with_arcs(
        keypair.clone(),
        DOMAIN.to_string(),
        Arc::new(InMemoryUserStore::new()),
        Arc::new(InMemorySessionStore::new()),
        email_sender.clone(),
    );
    state.agent_provisioning_enabled = true;
    let server = TestServer::new(routes::create_router(Arc::new(state))).unwrap();
    (server, MockEmailSender { sent: email_sender.sent.clone() }, keypair)
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
async fn merged_request_prepare_approve_single_pickup() {
    let (server, sender, idp_kp) = make_server();
    let session = create_user(&server, &sender, DELEGATOR, "testpassword").await;

    // The browser's config cert covering the delegator's `+` namespace (what
    // login issuance deposits in the keystore).
    let config_kp = KeyPair::generate();
    let config_cert = DeviceCert::create(
        DOMAIN, &config_kp.public_key(), Purpose::Authorization, Holder::new("br.main").unwrap(),
        vec![DELEGATOR.to_string(), "alice+*@example.com".to_string()],
        Duration::days(90), &idp_kp, None,
    )
    .unwrap();

    // 1. The service starts pairing: pubkey + handle + namespace hint + grant.
    let device_kp = KeyPair::generate();
    let r = server
        .post("/agent-provision/request")
        .json(&json!({
            "provisioning_pubkey": { "algorithm": "Ed25519", "publicKey": device_kp.public_key().to_base64() },
            "requested_handles": { "names": ["alice+poster"] },
            "namespace": "services",
            "grants": [{ "audience": AUDIENCE, "scopes": ["action:post"] }],
            "label": "mingo poster",
        }))
        .await;
    assert_eq!(r.status_code(), 200, "request: {:?}", r.text());
    let code = r.json::<Value>()["code"].as_str().unwrap().to_string();

    // 2. The approval page's display info carries the grants + namespace.
    let info: Value = server
        .post("/agent-provision/info")
        .json(&json!({ "code": code }))
        .await
        .json();
    assert_eq!(info["namespace"], "services");
    assert_eq!(info["grants"][0]["audience"], AUDIENCE);

    // 3. Approving with grants but without `prepare` is refused: the page must
    //    sign matchers against the broker-assigned holder.
    let c = csrf(&server, &session).await;
    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "identity_email": DELEGATOR }))
        .await;
    assert_ne!(r.status_code(), 200, "complete without prepare must be refused");

    // 4. Prepare: the broker assigns the holder + allocates status indices.
    let prep: Value = server
        .post("/agent-provision/prepare")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "identity_email": DELEGATOR }))
        .await
        .json();
    assert_eq!(prep["success"], true, "prepare: {prep}");
    assert_eq!(prep["agent_email"], AGENT);
    let holder = prep["holder"].as_str().unwrap().to_string();
    assert!(holder.contains('.'), "holder is `<ns-prefix>.<rand>`: {holder}");
    let status_uri = prep["status_uri"].as_str().unwrap().to_string();
    let status_idx = prep["grants"][0]["status_idx"].as_u64().expect("status idx allocated");

    // Re-prepare is idempotent for the same identity: same holder.
    let prep2: Value = server
        .post("/agent-provision/prepare")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "identity_email": DELEGATOR }))
        .await
        .json();
    assert_eq!(prep2["holder"], holder);

    // 5. A warrant with a matcher that doesn't cover the assigned holder is
    //    refused all-or-nothing at complete.
    let foreign = Warrant::create(
        AGENT, HolderMatcher::new("zz.other").unwrap(), AUDIENCE, vec!["action:post".into()],
        Duration::days(90), &config_kp,
        Some(StatusRef { uri: status_uri.clone(), idx: status_idx }),
    )
    .unwrap();
    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "identity_email": DELEGATOR,
            "warrants": [foreign.encoded()], "config_cert": config_cert.encoded() }))
        .await;
    assert_ne!(r.status_code(), 200, "foreign holder matcher must be refused");

    // 6. The page signs the warrant against the assigned holder and approves.
    let warrant = Warrant::create(
        AGENT, HolderMatcher::new(&holder).unwrap(), AUDIENCE, vec!["action:post".into()],
        Duration::days(90), &config_kp,
        Some(StatusRef { uri: status_uri.clone(), idx: status_idx }),
    )
    .unwrap();
    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "identity_email": DELEGATOR,
            "warrants": [warrant.encoded()], "config_cert": config_cert.encoded() }))
        .await;
    assert_eq!(r.status_code(), 200, "complete: {:?}", r.text());

    // 7. ONE poll returns both the device cert and the warrant.
    let poll: Value = server
        .post("/agent-provision/poll")
        .json(&json!({ "code": code }))
        .await
        .json();
    assert_eq!(poll["status"], "completed", "{poll}");
    assert_eq!(poll["credential"]["identity"], AGENT);
    let device_cert_jws = poll["credential"]["device_cert"].as_str().unwrap().to_string();
    let tail = poll["grants"][0]["warrant"].as_str().unwrap().to_string();
    assert_eq!(tail, format!("{}~{}", warrant.encoded(), config_cert.encoded()));

    // The issued device cert carries the SAME holder the warrant binds to.
    let device_cert = DeviceCert::parse(&device_cert_jws).unwrap();
    assert_eq!(device_cert.holder().as_str(), holder);
    assert_eq!(device_cert.purpose(), Purpose::Authentication);

    // 8. The grant landed in the delegator's warrant registry.
    let warrants: Value = server
        .get("/wsapi/warrants")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let w = &warrants["warrants"][0];
    assert_eq!(w["agent_email"], AGENT);
    assert_eq!(w["holder"], holder);

    // 9. Full presentation: mint an access cert with the agent device key,
    //    splice the delivered tail, verify the join.
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(
        DOMAIN, AGENT, Holder::new(holder.clone()).unwrap(), &access_kp.public_key(), "jti-m1", &device_kp,
    )
    .unwrap();
    let minted: Value = server
        .post("/access/mint")
        .json(&json!({ "device_cert": device_cert_jws, "access_request": areq.encoded() }))
        .await
        .json();
    assert_eq!(minted["success"], true, "mint: {minted}");
    let assertion = Assertion::create(AUDIENCE, Duration::minutes(5), &access_kp).unwrap();
    let presentation = format!(
        "{}~{}~{}",
        minted["access_cert"].as_str().unwrap(),
        assertion.encoded(),
        tail
    );
    let verified = AccessPresentation::parse(&presentation)
        .unwrap()
        .verify(AUDIENCE, |_| Ok(idp_kp.public_key()))
        .expect("merged-provisioned service presentation verifies");
    assert_eq!(verified.email, AGENT);
    assert_eq!(verified.holder.as_str(), holder);
    assert_eq!(verified.scopes, vec!["action:post".to_string()]);
}

/// A fixed "primary IdP key directory" for the primary-signed-cert path: the
/// registrar discovers `mingo.test`'s key through its issuer resolver.
struct StubResolver {
    domain: String,
    key: PublicKey,
}
impl IssuerKeyResolver for StubResolver {
    fn resolve_issuer_key<'a>(
        &'a self,
        domain: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<PublicKey, RegistrarError>> + Send + 'a>,
    > {
        Box::pin(async move {
            if domain == self.domain {
                Ok(self.key.clone())
            } else {
                Err(RegistrarError::ValidationError(format!("unknown issuer '{domain}'")))
            }
        })
    }
}

/// Primary-domain agent (issuer-consistency rule): the approval page hands
/// `complete` a PRIMARY-signed device cert carrying the prepared holder; the
/// registrar verifies it against the primary's discovered key and delivers it
/// (with the primary as the credential's IdP) instead of signing its own.
#[tokio::test]
async fn primary_signed_device_cert_is_validated_and_delivered() {
    const PRIMARY: &str = "mingo.test";
    const P_DELEGATOR: &str = "dan@mingo.test";
    const P_AGENT: &str = "dan+poster@mingo.test";

    let primary_kp = KeyPair::generate();
    let keypair = KeyPair::generate();
    let email_sender = Arc::new(MockEmailSender::new());
    let mut state = AppState::new_with_arcs(
        keypair,
        DOMAIN.to_string(),
        Arc::new(InMemoryUserStore::new()),
        Arc::new(InMemorySessionStore::new()),
        email_sender.clone(),
    );
    state.agent_provisioning_enabled = true;
    state.issuer_resolver_override = Some(Arc::new(StubResolver {
        domain: PRIMARY.to_string(),
        key: primary_kp.public_key(),
    }));
    let server = TestServer::new(routes::create_router(Arc::new(state))).unwrap();
    let sender = MockEmailSender { sent: email_sender.sent.clone() };
    let session = create_user(&server, &sender, P_DELEGATOR, "testpassword").await;

    // The user's config cert for the primary identity — issued by the PRIMARY
    // (deposited at dialog login), covering the `+` namespace.
    let config_kp = KeyPair::generate();
    let config_cert = DeviceCert::create(
        PRIMARY, &config_kp.public_key(), Purpose::Authorization, Holder::new("br.main").unwrap(),
        vec![P_DELEGATOR.to_string(), "dan+*@mingo.test".to_string()],
        Duration::days(90), &primary_kp, None,
    )
    .unwrap();

    let device_kp = KeyPair::generate();
    let r = server
        .post("/agent-provision/request")
        .json(&json!({
            "provisioning_pubkey": { "algorithm": "Ed25519", "publicKey": device_kp.public_key().to_base64() },
            "requested_handles": { "names": ["dan+poster"] },
            "namespace": "services",
            "grants": [{ "audience": AUDIENCE, "scopes": ["action:post"] }],
        }))
        .await;
    assert_eq!(r.status_code(), 200, "request: {:?}", r.text());
    let code = r.json::<Value>()["code"].as_str().unwrap().to_string();

    let c = csrf(&server, &session).await;
    let prep: Value = server
        .post("/agent-provision/prepare")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "identity_email": P_DELEGATOR }))
        .await
        .json();
    assert_eq!(prep["success"], true, "prepare: {prep}");
    assert_eq!(prep["agent_email"], P_AGENT);
    let holder = prep["holder"].as_str().unwrap().to_string();
    let status_uri = prep["status_uri"].as_str().unwrap().to_string();
    let status_idx = prep["grants"][0]["status_idx"].as_u64().unwrap();

    // The primary signs the agent cert over the request's key + PREPARED holder
    // (what its device-authorize agent mode does during the page's hop).
    let primary_cert = DeviceCert::create(
        PRIMARY, &device_kp.public_key(), Purpose::Authentication,
        Holder::new(holder.clone()).unwrap(), vec![P_AGENT.to_string()],
        Duration::days(90), &primary_kp, None,
    )
    .unwrap();
    let warrant = Warrant::create(
        P_AGENT, HolderMatcher::new(&holder).unwrap(), AUDIENCE, vec!["action:post".into()],
        Duration::days(90), &config_kp,
        Some(StatusRef { uri: status_uri, idx: status_idx }),
    )
    .unwrap();

    // A cert carrying a DIFFERENT holder than prepared is refused (rule 1: the
    // broker assigned the holder; nobody swaps in another).
    let wrong_holder_cert = DeviceCert::create(
        PRIMARY, &device_kp.public_key(), Purpose::Authentication,
        Holder::new("zz.rogue").unwrap(), vec![P_AGENT.to_string()],
        Duration::days(90), &primary_kp, None,
    )
    .unwrap();
    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "identity_email": P_DELEGATOR,
            "warrants": [warrant.encoded()], "config_cert": config_cert.encoded(),
            "device_cert": wrong_holder_cert.encoded() }))
        .await;
    assert_ne!(r.status_code(), 200, "wrong-holder primary cert must be refused");

    // A cert signed by a key that isn't the primary's discovered key is refused.
    let rogue_kp = KeyPair::generate();
    let rogue_cert = DeviceCert::create(
        PRIMARY, &device_kp.public_key(), Purpose::Authentication,
        Holder::new(holder.clone()).unwrap(), vec![P_AGENT.to_string()],
        Duration::days(90), &rogue_kp, None,
    )
    .unwrap();
    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "identity_email": P_DELEGATOR,
            "warrants": [warrant.encoded()], "config_cert": config_cert.encoded(),
            "device_cert": rogue_cert.encoded() }))
        .await;
    assert_ne!(r.status_code(), 200, "rogue-signed primary cert must be refused");

    // The genuine primary cert is accepted; poll delivers it with the primary
    // as the credential's IdP.
    // A mint URL off the issuer's origin is refused.
    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "identity_email": P_DELEGATOR,
            "warrants": [warrant.encoded()], "config_cert": config_cert.encoded(),
            "device_cert": primary_cert.encoded(),
            "access_mint": "https://evil.test/access/mint" }))
        .await;
    assert_ne!(r.status_code(), 200, "foreign-origin access_mint must be refused");

    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "identity_email": P_DELEGATOR,
            "warrants": [warrant.encoded()], "config_cert": config_cert.encoded(),
            "device_cert": primary_cert.encoded(),
            "access_mint": "https://mingo.test/api/browserid/access_cert" }))
        .await;
    assert_eq!(r.status_code(), 200, "complete: {:?}", r.text());

    let poll: Value = server
        .post("/agent-provision/poll")
        .json(&json!({ "code": code }))
        .await
        .json();
    assert_eq!(poll["status"], "completed", "{poll}");
    assert_eq!(poll["credential"]["device_cert"], primary_cert.encoded());
    assert_eq!(poll["credential"]["idp"], format!("https://{PRIMARY}"));
    assert_eq!(
        poll["credential"]["access_mint"],
        "https://mingo.test/api/browserid/access_cert",
        "the agent is told the primary's discovered mint URL"
    );
    let tail = poll["grants"][0]["warrant"].as_str().unwrap().to_string();

    // The provisioned service is visible in the holder registry (account
    // "Devices & services") under its holder, labeled from the request.
    let holders: Value = server
        .get("/wsapi/holders")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await
        .json();
    let all: Vec<Value> = holders["namespaces"].as_array().unwrap().iter()
        .flat_map(|n| n["holders"].as_array().unwrap().clone())
        .chain(holders["holders_without_namespace"].as_array().unwrap().clone())
        .collect();
    let row = all.iter().find(|h| h["holder_id"] == holder.as_str())
        .expect("provisioned holder listed in the registry");
    assert_eq!(row["identities"][0], P_AGENT);

    // The full presentation — access cert minted BY THE PRIMARY (as the agent
    // would at the primary's /access/mint) + the delivered warrant tail —
    // verifies with a single consistent issuer.
    let access_kp = KeyPair::generate();
    let access_cert = AccessCert::create(
        PRIMARY, P_AGENT, Holder::new(holder.clone()).unwrap(), &access_kp.public_key(),
        Duration::minutes(10), &primary_kp, None,
    )
    .unwrap();
    let assertion = Assertion::create(AUDIENCE, Duration::minutes(5), &access_kp).unwrap();
    let presentation = format!("{}~{}~{}", access_cert.encoded(), assertion.encoded(), tail);
    let verified = AccessPresentation::parse(&presentation)
        .unwrap()
        .verify(AUDIENCE, |iss| {
            if iss == PRIMARY { Ok(primary_kp.public_key()) } else {
                Err(browserid_core::Error::InvalidCertificate(format!("unknown issuer {iss}")))
            }
        })
        .expect("primary-rooted service presentation verifies");
    assert_eq!(verified.email, P_AGENT);
    assert_eq!(verified.holder.as_str(), holder);
}

/// As-you service (holder model): no requested handle → the service holds the
/// delegating identity ITSELF, isolated by its broker-assigned holder; the
/// warrant names the user, so writes stay owned by + attributed to the user.
#[tokio::test]
async fn as_you_service_provisions_under_the_users_own_identity() {
    let (server, sender, idp_kp) = make_server();
    let session = create_user(&server, &sender, DELEGATOR, "testpassword").await;

    let config_kp = KeyPair::generate();
    let config_cert = DeviceCert::create(
        DOMAIN, &config_kp.public_key(), Purpose::Authorization, Holder::new("br.main").unwrap(),
        vec![DELEGATOR.to_string()], Duration::days(90), &idp_kp, None,
    )
    .unwrap();

    let device_kp = KeyPair::generate();
    let r = server
        .post("/agent-provision/request")
        .json(&json!({
            "provisioning_pubkey": { "algorithm": "Ed25519", "publicKey": device_kp.public_key().to_base64() },
            "namespace": "services",
            "grants": [{ "audience": AUDIENCE, "scopes": ["action:post"] }],
            "label": "mingo poster",
        }))
        .await;
    assert_eq!(r.status_code(), 200, "request: {:?}", r.text());
    let code = r.json::<Value>()["code"].as_str().unwrap().to_string();

    let c = csrf(&server, &session).await;
    let prep: Value = server
        .post("/agent-provision/prepare")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "identity_email": DELEGATOR }))
        .await
        .json();
    assert_eq!(prep["success"], true, "prepare: {prep}");
    // The service's identity IS the user's own.
    assert_eq!(prep["agent_email"], DELEGATOR);
    let holder = prep["holder"].as_str().unwrap().to_string();
    let status_uri = prep["status_uri"].as_str().unwrap().to_string();
    let status_idx = prep["grants"][0]["status_idx"].as_u64().unwrap();

    let warrant = Warrant::create(
        DELEGATOR, HolderMatcher::new(&holder).unwrap(), AUDIENCE, vec!["action:post".into()],
        Duration::days(90), &config_kp,
        Some(StatusRef { uri: status_uri, idx: status_idx }),
    )
    .unwrap();
    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "identity_email": DELEGATOR,
            "warrants": [warrant.encoded()], "config_cert": config_cert.encoded() }))
        .await;
    assert_eq!(r.status_code(), 200, "complete: {:?}", r.text());

    let poll: Value = server
        .post("/agent-provision/poll")
        .json(&json!({ "code": code }))
        .await
        .json();
    assert_eq!(poll["status"], "completed", "{poll}");
    assert_eq!(poll["credential"]["identity"], DELEGATOR);
    assert_eq!(poll["credential"]["access_mint"], format!("http://{DOMAIN}/access/mint"));
    let device_cert = DeviceCert::parse(poll["credential"]["device_cert"].as_str().unwrap()).unwrap();
    assert_eq!(device_cert.holder().as_str(), holder);
    let tail = poll["grants"][0]["warrant"].as_str().unwrap().to_string();

    // Full presentation attributes to the USER (owner=you), on the service holder.
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(
        DOMAIN, DELEGATOR, Holder::new(holder.clone()).unwrap(), &access_kp.public_key(), "jti-s1", &device_kp,
    )
    .unwrap();
    let minted: Value = server
        .post("/access/mint")
        .json(&json!({ "device_cert": poll["credential"]["device_cert"], "access_request": areq.encoded() }))
        .await
        .json();
    assert_eq!(minted["success"], true, "mint: {minted}");
    let assertion = Assertion::create(AUDIENCE, Duration::minutes(5), &access_kp).unwrap();
    let presentation = format!(
        "{}~{}~{}",
        minted["access_cert"].as_str().unwrap(),
        assertion.encoded(),
        tail
    );
    let verified = AccessPresentation::parse(&presentation)
        .unwrap()
        .verify(AUDIENCE, |_| Ok(idp_kp.public_key()))
        .expect("as-you service presentation verifies");
    assert_eq!(verified.email, DELEGATOR);
    assert_eq!(verified.holder.as_str(), holder);
}

/// A grant-less request keeps today's shape: no prepare needed, `complete`
/// assigns the holder itself, poll delivers just the credential.
#[tokio::test]
async fn grantless_request_still_completes_without_prepare() {
    let (server, sender, _idp_kp) = make_server();
    let session = create_user(&server, &sender, DELEGATOR, "testpassword").await;

    let device_kp = KeyPair::generate();
    let r = server
        .post("/agent-provision/request")
        .json(&json!({
            "provisioning_pubkey": { "algorithm": "Ed25519", "publicKey": device_kp.public_key().to_base64() },
            "requested_handles": { "names": ["alice+bot"] },
        }))
        .await;
    assert_eq!(r.status_code(), 200, "request: {:?}", r.text());
    let code = r.json::<Value>()["code"].as_str().unwrap().to_string();

    let c = csrf(&server, &session).await;
    let r = server
        .post("/agent-provision/complete")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "csrf": c, "code": code, "approve": true, "identity_email": DELEGATOR }))
        .await;
    assert_eq!(r.status_code(), 200, "complete: {:?}", r.text());

    let poll: Value = server
        .post("/agent-provision/poll")
        .json(&json!({ "code": code }))
        .await
        .json();
    assert_eq!(poll["status"], "completed", "{poll}");
    assert_eq!(poll["grants"].as_array().map(|g| g.len()), Some(0));
    let device_cert = DeviceCert::parse(poll["credential"]["device_cert"].as_str().unwrap()).unwrap();
    // Default namespace: the holder sits under the user's `agents` prefix.
    assert!(device_cert.holder().as_str().contains('.'));
}
