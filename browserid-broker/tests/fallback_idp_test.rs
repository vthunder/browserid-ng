//! Fallback-IdP surface (apgv, device-cert model): SMTP /auth establishes an
//! email cookie that — together with the account's FULL broker session and
//! the central mint chokepoint (browserid-ng-7ww7/u4xz) — gates
//! /auth/device_cert, which batch-issues the user (authentication) + config
//! (authorization) device certs (iss = this broker) for an email whose domain
//! the broker doesn't own. Those certs then drive the standard mint →
//! presentation path. Mailbox control alone (the old cookie-only mint) is the
//! M1 password bypass and no longer issues anything.

mod common;

use browserid_broker::store::{SessionLevel, SessionStore, UserStore};
use browserid_core::device::{
    AccessPresentation, AccessRequest, DeviceCert, HolderMatcher, Purpose, Warrant,
};
use browserid_core::{Assertion, KeyPair};
use chrono::Duration;
use common::{create_test_server, create_user};
use serde_json::{json, Value};

/// Run the SMTP dance for `email` and return the fb_email cookie.
async fn fb_cookie(
    server: &axum_test::TestServer,
    email_sender: &common::MockEmailSender,
    email: &str,
) -> cookie::Cookie<'static> {
    let r = server.post("/auth/send").json(&json!({ "email": email })).await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    let code = email_sender.get_code(email).expect("code emailed");
    let r = server.post("/auth/verify").json(&json!({ "email": email, "code": code })).await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    r.maybe_cookie("fb_email").expect("email cookie set").into_owned()
}

#[tokio::test]
async fn smtp_auth_then_device_cert_issues_the_pair() {
    let ctx = common::create_test_context();
    let server = &ctx.server;
    let email_sender = &ctx.email_sender;
    let email = "someone@gmail.com"; // a domain this broker does NOT own
    let device_kp = KeyPair::generate();
    let config_kp = KeyPair::generate();
    let issue_body = json!({
        "email": email,
        "device_pubkey": device_kp.public_key().to_base64(),
        "config_pubkey": config_kp.public_key().to_base64(),
    });

    // The address backs a password account with a FULL session (7ww7: this
    // surface no longer mints for anything else).
    let session = create_user(server, email_sender, email, "password123").await;
    let session_cookie = cookie::Cookie::new("browserid_session", session);

    // 1. Issuance without the email cookie → 401, even with the full session
    //    (the SMTP-freshness contract stands).
    let r = server
        .post("/auth/device_cert")
        .add_cookie(session_cookie.clone())
        .json(&issue_body)
        .await;
    assert_eq!(r.status_code(), 401, "no fb cookie yet: {:?}", r.text());

    // 2. SMTP challenge (wrong code rejected on the way).
    let r = server.post("/auth/send").json(&json!({ "email": email })).await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    let code = email_sender.get_code(email).expect("code emailed");
    let r = server.post("/auth/verify").json(&json!({ "email": email, "code": "000000" })).await;
    assert_eq!(r.status_code(), 401);
    let r = server.post("/auth/verify").json(&json!({ "email": email, "code": code })).await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    let cookie = r.maybe_cookie("fb_email").expect("email cookie set");

    // 5. whoami reflects it.
    let who: Value = server.get("/whoami").add_cookie(cookie.clone()).await.json();
    assert_eq!(who["authenticated"], true);
    assert_eq!(who["email"], email);

    // 5b. The fb cookie ALONE no longer mints — the M1 password bypass (7ww7).
    let r = server.post("/auth/device_cert").add_cookie(cookie.clone()).json(&issue_body).await;
    assert_eq!(r.status_code(), 401, "cookie-only mint must be gone: {:?}", r.text());
    assert!(r.text().contains("password required"), "{:?}", r.text());

    // 6. Cookie + the account's full session → user + config certs, iss = broker.
    let r = server
        .post("/auth/device_cert")
        .add_cookie(cookie.clone())
        .add_cookie(session_cookie.clone())
        .json(&issue_body)
        .await;
    assert_eq!(r.status_code(), 200, "{:?}", r.text());
    let body: Value = r.json();
    let device_cert = DeviceCert::parse(body["device_cert"].as_str().unwrap()).unwrap();
    let config_cert = DeviceCert::parse(body["config_cert"].as_str().unwrap()).unwrap();
    assert_eq!(device_cert.iss(), "localhost:3000");
    assert_eq!(config_cert.iss(), "localhost:3000");
    assert_eq!(device_cert.purpose(), Purpose::Authentication);
    assert_eq!(config_cert.purpose(), Purpose::Authorization);
    // The broker assigns an opaque `<ns>.<id>` holder, shared by both certs.
    let holder = device_cert.holder().clone();
    assert!(holder.as_str().contains('.'), "holder is namespaced: {}", holder.as_str());
    assert_eq!(device_cert.holder(), config_cert.holder());
    assert!(device_cert.authorizes_identity(email));
    assert!(config_cert.authorizes_identity(email));
    // Blast-radius narrowing (7ww7): the explicit `local+*@domain` wildcard
    // is gone from the cert DATA — both certs name the exact address only.
    // (Protocol-level subaddressing still implies the base covers +tags, but
    // that rule pins the presentable identity to the warrant's exact grantee,
    // so a base cert without a matching warrant authorizes nothing.)
    assert_eq!(config_cert.claims().identities, vec![email.to_string()]);
    assert_eq!(device_cert.claims().identities, vec![email.to_string()]);
    // Per-device status refs, distinct per key.
    assert!(device_cert.claims().status.is_some());
    assert!(config_cert.claims().status.is_some());
    assert_ne!(device_cert.claims().status, config_cert.claims().status);

    // 7. The cookie only authorizes its own email (session or not).
    let r = server
        .post("/auth/device_cert")
        .add_cookie(cookie.clone())
        .add_cookie(session_cookie.clone())
        .json(&json!({
            "email": "other@gmail.com",
            "device_pubkey": device_kp.public_key().to_base64(),
            "config_pubkey": config_kp.public_key().to_base64(),
        }))
        .await;
    assert_eq!(r.status_code(), 401, "cookie must not vouch for a different email");

    // 8. The full login path: mint an access cert with the device key, sign a
    //    warrant with the config key + an assertion with the access key, and
    //    verify the 4-object presentation against the broker's key.
    let audience = "https://rp.example.com";
    let access_kp = KeyPair::generate();
    let areq = AccessRequest::create(
        "localhost:3000", email, holder.clone(), &access_kp.public_key(), "jti-fb-1", &device_kp,
    )
    .unwrap();
    let r = server
        .post("/access/mint")
        .json(&json!({ "device_cert": body["device_cert"], "access_request": areq.encoded() }))
        .await;
    assert_eq!(r.status_code(), 200, "mint: {:?}", r.text());
    let minted: Value = r.json();
    let access_cert = minted["access_cert"].as_str().unwrap();

    let warrant = Warrant::create(
        email, email, HolderMatcher::new(holder.as_str()).unwrap(), audience, vec!["login".into()], Duration::days(90), &config_kp, None,
    )
    .unwrap();
    let assertion = Assertion::create(audience, Duration::minutes(5), &access_kp).unwrap();
    let presentation = format!(
        "{}~{}~{}~{}",
        access_cert,
        assertion.encoded(),
        warrant.encoded(),
        body["config_cert"].as_str().unwrap()
    );

    // The broker's public key — an RP resolves this from the `_browserid`
    // DNSSEC record (the served `.well-known` carries no key, bean zexp).
    let broker_key = ctx.broker_key.clone();

    let verified = AccessPresentation::parse(&presentation)
        .unwrap()
        .verify(audience, |_iss| Ok(broker_key.clone()))
        .expect("full fallback-issued presentation verifies");
    assert_eq!(verified.email, email);
    assert_eq!(verified.holder, holder);
    assert_eq!(verified.scopes, vec!["login".to_string()]);

    // 9. auth_with_presentation is for PRIMARY identities only: a broker-issued
    //    (fallback) presentation must be refused — broker-rooted emails join a
    //    session with their password. (This drives the endpoint through full
    //    verification: the broker's own audience, DNSSEC discovery, then the
    //    issuer gate.)
    let broker_audience = "http://localhost:3000";
    let warrant_b = Warrant::create(
        email, email, HolderMatcher::new(holder.as_str()).unwrap(), broker_audience, vec!["login".into()], Duration::days(90), &config_kp, None,
    )
    .unwrap();
    let assertion_b = Assertion::create(broker_audience, Duration::minutes(5), &access_kp).unwrap();
    let presentation_b = format!(
        "{}~{}~{}~{}",
        access_cert,
        assertion_b.encoded(),
        warrant_b.encoded(),
        body["config_cert"].as_str().unwrap()
    );
    let r = server
        .post("/wsapi/auth_with_presentation")
        .json(&json!({ "presentation": presentation_b }))
        .await;
    assert_ne!(r.status_code(), 200, "broker-rooted presentation must be refused");
    assert!(
        r.text().contains("broker-rooted") || r.text().contains("failed"),
        "unexpected refusal reason: {}",
        r.text()
    );
}

/// The removed no-account path (7ww7/kgb9): a mailbox with no broker account
/// gets NOTHING from this surface — no cookie-only cert issuance.
#[tokio::test]
async fn no_account_cookie_only_issuance_is_gone() {
    let ctx = common::create_test_context();
    let email = "drifter@gmail.com"; // valid SMTP dance, but no account
    let cookie = fb_cookie(&ctx.server, &ctx.email_sender, email).await;

    let r = ctx
        .server
        .post("/auth/device_cert")
        .add_cookie(cookie)
        .json(&json!({
            "email": email,
            "device_pubkey": KeyPair::generate().public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
        }))
        .await;
    assert_eq!(r.status_code(), 403, "{:?}", r.text());
    assert!(r.text().contains("no account"), "{:?}", r.text());
}

/// A lightweight (E1/E2-established) session + the fb cookie still isn't
/// enough for an E3 mint here — the chokepoint demands the password (Full).
#[tokio::test]
async fn lightweight_session_still_needs_the_password() {
    let ctx = common::create_test_context();
    let email = "someone-light@gmail.com";
    create_user(&ctx.server, &ctx.email_sender, email, "password123").await;
    let user = ctx.user_store.get_user_by_email(email).unwrap().unwrap();
    let light = ctx
        .session_store
        .create(user.id, SessionLevel::Lightweight)
        .unwrap()
        .id
        .0;
    let cookie = fb_cookie(&ctx.server, &ctx.email_sender, email).await;

    let r = ctx
        .server
        .post("/auth/device_cert")
        .add_cookie(cookie)
        .add_cookie(cookie::Cookie::new("browserid_session", light))
        .json(&json!({
            "email": email,
            "device_pubkey": KeyPair::generate().public_key().to_base64(),
            "config_pubkey": KeyPair::generate().public_key().to_base64(),
        }))
        .await;
    assert_eq!(r.status_code(), 401, "{:?}", r.text());
    assert!(r.text().contains("password required"), "{:?}", r.text());
}

#[tokio::test]
async fn auth_send_rate_limited_per_email() {
    let (server, _e) = create_test_server();
    let email = "flood-unique@example.com";
    for _ in 0..5 {
        let r = server.post("/auth/send").json(&json!({ "email": email })).await;
        assert_eq!(r.status_code(), 200, "{:?}", r.text());
    }
    let r = server.post("/auth/send").json(&json!({ "email": email })).await;
    assert_eq!(r.status_code(), 429, "6th send to one address must be capped");
}

#[tokio::test]
async fn verify_code_brute_force_is_capped() {
    let (server, email_sender) = create_test_server();
    let email = "brute-unique@example.com";
    server.post("/auth/send").json(&json!({ "email": email })).await;
    let code = email_sender.get_code(email).unwrap();
    // 5 wrong attempts burn the code.
    for _ in 0..5 {
        let r = server.post("/auth/verify").json(&json!({ "email": email, "code": "999998" })).await;
        assert_eq!(r.status_code(), 401);
    }
    // Even the correct code now fails — it was burned.
    let r = server.post("/auth/verify").json(&json!({ "email": email, "code": code })).await;
    assert_eq!(r.status_code(), 401, "code must be burned after too many wrong attempts");
}
