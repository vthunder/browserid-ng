//! FedCM IdP spike (browserid-ng-mhyp): browserid.me as a FedCM Identity
//! Provider for fallback identities. Proves the device-model token the FedCM
//! assertion endpoint mints is a standard `cert~assertion` that verifies with
//! the existing core verifier — ZERO verifier changes — and honors the
//! fallback-only + audience-binding rules.

mod common;

use axum::http::{HeaderName, HeaderValue};
use browserid_broker::error::BrokerError;
use browserid_broker::verifier::verify_access_with_dns;
use browserid_broker::{Discoverer, FallbackResult};
use browserid_core::discovery::SupportDocument;
use browserid_core::PublicKey;
use common::{create_test_server, create_user};
use serde_json::Value;

const AUDIENCE: &str = "https://rp.example.com";
const BROKER: &str = "localhost:3000";

/// A minimal discoverer that says "no domain has a primary; the broker vouches"
/// — the fallback case for a Secondary email. Mirrors an RP verifying a
/// browserid.me-issued fallback token via /verify with accepted_fallbacks.
struct BrokerFallback {
    key: PublicKey,
}

impl Discoverer for BrokerFallback {
    fn discover(
        &self,
        _domain: &str,
    ) -> impl std::future::Future<Output = Result<FallbackResult, BrokerError>> + Send {
        let res = Ok(FallbackResult {
            document: SupportDocument::new(self.key.clone()),
            authoritative_domain: BROKER.to_string(),
            is_primary: false,
            serving_host: None,
        });
        async move { res }
    }
}

fn sec_fetch_dest() -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("sec-fetch-dest"),
        HeaderValue::from_static("webidentity"),
    )
}

fn never_revoked(_idx: u64) -> Result<bool, String> {
    Ok(false)
}

/// StatusCtx matching the test broker's own status URI, nothing revoked.
macro_rules! own_status_ctx {
    ($cache:expr) => {
        browserid_broker::verifier::StatusCtx {
            own_uri: browserid_registrar::consent::status_list_uri(BROKER),
            is_own_revoked: &never_revoked,
            cache: $cache,
            allow_private_hosts: true,
        }
    };
}

#[tokio::test]
async fn fedcm_mints_verifiable_assertion() {
    let ctx = common::create_test_context();
    let server = &ctx.server;
    let email_sender = &ctx.email_sender;

    // The broker signing key — resolved from the `_browserid` DNSSEC record in
    // production (the served `.well-known` carries no key, bean zexp).
    let broker_pub = ctx.broker_key.clone();

    // A fallback (SMTP-verified Secondary) identity + its session.
    let session = create_user(&server, &email_sender, "alice@example.com", "Password123!").await;
    let sess_cookie = || cookie::Cookie::new("browserid_session", session.clone());

    // --- metadata endpoints (pure) ---
    let wi: Value = server.get("/.well-known/web-identity").await.json();
    assert!(wi["provider_urls"][0]
        .as_str()
        .unwrap()
        .ends_with("/fedcm/config.json"));
    let cfg: Value = server.get("/fedcm/config.json").await.json();
    assert_eq!(cfg["accounts_endpoint"], "/fedcm/accounts");
    assert_eq!(cfg["id_assertion_endpoint"], "/fedcm/assertion");

    // --- accounts endpoint ---
    let (h, v) = sec_fetch_dest();
    let acc = server
        .get("/fedcm/accounts")
        .add_header(h, v)
        .add_cookie(sess_cookie())
        .await;
    assert_eq!(acc.status_code(), 200);
    let acc_json: Value = acc.json();
    assert_eq!(acc_json["accounts"][0]["email"], "alice@example.com");
    assert_eq!(acc_json["accounts"][0]["login_hints"][0], "alice@example.com");

    // Without the browser-set FedCM header, the credentialed endpoint refuses.
    let bad = server.get("/fedcm/accounts").add_cookie(sess_cookie()).await;
    assert_eq!(bad.status_code(), 400);

    // No session → 401 (FedCM's "no accounts" signal).
    let (h, v) = sec_fetch_dest();
    let anon = server.get("/fedcm/accounts").add_header(h, v).await;
    assert_eq!(anon.status_code(), 401);

    // --- assertion endpoint ---
    let res = server
        .post("/fedcm/assertion")
        .add_header(HeaderName::from_static("origin"), HeaderValue::from_static(AUDIENCE))
        .add_header(sec_fetch_dest().0, sec_fetch_dest().1)
        .add_cookie(sess_cookie())
        .form(&[("account_id", "alice@example.com")])
        .await;
    assert_eq!(res.status_code(), 200);
    let token = res.json::<Value>()["token"]
        .as_str()
        .expect("token in response")
        .to_string();

    // THE proof: the token verifies through the UNCHANGED RP verifier path
    // (verify_assertion_with_dns + accepted_fallbacks), yielding the right email.
    let disc = BrokerFallback { key: broker_pub.clone() };
    let cache = std::sync::RwLock::new(std::collections::HashMap::new());
    let ok =
        verify_access_with_dns(&token, AUDIENCE, &disc, &[BROKER.to_string()], own_status_ctx!(&cache))
            .await;
    assert_eq!(ok.status, "okay", "reason: {:?}", ok.reason);
    assert_eq!(ok.email.as_deref(), Some("alice@example.com"));

    // Audience binding: the same token must NOT verify for a different RP.
    let wrong_aud = verify_access_with_dns(
        &token, "https://evil.example.com", &disc, &[BROKER.to_string()], own_status_ctx!(&cache),
    )
    .await;
    assert_eq!(wrong_aud.status, "failure");

    // Fallback gate: an RP that does NOT accept this broker as a fallback rejects it.
    let not_accepted = verify_access_with_dns(
        &token, AUDIENCE, &disc, &["other.example".to_string()], own_status_ctx!(&cache),
    )
    .await;
    assert_eq!(not_accepted.status, "failure");
}

#[tokio::test]
async fn fedcm_assertion_rejects_unowned_account() {
    let (server, email_sender) = create_test_server();
    let session = create_user(&server, &email_sender, "alice@example.com", "Password123!").await;

    // Asking for an account this session doesn't own must be refused.
    let res = server
        .post("/fedcm/assertion")
        .add_header(HeaderName::from_static("origin"), HeaderValue::from_static(AUDIENCE))
        .add_header(sec_fetch_dest().0, sec_fetch_dest().1)
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .form(&[("account_id", "someone-else@example.com")])
        .await;
    assert_eq!(res.status_code(), 403);
}

#[tokio::test]
async fn fedcm_silent_requires_server_side_optin() {
    // Server-side enforcement: an AUTO-selected (silent) assertion is refused
    // until the user has opted in via an INTERACTIVE selection; RP logout
    // (/fedcm/reset) revokes it again.
    let (server, email_sender) = create_test_server();
    let session = create_user(&server, &email_sender, "alice@example.com", "Password123!").await;

    // 1. Silent (auto-selected) with no prior opt-in → refused.
    assert_eq!(post_silent(&server, &session, "true").await, 403, "silent without opt-in refused");
    // 2. Interactive selection → allowed, records the opt-in.
    assert_eq!(post_silent(&server, &session, "false").await, 200, "interactive allowed");
    // 3. Now silent is allowed.
    assert_eq!(post_silent(&server, &session, "true").await, 200, "silent allowed after opt-in");
    // 4. RP logout (/fedcm/reset) revokes → silent refused again.
    let reset = server
        .post("/fedcm/reset")
        .add_header(HeaderName::from_static("origin"), HeaderValue::from_static(AUDIENCE))
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await;
    assert_eq!(reset.status_code(), 200);
    assert_eq!(post_silent(&server, &session, "true").await, 403, "silent refused after reset");
}

async fn post_silent(
    server: &axum_test::TestServer,
    session: &str,
    auto: &str,
) -> axum::http::StatusCode {
    server
        .post("/fedcm/assertion")
        .add_header(HeaderName::from_static("origin"), HeaderValue::from_static(AUDIENCE))
        .add_header(sec_fetch_dest().0, sec_fetch_dest().1)
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .form(&[("account_id", "alice@example.com"), ("is_auto_selected", auto)])
        .await
        .status_code()
}

#[tokio::test]
async fn fedcm_assertion_rejects_non_fedcm_request() {
    // Security gate: a cross-site fetch() (no Sec-Fetch-Dest: webidentity) must
    // NOT be able to mint an assertion, even with a valid session cookie.
    let (server, email_sender) = create_test_server();
    let session = create_user(&server, &email_sender, "alice@example.com", "Password123!").await;

    let res = server
        .post("/fedcm/assertion")
        .add_header(HeaderName::from_static("origin"), HeaderValue::from_static("https://evil.example"))
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .form(&[("account_id", "alice@example.com")])
        .await;
    assert_eq!(res.status_code(), 400, "no Sec-Fetch-Dest → rejected");
}
