//! The OIDC claim ceremony end-to-end (browserid-ng-qer8): a Google-hosted
//! mailbox is claimed by signing in with Google instead of a mailed code.
//! A mock Google (token endpoint + JWKS) runs on a local listener and mints
//! real RS256 ID tokens with a throwaway RSA key, so the broker's callback
//! leg — code exchange, JWKS fetch, ID-token verification, session attach —
//! runs exactly as in production.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::routing::{get, post};
use axum::{Json, Router};
use browserid_broker::authority::AuthorityChecker;
use browserid_broker::oidc::{OidcProvider, OidcRuntime, GOOGLE_ISSUER};
use browserid_broker::store::ProofMethod;
use browserid_broker::UserStore;
use common::{create_test_context_customized, create_user, TestContext};
use serde_json::{json, Value};

// The same throwaway RSA test key as src/oidc/tests.rs (integration tests
// cannot reach cfg(test) items).
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

fn mint(claims: &Value) -> String {
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

/// A stand-in Google: the token endpoint returns whatever ID token the test
/// staged in `next_claims`; the JWKS endpoint serves the test key.
struct MockGoogle {
    base: String,
    next_claims: Arc<Mutex<Option<Value>>>,
}

impl MockGoogle {
    /// Stage the ID token the next token-exchange will return.
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
                    let claims = next
                        .lock()
                        .unwrap()
                        .clone()
                        .expect("test staged no claims before the token exchange");
                    Json(json!({
                        "id_token": mint(&claims),
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

/// Broker configured for OIDC against the mock Google, with a fixed
/// authority map: `gmail.com` (consumer), `acme.test` (Workspace via Google
/// MX), `plain.test` (ordinary mail domain).
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
                ("acme.test".to_string(), Some("aspmx.l.google.com".to_string())),
                ("plain.test".to_string(), Some("mx.plain.test".to_string())),
            ]),
            None,
        );
    });
    (ctx, mock)
}

/// Begin the claim: GET /oidc/claim, then pull the `state`/`nonce` the
/// broker put in the Google authorization URL, plus the flow-binding cookie.
async fn begin_claim(
    ctx: &TestContext,
    email: &str,
) -> (String, String, cookie::Cookie<'static>) {
    let resp = ctx
        .server
        .get(&format!("/oidc/claim?email={email}"))
        .await;
    assert_eq!(resp.status_code(), 303, "claim leg should redirect to Google");
    let loc = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    let url = reqwest::Url::parse(&loc).expect("auth URL parses");
    let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let flow_cookie = resp
        .maybe_cookie("browserid_oidc_flow")
        .expect("claim leg sets the flow cookie");
    (q["state"].clone(), q["nonce"].clone(), flow_cookie)
}

fn location_of(resp: &axum_test::TestResponse) -> String {
    resp.headers().get("location").unwrap().to_str().unwrap().to_string()
}

#[tokio::test]
async fn address_info_advertises_the_google_ceremony() {
    let (ctx, _mock) = oidc_context().await;

    // Consumer Gmail and a Workspace domain (Google MX) get the OIDC
    // ceremony and this broker's claim URL.
    for email in ["dan@gmail.com", "dan@acme.test"] {
        let body: Value = ctx
            .server
            .get(&format!("/wsapi/address_info?email={email}"))
            .await
            .json();
        assert_eq!(body["type"], "secondary");
        assert_eq!(body["proof"], "oidc", "{email} should get the oidc ceremony");
        assert_eq!(body["claim"], "http://localhost:3000/oidc/claim");
    }

    // An ordinary mail domain keeps the SMTP loop.
    let body: Value = ctx
        .server
        .get("/wsapi/address_info?email=dan@plain.test")
        .await
        .json();
    assert_eq!(body["proof"], "smtp");
    assert!(body.get("claim").is_none());
}

#[tokio::test]
async fn unconfigured_broker_never_advertises_or_serves_oidc() {
    // Same authority map, but no OidcRuntime: gmail reads as plain SMTP and
    // the claim route refuses.
    let ctx = create_test_context_customized(|state| {
        state.authority = AuthorityChecker::fixed_with_mx_hosts(
            HashMap::new(),
            HashMap::from([("gmail.com".to_string(), Some("aspmx.l.google.com".to_string()))]),
            None,
        );
    });
    let body: Value = ctx
        .server
        .get("/wsapi/address_info?email=dan@gmail.com")
        .await
        .json();
    assert_eq!(body["proof"], "smtp");

    let resp = ctx.server.get("/oidc/claim?email=dan@gmail.com").await;
    assert_eq!(resp.status_code(), 400);
}

#[tokio::test]
async fn cold_claim_attaches_the_identity_and_signs_in() {
    let (ctx, mock) = oidc_context().await;

    // Claimed with dots + tag (`+` URL-encoded — it lives in a query
    // string): the broker must attach the canonical mailbox.
    let (state_tok, nonce, flow_cookie) = begin_claim(&ctx, "d.a.n%2Bx@gmail.com").await;
    mock.respond_with(base_claims("dan@gmail.com", &nonce, "google-sub-1"));

    let resp = ctx
        .server
        .get(&format!("/oidc/callback?code=c0de&state={state_tok}"))
        .add_cookie(flow_cookie)
        .await;
    assert_eq!(resp.status_code(), 303);
    let loc = location_of(&resp);
    assert!(
        loc.starts_with("/dialog/dialog.html?resume=oidc_claim#"),
        "callback lands on the dialog resume page: {loc}"
    );
    assert!(loc.contains("status=ok"), "expected ok, got: {loc}");
    assert!(loc.contains("email=dan@gmail.com"), "normalized email in fragment: {loc}");

    // A cold claim ends signed in.
    resp.maybe_cookie("browserid_session")
        .expect("cold claim sets a session cookie");

    // The identity is attached, verified, and OIDC-proven by <iss>#<sub>.
    let rec = ctx.user_store.get_email("dan@gmail.com").unwrap().unwrap();
    assert!(rec.verified);
    assert_eq!(rec.proof, ProofMethod::Oidc);
    assert_eq!(
        rec.proof_subject.as_deref(),
        Some(format!("{GOOGLE_ISSUER}#google-sub-1").as_str())
    );
}

#[tokio::test]
async fn cold_reclaim_follows_the_google_account_not_the_address() {
    let (ctx, mock) = oidc_context().await;

    // First claim.
    let (st1, n1, c1) = begin_claim(&ctx, "dan@gmail.com").await;
    mock.respond_with(base_claims("dan@gmail.com", &n1, "google-sub-1"));
    ctx.server
        .get(&format!("/oidc/callback?code=c&state={st1}"))
        .add_cookie(c1)
        .await;
    let first_owner = ctx.user_store.get_email("dan@gmail.com").unwrap().unwrap().user_id;

    // Same Google account proves it again cold: same broker account.
    let (st2, n2, c2) = begin_claim(&ctx, "dan@gmail.com").await;
    mock.respond_with(base_claims("dan@gmail.com", &n2, "google-sub-1"));
    ctx.server
        .get(&format!("/oidc/callback?code=c&state={st2}"))
        .add_cookie(c2)
        .await;
    assert_eq!(
        ctx.user_store.get_email("dan@gmail.com").unwrap().unwrap().user_id,
        first_owner
    );

    // A DIFFERENT Google account proving the same address is the identifier
    // changing hands: the identity moves to a fresh account instead of
    // inheriting the old one.
    let (st3, n3, c3) = begin_claim(&ctx, "dan@gmail.com").await;
    mock.respond_with(base_claims("dan@gmail.com", &n3, "google-sub-OTHER"));
    let resp = ctx
        .server
        .get(&format!("/oidc/callback?code=c&state={st3}"))
        .add_cookie(c3)
        .await;
    assert!(location_of(&resp).contains("status=ok"));
    let rec = ctx.user_store.get_email("dan@gmail.com").unwrap().unwrap();
    assert_ne!(rec.user_id, first_owner, "reassigned mailbox must not inherit the old account");
    assert_eq!(
        rec.proof_subject.as_deref(),
        Some(format!("{GOOGLE_ISSUER}#google-sub-OTHER").as_str())
    );
}

/// The login-CSRF guard: a callback URL forwarded to a browser that did not
/// begin the flow (no flow cookie) must not attach anything.
#[tokio::test]
async fn callback_requires_the_flow_binding_cookie() {
    let (ctx, mock) = oidc_context().await;

    let (state_tok, nonce, _flow_cookie) = begin_claim(&ctx, "dan@gmail.com").await;
    mock.respond_with(base_claims("dan@gmail.com", &nonce, "google-sub-1"));

    // No flow cookie rides along.
    let resp = ctx
        .server
        .get(&format!("/oidc/callback?code=c0de&state={state_tok}"))
        .await;
    let loc = location_of(&resp);
    assert!(loc.contains("oidc_error="), "expected an error redirect: {loc}");
    assert!(resp.maybe_cookie("browserid_session").is_none());
    assert!(ctx.user_store.get_email("dan@gmail.com").unwrap().is_none());
}

#[tokio::test]
async fn the_state_token_is_single_use() {
    let (ctx, mock) = oidc_context().await;

    let (state_tok, nonce, flow_cookie) = begin_claim(&ctx, "dan@gmail.com").await;
    mock.respond_with(base_claims("dan@gmail.com", &nonce, "google-sub-1"));

    let first = ctx
        .server
        .get(&format!("/oidc/callback?code=c&state={state_tok}"))
        .add_cookie(flow_cookie.clone())
        .await;
    assert!(location_of(&first).contains("status=ok"));

    // Replaying the same callback finds no flow.
    let replay = ctx
        .server
        .get(&format!("/oidc/callback?code=c&state={state_tok}"))
        .add_cookie(flow_cookie)
        .await;
    assert!(location_of(&replay).contains("oidc_error="));
}

#[tokio::test]
async fn the_token_email_must_match_the_claim() {
    let (ctx, mock) = oidc_context().await;

    let (state_tok, nonce, flow_cookie) = begin_claim(&ctx, "dan@gmail.com").await;
    // The user signed in to Google as someone else.
    mock.respond_with(base_claims("mallory@gmail.com", &nonce, "google-sub-m"));

    let resp = ctx
        .server
        .get(&format!("/oidc/callback?code=c&state={state_tok}"))
        .add_cookie(flow_cookie)
        .await;
    assert!(location_of(&resp).contains("oidc_error="));
    assert!(ctx.user_store.get_email("dan@gmail.com").unwrap().is_none());
    assert!(ctx.user_store.get_email("mallory@gmail.com").unwrap().is_none());
}

#[tokio::test]
async fn workspace_claims_require_the_hosted_domain() {
    let (ctx, mock) = oidc_context().await;

    // hd matches the Workspace domain: attaches.
    let (st1, n1, c1) = begin_claim(&ctx, "dan@acme.test").await;
    let mut good = base_claims("dan@acme.test", &n1, "ws-sub-1");
    good["hd"] = json!("acme.test");
    mock.respond_with(good);
    let resp = ctx
        .server
        .get(&format!("/oidc/callback?code=c&state={st1}"))
        .add_cookie(c1)
        .await;
    assert!(location_of(&resp).contains("status=ok"));
    assert!(ctx.user_store.get_email("dan@acme.test").unwrap().is_some());

    // Missing hd (a consumer account with a matching email string) must not
    // claim a Workspace address.
    let (st2, n2, c2) = begin_claim(&ctx, "eve@acme.test").await;
    mock.respond_with(base_claims("eve@acme.test", &n2, "ws-sub-2"));
    let resp = ctx
        .server
        .get(&format!("/oidc/callback?code=c&state={st2}"))
        .add_cookie(c2)
        .await;
    assert!(location_of(&resp).contains("oidc_error="));
    assert!(ctx.user_store.get_email("eve@acme.test").unwrap().is_none());
}

#[tokio::test]
async fn claim_refuses_ineligible_domains_and_agent_shaped_locals() {
    let (ctx, _mock) = oidc_context().await;

    // Not Google-hosted mail.
    let resp = ctx.server.get("/oidc/claim?email=dan@plain.test").await;
    assert_eq!(resp.status_code(), 400);

    // A Workspace local part containing `+` could impersonate an agent
    // sub-identity (`<label>+<tag>`); refused. (Consumer Gmail is fine —
    // normalization strips the tag before it can collide.)
    let resp = ctx.server.get("/oidc/claim?email=dan%2Bagent@acme.test").await;
    assert_eq!(resp.status_code(), 400);
    let resp = ctx.server.get("/oidc/claim?email=dan%2Btag@gmail.com").await;
    assert_eq!(resp.status_code(), 303);
}

#[tokio::test]
async fn signed_in_claim_attaches_to_the_session_account() {
    let (ctx, mock) = oidc_context().await;

    // An existing password account (plain.test stays SMTP-provable).
    let session = create_user(&ctx.server, &ctx.email_sender, "me@plain.test", "password123").await;
    let me = ctx.user_store.get_email("me@plain.test").unwrap().unwrap().user_id;

    // Claim a Gmail identity while signed in: the claim leg sees the session
    // and the callback attaches to it.
    let resp = ctx
        .server
        .get("/oidc/claim?email=me@gmail.com")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .await;
    assert_eq!(resp.status_code(), 303);
    let loc = location_of(&resp);
    let url = reqwest::Url::parse(&loc).unwrap();
    let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let flow_cookie = resp.maybe_cookie("browserid_oidc_flow").unwrap();

    mock.respond_with(base_claims("me@gmail.com", &q["nonce"], "google-sub-me"));
    let resp = ctx
        .server
        .get(&format!("/oidc/callback?code=c&state={}", q["state"]))
        .add_cookie(flow_cookie)
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .await;
    assert!(location_of(&resp).contains("status=ok"));

    let rec = ctx.user_store.get_email("me@gmail.com").unwrap().unwrap();
    assert_eq!(rec.user_id, me, "attaches to the signed-in account");
    assert_eq!(rec.proof, ProofMethod::Oidc);
}
