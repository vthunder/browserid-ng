//! Full agent→RP flow (l8lw Phase 2), every hop over real HTTP:
//!
//!   broker (agent-enabled IdP)      RP API (axum + browserid-rp)
//!        ▲          ▲                   ▲          ▲
//!        │ provision│ re-mint           │ 401+     │ POST /token
//!        │          │                   │ challenge│ then Bearer
//!        └──────────┴──── agent SDK ────┴──────────┘
//!
//! The RP trusts the broker by fetching its /.well-known/browserid — no keys
//! are shared out of band anywhere in this test.

mod common;

use std::sync::Arc;

use axum::extract::{Form, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use browserid_agent::{AgentError, AgentIdentity};
use browserid_core::rp_auth::GRANT_TYPE_ASSERTION;
use browserid_core::TokenRequest;
use browserid_rp::{oauth_metadata, TokenStore, Verifier};
use common::{mint_api_key, start_broker};
use serde_json::{json, Value};

struct RpState {
    verifier: Verifier,
    tokens: TokenStore,
    origin: String,
}

/// A protected resource: bearer token or a self-describing 401
async fn data(State(rp): State<Arc<RpState>>, headers: HeaderMap) -> Response {
    let email = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(|t| rp.tokens.authenticate(t));

    match email {
        Some(email) => Json(json!({ "email": email, "data": "the goods" })).into_response(),
        None => {
            let challenge = rp
                .verifier
                .challenge(format!("{}/token", rp.origin))
                .with_realm("api")
                .to_header_value();
            (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, challenge)],
            )
                .into_response()
        }
    }
}

/// The RP's whole browserid opt-in: one token-exchange endpoint
async fn token(State(rp): State<Arc<RpState>>, Form(req): Form<TokenRequest>) -> Response {
    match browserid_rp::exchange(&rp.verifier, &rp.tokens, &req) {
        Ok(response) => Json(response).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(e.to_response())).into_response(),
    }
}

async fn metadata(State(rp): State<Arc<RpState>>) -> Json<Value> {
    Json(oauth_metadata(&rp.origin, &format!("{}/token", rp.origin)))
}

/// A public endpoint that never challenges (for the NoChallenge case)
async fn open() -> Json<Value> {
    Json(json!({ "public": true }))
}

/// Start the RP on 127.0.0.1:0, trusting the broker via its well-known doc
async fn start_rp(broker_base: &str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());

    let verifier = Verifier::new(origin.clone())
        .trust_issuer_from_well_known(broker_base)
        .await
        .unwrap();

    let state = Arc::new(RpState {
        verifier,
        tokens: TokenStore::new(chrono::Duration::hours(1)),
        origin: origin.clone(),
    });
    let app = Router::new()
        .route("/data", get(data))
        .route("/token", post(token))
        .route("/open", get(open))
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .with_state(state);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    origin
}

#[tokio::test]
async fn agent_authenticates_to_cold_rp() {
    let (broker, _) = start_broker().await;
    let api_key = mint_api_key(&broker).await;
    let rp = start_rp(&broker).await;

    let mut agent = AgentIdentity::provision(&broker, &api_key, Some("worker"))
        .await
        .unwrap();

    // Cold hit: discover the challenge, exchange an assertion, get a token
    let grant = agent.token_for(&format!("{rp}/data")).await.unwrap();
    assert_eq!(grant.token_type, "Bearer");
    assert!(grant.access_token.starts_with("bidt_"));
    assert_eq!(grant.email.as_deref(), Some(agent.email()));

    // The RP's own bearer token now works like any other
    let body: Value = reqwest::Client::new()
        .get(format!("{rp}/data"))
        .bearer_auth(&grant.access_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["email"], agent.email());
    assert_eq!(body["data"], "the goods");
}

#[tokio::test]
async fn rp_advertises_oauth_metadata() {
    let (broker, _) = start_broker().await;
    let rp = start_rp(&broker).await;

    let metadata: Value = reqwest::get(format!("{rp}/.well-known/oauth-authorization-server"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(metadata["issuer"], rp);
    assert_eq!(metadata["token_endpoint"], format!("{rp}/token"));
    assert_eq!(metadata["grant_types_supported"][0], GRANT_TYPE_ASSERTION);
}

#[tokio::test]
async fn no_challenge_and_bad_assertion_are_clean_errors() {
    let (broker, _) = start_broker().await;
    let api_key = mint_api_key(&broker).await;
    let rp = start_rp(&broker).await;

    let mut agent = AgentIdentity::provision(&broker, &api_key, None).await.unwrap();

    // An endpoint that never challenges
    match agent.token_for(&format!("{rp}/open")).await {
        Err(AgentError::NoChallenge { status: 200, .. }) => {}
        other => panic!("expected NoChallenge, got {other:?}"),
    }

    // A garbage assertion is refused with an OAuth-shaped 400
    let response = reqwest::Client::new()
        .post(format!("{rp}/token"))
        .form(&TokenRequest::new("not-an-assertion"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}
