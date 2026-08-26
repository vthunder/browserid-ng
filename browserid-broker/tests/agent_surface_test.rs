//! The agent-facing surface of the broker origin: recoverable 404s (markdown
//! site map / structured JSON errors), the published OpenAPI spec, and the
//! llms.txt redirect to the marketing origin.

mod common;

use std::sync::Arc;

use axum_test::TestServer;
use browserid_broker::{routes, AppState, InMemorySessionStore, InMemoryUserStore};
use browserid_core::KeyPair;
use common::{create_test_server, MockEmailSender};
use serde_json::Value;

/// An unknown path is a real 404 with a short markdown body pointing agents
/// at llms.txt / the OpenAPI spec — never an empty or HTML-shell response.
#[tokio::test]
async fn test_unknown_path_is_markdown_404() {
    let (server, _) = create_test_server();

    let response = server.get("/some-path-that-does-not-exist").await;

    assert_eq!(response.status_code(), 404);
    let content_type = response.headers().get("content-type").unwrap().to_str().unwrap();
    assert_eq!(content_type, "text/markdown; charset=utf-8");
    let body = response.text();
    assert!(body.contains("llms.txt"), "404 must point at the agent index: {body}");
    assert!(body.contains("/openapi.json"), "404 must point at the API spec: {body}");
    assert!(body.contains("/some-path-that-does-not-exist"), "404 names the missing path");
}

/// The 404 is content-negotiated (Vary: Accept): browsers asking for
/// text/html get clickable links instead of raw markdown.
#[tokio::test]
async fn test_unknown_path_html_404_for_browsers() {
    let (server, _) = create_test_server();

    let response = server
        .get("/nope")
        .add_header("accept", "text/html,application/xhtml+xml")
        .await;

    assert_eq!(response.status_code(), 404);
    let content_type = response.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(content_type.starts_with("text/html"));
    assert_eq!(response.headers().get("vary").unwrap(), "Accept");
    assert!(response.text().contains("llms.txt"));
}

/// API-shaped misses (path prefix or Accept: application/json) get a
/// structured JSON error with code/message/hint — agents can't parse HTML.
#[tokio::test]
async fn test_unknown_api_path_is_json_404() {
    let (server, _) = create_test_server();

    for (path, accept) in [
        ("/wsapi/does_not_exist", None),
        ("/api/v1/users", None),
        ("/anything", Some("application/json")),
    ] {
        let mut req = server.get(path);
        if let Some(a) = accept {
            req = req.add_header("accept", a);
        }
        let response = req.await;
        assert_eq!(response.status_code(), 404, "{path}");
        let body: Value = response.json();
        assert_eq!(body["error"]["code"], "not_found", "{path}");
        assert!(body["error"]["message"].is_string(), "{path}");
        assert!(body["error"]["hint"].is_string(), "{path}");
    }
}

/// /openapi.json serves the compiled-in spec: valid JSON, CORS-open, and
/// describing the endpoints RPs actually call.
#[tokio::test]
async fn test_openapi_spec_served() {
    let (server, _) = create_test_server();

    let response = server.get("/openapi.json").await;

    assert_eq!(response.status_code(), 200);
    let content_type = response.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(content_type.starts_with("application/json"));
    let spec: Value = response.json();
    assert!(spec["openapi"].as_str().unwrap().starts_with("3."));
    for path in ["/verify", "/validate-record", "/status/check", "/.well-known/browserid"] {
        assert!(spec["paths"][path].is_object(), "spec must document {path}");
    }
    // The retired /verify-access must not be advertised (bean 992k).
    assert!(spec["paths"]["/verify-access"].is_null(), "retired /verify-access must not be documented");

    // CORS: public documentation, fetchable from any origin.
    let cors = server
        .get("/openapi.json")
        .add_header("origin", "https://app.example.com")
        .await;
    assert_eq!(cors.headers().get("access-control-allow-origin").unwrap(), "*");
}

/// The marketing origin serves a byte-identical copy of the spec (its
/// Dockerfile can only COPY from marketing/, so the file is duplicated —
/// this is the sync check).
#[test]
fn test_openapi_spec_matches_marketing_copy() {
    let broker = include_str!("../openapi.json");
    let marketing =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../marketing/openapi.json"))
            .expect("marketing/openapi.json must exist");
    assert_eq!(broker, marketing, "browserid-broker/openapi.json and marketing/openapi.json have diverged — copy one over the other");
}

/// With the origin split deployed, /llms.txt on the auth origin redirects to
/// the marketing origin's copy (the single source of truth).
#[tokio::test]
async fn test_llms_txt_redirects_to_marketing_origin() {
    let keypair = KeyPair::generate();
    let email_sender = Arc::new(MockEmailSender::new());
    let mut state = AppState::new_with_arcs(
        keypair,
        "localhost".to_string(),
        Arc::new(InMemoryUserStore::new()),
        Arc::new(InMemorySessionStore::new()),
        email_sender,
    );
    state.marketing_url = Some("https://www.browserid.me".to_string());
    let server = TestServer::new(routes::create_router(Arc::new(state))).unwrap();

    let response = server.get("/llms.txt").await;

    assert_eq!(response.status_code(), 308);
    assert_eq!(
        response.headers().get("location").unwrap(),
        "https://www.browserid.me/llms.txt"
    );
}

/// Without a marketing origin (local dev) /llms.txt falls back to the
/// agent-friendly 404 rather than an empty response.
#[tokio::test]
async fn test_llms_txt_without_marketing_origin() {
    let (server, _) = create_test_server();
    let response = server.get("/llms.txt").await;
    assert_eq!(response.status_code(), 404);
    assert!(response.text().contains("llms.txt"));
}

/// /verify is the hosted-verifier route; its former name /verify-access was
/// retired on 2026-08-26 (bean 992k) once every consumer had moved. Pin the
/// retirement: the old path must be GONE (structured JSON 404), not quietly
/// answering again.
#[tokio::test]
async fn test_verify_access_is_retired() {
    let (server, _) = create_test_server();

    let body = serde_json::json!({
        "presentation": "not~a~real~presentation",
        "audience": "https://rp.example.com",
    });
    let canonical = server.post("/verify").json(&body).await;
    assert_eq!(canonical.status_code(), 200);
    let canonical: Value = canonical.json();
    assert_eq!(canonical["status"], "failure");

    let retired = server
        .post("/verify-access")
        .add_header("accept", "application/json")
        .json(&body)
        .await;
    assert_eq!(retired.status_code(), 404, "/verify-access must be retired (bean 992k)");
    let retired: Value = retired.json();
    assert_eq!(retired["error"]["code"], "not_found");
}

/// Malformed bodies on the public API endpoints return structured JSON 400s
/// (error.code = bad_request), not axum's plain-text rejection.
#[tokio::test]
async fn test_malformed_api_bodies_get_json_errors() {
    let (server, _) = create_test_server();

    for path in ["/verify", "/validate-record", "/status/check"] {
        // Missing required fields.
        let response = server.post(path).json(&serde_json::json!({})).await;
        assert_eq!(response.status_code(), 400, "{path}");
        let body: Value = response.json();
        assert_eq!(body["error"]["code"], "bad_request", "{path}: {body}");
        assert!(body["error"]["message"].is_string(), "{path}");

        // Not JSON at all.
        let response = server
            .post(path)
            .add_header("content-type", "application/json")
            .text("this is not json")
            .await;
        assert_eq!(response.status_code(), 400, "{path}");
        let body: Value = response.json();
        assert_eq!(body["error"]["code"], "bad_request", "{path}: {body}");
    }
}

/// The v1 verification API stamps every response — success or error — with
/// `API-Version: 1`, the header the published versioning policy (openapi.json
/// info.description) promises to integrators.
#[tokio::test]
async fn test_verification_api_carries_api_version_header() {
    let (server, _) = create_test_server();

    // A failure-shaped but well-formed /verify call (HTTP 200).
    let response = server
        .post("/verify")
        .json(&serde_json::json!({
            "presentation": "not~a~real~presentation",
            "audience": "https://rp.example.com",
        }))
        .await;
    assert_eq!(response.status_code(), 200);
    assert_eq!(
        response.headers().get("api-version").expect("/verify 200 must carry API-Version"),
        "1"
    );

    // Malformed bodies (HTTP 400) carry it too — the layer wraps the routes,
    // not just the happy path.
    for path in ["/verify", "/validate-record", "/status/check"] {
        let response = server.post(path).json(&serde_json::json!({})).await;
        assert_eq!(response.status_code(), 400, "{path}");
        assert_eq!(
            response
                .headers()
                .get("api-version")
                .unwrap_or_else(|| panic!("{path} 400 must carry API-Version")),
            "1",
            "{path}"
        );
    }

    // Routes outside the versioned verification surface don't claim a version.
    let feed = server.get("/guestbook/feed").await;
    assert!(
        feed.headers().get("api-version").is_none(),
        "/guestbook/feed is not part of the versioned API"
    );
}

/// The published spec declares the versioning & deprecation policy agents rely
/// on: the API-Version response header on the verification endpoints and the
/// Deprecation/Sunset commitment in the description.
#[tokio::test]
async fn test_openapi_spec_declares_versioning_policy() {
    let (server, _) = create_test_server();
    let spec: Value = server.get("/openapi.json").await.json();

    let description = spec["info"]["description"].as_str().unwrap();
    assert!(
        description.contains("Versioning & deprecation policy"),
        "info.description must state the policy"
    );
    assert!(
        description.contains("Deprecation") && description.contains("Sunset"),
        "policy must name the deprecation signal headers"
    );
    assert!(description.contains("Pricing: free"), "info.description must state pricing");

    for path in ["/verify", "/validate-record", "/status/check"] {
        let headers = &spec["paths"][path]["post"]["responses"]["200"]["headers"];
        assert!(headers["API-Version"].is_object(), "{path} 200 must document API-Version");
    }
    assert!(spec["components"]["headers"]["ApiVersion"].is_object());
}
