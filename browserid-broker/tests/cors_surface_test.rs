//! Pins the per-surface CORS posture (audit L9) — and its one hard-won
//! regression: the hosted-primary IdP's headless mint is called CROSS-ORIGIN
//! by login dialogs (the tenant surface lives on idp.<domain>, a different
//! origin than the broker), so stripping its CORS kills every tenant-identity
//! sign-in with "Failed to fetch" (2026-08-25). Conversely, /wsapi/* must
//! emit NO CORS headers — that closure is the point of L9.

mod common;

use common::create_test_server;

#[tokio::test]
async fn hosted_idp_mint_answers_cors_preflight() {
    let (server, _) = create_test_server();
    let response = server
        .method(axum_test::http::Method::OPTIONS, "/idp/access_cert")
        .add_header("origin", "https://browserid.me")
        .add_header("access-control-request-method", "POST")
        .add_header("access-control-request-headers", "content-type")
        .await;
    assert!(
        response.status_code().is_success(),
        "preflight must succeed, got {}",
        response.status_code()
    );
    let allow = response
        .maybe_header("access-control-allow-origin")
        .expect("mint preflight must carry Access-Control-Allow-Origin");
    assert_eq!(allow.to_str().unwrap(), "*");
}

#[tokio::test]
async fn wsapi_emits_no_cors_headers() {
    let (server, _) = create_test_server();
    let response = server
        .get("/wsapi/address_info?email=x@example.com")
        .add_header("origin", "https://evil.example")
        .await;
    assert!(
        response
            .maybe_header("access-control-allow-origin")
            .is_none(),
        "/wsapi/* must not answer cross-origin (audit L9)"
    );
}

#[tokio::test]
async fn public_reads_answer_any_origin() {
    let (server, _) = create_test_server();
    for path in [
        "/.well-known/browserid",
        "/guestbook/feed",
        "/.well-known/browserid-status",
    ] {
        let response = server
            .get(path)
            .add_header("origin", "https://rp.example")
            .await;
        let allow = response
            .maybe_header("access-control-allow-origin")
            .unwrap_or_else(|| panic!("{path} must answer cross-origin reads"));
        assert_eq!(allow.to_str().unwrap(), "*", "{path}");
    }
}
