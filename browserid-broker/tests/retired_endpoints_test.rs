//! Pins the M7 endpoint retirement (browserid-ng-8gqm): the persona-era
//! signup/reset/status lanes each leaked account existence to unauthenticated
//! callers, and every consumer moved to the unified sign-in code flow — so
//! the routes must be GONE, not merely unused. If one of these starts
//! answering again, the enumeration surface is back.

mod common;

use common::create_test_server;
use serde_json::json;

#[tokio::test]
async fn retired_wsapi_routes_are_gone() {
    let (server, _) = create_test_server();

    for path in [
        "/wsapi/stage_user",
        "/wsapi/complete_user_creation",
        "/wsapi/stage_reset",
        "/wsapi/complete_reset",
    ] {
        let response = server
            .post(path)
            .json(&json!({ "email": "x@example.com", "pass": "password123", "token": "000000" }))
            .await;
        assert_eq!(
            response.status_code(),
            404,
            "{path} must be retired (M7, browserid-ng-8gqm)"
        );
    }

    for path in [
        "/wsapi/user_creation_status?email=x@example.com",
        "/wsapi/password_reset_status?email=x@example.com",
        "/wsapi/email_addition_status?email=x@example.com",
    ] {
        let response = server.get(path).await;
        assert_eq!(
            response.status_code(),
            404,
            "{path} must be retired (M7, browserid-ng-8gqm)"
        );
    }
}
