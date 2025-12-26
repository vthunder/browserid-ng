//! Tests ported from browserid/tests/password-length-test.js

mod common;

use common::create_test_server;
use serde_json::{json, Value};

/// Test: password that is too short fails
#[tokio::test]
async fn test_password_too_short() {
    let (server, _) = create_test_server();

    let response = server
        .post("/wsapi/stage_user")
        .json(&json!({
            "email": "short@example.com",
            "pass": "1234567"  // 7 chars, less than 8
        }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: password that is too long fails
#[tokio::test]
async fn test_password_too_long() {
    let (server, _) = create_test_server();

    // 81 characters - more than 80
    let long_password = "0".repeat(81);

    let response = server
        .post("/wsapi/stage_user")
        .json(&json!({
            "email": "long@example.com",
            "pass": long_password
        }))
        .await;

    assert_eq!(response.status_code(), 400);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: password at minimum length succeeds
#[tokio::test]
async fn test_password_at_min_length() {
    let (server, _) = create_test_server();

    let response = server
        .post("/wsapi/stage_user")
        .json(&json!({
            "email": "minlen@example.com",
            "pass": "12345678"  // exactly 8 chars
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);
}

/// Test: password at maximum length succeeds
#[tokio::test]
async fn test_password_at_max_length() {
    let (server, _) = create_test_server();

    // Exactly 80 characters
    let max_password = "0".repeat(80);

    let response = server
        .post("/wsapi/stage_user")
        .json(&json!({
            "email": "maxlen@example.com",
            "pass": max_password
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);
}

/// Test: password of normal length succeeds
#[tokio::test]
async fn test_password_normal_length() {
    let (server, _) = create_test_server();

    let response = server
        .post("/wsapi/stage_user")
        .json(&json!({
            "email": "normal@example.com",
            "pass": "ahhh. this is just right."
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);
}
