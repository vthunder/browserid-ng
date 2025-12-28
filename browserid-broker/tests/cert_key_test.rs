//! Tests ported from browserid/tests/cert-key-test.js

mod common;

use chrono::{Duration, Utc};
use common::{create_test_context, create_test_server, create_user};
use browserid_core::KeyPair;
use serde_json::{json, Value};

/// Test: cert_key requires authentication
#[tokio::test]
async fn test_cert_key_requires_auth() {
    let (server, _) = create_test_server();
    let user_keypair = KeyPair::generate();

    let response = server
        .post("/wsapi/cert_key")
        .json(&json!({
            "email": "test@example.com",
            "pubkey": {
                "algorithm": "Ed25519",
                "publicKey": user_keypair.public_key().to_base64()
            },
            "ephemeral": false
        }))
        .await;

    assert_eq!(response.status_code(), 401);
}

/// Test: cert_key with valid email returns certificate
#[tokio::test]
async fn test_cert_key_success() {
    let (server, email_sender) = create_test_server();
    let email = "certme@example.com";
    let password = "testpassword";

    // Create user
    let session_cookie = create_user(&server, &email_sender, email, password).await;

    // Generate user keypair
    let user_keypair = KeyPair::generate();

    // Request certificate
    let response = server
        .post("/wsapi/cert_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .json(&json!({
            "email": email,
            "pubkey": {
                "algorithm": "Ed25519",
                "publicKey": user_keypair.public_key().to_base64()
            },
            "ephemeral": false
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Should have certificate
    let cert = body["cert"].as_str().unwrap();
    assert!(!cert.is_empty());
    // Certificate is JWT format: header.payload.signature
    assert_eq!(cert.split('.').count(), 3);
}

/// Test: cert_key with wrong email fails
#[tokio::test]
async fn test_cert_key_wrong_email() {
    let (server, email_sender) = create_test_server();
    let email = "myemail@example.com";
    let password = "testpassword";

    // Create user
    let session_cookie = create_user(&server, &email_sender, email, password).await;

    // Generate user keypair
    let user_keypair = KeyPair::generate();

    // Request certificate for different email
    let response = server
        .post("/wsapi/cert_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .json(&json!({
            "email": "notmyemail@example.com",
            "pubkey": {
                "algorithm": "Ed25519",
                "publicKey": user_keypair.public_key().to_base64()
            },
            "ephemeral": false
        }))
        .await;

    assert_eq!(response.status_code(), 404);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
}

/// Test: ephemeral certificate has shorter validity
#[tokio::test]
async fn test_cert_key_ephemeral() {
    let (server, email_sender) = create_test_server();
    let email = "ephemeral@example.com";
    let password = "testpassword";

    // Create user
    let session_cookie = create_user(&server, &email_sender, email, password).await;

    // Generate user keypair
    let user_keypair = KeyPair::generate();

    // Request ephemeral certificate
    let response = server
        .post("/wsapi/cert_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .json(&json!({
            "email": email,
            "pubkey": {
                "algorithm": "Ed25519",
                "publicKey": user_keypair.public_key().to_base64()
            },
            "ephemeral": true
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Should have certificate
    let cert = body["cert"].as_str().unwrap();
    assert!(!cert.is_empty());

    // Decode and check expiry (ephemeral should be ~1 hour, not 24 hours)
    let parts: Vec<&str> = cert.split('.').collect();
    let payload = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1],
    )
    .unwrap();
    let claims: Value = serde_json::from_slice(&payload).unwrap();

    let exp = claims["exp"].as_i64().unwrap();
    let iat = claims["iat"].as_i64().unwrap();
    let validity_seconds = exp - iat;

    // Ephemeral should be about 1 hour (3600 seconds), not 24 hours
    assert!(validity_seconds <= 3600 + 60); // 1 hour + margin
    assert!(validity_seconds >= 3600 - 60); // 1 hour - margin
}

/// Test: normal certificate has 24 hour validity
#[tokio::test]
async fn test_cert_key_24_hour_validity() {
    let (server, email_sender) = create_test_server();
    let email = "duration@example.com";
    let password = "testpassword";

    // Create user
    let session_cookie = create_user(&server, &email_sender, email, password).await;

    // Generate user keypair
    let user_keypair = KeyPair::generate();

    // Request normal (non-ephemeral) certificate
    let response = server
        .post("/wsapi/cert_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .json(&json!({
            "email": email,
            "pubkey": {
                "algorithm": "Ed25519",
                "publicKey": user_keypair.public_key().to_base64()
            },
            "ephemeral": false
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // Decode and check expiry
    let cert = body["cert"].as_str().unwrap();
    let parts: Vec<&str> = cert.split('.').collect();
    let payload = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1],
    )
    .unwrap();
    let claims: Value = serde_json::from_slice(&payload).unwrap();

    let exp = claims["exp"].as_i64().unwrap();
    let iat = claims["iat"].as_i64().unwrap();
    let validity_seconds = exp - iat;

    // Normal certificate should be about 24 hours (86400 seconds)
    let expected_seconds = 24 * 60 * 60;
    assert!(validity_seconds <= expected_seconds + 60); // 24 hours + margin
    assert!(validity_seconds >= expected_seconds - 60); // 24 hours - margin
}

/// Test: certificate issuance works within 90-day verification window
#[tokio::test]
async fn test_cert_key_within_90_day_window() {
    let ctx = create_test_context();
    let email = "reissue@example.com";
    let password = "testpassword";

    // Create user
    let session_cookie = create_user(&ctx.server, &ctx.email_sender, email, password).await;

    // Set verified_at to 89 days ago (still within window)
    let verified_at = Utc::now() - Duration::days(89);
    ctx.user_store.set_verified_at(email, verified_at).unwrap();

    // Generate user keypair
    let user_keypair = KeyPair::generate();

    // Request certificate - should succeed
    let response = ctx
        .server
        .post("/wsapi/cert_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .json(&json!({
            "email": email,
            "pubkey": {
                "algorithm": "Ed25519",
                "publicKey": user_keypair.public_key().to_base64()
            },
            "ephemeral": false
        }))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);
    assert!(body["cert"].as_str().is_some());
}

/// Test: certificate issuance fails after 90-day verification window
#[tokio::test]
async fn test_cert_key_expired_verification() {
    let ctx = create_test_context();
    let email = "expired@example.com";
    let password = "testpassword";

    // Create user
    let session_cookie = create_user(&ctx.server, &ctx.email_sender, email, password).await;

    // Set verified_at to 91 days ago (outside window)
    let verified_at = Utc::now() - Duration::days(91);
    ctx.user_store.set_verified_at(email, verified_at).unwrap();

    // Generate user keypair
    let user_keypair = KeyPair::generate();

    // Request certificate - should fail
    let response = ctx
        .server
        .post("/wsapi/cert_key")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .json(&json!({
            "email": email,
            "pubkey": {
                "algorithm": "Ed25519",
                "publicKey": user_keypair.public_key().to_base64()
            },
            "ephemeral": false
        }))
        .await;

    assert_eq!(response.status_code(), 403);
    let body: Value = response.json();
    assert_eq!(body["success"], false);
    assert!(body["reason"]
        .as_str()
        .unwrap()
        .contains("verification expired"));
}
