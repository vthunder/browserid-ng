//! Tests ported from browserid/tests/cert-key-test.js

mod common;

use common::{create_test_server, create_user};
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

    // Decode and check expiry (ephemeral should be ~1 hour, not 30 days)
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

    // Ephemeral should be about 1 hour (3600 seconds), not 30 days
    assert!(validity_seconds <= 3600 + 60); // 1 hour + margin
    assert!(validity_seconds >= 3600 - 60); // 1 hour - margin
}
