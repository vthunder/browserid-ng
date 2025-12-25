//! Certificate Authority tests
//!
//! Ported from: ~/src/browserid/tests/ca-test.js
//!
//! Original test structure:
//! - generate a keypair
//!   - got a keypair
//!   - certify a public key
//!     - does not error out
//!     - looks ok (3 parts separated by dots)

use browserid_core::{Certificate, KeyPair};
use chrono::Duration;

/// Test: generate a keypair - got a keypair
#[test]
fn test_generate_keypair() {
    let kp = KeyPair::generate();
    let pk = kp.public_key();

    // Verify we got valid key material
    assert_eq!(pk.as_bytes().len(), 32, "public key should be 32 bytes");
}

/// Test: certify a public key - does not error out
#[test]
fn test_certify_public_key_succeeds() {
    let issuer = "127.0.0.1";
    let email_addr = "foo@foo.com";

    // Domain keypair (the CA)
    let domain_key = KeyPair::generate();

    // User keypair
    let user_key = KeyPair::generate();

    // Certify - should not error
    let result = Certificate::create(
        issuer,
        email_addr,
        &user_key.public_key(),
        Duration::seconds(5),
        &domain_key,
    );

    assert!(result.is_ok(), "certify should not error out");
}

/// Test: certify a public key - looks ok (3 JWT parts)
#[test]
fn test_certificate_has_three_parts() {
    let issuer = "127.0.0.1";
    let email_addr = "foo@foo.com";

    let domain_key = KeyPair::generate();
    let user_key = KeyPair::generate();

    let cert = Certificate::create(
        issuer,
        email_addr,
        &user_key.public_key(),
        Duration::seconds(5),
        &domain_key,
    )
    .unwrap();

    // Original test: assert.equal(cert_raw.split(".").length, 3);
    let parts: Vec<&str> = cert.encoded().split('.').collect();
    assert_eq!(parts.len(), 3, "certificate should have 3 JWT parts");
}

/// Additional test: certificate can be verified with issuer's public key
#[test]
fn test_certificate_verifies_with_issuer_key() {
    let domain_key = KeyPair::generate();
    let user_key = KeyPair::generate();

    let cert = Certificate::create(
        "example.com",
        "alice@example.com",
        &user_key.public_key(),
        Duration::hours(1),
        &domain_key,
    )
    .unwrap();

    // Verify with correct key should succeed
    assert!(cert.verify(&domain_key.public_key()).is_ok());
}

/// Additional test: certificate fails verification with wrong key
#[test]
fn test_certificate_fails_with_wrong_key() {
    let domain_key = KeyPair::generate();
    let wrong_key = KeyPair::generate();
    let user_key = KeyPair::generate();

    let cert = Certificate::create(
        "example.com",
        "alice@example.com",
        &user_key.public_key(),
        Duration::hours(1),
        &domain_key,
    )
    .unwrap();

    // Verify with wrong key should fail
    assert!(cert.verify(&wrong_key.public_key()).is_err());
}

/// Additional test: certificate contains correct claims
#[test]
fn test_certificate_claims() {
    let domain_key = KeyPair::generate();
    let user_key = KeyPair::generate();

    let cert = Certificate::create(
        "example.com",
        "alice@example.com",
        &user_key.public_key(),
        Duration::hours(1),
        &domain_key,
    )
    .unwrap();

    assert_eq!(cert.issuer(), "example.com");
    assert_eq!(cert.email(), Some("alice@example.com"));
    assert_eq!(cert.public_key(), &user_key.public_key());
}
