//! Conformance Tests
//!
//! Ported from: ~/src/browserid/tests/conformance-test.js
//!
//! Tests JWT format compliance to ensure interoperability:
//! - Assertion format (3 parts, proper header/payload/signature)
//! - Field presence and types
//! - Base64url encoding
//!
//! Note: Original Persona used RS256/DS128 algorithms. We use EdDSA (Ed25519).
//! The format tests remain valid; algorithm-specific tests are adapted.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use browserid_core::{Assertion, KeyPair};
use chrono::Duration;
use serde_json::Value;

// =============================================================================
// Helper Functions
// Ported from conformance-test.js lines 47-141
// =============================================================================

/// Extract and parse JWT components without verification
/// Ported from: extractComponents() in conformance-test.js
fn extract_components(signed_object: &str) -> Result<JwtComponents, String> {
    let parts: Vec<&str> = signed_object.split('.').collect();
    if parts.len() != 3 {
        return Err(format!(
            "signed object must have three parts, this one has {}",
            parts.len()
        ));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| format!("failed to decode header: {}", e))?;
    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("failed to parse header JSON: {}", e))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("failed to decode payload: {}", e))?;
    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("failed to parse payload JSON: {}", e))?;

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| format!("failed to decode signature: {}", e))?;

    Ok(JwtComponents {
        header,
        payload,
        signature: signature_bytes,
    })
}

#[derive(Debug)]
struct JwtComponents {
    header: Value,
    payload: Value,
    signature: Vec<u8>,
}

// =============================================================================
// Constants
// Ported from conformance-test.js lines 143-148
// =============================================================================

const AUDIENCE: &str = "http://foobar.com";
const ISSUER: &str = "issuer.com";
const EMAIL: &str = "john@example.com";

// =============================================================================
// Assertion Format Tests
// Ported from conformance-test.js lines 150-191
// =============================================================================

mod assertion_format {
    use super::*;

    /// Test: sign an assertion - works
    #[test]
    fn test_assertion_creation_succeeds() {
        let user_keypair = KeyPair::generate();
        let assertion = Assertion::create(AUDIENCE, Duration::minutes(1), &user_keypair);
        assert!(assertion.is_ok(), "assertion creation should succeed");
    }

    /// Test: sign an assertion - has three parts
    /// Original: "has three part": function(err, signedObject) {
    ///             assert.equal(signedObject.split(".").length, 3);
    #[test]
    fn test_assertion_has_three_parts() {
        let user_keypair = KeyPair::generate();
        let assertion = Assertion::create(AUDIENCE, Duration::minutes(1), &user_keypair).unwrap();

        let parts: Vec<&str> = assertion.encoded().split('.').collect();
        assert_eq!(parts.len(), 3, "assertion should have exactly 3 JWT parts");
    }

    /// Test: assertion header format
    /// Original: "has proper header": function(components) {
    ///             assert.isObject(components.header);
    ///             assert.equal(components.header.alg, 'DS128');
    ///             assert.equal(Object.keys(components.header).length, 1);
    /// Note: We use EdDSA instead of DS128
    #[test]
    fn test_assertion_header_format() {
        let user_keypair = KeyPair::generate();
        let assertion = Assertion::create(AUDIENCE, Duration::minutes(1), &user_keypair).unwrap();

        let components = extract_components(assertion.encoded()).unwrap();

        // Header should be an object
        assert!(components.header.is_object(), "header should be an object");

        // Algorithm should be EdDSA (we use Ed25519)
        assert_eq!(
            components.header.get("alg").and_then(|v| v.as_str()),
            Some("EdDSA"),
            "algorithm should be EdDSA"
        );

        // Header should have minimal fields (alg, optionally typ)
        let header_obj = components.header.as_object().unwrap();
        assert!(
            header_obj.len() <= 2,
            "header should have at most 2 fields (alg, typ)"
        );
    }

    /// Test: assertion payload format
    /// Original: "has proper payload": function(components) {
    ///             assert.isObject(components.payload);
    ///             assert.equal(components.payload.exp, in_a_minute.valueOf());
    ///             assert.equal(components.payload.aud, AUDIENCE);
    ///             assert.equal(Object.keys(components.payload).length, 2);
    #[test]
    fn test_assertion_payload_format() {
        let user_keypair = KeyPair::generate();
        let assertion = Assertion::create(AUDIENCE, Duration::minutes(1), &user_keypair).unwrap();

        let components = extract_components(assertion.encoded()).unwrap();

        // Payload should be an object
        assert!(components.payload.is_object(), "payload should be an object");

        // Must have 'exp' (expiration) field
        let exp = components.payload.get("exp");
        assert!(exp.is_some(), "payload must have 'exp' field");
        assert!(
            exp.unwrap().is_number(),
            "'exp' should be a number (Unix timestamp)"
        );

        // Must have 'aud' (audience) field
        let aud = components.payload.get("aud");
        assert!(aud.is_some(), "payload must have 'aud' field");
        assert_eq!(
            aud.unwrap().as_str(),
            Some(AUDIENCE),
            "'aud' should match the audience"
        );

        // Should have only these required fields (exp, aud)
        let payload_obj = components.payload.as_object().unwrap();
        assert_eq!(
            payload_obj.len(),
            2,
            "assertion payload should have exactly 2 fields (exp, aud)"
        );
    }

    /// Test: assertion signature format
    /// Original: "has proper signature": function(components) {
    ///             assert.isString(components.signature);
    ///             assert.ok(components.signature.length <= 80);
    ///             assert.ok(components.signature.length > 75);
    /// Note: Ed25519 signatures are exactly 64 bytes
    #[test]
    fn test_assertion_signature_format() {
        let user_keypair = KeyPair::generate();
        let assertion = Assertion::create(AUDIENCE, Duration::minutes(1), &user_keypair).unwrap();

        let components = extract_components(assertion.encoded()).unwrap();

        // Ed25519 signatures are exactly 64 bytes
        assert_eq!(
            components.signature.len(),
            64,
            "Ed25519 signature should be exactly 64 bytes"
        );
    }
}
