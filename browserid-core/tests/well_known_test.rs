//! Well-known document tests
//!
//! Ported from: ~/src/browserid/tests/well-known-test.js
//!
//! Original test structure:
//! - Retrieving a public key is straight forward
//! - Retrieving a public key should follow authority delegation
//! - Cycles should be detected
//! - We should not follow an infinite series of delegations of authority
//! - A domain delegating to itself is hozed
//! - if the authority key is malformed -> support is disabled
//! - if `disabled: true` is present -> support is disabled

use browserid_core::discovery::{
    discover, DiscoveryConfig, SupportDocument, SupportDocumentFetcher,
};
use browserid_core::{Error, KeyPair, Result};
use std::collections::HashMap;

// =============================================================================
// Test Fixtures
// =============================================================================

/// Mock fetcher for testing discovery without HTTP
struct MockFetcher {
    documents: HashMap<String, SupportDocument>,
}

impl MockFetcher {
    fn new() -> Self {
        Self {
            documents: HashMap::new(),
        }
    }

    fn add_domain(&mut self, domain: &str, doc: SupportDocument) {
        self.documents.insert(domain.to_string(), doc);
    }
}

impl SupportDocumentFetcher for MockFetcher {
    fn fetch(&self, domain: &str) -> Result<SupportDocument> {
        self.documents.get(domain).cloned().ok_or_else(|| Error::DiscoveryFailed {
            domain: domain.to_string(),
            reason: format!(
                "{} is not a browserid primary - non-200 response code to /.well-known/browserid",
                domain
            ),
        })
    }
}

// =============================================================================
// Public Key Retrieval Tests
// Ported from: well-known-test.js lines 76-84
// =============================================================================

mod public_key_retrieval {
    use super::*;

    /// Test: Retrieving a public key is straight forward
    /// Original: "Retrieving a public key is straight forward" -> "succeeds"
    #[test]
    fn test_public_key_retrieval_straightforward() {
        let domain_key = KeyPair::generate();
        let mut fetcher = MockFetcher::new();

        fetcher.add_domain(
            "example.domain",
            SupportDocument::new(domain_key.public_key())
                .with_authentication("/sign_in.html")
                .with_provisioning("/provision.html"),
        );

        let config = DiscoveryConfig::default();
        let result = discover("example.domain", &fetcher, &config).unwrap();

        // Original test verified keysize and algorithm
        // Our Ed25519 keys are 32 bytes (256 bits)
        assert_eq!(result.document.public_key.as_bytes().len(), 32);
    }

    /// Test: Retrieving a public key should follow authority delegation
    /// Original: "Retrieving a public key should follow authority delegation" -> "succeeds"
    #[test]
    fn test_public_key_retrieval_follows_delegation() {
        let domain_key = KeyPair::generate();
        let mut fetcher = MockFetcher::new();

        // delegate.example.domain delegates to example.domain
        fetcher.add_domain(
            "delegate.example.domain",
            SupportDocument::delegate("example.domain"),
        );

        fetcher.add_domain(
            "example.domain",
            SupportDocument::new(domain_key.public_key())
                .with_authentication("/sign_in.html")
                .with_provisioning("/provision.html"),
        );

        let config = DiscoveryConfig::default();
        let result = discover("delegate.example.domain", &fetcher, &config).unwrap();

        // Should have followed delegation to get the key from example.domain
        assert_eq!(result.domain, "example.domain");
        assert_eq!(result.document.public_key.as_bytes().len(), 32);
    }
}

// =============================================================================
// Cycle Detection Tests
// Ported from: well-known-test.js lines 99-110
// =============================================================================

mod cycle_detection {
    use super::*;

    /// Test: Cycles should be detected
    /// Original: "Cycles should be detected" -> error contains "Circular reference"
    ///
    /// Setup: cycle.domain -> cycle2.domain -> cycle.domain
    #[test]
    fn test_cycle_detected() {
        let mut fetcher = MockFetcher::new();

        // cycle.domain delegates to cycle2.domain
        fetcher.add_domain("cycle.domain", SupportDocument::delegate("cycle2.domain"));

        // cycle2.domain delegates back to cycle.domain (cycle!)
        fetcher.add_domain("cycle2.domain", SupportDocument::delegate("cycle.domain"));

        let config = DiscoveryConfig::default();
        let result = discover("cycle.domain", &fetcher, &config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = err.to_string();

        // Original error: "Circular reference in delegating authority: cycle.domain > cycle2.domain"
        assert!(
            err_str.contains("Circular reference"),
            "Error should mention circular reference: {}",
            err_str
        );
    }
}

// =============================================================================
// Delegation Depth Tests
// Ported from: well-known-test.js lines 112-125
// =============================================================================

mod delegation_depth {
    use super::*;

    /// Test: We should not follow an infinite series of delegations of authority
    /// Original: "We should not follow an infinite series of delegations" -> "Too many hops"
    ///
    /// Setup: delegate0 -> delegate1 -> ... -> delegate10 (chain of 11 delegations)
    #[test]
    fn test_too_many_hops_detected() {
        let mut fetcher = MockFetcher::new();

        // Create a chain of delegations: delegate0 -> delegate1 -> ... -> delegate10
        for i in 0..11 {
            fetcher.add_domain(
                &format!("delegate{}.domain", i),
                SupportDocument::delegate(format!("delegate{}.domain", i + 1)),
            );
        }

        let config = DiscoveryConfig {
            max_delegation_depth: 6, // Original limit was 6 hops
            ..Default::default()
        };
        let result = discover("delegate0.domain", &fetcher, &config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = err.to_string();

        // Original error: "Too many hops while delegating authority: delegate0.domain > ..."
        assert!(
            err_str.contains("Too many hops"),
            "Error should mention too many hops: {}",
            err_str
        );

        // Verify the chain is included in the error
        assert!(
            err_str.contains("delegate0.domain"),
            "Error should include delegation chain: {}",
            err_str
        );
    }
}

// =============================================================================
// Self-Delegation Tests
// Ported from: well-known-test.js lines 127-136
// =============================================================================

mod self_delegation {
    use super::*;

    /// Test: A domain delegating to itself is hozed
    /// Original: "A domain delegating to itself is hozed" -> "Circular reference"
    ///
    /// Setup: hozed.domain delegates to hozed.domain
    #[test]
    fn test_self_delegation_detected() {
        let mut fetcher = MockFetcher::new();

        // hozed.domain delegates to itself
        fetcher.add_domain("hozed.domain", SupportDocument::delegate("hozed.domain"));

        let config = DiscoveryConfig::default();
        let result = discover("hozed.domain", &fetcher, &config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = err.to_string();

        // Original error: "Circular reference in delegating authority"
        assert!(
            err_str.contains("Circular reference"),
            "Error should mention circular reference: {}",
            err_str
        );
    }
}

// =============================================================================
// Malformed Authority Tests
// Ported from: well-known-test.js lines 138-148
// =============================================================================

mod malformed_authority {
    use super::*;

    /// Test: if the authority key is malformed, support is disabled
    /// Original: "if the authority key is malformed" -> "support is disabled"
    ///
    /// Note: In the original test, borkedauthority.domain had:
    /// { "authority": ["arrays.are.not", "cool.in.this.document"], ... }
    ///
    /// In Rust with serde, this would fail to parse as a String.
    /// We test this behavior through JSON parsing.
    #[test]
    fn test_malformed_authority_json_fails_to_parse() {
        let malformed_json = r#"{
            "authority": ["arrays.are.not", "cool.in.this.document"],
            "provisioning": "/provision.html",
            "authentication": "/sign_in.html",
            "public-key": {
                "algorithm": "Ed25519",
                "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }
        }"#;

        // Should fail to parse because authority is an array, not a string
        let result: std::result::Result<SupportDocument, _> = serde_json::from_str(malformed_json);
        assert!(
            result.is_err(),
            "Malformed authority (array) should fail to parse"
        );
    }

    /// Test: empty authority string is treated as no delegation
    #[test]
    fn test_empty_authority_is_invalid() {
        let key = KeyPair::generate();
        let mut fetcher = MockFetcher::new();

        // Create a document with empty authority string
        let mut doc = SupportDocument::new(key.public_key());
        doc.authority = Some("".to_string());
        fetcher.add_domain("empty.authority.domain", doc);

        let config = DiscoveryConfig::default();
        let result = discover("empty.authority.domain", &fetcher, &config);

        // Empty authority means we try to fetch "" which should fail
        assert!(result.is_err());
    }
}

// =============================================================================
// Disabled Domain Tests
// Ported from: well-known-test.js lines 150-161
// =============================================================================

mod disabled_domain {
    use super::*;

    /// Test: if `disabled: true` is present, support is disabled
    /// Original: "if `disabled: true` is present" -> "support is disabled"
    #[test]
    fn test_disabled_domain_returns_disabled() {
        let mut fetcher = MockFetcher::new();

        fetcher.add_domain("disabled.domain", SupportDocument::disabled());

        let config = DiscoveryConfig::default();
        let result = discover("disabled.domain", &fetcher, &config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = err.to_string();

        assert!(
            err_str.contains("disabled"),
            "Error should indicate domain is disabled: {}",
            err_str
        );
    }

    /// Test: disabled field serializes correctly in JSON
    #[test]
    fn test_disabled_field_serialization() {
        let key = KeyPair::generate();

        // Enabled document should not include disabled field (default false)
        let enabled_doc = SupportDocument::new(key.public_key());
        let json = serde_json::to_string(&enabled_doc).unwrap();
        assert!(
            !json.contains("disabled"),
            "Enabled document should not include disabled field"
        );

        // Disabled document should include disabled: true
        let disabled_doc = SupportDocument::disabled();
        let json = serde_json::to_string(&disabled_doc).unwrap();
        assert!(json.contains(r#""disabled":true"#), "Disabled document should include disabled: true");
    }

    /// Test: disabled field deserializes correctly from JSON
    #[test]
    fn test_disabled_field_deserialization() {
        // Use the correct public key format: algorithm + publicKey (base64)
        let disabled_json = r#"{
            "disabled": true,
            "provisioning": "/provision.html",
            "authentication": "/sign_in.html",
            "public-key": {
                "algorithm": "Ed25519",
                "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }
        }"#;

        let doc: SupportDocument = serde_json::from_str(disabled_json).unwrap();
        assert!(doc.is_disabled(), "Document should be marked as disabled");
    }

    /// Test: missing disabled field defaults to false
    #[test]
    fn test_missing_disabled_field_defaults_to_false() {
        // Use the correct public key format: algorithm + publicKey (base64)
        let enabled_json = r#"{
            "provisioning": "/provision.html",
            "authentication": "/sign_in.html",
            "public-key": {
                "algorithm": "Ed25519",
                "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }
        }"#;

        let doc: SupportDocument = serde_json::from_str(enabled_json).unwrap();
        assert!(!doc.is_disabled(), "Document should default to enabled");
    }
}

// =============================================================================
// Support Document Format Tests
// =============================================================================

mod support_document_format {
    use super::*;

    /// Test: support document with delegation serializes correctly
    #[test]
    fn test_delegation_document_format() {
        let doc = SupportDocument::delegate("idp.example.org");

        let json = serde_json::to_string(&doc).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed.get("authority").and_then(|v| v.as_str()),
            Some("idp.example.org")
        );
    }

    /// Test: support document with public key and paths serializes correctly
    #[test]
    fn test_full_document_format() {
        let key = KeyPair::generate();
        let doc = SupportDocument::new(key.public_key())
            .with_authentication("/sign_in.html")
            .with_provisioning("/provision.html");

        let json = serde_json::to_string(&doc).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("public-key").is_some());
        assert_eq!(
            parsed.get("authentication").and_then(|v| v.as_str()),
            Some("/sign_in.html")
        );
        assert_eq!(
            parsed.get("provisioning").and_then(|v| v.as_str()),
            Some("/provision.html")
        );
    }
}
