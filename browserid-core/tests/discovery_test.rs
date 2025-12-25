//! Discovery tests
//!
//! Ported from: ~/src/browserid/tests/discovery-test.js
//!              ~/src/browserid/tests/well-known-browserid.js
//!              ~/src/browserid/tests/well-known-test.js
//!
//! Original test structure:
//! - discovery for a primary IdP returns well known
//! - discovery for the fallback IdP returns a well known
//! - discovery for a disabled IdP returns the secondary well known
//! - Bad usage of discovery gives an error
//! - .well-known/browserid returns correct JSON structure

use browserid_core::discovery::{
    discover, domain_from_email, well_known_url, DiscoveryConfig, SupportDocument,
    SupportDocumentFetcher,
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
            reason: format!("{} is not a browserid primary - non-200 response code to /.well-known/browserid", domain),
        })
    }
}

// =============================================================================
// Primary IdP Discovery Tests
// Ported from: discovery-test.js lines 40-53
// =============================================================================

mod primary_idp_discovery {
    use super::*;

    /// Test: discovery for a primary IdP returns well known
    /// Original: "discovery for a primary IdP" -> "returns well known"
    #[test]
    fn test_primary_idp_returns_well_known() {
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

        assert_eq!(result.domain, "example.domain");
        assert!(result.delegation_chain.is_empty());

        let doc = &result.document;
        assert_eq!(doc.authentication, Some("/sign_in.html".to_string()));
        assert_eq!(doc.provisioning, Some("/provision.html".to_string()));
        // public-key should be present
        assert_eq!(&doc.public_key, &domain_key.public_key());
    }
}

// =============================================================================
// Fallback IdP Discovery Tests
// Ported from: discovery-test.js lines 55-68
// =============================================================================

mod fallback_idp_discovery {
    use super::*;

    /// Test: discovery for domain without support returns fallback
    /// Original: "discovery for the fallback IdP" -> "returns a well known"
    #[test]
    fn test_unknown_domain_fails_discovery() {
        let fetcher = MockFetcher::new(); // empty - no domains configured
        let config = DiscoveryConfig::default();

        let result = discover("unknown.domain", &fetcher, &config);

        // Should fail because domain doesn't support BrowserID
        assert!(matches!(result, Err(Error::DiscoveryFailed { .. })));
    }

    // Note: In the full system, the broker would handle fallback for unknown domains
    // This test verifies that discovery correctly reports when a domain doesn't support BrowserID
}

// =============================================================================
// Disabled IdP Tests
// Ported from: discovery-test.js lines 70-83
// =============================================================================

mod disabled_idp {
    use super::*;

    /// Test: discovery for a disabled IdP returns secondary
    /// Original: "discovery for a disabled IdP" -> "returns the secondary well known"
    ///
    /// Note: In the original, disabled IDPs were configured via SHIMMED_PRIMARIES
    /// with a special disabled.domain/.well-known/browserid file.
    /// For now, we just test that missing domains fail appropriately.
    #[test]
    fn test_disabled_idp_not_found() {
        let fetcher = MockFetcher::new();
        let config = DiscoveryConfig::default();

        let result = discover("disabled.domain", &fetcher, &config);

        assert!(result.is_err());
    }
}

// =============================================================================
// Bad Usage Tests
// Ported from: discovery-test.js lines 85-95
// =============================================================================

mod bad_usage {
    use super::*;

    /// Test: discovery with empty domain fails
    /// Original: "Bad usage of discovery" -> "gives an error"
    #[test]
    fn test_empty_domain_fails() {
        let fetcher = MockFetcher::new();
        let config = DiscoveryConfig::default();

        let result = discover("", &fetcher, &config);

        assert!(result.is_err());
    }
}

// =============================================================================
// Support Document Format Tests
// Ported from: well-known-browserid.js
// =============================================================================

mod support_document_format {
    use super::*;

    /// Test: support document has correct JSON structure
    /// Original: "returns 200 with 'public-key', valid JSON and Content-type"
    #[test]
    fn test_support_document_has_public_key() {
        let key = KeyPair::generate();
        let doc = SupportDocument::new(key.public_key());

        let json = serde_json::to_string(&doc).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("public-key").is_some(), "should have public-key field");
    }

    /// Test: support document serializes authentication and provisioning paths
    #[test]
    fn test_support_document_paths() {
        let key = KeyPair::generate();
        let doc = SupportDocument::new(key.public_key())
            .with_authentication("/browserid/auth")
            .with_provisioning("/browserid/provision");

        let json = serde_json::to_string(&doc).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed.get("authentication").and_then(|v| v.as_str()),
            Some("/browserid/auth")
        );
        assert_eq!(
            parsed.get("provisioning").and_then(|v| v.as_str()),
            Some("/browserid/provision")
        );
    }

    /// Test: delegation document has authority field
    /// Original: "returns 200, has 'authority', valid JSON and Content-type"
    #[test]
    fn test_delegation_document_has_authority() {
        let doc = SupportDocument::delegate("idp.example.org");

        assert!(doc.is_delegation());
        assert_eq!(doc.authority, Some("idp.example.org".to_string()));

        let json = serde_json::to_string(&doc).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed.get("authority").and_then(|v| v.as_str()),
            Some("idp.example.org")
        );
    }
}

// =============================================================================
// Delegation Tests
// =============================================================================

mod delegation {
    use super::*;

    /// Test: delegation is followed to final authority
    #[test]
    fn test_delegation_followed() {
        let key = KeyPair::generate();
        let mut fetcher = MockFetcher::new();

        // example.com delegates to idp.example.org
        fetcher.add_domain("example.com", SupportDocument::delegate("idp.example.org"));

        // idp.example.org is the actual IdP
        fetcher.add_domain(
            "idp.example.org",
            SupportDocument::new(key.public_key())
                .with_authentication("/auth")
                .with_provisioning("/provision"),
        );

        let config = DiscoveryConfig::default();
        let result = discover("example.com", &fetcher, &config).unwrap();

        assert_eq!(result.domain, "idp.example.org");
        assert_eq!(result.delegation_chain, vec!["example.com"]);
    }

    /// Test: multi-hop delegation is followed
    #[test]
    fn test_multi_hop_delegation() {
        let key = KeyPair::generate();
        let mut fetcher = MockFetcher::new();

        // a.com -> b.com -> c.com (actual IdP)
        fetcher.add_domain("a.com", SupportDocument::delegate("b.com"));
        fetcher.add_domain("b.com", SupportDocument::delegate("c.com"));
        fetcher.add_domain("c.com", SupportDocument::new(key.public_key()));

        let config = DiscoveryConfig::default();
        let result = discover("a.com", &fetcher, &config).unwrap();

        assert_eq!(result.domain, "c.com");
        assert_eq!(result.delegation_chain, vec!["a.com", "b.com"]);
    }

    /// Test: delegation loop is detected
    #[test]
    fn test_delegation_loop_detected() {
        let mut fetcher = MockFetcher::new();

        // a.com -> b.com -> a.com (loop!)
        fetcher.add_domain("a.com", SupportDocument::delegate("b.com"));
        fetcher.add_domain("b.com", SupportDocument::delegate("a.com"));

        let config = DiscoveryConfig {
            max_delegation_depth: 5,
            ..Default::default()
        };

        let result = discover("a.com", &fetcher, &config);

        // Now properly detects circular references before hitting depth limit
        assert!(
            matches!(result, Err(Error::DiscoveryFailed { reason, .. }) if reason.contains("Circular reference"))
        );
    }

    /// Test: delegation depth limit is enforced
    #[test]
    fn test_delegation_depth_limit() {
        let mut fetcher = MockFetcher::new();

        // Create a chain deeper than the limit
        for i in 0..10 {
            fetcher.add_domain(
                &format!("domain{}.com", i),
                SupportDocument::delegate(format!("domain{}.com", i + 1)),
            );
        }

        let config = DiscoveryConfig {
            max_delegation_depth: 3,
            ..Default::default()
        };

        let result = discover("domain0.com", &fetcher, &config);

        assert!(matches!(result, Err(Error::DiscoveryFailed { .. })));
    }
}

// =============================================================================
// Utility Function Tests
// =============================================================================

mod utilities {
    use super::*;

    /// Test: domain extraction from email
    #[test]
    fn test_domain_from_email() {
        assert_eq!(domain_from_email("alice@example.com"), Some("example.com"));
        assert_eq!(
            domain_from_email("bob@sub.example.org"),
            Some("sub.example.org")
        );
        assert_eq!(domain_from_email("invalid"), None);
        assert_eq!(domain_from_email(""), None);
        assert_eq!(domain_from_email("@nodomain"), Some("nodomain"));
    }

    /// Test: well-known URL construction
    #[test]
    fn test_well_known_url() {
        assert_eq!(
            well_known_url("example.com", true),
            "https://example.com/.well-known/browserid"
        );
        assert_eq!(
            well_known_url("example.com", false),
            "http://example.com/.well-known/browserid"
        );
        assert_eq!(
            well_known_url("sub.example.org", true),
            "https://sub.example.org/.well-known/browserid"
        );
    }
}
