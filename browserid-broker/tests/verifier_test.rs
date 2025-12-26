//! Tests for assertion verification with fallback broker support

use browserid_broker::verifier::verify_assertion;
use browserid_core::{
    discovery::{SupportDocument, SupportDocumentFetcher},
    Assertion, BackedAssertion, Certificate, Error as CoreError, KeyPair, Result as CoreResult,
};
use chrono::Duration;
use std::collections::HashMap;

struct MockFetcher {
    documents: HashMap<String, SupportDocument>,
}

impl SupportDocumentFetcher for MockFetcher {
    fn fetch(&self, domain: &str) -> CoreResult<SupportDocument> {
        self.documents.get(domain).cloned().ok_or_else(|| CoreError::DiscoveryFailed {
            domain: domain.to_string(),
            reason: "not found".into(),
        })
    }
}

#[test]
fn test_verify_assertion_success() {
    let domain_key = KeyPair::generate();
    let user_key = KeyPair::generate();

    // Create certificate
    let cert = Certificate::create(
        "example.com",
        "alice@example.com",
        &user_key.public_key(),
        Duration::hours(1),
        &domain_key,
    )
    .unwrap();

    // Create assertion
    let assertion =
        Assertion::create("https://relying-party.com", Duration::minutes(5), &user_key).unwrap();

    // Bundle into backed assertion
    let backed = BackedAssertion::new(cert, assertion);
    let encoded = backed.encode();

    // Set up mock fetcher
    let mut fetcher = MockFetcher {
        documents: HashMap::new(),
    };
    fetcher.documents.insert(
        "example.com".to_string(),
        SupportDocument::new(domain_key.public_key()),
    );

    // Verify (trusted_broker doesn't matter here since issuer == email domain)
    let result = verify_assertion(&encoded, "https://relying-party.com", "broker.example.com", &fetcher);

    assert_eq!(result.status, "okay");
    assert_eq!(result.email.unwrap(), "alice@example.com");
    assert_eq!(result.issuer.unwrap(), "example.com");
}

#[test]
fn test_verify_assertion_wrong_audience() {
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

    let assertion =
        Assertion::create("https://correct-audience.com", Duration::minutes(5), &user_key).unwrap();

    let backed = BackedAssertion::new(cert, assertion);
    let encoded = backed.encode();

    let mut fetcher = MockFetcher {
        documents: HashMap::new(),
    };
    fetcher.documents.insert(
        "example.com".to_string(),
        SupportDocument::new(domain_key.public_key()),
    );

    let result = verify_assertion(&encoded, "https://wrong-audience.com", "broker.example.com", &fetcher);

    assert_eq!(result.status, "failure");
    assert!(result.reason.unwrap().contains("audience"));
}

#[test]
fn test_verify_assertion_invalid_format() {
    let fetcher = MockFetcher {
        documents: HashMap::new(),
    };

    let result = verify_assertion("not-a-valid-assertion", "https://example.com", "broker.example.com", &fetcher);

    assert_eq!(result.status, "failure");
    assert!(result.reason.is_some());
}

#[test]
fn test_verify_assertion_fallback_broker() {
    // Broker keypair (the fallback IdP)
    let broker_key = KeyPair::generate();
    let user_key = KeyPair::generate();

    // Certificate issued by broker for user@external.com
    // (external.com has no native BrowserID support)
    let cert = Certificate::create(
        "broker.example.com", // issuer is the broker, not email domain
        "alice@external.com",
        &user_key.public_key(),
        Duration::hours(1),
        &broker_key,
    )
    .unwrap();

    let assertion =
        Assertion::create("https://relying-party.com", Duration::minutes(5), &user_key).unwrap();

    let backed = BackedAssertion::new(cert, assertion);
    let encoded = backed.encode();

    // Set up fetcher: broker has support doc, external.com does not
    let mut fetcher = MockFetcher {
        documents: HashMap::new(),
    };
    // Only broker has a support document
    fetcher.documents.insert(
        "broker.example.com".to_string(),
        SupportDocument::new(broker_key.public_key()),
    );
    // external.com has no entry - discovery will fail

    // Verify should succeed because issuer == trusted_broker
    let result = verify_assertion(&encoded, "https://relying-party.com", "broker.example.com", &fetcher);

    assert_eq!(result.status, "okay");
    assert_eq!(result.email.unwrap(), "alice@external.com");
    assert_eq!(result.issuer.unwrap(), "broker.example.com");
}

#[test]
fn test_verify_assertion_untrusted_issuer_rejected() {
    // Evil broker tries to issue certs for external.com emails
    let evil_key = KeyPair::generate();
    let user_key = KeyPair::generate();

    let cert = Certificate::create(
        "evil.com", // untrusted issuer
        "alice@external.com",
        &user_key.public_key(),
        Duration::hours(1),
        &evil_key,
    )
    .unwrap();

    let assertion =
        Assertion::create("https://relying-party.com", Duration::minutes(5), &user_key).unwrap();

    let backed = BackedAssertion::new(cert, assertion);
    let encoded = backed.encode();

    let mut fetcher = MockFetcher {
        documents: HashMap::new(),
    };
    // evil.com has a valid support document
    fetcher.documents.insert(
        "evil.com".to_string(),
        SupportDocument::new(evil_key.public_key()),
    );
    // external.com has no entry

    // Should FAIL because evil.com is not the trusted broker
    let result = verify_assertion(&encoded, "https://relying-party.com", "broker.example.com", &fetcher);

    assert_eq!(result.status, "failure");
    assert!(result.reason.unwrap().contains("not authorized"));
}

#[test]
fn test_verify_assertion_primary_cannot_speak_for_other_domain() {
    // Mirrors browserid verifier-test.js lines 946-981:
    // A valid primary (example.domain) cannot issue certs for emails
    // from a different domain (somedomain.com)
    let primary_key = KeyPair::generate();
    let user_key = KeyPair::generate();

    // example.domain tries to issue cert for alice@otherdomain.com
    let cert = Certificate::create(
        "example.domain",
        "alice@otherdomain.com", // wrong domain!
        &user_key.public_key(),
        Duration::hours(1),
        &primary_key,
    )
    .unwrap();

    let assertion =
        Assertion::create("https://relying-party.com", Duration::minutes(5), &user_key).unwrap();

    let backed = BackedAssertion::new(cert, assertion);
    let encoded = backed.encode();

    let mut fetcher = MockFetcher {
        documents: HashMap::new(),
    };
    // example.domain is a valid primary with BrowserID support
    fetcher.documents.insert(
        "example.domain".to_string(),
        SupportDocument::new(primary_key.public_key()),
    );
    // otherdomain.com also has BrowserID support (so fallback doesn't apply)
    let other_key = KeyPair::generate();
    fetcher.documents.insert(
        "otherdomain.com".to_string(),
        SupportDocument::new(other_key.public_key()),
    );

    // Should FAIL: example.domain may not speak for emails from otherdomain.com
    let result = verify_assertion(&encoded, "https://relying-party.com", "broker.example.com", &fetcher);

    assert_eq!(result.status, "failure");
    assert!(result.reason.unwrap().contains("not authorized"));
}
