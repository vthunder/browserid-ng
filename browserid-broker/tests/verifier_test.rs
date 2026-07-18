//! Tests for assertion verification — DNSSEC-rooted (browserid-ng-28uc).
//!
//! The issuer's identity key is resolved SOLELY via DNSSEC (modeled here by
//! `MockDiscoverer`). There is no `.well-known`-only key-trust path, so a domain
//! is a primary IdP only if it publishes an authenticated `_browserid` record;
//! otherwise the only acceptable issuer is the trusted broker.

use browserid_broker::error::BrokerError;
use browserid_broker::fallback_fetcher::{Discoverer, FallbackResult};
use browserid_broker::verifier::verify_assertion_with_dns;
use browserid_core::{
    discovery::SupportDocument, Assertion, BackedAssertion, Certificate, KeyPair, PublicKey,
};
use chrono::Duration;
use std::collections::{HashMap, HashSet};

const BROKER: &str = "broker.example.com";
const RP: &str = "https://relying-party.com";

/// Mock DNSSEC-first discovery. Domains registered as `primaries` resolve to a
/// primary IdP carrying the given DNSSEC-validated key; `bogus` domains
/// hard-error (DNSSEC validation failure); every other domain falls back to the
/// broker, whose key is itself DNSSEC-rooted.
struct MockDiscoverer {
    primaries: HashMap<String, PublicKey>,
    bogus: HashSet<String>,
    broker_key: PublicKey,
}

impl MockDiscoverer {
    fn new(broker_key: PublicKey) -> Self {
        Self {
            primaries: HashMap::new(),
            bogus: HashSet::new(),
            broker_key,
        }
    }

    fn with_primary(mut self, domain: &str, key: PublicKey) -> Self {
        self.primaries.insert(domain.to_string(), key);
        self
    }

    fn with_bogus(mut self, domain: &str) -> Self {
        self.bogus.insert(domain.to_string());
        self
    }

    fn resolve(&self, domain: &str) -> Result<FallbackResult, BrokerError> {
        if self.bogus.contains(domain) {
            return Err(BrokerError::DnssecValidationFailed {
                domain: domain.to_string(),
            });
        }
        if let Some(key) = self.primaries.get(domain) {
            Ok(FallbackResult {
                document: SupportDocument::new(key.clone()),
                authoritative_domain: domain.to_string(),
                is_primary: true,
            })
        } else {
            Ok(FallbackResult {
                document: SupportDocument::new(self.broker_key.clone()),
                authoritative_domain: BROKER.to_string(),
                is_primary: false,
            })
        }
    }
}

impl Discoverer for MockDiscoverer {
    fn discover(
        &self,
        domain: &str,
    ) -> impl std::future::Future<Output = Result<FallbackResult, BrokerError>> + Send {
        let res = self.resolve(domain);
        async move { res }
    }
}

/// Build an encoded backed assertion.
#[allow(clippy::too_many_arguments)]
fn backed(
    issuer: &str,
    email: &str,
    audience: &str,
    cert_dur: Duration,
    assert_dur: Duration,
    cert_signer: &KeyPair,
    assertion_signer: &KeyPair,
    cert_subject: &KeyPair,
) -> String {
    let cert = Certificate::create(
        issuer,
        email,
        &cert_subject.public_key(),
        cert_dur,
        cert_signer,
    )
    .unwrap();
    let assertion = Assertion::create(audience, assert_dur, assertion_signer).unwrap();
    BackedAssertion::new(cert, assertion).encode()
}

/// The common well-formed case: cert signed by `signer` for `user`.
fn ok_backed(issuer: &str, email: &str, audience: &str, signer: &KeyPair, user: &KeyPair) -> String {
    backed(
        issuer,
        email,
        audience,
        Duration::hours(1),
        Duration::minutes(5),
        signer,
        user,
        user,
    )
}

// --- happy paths ---------------------------------------------------------

#[tokio::test]
async fn primary_verifies_via_dnssec() {
    let domain_key = KeyPair::generate();
    let user = KeyPair::generate();
    let broker_key = KeyPair::generate();
    let disc = MockDiscoverer::new(broker_key.public_key())
        .with_primary("example.com", domain_key.public_key());

    let enc = ok_backed("example.com", "alice@example.com", RP, &domain_key, &user);
    let result = verify_assertion_with_dns(&enc, RP, &disc, &[BROKER.to_string()]).await;

    assert_eq!(result.status, "okay", "reason: {:?}", result.reason);
    assert_eq!(result.email.unwrap(), "alice@example.com");
    assert_eq!(result.issuer.unwrap(), "example.com");
}

#[tokio::test]
async fn broker_fallback_verifies() {
    // external.com has no DNSSEC record → broker fallback. Cert issued by broker.
    let broker_key = KeyPair::generate();
    let user = KeyPair::generate();
    let disc = MockDiscoverer::new(broker_key.public_key());

    let enc = ok_backed(BROKER, "alice@external.com", RP, &broker_key, &user);
    let result = verify_assertion_with_dns(&enc, RP, &disc, &[BROKER.to_string()]).await;

    assert_eq!(result.status, "okay", "reason: {:?}", result.reason);
    assert_eq!(result.email.unwrap(), "alice@external.com");
    assert_eq!(result.issuer.unwrap(), BROKER);
}

// --- the downgrade closure (the point of 28uc) ---------------------------

#[tokio::test]
async fn non_dnssec_domain_cannot_be_primary() {
    // example.com does NOT publish a DNSSEC record (not in `primaries`), so it
    // resolves to broker fallback. A cert claiming issuer == example.com must be
    // rejected — there is no `.well-known`-only path to be trusted as a primary.
    let some_key = KeyPair::generate();
    let user = KeyPair::generate();
    let broker_key = KeyPair::generate();
    let disc = MockDiscoverer::new(broker_key.public_key()); // no primaries

    let enc = ok_backed("example.com", "alice@example.com", RP, &some_key, &user);
    let result = verify_assertion_with_dns(&enc, RP, &disc, &[BROKER.to_string()]).await;

    assert_eq!(result.status, "failure");
    assert!(
        result.reason.as_ref().unwrap().contains("not an accepted fallback"),
        "reason: {:?}",
        result.reason
    );
}

#[tokio::test]
async fn bogus_dnssec_is_rejected() {
    let user = KeyPair::generate();
    let signer = KeyPair::generate();
    let broker_key = KeyPair::generate();
    let disc = MockDiscoverer::new(broker_key.public_key()).with_bogus("bogus.com");

    let enc = ok_backed("bogus.com", "alice@bogus.com", RP, &signer, &user);
    let result = verify_assertion_with_dns(&enc, RP, &disc, &[BROKER.to_string()]).await;

    assert_eq!(result.status, "failure");
    assert!(
        result.reason.as_ref().unwrap().to_lowercase().contains("discovery"),
        "reason: {:?}",
        result.reason
    );
}

#[tokio::test]
async fn untrusted_issuer_rejected() {
    // Cert from evil.com for an external (broker-served) email → not the broker.
    let evil = KeyPair::generate();
    let user = KeyPair::generate();
    let broker_key = KeyPair::generate();
    let disc = MockDiscoverer::new(broker_key.public_key());

    let enc = ok_backed("evil.com", "alice@external.com", RP, &evil, &user);
    let result = verify_assertion_with_dns(&enc, RP, &disc, &[BROKER.to_string()]).await;

    assert_eq!(result.status, "failure");
    assert!(result.reason.unwrap().contains("not an accepted fallback"));
}

#[tokio::test]
async fn accepted_external_fallback_is_authorized() {
    // A cert from an external fallback (fallback.example) for a no-primary
    // email verifies when the RP lists it in accepted_fallbacks (spec §8.1) —
    // even though it is not this broker. The fallback publishes its own DNSSEC
    // key (a "primary" for its own domain in the mock).
    let fallback_key = KeyPair::generate();
    let user = KeyPair::generate();
    let broker_key = KeyPair::generate();
    let disc = MockDiscoverer::new(broker_key.public_key())
        .with_primary("fallback.example", fallback_key.public_key());

    let enc = ok_backed("fallback.example", "alice@external.com", RP, &fallback_key, &user);

    // Not accepted by default (only BROKER) → rejected.
    let default = verify_assertion_with_dns(&enc, RP, &disc, &[BROKER.to_string()]).await;
    assert_eq!(default.status, "failure", "reason: {:?}", default.reason);
    assert!(default.reason.unwrap().contains("not an accepted fallback"));

    // Accepted when the RP lists it → okay, issuer = the external fallback.
    let ok = verify_assertion_with_dns(&enc, RP, &disc, &["fallback.example".to_string()]).await;
    assert_eq!(ok.status, "okay", "reason: {:?}", ok.reason);
    assert_eq!(ok.email.unwrap(), "alice@external.com");
    assert_eq!(ok.issuer.unwrap(), "fallback.example");
}

#[tokio::test]
async fn primary_cannot_speak_for_other_domain() {
    // example.domain is a valid primary but may not issue for otherdomain.com,
    // which is itself a primary.
    let primary_key = KeyPair::generate();
    let other_key = KeyPair::generate();
    let user = KeyPair::generate();
    let broker_key = KeyPair::generate();
    let disc = MockDiscoverer::new(broker_key.public_key())
        .with_primary("example.domain", primary_key.public_key())
        .with_primary("otherdomain.com", other_key.public_key());

    let enc = ok_backed(
        "example.domain",
        "alice@otherdomain.com",
        RP,
        &primary_key,
        &user,
    );
    let result = verify_assertion_with_dns(&enc, RP, &disc, &[BROKER.to_string()]).await;

    assert_eq!(result.status, "failure");
    assert!(result.reason.unwrap().contains("not authorized for primary domain"));
}

// --- crypto / format failures --------------------------------------------

#[tokio::test]
async fn wrong_audience_rejected() {
    let domain_key = KeyPair::generate();
    let user = KeyPair::generate();
    let disc = MockDiscoverer::new(KeyPair::generate().public_key())
        .with_primary("example.com", domain_key.public_key());

    let enc = ok_backed(
        "example.com",
        "alice@example.com",
        "https://correct.com",
        &domain_key,
        &user,
    );
    let result = verify_assertion_with_dns(&enc, "https://wrong.com", &disc, &[BROKER.to_string()]).await;

    assert_eq!(result.status, "failure");
    assert!(result.reason.unwrap().to_lowercase().contains("audience"));
}

#[tokio::test]
async fn wrong_port_or_scheme_rejected() {
    let domain_key = KeyPair::generate();
    let user = KeyPair::generate();
    let disc = MockDiscoverer::new(KeyPair::generate().public_key())
        .with_primary("example.com", domain_key.public_key());

    let enc = ok_backed(
        "example.com",
        "alice@example.com",
        "http://fakesite.com:8080",
        &domain_key,
        &user,
    );
    // wrong port
    let r1 = verify_assertion_with_dns(&enc, "http://fakesite.com:8888", &disc, &[BROKER.to_string()]).await;
    assert_eq!(r1.status, "failure");
    assert!(r1.reason.unwrap().to_lowercase().contains("audience"));
    // wrong scheme
    let r2 = verify_assertion_with_dns(&enc, "https://fakesite.com:8080", &disc, &[BROKER.to_string()]).await;
    assert_eq!(r2.status, "failure");
    assert!(r2.reason.unwrap().to_lowercase().contains("audience"));
}

#[tokio::test]
async fn expired_assertion_rejected() {
    let domain_key = KeyPair::generate();
    let user = KeyPair::generate();
    let disc = MockDiscoverer::new(KeyPair::generate().public_key())
        .with_primary("example.com", domain_key.public_key());

    let enc = backed(
        "example.com",
        "alice@example.com",
        RP,
        Duration::hours(1),
        Duration::milliseconds(-10),
        &domain_key,
        &user,
        &user,
    );
    let result = verify_assertion_with_dns(&enc, RP, &disc, &[BROKER.to_string()]).await;
    assert_eq!(result.status, "failure");
    assert!(result.reason.unwrap().to_lowercase().contains("expired"));
}

#[tokio::test]
async fn expired_certificate_rejected() {
    let domain_key = KeyPair::generate();
    let user = KeyPair::generate();
    let disc = MockDiscoverer::new(KeyPair::generate().public_key())
        .with_primary("example.com", domain_key.public_key());

    let enc = backed(
        "example.com",
        "alice@example.com",
        RP,
        Duration::milliseconds(-10),
        Duration::minutes(5),
        &domain_key,
        &user,
        &user,
    );
    let result = verify_assertion_with_dns(&enc, RP, &disc, &[BROKER.to_string()]).await;
    assert_eq!(result.status, "failure");
    assert!(result.reason.unwrap().to_lowercase().contains("expired"));
}

#[tokio::test]
async fn bad_certificate_signature_rejected() {
    // Domain publishes domain_key (via DNSSEC), but the cert was signed by wrong_key.
    let domain_key = KeyPair::generate();
    let wrong_key = KeyPair::generate();
    let user = KeyPair::generate();
    let disc = MockDiscoverer::new(KeyPair::generate().public_key())
        .with_primary("example.com", domain_key.public_key());

    let enc = ok_backed("example.com", "alice@example.com", RP, &wrong_key, &user);
    let result = verify_assertion_with_dns(&enc, RP, &disc, &[BROKER.to_string()]).await;
    assert_eq!(result.status, "failure");
    assert!(result.reason.unwrap().to_lowercase().contains("signature"));
}

#[tokio::test]
async fn bad_assertion_signature_rejected() {
    // Cert binds user's key, but the assertion is signed by a different key.
    let domain_key = KeyPair::generate();
    let user = KeyPair::generate();
    let wrong_user = KeyPair::generate();
    let disc = MockDiscoverer::new(KeyPair::generate().public_key())
        .with_primary("example.com", domain_key.public_key());

    let enc = backed(
        "example.com",
        "alice@example.com",
        RP,
        Duration::hours(1),
        Duration::minutes(5),
        &domain_key,
        &wrong_user, // assertion signer != cert subject
        &user,
    );
    let result = verify_assertion_with_dns(&enc, RP, &disc, &[BROKER.to_string()]).await;
    assert_eq!(result.status, "failure");
    assert!(result.reason.unwrap().to_lowercase().contains("signature"));
}

#[tokio::test]
async fn invalid_format_rejected() {
    let disc = MockDiscoverer::new(KeyPair::generate().public_key());
    let result = verify_assertion_with_dns("not-a-valid-assertion", RP, &disc, &[BROKER.to_string()]).await;
    assert_eq!(result.status, "failure");
    assert!(result.reason.is_some());
}

#[tokio::test]
async fn no_certificate_rejected() {
    let disc = MockDiscoverer::new(KeyPair::generate().public_key());
    // A bare JWT with no `~`-joined certificate bundle.
    let raw = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tIiwiZXhwIjoxNzM1MjUwMDAwfQ.signature";
    let result = verify_assertion_with_dns(raw, RP, &disc, &[BROKER.to_string()]).await;
    assert_eq!(result.status, "failure");
    assert!(result.reason.is_some());
}

// ---------------------------------------------------------------------------
// Device-cert model (DC Phase 6): verify_access_with_dns conformance.
// ---------------------------------------------------------------------------

use browserid_broker::verifier::verify_access_with_dns;
use browserid_core::device::{
    AccessCert as DAccessCert, DeviceCert, Purpose, Subject, Warrant as DWarrant,
};

fn device_presentation(
    idp_domain: &str,
    config_iss: &str,
    email: &str,
    audience: &str,
    idp: &KeyPair,
) -> String {
    let access_key = KeyPair::generate();
    let config_key = KeyPair::generate();
    let access_cert = DAccessCert::create(
        idp_domain, email, Subject::User, &access_key.public_key(),
        Duration::hours(24), idp, None,
    ).unwrap();
    let config_cert = DeviceCert::create(
        config_iss, &config_key.public_key(), Purpose::Authorization, Subject::User,
        vec![email.to_string()], Duration::days(90), idp, None,
    ).unwrap();
    let warrant = DWarrant::create(
        email, Subject::User, audience, vec!["login".into()],
        Duration::days(90), &config_key, None,
    ).unwrap();
    let assertion = Assertion::create(audience, Duration::minutes(5), &access_key).unwrap();
    format!("{}~{}~{}~{}", access_cert.encoded(), assertion.encoded(), warrant.encoded(), config_cert.encoded())
}

#[tokio::test]
async fn verify_access_primary_conformance_okay() {
    let idp = KeyPair::generate();
    let disc = MockDiscoverer::new(idp.public_key()).with_primary("sandmill.org", idp.public_key());
    let pres = device_presentation("sandmill.org", "sandmill.org", "danmills@sandmill.org", "https://mingo.place", &idp);
    let r = verify_access_with_dns(&pres, "https://mingo.place", &disc, &[BROKER.to_string()]).await;
    assert_eq!(r.status, "okay", "{:?}", r);
    assert_eq!(r.email.as_deref(), Some("danmills@sandmill.org"));
    assert_eq!(r.subject.as_deref(), Some("user"));
}

#[tokio::test]
async fn verify_access_rejects_config_cert_from_rogue_idp() {
    // config cert claims a different issuer than the access cert → privilege-escalation reject.
    let idp = KeyPair::generate();
    let disc = MockDiscoverer::new(idp.public_key()).with_primary("sandmill.org", idp.public_key());
    let pres = device_presentation("sandmill.org", "evil.example", "danmills@sandmill.org", "https://mingo.place", &idp);
    let r = verify_access_with_dns(&pres, "https://mingo.place", &disc, &[BROKER.to_string()]).await;
    assert_eq!(r.status, "failure");
}

#[tokio::test]
async fn verify_access_rejects_fallback_issuer_for_primary_domain() {
    // access cert issued by browserid.me (fallback) for a PRIMARY domain → must fail.
    let idp = KeyPair::generate();       // the real sandmill.org primary key
    let fallback = KeyPair::generate();  // browserid.me
    let disc = MockDiscoverer::new(fallback.public_key()).with_primary("sandmill.org", idp.public_key());
    // Present certs issued by the FALLBACK for a sandmill.org identity.
    let pres = device_presentation(BROKER, BROKER, "danmills@sandmill.org", "https://mingo.place", &fallback);
    let r = verify_access_with_dns(&pres, "https://mingo.place", &disc, &[BROKER.to_string()]).await;
    assert_eq!(r.status, "failure", "fallback must not vouch for a primary domain: {:?}", r);
}
