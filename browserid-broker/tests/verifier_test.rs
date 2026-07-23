//! Tests for access-presentation verification — DNSSEC-rooted (browserid-ng-28uc).
//!
//! The issuer's identity key is resolved SOLELY via DNSSEC (modeled here by
//! `MockDiscoverer`). There is no `.well-known`-only key-trust path, so a domain
//! is a primary IdP only if it publishes an authenticated `_browserid` record;
//! otherwise the only acceptable issuer is the trusted broker.

use browserid_broker::error::BrokerError;
use browserid_broker::fallback_fetcher::{Discoverer, FallbackResult};
use browserid_core::{discovery::SupportDocument, Assertion, KeyPair, PublicKey};
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

// ---------------------------------------------------------------------------
// Device-cert model (DC Phase 6): verify_access_with_dns conformance.
// ---------------------------------------------------------------------------

use browserid_broker::verifier::verify_access_with_dns;
use browserid_core::device::{
    AccessCert as DAccessCert, DeviceCert, Holder, HolderMatcher, Purpose, Warrant as DWarrant,
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
    let holder = Holder::new("br1a2b3c.main").unwrap();
    let access_cert = DAccessCert::create(
        idp_domain, email, holder.clone(), &access_key.public_key(),
        Duration::hours(24), idp, None,
    ).unwrap();
    let config_cert = DeviceCert::create(
        config_iss, &config_key.public_key(), Purpose::Authorization, holder.clone(),
        vec![email.to_string()], Duration::days(90), idp, None,
    ).unwrap();
    let warrant = DWarrant::create(
        email, email, HolderMatcher::new("br1a2b3c.*").unwrap(), audience, vec!["login".into()],
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
    assert_eq!(r.holder.as_deref(), Some("br1a2b3c.main"));
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
