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

use browserid_broker::verifier::{verify_access_with_dns, StatusCtx};
use browserid_core::device::{
    AccessCert as DAccessCert, DeviceCert, Holder, HolderMatcher, Purpose, Warrant as DWarrant,
};
use browserid_core::{StatusListToken, StatusRef};
use std::sync::RwLock;

const OWN_STATUS_URI: &str = "https://broker.example.com/.well-known/browserid-status";

fn device_presentation(
    idp_domain: &str,
    config_iss: &str,
    email: &str,
    audience: &str,
    idp: &KeyPair,
) -> String {
    device_presentation_with_status(idp_domain, config_iss, email, audience, idp, None)
}

fn device_presentation_with_status(
    idp_domain: &str,
    config_iss: &str,
    email: &str,
    audience: &str,
    idp: &KeyPair,
    access_status: Option<StatusRef>,
) -> String {
    let access_key = KeyPair::generate();
    let config_key = KeyPair::generate();
    let holder = Holder::new("br1a2b3c.main").unwrap();
    let access_cert = DAccessCert::create(
        idp_domain, email, holder.clone(), &access_key.public_key(),
        Duration::hours(24), idp, access_status,
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

/// StatusCtx whose own-list check consults `revoked` and whose foreign cache
/// starts empty. Tests that need a foreign list serve it over HTTP.
macro_rules! status_ctx {
    ($cache:expr, $check:expr) => {
        StatusCtx { own_uri: OWN_STATUS_URI.to_string(), is_own_revoked: $check, cache: $cache }
    };
}

fn never_revoked(_idx: u64) -> Result<bool, String> {
    Ok(false)
}

#[tokio::test]
async fn verify_access_primary_conformance_okay() {
    let idp = KeyPair::generate();
    let disc = MockDiscoverer::new(idp.public_key()).with_primary("sandmill.org", idp.public_key());
    let pres = device_presentation("sandmill.org", "sandmill.org", "danmills@sandmill.org", "https://mingo.place", &idp);
    let cache = RwLock::new(HashMap::new());
    let r = verify_access_with_dns(&pres, "https://mingo.place", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
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
    let cache = RwLock::new(HashMap::new());
    let r = verify_access_with_dns(&pres, "https://mingo.place", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
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
    let cache = RwLock::new(HashMap::new());
    let r = verify_access_with_dns(&pres, "https://mingo.place", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
    assert_eq!(r.status, "failure", "fallback must not vouch for a primary domain: {:?}", r);
}

// ---------------------------------------------------------------------------
// Status enforcement (core §6.4): three authorities, fail-closed (4lxl).
// ---------------------------------------------------------------------------

fn primary_setup() -> (KeyPair, MockDiscoverer) {
    let idp = KeyPair::generate();
    let disc = MockDiscoverer::new(idp.public_key()).with_primary("sandmill.org", idp.public_key());
    (idp, disc)
}

#[tokio::test]
async fn verify_access_rejects_revoked_own_credential() {
    let (idp, disc) = primary_setup();
    let pres = device_presentation_with_status(
        "sandmill.org", "sandmill.org", "danmills@sandmill.org", "https://mingo.place", &idp,
        Some(StatusRef { uri: OWN_STATUS_URI.into(), idx: 7 }),
    );
    let cache = RwLock::new(HashMap::new());
    let revoked_7 = |idx: u64| -> Result<bool, String> { Ok(idx == 7) };
    let r = verify_access_with_dns(&pres, "https://mingo.place", &disc, &[BROKER.to_string()], status_ctx!(&cache, &revoked_7)).await;
    assert_eq!(r.status, "failure", "{:?}", r);
    assert!(r.reason.as_deref().unwrap_or("").contains("revoked"), "{:?}", r);
}

#[tokio::test]
async fn verify_access_own_store_error_fails_closed() {
    let (idp, disc) = primary_setup();
    let pres = device_presentation_with_status(
        "sandmill.org", "sandmill.org", "danmills@sandmill.org", "https://mingo.place", &idp,
        Some(StatusRef { uri: OWN_STATUS_URI.into(), idx: 7 }),
    );
    let cache = RwLock::new(HashMap::new());
    let broken = |_: u64| -> Result<bool, String> { Err("db down".into()) };
    let r = verify_access_with_dns(&pres, "https://mingo.place", &disc, &[BROKER.to_string()], status_ctx!(&cache, &broken)).await;
    assert_eq!(r.status, "failure", "store error must fail closed: {:?}", r);
}

#[tokio::test]
async fn verify_access_rejects_unreachable_foreign_status() {
    let (idp, disc) = primary_setup();
    // Port 9 (discard) is closed: fetch fails fast → fail-closed reject.
    let pres = device_presentation_with_status(
        "sandmill.org", "sandmill.org", "danmills@sandmill.org", "https://mingo.place", &idp,
        Some(StatusRef { uri: "http://127.0.0.1:9/.well-known/browserid-status".into(), idx: 0 }),
    );
    let cache = RwLock::new(HashMap::new());
    let r = verify_access_with_dns(&pres, "https://mingo.place", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
    assert_eq!(r.status, "failure", "{:?}", r);
    assert!(r.reason.as_deref().unwrap_or("").contains("fail-closed"), "{:?}", r);
}

#[tokio::test]
async fn verify_access_checks_foreign_status_list() {
    let (idp, _) = primary_setup();
    // A foreign status authority: its list says idx 3 is revoked, idx 5 is not.
    let authority_key = KeyPair::generate();
    let list = browserid_core::StatusList::from_revoked([3], 16);
    let make_pres = |idx: u64, authority: &str| {
        device_presentation_with_status(
            "sandmill.org", "sandmill.org", "danmills@sandmill.org", "https://mingo.place", &idp,
            Some(StatusRef { uri: format!("http://{authority}/.well-known/browserid-status"), idx }),
        )
    };

    // Sign the list AFTER we know the port (uri is a signed claim).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let uri = format!("http://{authority}/.well-known/browserid-status");
    let token = StatusListToken::create(&authority, &uri, &list, &authority_key).unwrap();
    let body = token.encoded().to_string();
    use axum::routing::get;
    let app = axum::Router::new()
        .route("/.well-known/browserid-status", get(move || std::future::ready(body.clone())));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // The discoverer knows both the IdP and the status authority's key.
    let disc = MockDiscoverer::new(idp.public_key())
        .with_primary("sandmill.org", idp.public_key())
        .with_primary(&authority, authority_key.public_key());

    let cache = RwLock::new(HashMap::new());
    let r = verify_access_with_dns(&make_pres(3, &authority), "https://mingo.place", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
    assert_eq!(r.status, "failure", "revoked foreign bit must reject: {:?}", r);

    let r = verify_access_with_dns(&make_pres(5, &authority), "https://mingo.place", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
    assert_eq!(r.status, "okay", "clear foreign bit must pass (and cache): {:?}", r);
    assert!(cache.read().unwrap().len() == 1, "verified foreign list is cached");
}

#[tokio::test]
async fn verify_access_rejects_foreign_list_from_non_authoritative_signer() {
    let (idp, _) = primary_setup();
    // List hosted at 127.0.0.1:PORT but signed with iss=evil.example — the
    // signer is not the URI's host, so even a valid signature must not count.
    let evil_key = KeyPair::generate();
    let list = browserid_core::StatusList::from_revoked([], 16);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let uri = format!("http://{authority}/.well-known/browserid-status");
    let token = StatusListToken::create("evil.example", &uri, &list, &evil_key).unwrap();
    let body = token.encoded().to_string();
    use axum::routing::get;
    let app = axum::Router::new()
        .route("/.well-known/browserid-status", get(move || std::future::ready(body.clone())));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let disc = MockDiscoverer::new(idp.public_key())
        .with_primary("sandmill.org", idp.public_key())
        .with_primary("evil.example", evil_key.public_key());

    let pres = device_presentation_with_status(
        "sandmill.org", "sandmill.org", "danmills@sandmill.org", "https://mingo.place", &idp,
        Some(StatusRef { uri, idx: 0 }),
    );
    let cache = RwLock::new(HashMap::new());
    let r = verify_access_with_dns(&pres, "https://mingo.place", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
    assert_eq!(r.status, "failure", "non-authoritative signer must reject: {:?}", r);
    assert!(r.reason.as_deref().unwrap_or("").contains("non-authoritative"), "{:?}", r);
}
