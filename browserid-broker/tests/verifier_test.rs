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
                serving_host: None,
            })
        } else {
            Ok(FallbackResult {
                document: SupportDocument::new(self.broker_key.clone()),
                authoritative_domain: BROKER.to_string(),
                is_primary: false,
                serving_host: None,
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
        StatusCtx { own_uri: OWN_STATUS_URI.to_string(), is_own_revoked: $check, cache: $cache, allow_private_hosts: true }
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
    // Both names, always: for an as-you presentation the acting identity
    // (warrant grantee) equals the attributed one.
    assert_eq!(r.grantee.as_deref(), Some("danmills@sandmill.org"));
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

/// An on-behalf-of presentation whose GRANTEE (actor) and GRANTOR (attributed
/// identity) live at DIFFERENT IdPs: the access cert is signed by the
/// grantee's IdP, the config cert (and thus the warrant) by the grantor's.
/// This is the shape a `@sandmill.org` agent posting as an
/// `@bsky.browserid.me` handle produces.
#[allow(clippy::too_many_arguments)]
fn onbehalf_presentation(
    grantee: &str,
    grantee_iss: &str,
    grantee_idp: &KeyPair,
    grantor: &str,
    grantor_iss: &str,
    grantor_idp: &KeyPair,
    audience: &str,
) -> String {
    let access_key = KeyPair::generate();
    let config_key = KeyPair::generate();
    let holder = Holder::new("br1a2b3c.main").unwrap();
    // The access cert certifies the actor, signed by the actor's IdP.
    let access_cert = DAccessCert::create(
        grantee_iss, grantee, holder.clone(), &access_key.public_key(),
        Duration::hours(24), grantee_idp, None,
    ).unwrap();
    // The config cert authorizes the GRANTOR identity, signed by the grantor's IdP.
    let config_cert = DeviceCert::create(
        grantor_iss, &config_key.public_key(), Purpose::Authorization, holder.clone(),
        vec![grantor.to_string()], Duration::days(90), grantor_idp, None,
    ).unwrap();
    // The warrant attributes to the grantor, executed by the grantee, signed
    // by the config key the grantor's IdP certified.
    let warrant = DWarrant::create(
        grantor, grantee, HolderMatcher::new("br1a2b3c.*").unwrap(), audience,
        vec!["login".into()], Duration::days(90), &config_key, None,
    ).unwrap();
    let assertion = Assertion::create(audience, Duration::minutes(5), &access_key).unwrap();
    format!("{}~{}~{}~{}", access_cert.encoded(), assertion.encoded(), warrant.encoded(), config_cert.encoded())
}

/// browserid-bsky-ru7u F10 regression. A cross-issuer on-behalf-of bundle — a
/// `@sandmill.org` agent posting as an `@bsky.browserid.me` handle — must
/// verify: the grantor's IdP (`bsky.browserid.me`) is authoritative for the
/// grantor, and the grantee's (`sandmill.org`) for the grantee. The path once
/// resolved only the access cert's issuer and rejected the grantor's own IdP
/// as "not authoritative".
#[tokio::test]
async fn verify_access_accepts_cross_issuer_on_behalf_of() {
    let grantee_idp = KeyPair::generate(); // sandmill.org
    let grantor_idp = KeyPair::generate(); // bsky.browserid.me
    let disc = MockDiscoverer::new(grantee_idp.public_key())
        .with_primary("sandmill.org", grantee_idp.public_key())
        .with_primary("bsky.browserid.me", grantor_idp.public_key());
    let pres = onbehalf_presentation(
        "danmills+claude@sandmill.org", "sandmill.org", &grantee_idp,
        "danmills.bsky.social@bsky.browserid.me", "bsky.browserid.me", &grantor_idp,
        "https://bsky.browserid.me",
    );
    let cache = RwLock::new(HashMap::new());
    let r = verify_access_with_dns(&pres, "https://bsky.browserid.me", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
    assert_eq!(r.status, "okay", "{:?}", r);
    // The attributed identity is the GRANTOR; the acting one is the grantee.
    assert_eq!(r.email.as_deref(), Some("danmills.bsky.social@bsky.browserid.me"));
    assert_eq!(r.grantee.as_deref(), Some("danmills+claude@sandmill.org"));
}

/// The cross-issuer path must not become a hole: a config cert signed by an
/// IdP that is NOT authoritative for the grantor is still rejected, even when
/// the access cert's own issuer is fine.
#[tokio::test]
async fn verify_access_rejects_cross_issuer_with_rogue_grantor_idp() {
    let grantee_idp = KeyPair::generate(); // sandmill.org, legitimate
    let rogue = KeyPair::generate(); // signs the config cert but is not bsky's IdP
    let real_bsky = KeyPair::generate();
    let disc = MockDiscoverer::new(grantee_idp.public_key())
        .with_primary("sandmill.org", grantee_idp.public_key())
        .with_primary("bsky.browserid.me", real_bsky.public_key());
    // config_iss claims bsky.browserid.me but is signed by `rogue`, not the
    // key discovery publishes for it.
    let pres = onbehalf_presentation(
        "danmills+claude@sandmill.org", "sandmill.org", &grantee_idp,
        "danmills.bsky.social@bsky.browserid.me", "bsky.browserid.me", &rogue,
        "https://bsky.browserid.me",
    );
    let cache = RwLock::new(HashMap::new());
    let r = verify_access_with_dns(&pres, "https://bsky.browserid.me", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
    assert_eq!(r.status, "failure", "a config cert not signed by the grantor's real IdP must fail: {:?}", r);
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
async fn failed_foreign_status_fetch_is_negative_cached() {
    // M4 follow-up: a repeat check against a URI that just failed must be
    // refused from the negative cache (instant, still fail-closed) instead of
    // stalling on the network again. Distinct URI from the test above so the
    // process-wide negative cache can't couple the two tests.
    let (idp, disc) = primary_setup();
    let pres = device_presentation_with_status(
        "sandmill.org", "sandmill.org", "danmills@sandmill.org", "https://mingo.place", &idp,
        Some(StatusRef { uri: "http://127.0.0.1:9/.well-known/browserid-status-negcache".into(), idx: 0 }),
    );
    let cache = RwLock::new(HashMap::new());
    let r = verify_access_with_dns(&pres, "https://mingo.place", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
    assert_eq!(r.status, "failure", "{:?}", r);
    assert!(!r.reason.as_deref().unwrap_or("").contains("cached failure"), "first miss must be a live fetch: {:?}", r);
    let r = verify_access_with_dns(&pres, "https://mingo.place", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
    assert_eq!(r.status, "failure", "{:?}", r);
    assert!(r.reason.as_deref().unwrap_or("").contains("cached failure"), "repeat must come from the negative cache: {:?}", r);
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

// ---------------------------------------------------------------------------
// Two-object record validation (operation A, spec §6.4): validate_record_with_dns.
// ---------------------------------------------------------------------------

use browserid_broker::verifier::validate_record_with_dns;
use browserid_core::{Binding, ConnectionProtocol};

/// A held v2 connection record (`warrant~config_cert`): the grantor's config
/// cert signed by `idp` under `config_iss`, the warrant self-granted and bound
/// to an OAuth connection, with a broker-registry status ref at `idx`.
fn connection_record(config_iss: &str, email: &str, audience: &str, idp: &KeyPair, idx: u64) -> String {
    let config_key = KeyPair::generate();
    let config_cert = DeviceCert::create(
        config_iss, &config_key.public_key(), Purpose::Authorization,
        Holder::new("br1a2b3c.main").unwrap(), vec![email.to_string()],
        Duration::days(90), idp, None,
    ).unwrap();
    let warrant = DWarrant::create_v2(
        email, email,
        Binding::Connection {
            protocol: ConnectionProtocol::Oauth,
            id: "cn_8f3a".into(),
            client_host: "claude.ai".into(),
            client_name: "Claude".into(),
        },
        audience, vec!["tool:read_file".into()],
        Duration::days(90), &config_key,
        StatusRef { uri: OWN_STATUS_URI.into(), idx },
    ).unwrap();
    format!("{}~{}", warrant.encoded(), config_cert.encoded())
}

#[tokio::test]
async fn validate_record_conformance_okay() {
    let idp = KeyPair::generate();
    let disc = MockDiscoverer::new(idp.public_key()).with_primary("sandmill.org", idp.public_key());
    let rec = connection_record("sandmill.org", "danmills@sandmill.org", "https://gate.dan.dev/notes", &idp, 168);
    let cache = RwLock::new(HashMap::new());
    let r = validate_record_with_dns(&rec, "https://gate.dan.dev/notes", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
    assert_eq!(r.status, "okay", "{:?}", r);
    assert_eq!(r.grantor.as_deref(), Some("danmills@sandmill.org"));
    assert_eq!(r.grantee.as_deref(), Some("danmills@sandmill.org"));
    assert!(matches!(r.binding.as_ref().map(|b| b.entries()), Some([Binding::Connection { .. }])), "{:?}", r.binding);
    assert_eq!(r.scopes.as_deref(), Some(&["tool:read_file".to_string()][..]));
    // The warrant's registry ref rides back for the resource's per-use re-checks.
    assert_eq!(r.status_refs.as_ref().map(|s| s.len()), Some(1));
    assert!(r.expires_at.is_some());
}

#[tokio::test]
async fn validate_record_rejects_wrong_audience() {
    let idp = KeyPair::generate();
    let disc = MockDiscoverer::new(idp.public_key()).with_primary("sandmill.org", idp.public_key());
    let rec = connection_record("sandmill.org", "danmills@sandmill.org", "https://gate.dan.dev/notes", &idp, 168);
    let cache = RwLock::new(HashMap::new());
    let r = validate_record_with_dns(&rec, "https://other.example", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
    assert_eq!(r.status, "failure");
}

#[tokio::test]
async fn validate_record_rejects_nonauthoritative_issuer() {
    // Config cert claims an issuer that is not the grantor domain's primary.
    let idp = KeyPair::generate();
    let disc = MockDiscoverer::new(idp.public_key()).with_primary("sandmill.org", idp.public_key());
    let rec = connection_record("evil.example", "danmills@sandmill.org", "https://gate.dan.dev/notes", &idp, 168);
    let cache = RwLock::new(HashMap::new());
    let r = validate_record_with_dns(&rec, "https://gate.dan.dev/notes", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
    assert_eq!(r.status, "failure", "{:?}", r);
}

#[tokio::test]
async fn validate_record_status_is_fail_closed() {
    let idp = KeyPair::generate();
    let disc = MockDiscoverer::new(idp.public_key()).with_primary("sandmill.org", idp.public_key());
    let rec = connection_record("sandmill.org", "danmills@sandmill.org", "https://gate.dan.dev/notes", &idp, 168);

    // Revoked bit set → reject.
    fn revoked_168(idx: u64) -> Result<bool, String> { Ok(idx == 168) }
    let cache = RwLock::new(HashMap::new());
    let r = validate_record_with_dns(&rec, "https://gate.dan.dev/notes", &disc, &[BROKER.to_string()], status_ctx!(&cache, &revoked_168)).await;
    assert_eq!(r.status, "failure");
    assert!(r.reason.as_deref().unwrap_or("").contains("revoked"), "{:?}", r.reason);

    // Uncheckable status → reject (cannot prove unrevoked).
    fn broken(_idx: u64) -> Result<bool, String> { Err("store down".into()) }
    let cache = RwLock::new(HashMap::new());
    let r = validate_record_with_dns(&rec, "https://gate.dan.dev/notes", &disc, &[BROKER.to_string()], status_ctx!(&cache, &broken)).await;
    assert_eq!(r.status, "failure");
    assert!(r.reason.as_deref().unwrap_or("").contains("fail-closed"), "{:?}", r.reason);
}

#[tokio::test]
async fn validate_record_accepts_v1_as_holder_binding() {
    // A v1 warrant (status optional) admits as a holder-binding record.
    let idp = KeyPair::generate();
    let disc = MockDiscoverer::new(idp.public_key()).with_primary("sandmill.org", idp.public_key());
    let config_key = KeyPair::generate();
    let config_cert = DeviceCert::create(
        "sandmill.org", &config_key.public_key(), Purpose::Authorization,
        Holder::new("br1a2b3c.main").unwrap(), vec!["danmills@sandmill.org".to_string()],
        Duration::days(90), &idp, None,
    ).unwrap();
    let warrant = DWarrant::create(
        "danmills@sandmill.org", "danmills@sandmill.org", HolderMatcher::new("*").unwrap(),
        "https://gate.dan.dev/notes", vec!["login".into()], Duration::days(90), &config_key, None,
    ).unwrap();
    let rec = format!("{}~{}", warrant.encoded(), config_cert.encoded());
    let cache = RwLock::new(HashMap::new());
    let r = validate_record_with_dns(&rec, "https://gate.dan.dev/notes", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
    assert_eq!(r.status, "okay", "{:?}", r);
    assert!(matches!(r.binding.as_ref().map(|b| b.entries()), Some([Binding::Holder { .. }])), "{:?}", r.binding);
}

#[tokio::test]
async fn validate_record_rejects_garbage_shapes() {
    let idp = KeyPair::generate();
    let disc = MockDiscoverer::new(idp.public_key()).with_primary("sandmill.org", idp.public_key());
    let cache = RwLock::new(HashMap::new());
    for bad in ["", "one-object", "a~b~c"] {
        let r = validate_record_with_dns(bad, "https://gate.dan.dev/notes", &disc, &[BROKER.to_string()], status_ctx!(&cache, &never_revoked)).await;
        assert_eq!(r.status, "failure", "shape '{bad}' must reject");
    }
}
