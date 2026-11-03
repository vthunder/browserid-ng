//! Security audit 2026-11, WS6 — regression tests for the hosted verifier
//! (`verify_access_with_dns`, `validate_record_with_dns`,
//! `resolve_conformant_key`): threat-model I3, I9; WS1 candidate D7.
//!
//! Discovery is mocked (no DNS, no HTTP); status refs point at the "own"
//! list so revocation resolves locally. `#[ignore]`d tests with an
//! `AUDIT-2026-11` comment fail today and are the acceptance test for the fix.
//!
//! Report: docs/security-audit-2026-11-ws6-core-verifier.md.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use browserid_core::device::{
    AccessCert, AccessCertClaims, Binding, DeviceCert, DeviceCertClaims, HolderMatcher, Warrant,
    WarrantClaims, TYP_ACCESS_CERT, TYP_DEVICE_CERT, TYP_WARRANT_V2,
};
use browserid_core::discovery::SupportDocument;
use browserid_core::{
    Assertion, Cap, Holder, KeyPair, PublicKey, Purpose, ScopeEntry, ScopeParams, StatusList,
    StatusListToken, StatusRef,
};
use browserid_verifier::{
    validate_record_with_dns, verify_access_with_dns, Discoverer, FallbackResult, StatusCtx,
    VerifierError,
};
use serde_json::json;

const AUD: &str = "https://rp.example";
const OWN_LIST: &str = "https://browserid.me/.well-known/browserid-status";
const DAY: i64 = 86_400;

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}
fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(&[seed; 32]).unwrap()
}
fn own(idx: u64) -> Option<StatusRef> {
    Some(StatusRef { uri: OWN_LIST.into(), idx })
}
/// The status list a cert issued by `host` must point at (§6.3: the cert's
/// `iss`, or the `host=` it delegates to).
fn list_uri(host: &str) -> String {
    format!("https://{host}/.well-known/browserid-status")
}

/// Scripted discovery: `domain → (key, is_primary)`. A no-primary domain
/// resolves to the fallback `browserid.me`'s key, as `FallbackFetcher` does.
/// `delegates` is a primary's DNSSEC `host=` (a hosted primary's provider).
struct Mock {
    primaries: HashMap<String, PublicKey>,
    fallback: (String, PublicKey),
    delegates: HashMap<String, String>,
}

impl Mock {
    fn lookup(&self, domain: &str) -> Result<FallbackResult, VerifierError> {
        let doc = |k: &PublicKey| -> SupportDocument {
            serde_json::from_value(json!({ "public-key": serde_json::to_value(k).unwrap() })).unwrap()
        };
        if let Some(k) = self.primaries.get(domain) {
            return Ok(FallbackResult {
                document: doc(k),
                authoritative_domain: domain.to_string(),
                is_primary: true,
                serving_host: self.delegates.get(domain).cloned(),
            });
        }
        Ok(FallbackResult {
            document: doc(&self.fallback.1),
            authoritative_domain: self.fallback.0.clone(),
            is_primary: false,
            serving_host: None,
        })
    }
}

impl Discoverer for Mock {
    fn discover(
        &self,
        domain: &str,
    ) -> impl std::future::Future<Output = Result<FallbackResult, VerifierError>> + Send {
        let r = self.lookup(domain);
        async move { r }
    }
}

struct Status {
    cache: RwLock<HashMap<String, StatusListToken>>,
}
impl Status {
    fn new() -> Self {
        Self { cache: RwLock::new(HashMap::new()) }
    }
    /// Pre-verify `iss`'s (empty) status list into the cache, as the hosted
    /// verifier would after one authenticated fetch — so a primary-issued
    /// cert's own-issuer ref resolves without touching the network.
    fn seed(&self, iss: &str, key: &KeyPair) -> &Self {
        let uri = list_uri(iss);
        let tok = StatusListToken::create(iss, &uri, &StatusList::from_revoked([], 1024), key).unwrap();
        self.cache.write().unwrap().insert(uri, tok);
        self
    }
    fn ctx(&self) -> StatusCtx<'_> {
        StatusCtx {
            own_uri: OWN_LIST.into(),
            is_own_revoked: &|_| Ok(false),
            cache: &self.cache,
            allow_private_hosts: false,
        }
    }
}

/// One identity's half of a bundle: who it is, which issuer signs for it.
struct Party<'a> {
    email: &'a str,
    iss: &'a str,
    idp: &'a KeyPair,
}

/// Build `access_cert~assertion~warrant~config_cert` where `grantee` mints
/// the access cert and `grantor` signs the warrant under its config cert.
/// Each cert's status ref points at its own issuer's list (§6.3) unless
/// `access_uri` overrides the access cert's; the warrant's ref is on the
/// registry's (own) list.
fn bundle(grantee: &Party, grantor: &Party, scopes: Vec<ScopeEntry>, access_uri: Option<&str>) -> String {
    let access_uri = access_uri.map(str::to_string).unwrap_or_else(|| list_uri(grantee.iss));
    bundle_with(grantee, grantor, scopes, &access_uri, &list_uri(grantor.iss))
}

fn bundle_with(grantee: &Party, grantor: &Party, scopes: Vec<ScopeEntry>, access_uri: &str, config_uri: &str) -> String {
    let t = now();
    let access_key = key(3);
    let config_key = key(4);
    let access = AccessCert::from_claims(
        AccessCertClaims {
            typ: TYP_ACCESS_CERT.into(),
            iss: grantee.iss.into(),
            iat: t - 60,
            exp: t + DAY,
            identity: grantee.email.into(),
            holder: Holder::new("br.main").unwrap(),
            access_key: access_key.public_key(),
            status: Some(StatusRef { uri: access_uri.into(), idx: 7 }),
            constraints: None,
        },
        grantee.idp,
    )
    .unwrap();
    let config = DeviceCert::from_claims(
        DeviceCertClaims {
            typ: TYP_DEVICE_CERT.into(),
            iss: grantor.iss.into(),
            iat: t - 60,
            exp: t + 90 * DAY,
            purpose: Purpose::Authorization,
            holder: Holder::new("br.main").unwrap(),
            identities: vec![grantor.email.into()],
            public_key: config_key.public_key(),
            status: Some(StatusRef { uri: config_uri.into(), idx: 2 }),
            managed: None,
            constraints: None,
            prov: None,
        },
        grantor.idp,
    )
    .unwrap();
    let warrant = Warrant::from_claims(
        WarrantClaims {
            typ: TYP_WARRANT_V2.into(),
            iat: t - 60,
            exp: t + 90 * DAY,
            grantor: grantor.email.into(),
            grantee: grantee.email.into(),
            holder: None,
            binding: Some(Binding::Holder { matcher: HolderMatcher::new("br.*").unwrap() }.into()),
            audience: AUD.into(),
            scopes,
            status: own(42),
            unknown: Default::default(),
        },
        &config_key,
    )
    .unwrap();
    let assertion = Assertion::create(AUD, chrono::Duration::minutes(5), &access_key).unwrap();
    format!("{}~{}~{}~{}", access.encoded(), assertion.encoded(), warrant.encoded(), config.encoded())
}

fn pay_scope() -> ScopeEntry {
    ScopeEntry::Parameterized(ScopeParams {
        scope: "pay:usd".into(),
        mode: None,
        cap: Some(Cap { amount: "20.00".into(), currency: "USD".into(), window: Some("P1D".into()) }),
        counterparties: None,
        max_duration: None,
        min_reputation: None,
    })
}

// ---------------------------------------------------------------------------
// Sanity.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn primary_issued_bundle_verifies() {
    let idp = key(1);
    let disc = Mock { primaries: HashMap::from([("example.com".into(), idp.public_key())]), fallback: ("browserid.me".into(), key(2).public_key()), delegates: HashMap::new() };
    let alice = Party { email: "alice@example.com", iss: "example.com", idp: &idp };
    let st = Status::new();
    st.seed("example.com", &idp);
    let r = verify_access_with_dns(&bundle(&alice, &alice, vec![], None), AUD, &disc, &[], st.ctx()).await;
    assert_eq!(r.status, "okay", "{:?}", r.reason);
    assert_eq!(r.email.as_deref(), Some("alice@example.com"));
}

// ---------------------------------------------------------------------------
// D7 — scope parameters are dropped at the HTTP boundary.
// ---------------------------------------------------------------------------

/// S7's relay rule: a verifier returns scope entries verbatim — the `cap` on
/// a `pay:` entry must reach the SDK consumer through the hosted `/verify`
/// response (audit 2026-11 D7, fixed: `scopes` is `Vec<ScopeEntry>`).
#[tokio::test]
async fn d7_verify_response_carries_scope_parameters() {
    let idp = key(1);
    let disc = Mock { primaries: HashMap::from([("example.com".into(), idp.public_key())]), fallback: ("browserid.me".into(), key(2).public_key()), delegates: HashMap::new() };
    let alice = Party { email: "alice@example.com", iss: "example.com", idp: &idp };
    let st = Status::new();
    st.seed("example.com", &idp);
    let r = verify_access_with_dns(&bundle(&alice, &alice, vec![pay_scope()], None), AUD, &disc, &[], st.ctx()).await;
    assert_eq!(r.status, "okay", "{:?}", r.reason);
    let out = serde_json::to_value(&r).unwrap();
    assert_eq!(
        out["scopes"][0]["cap"]["amount"], json!("20.00"),
        "cap must survive the hosted verifier; got {}", out["scopes"]
    );
}

#[tokio::test]
async fn d7_validate_record_response_carries_scope_parameters() {
    let idp = key(1);
    let disc = Mock { primaries: HashMap::from([("example.com".into(), idp.public_key())]), fallback: ("browserid.me".into(), key(2).public_key()), delegates: HashMap::new() };
    let alice = Party { email: "alice@example.com", iss: "example.com", idp: &idp };
    let full = bundle(&alice, &alice, vec![pay_scope()], None);
    let parts: Vec<&str> = full.split('~').collect();
    let record = format!("{}~{}", parts[2], parts[3]);
    let st = Status::new();
    st.seed("example.com", &idp);
    let r = validate_record_with_dns(&record, AUD, &disc, &[], st.ctx()).await;
    assert_eq!(r.status, "okay", "{:?}", r.reason);
    let out = serde_json::to_value(&r).unwrap();
    assert_eq!(out["scopes"][0]["cap"]["amount"], json!("20.00"), "got {}", out["scopes"]);
}

// ---------------------------------------------------------------------------
// I3 — per-identity issuer authority, grantee and grantor independently.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn i3_fallback_issued_cert_for_a_primary_domain_rejects() {
    let primary = key(1);
    let fallback = key(2);
    let disc = Mock { primaries: HashMap::from([("example.com".into(), primary.public_key())]), fallback: ("browserid.me".into(), fallback.public_key()), delegates: HashMap::new() };
    // browserid.me (an accepted fallback) vouches for alice@example.com, which has a primary.
    let alice_via_fallback = Party { email: "alice@example.com", iss: "browserid.me", idp: &fallback };
    let st = Status::new();
    let r = verify_access_with_dns(&bundle(&alice_via_fallback, &alice_via_fallback, vec![], None), AUD, &disc, &["browserid.me".into()], st.ctx()).await;
    assert_eq!(r.status, "failure");
    assert!(r.reason.unwrap().contains("not authorized for primary domain"));
}

#[tokio::test]
async fn i3_issuer_outside_the_accepted_set_rejects() {
    let fallback = key(2);
    let disc = Mock { primaries: HashMap::new(), fallback: ("browserid.me".into(), fallback.public_key()), delegates: HashMap::new() };
    let bob = Party { email: "bob@noprimary.example", iss: "browserid.me", idp: &fallback };
    let st = Status::new();
    // Empty accepted set: primaries only.
    let r = verify_access_with_dns(&bundle(&bob, &bob, vec![], None), AUD, &disc, &[], st.ctx()).await;
    assert_eq!(r.status, "failure");
    assert!(r.reason.unwrap().contains("not an accepted fallback"));
    // Accepting it flips the verdict.
    let r = verify_access_with_dns(&bundle(&bob, &bob, vec![], None), AUD, &disc, &["browserid.me".into()], st.ctx()).await;
    assert_eq!(r.status, "okay", "{:?}", r.reason);
}

#[tokio::test]
async fn i3_grantor_and_grantee_issuers_are_checked_independently() {
    let a_idp = key(1);
    let b_idp = key(5);
    let disc = Mock {
        primaries: HashMap::from([("a.example".into(), a_idp.public_key()), ("b.example".into(), b_idp.public_key())]),
        fallback: ("browserid.me".into(), key(2).public_key()),
        delegates: HashMap::new(),
    };
    let agent = Party { email: "agent@a.example", iss: "a.example", idp: &a_idp };
    let st = Status::new();
    st.seed("a.example", &a_idp).seed("b.example", &b_idp);

    // Honest cross-issuer delegation: b.example's primary signs the grantor's config cert.
    let owner = Party { email: "owner@b.example", iss: "b.example", idp: &b_idp };
    let r = verify_access_with_dns(&bundle(&agent, &owner, vec![], None), AUD, &disc, &[], st.ctx()).await;
    assert_eq!(r.status, "okay", "{:?}", r.reason);
    assert_eq!(r.email.as_deref(), Some("owner@b.example"));
    assert_eq!(r.grantee.as_deref(), Some("agent@a.example"));

    // a.example's primary tries to vouch for a b.example grantor: the config
    // cert signature is fine under a.example's key, but a.example is not
    // authoritative for b.example.
    let forged_owner = Party { email: "owner@b.example", iss: "a.example", idp: &a_idp };
    let r = verify_access_with_dns(&bundle(&agent, &forged_owner, vec![], None), AUD, &disc, &[], st.ctx()).await;
    assert_eq!(r.status, "failure");
    assert!(r.reason.unwrap().contains("not authorized for primary domain 'b.example'"));
}

// ---------------------------------------------------------------------------
// I9 — status: fail-closed, no private hosts, signer must answer for the host.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn i9_uncheckable_own_status_rejects() {
    // A broker-issued (fallback) identity: its certs legitimately point at
    // the broker's own list (§6.3 — the list host is the cert's `iss`).
    let fallback = key(2);
    let disc = Mock { primaries: HashMap::new(), fallback: ("browserid.me".into(), fallback.public_key()), delegates: HashMap::new() };
    let bob = Party { email: "bob@noprimary.example", iss: "browserid.me", idp: &fallback };
    let cache = RwLock::new(HashMap::new());
    let ctx = StatusCtx { own_uri: OWN_LIST.into(), is_own_revoked: &|_| Err("db down".into()), cache: &cache, allow_private_hosts: false };
    let r = verify_access_with_dns(&bundle(&bob, &bob, vec![], None), AUD, &disc, &["browserid.me".into()], ctx).await;
    assert_eq!(r.status, "failure");
    assert!(r.reason.unwrap().contains("fail-closed"));
}

#[tokio::test]
async fn i9_foreign_status_on_a_private_or_plain_http_host_is_never_fetched() {
    let idp = key(1);
    let disc = Mock { primaries: HashMap::from([("example.com".into(), idp.public_key())]), fallback: ("browserid.me".into(), key(2).public_key()), delegates: HashMap::new() };
    let alice = Party { email: "alice@example.com", iss: "example.com", idp: &idp };
    for uri in ["https://127.0.0.1:1/list", "http://example.com/list", "https://169.254.169.254/latest/meta-data", "https://[::1]/list"] {
        let st = Status::new();
        let r = verify_access_with_dns(&bundle(&alice, &alice, vec![], Some(uri)), AUD, &disc, &[], st.ctx()).await;
        assert_eq!(r.status, "failure", "{uri}");
        let reason = r.reason.unwrap();
        // Since W6-4 the host != iss rule rejects these before the SSRF
        // guard is reached; either way no request may be made.
        assert!(
            reason.contains("status unavailable (fail-closed)") || reason.contains("status.uri host is not its issuer"),
            "{uri}: {reason}"
        );
        assert!(!reason.contains("fetch "), "{uri}: the guard must trip before any request: {reason}");
    }
}

/// The SSRF guard itself (audit H1), pinned directly now that the W6-4 host
/// rule rejects a cross-host ref before the guard runs.
#[tokio::test]
async fn i9_status_url_guard_refuses_private_and_plain_http() {
    for uri in ["https://127.0.0.1:1/list", "http://example.com/list", "https://169.254.169.254/latest/meta-data", "https://[::1]/list", "https://10.0.0.8/list", "https://[fd00::1]/list"] {
        assert!(browserid_verifier::verify::validate_status_url(uri, false).await.is_err(), "{uri}");
    }
}

// ---------------------------------------------------------------------------
// W6-4 — §6.3 (2026-11 text): a CERT's `status.uri` host MUST equal its `iss`.
// ---------------------------------------------------------------------------

/// The hosted verifier binds a LIST's `iss` to the URI host; it must also
/// bind a CERT's `status.uri` host to the cert's own `iss`. Here a primary's
/// access and config certs point at the broker's own list (`browserid.me`),
/// which the own-list shortcut would answer locally — the bundle must not
/// verify, and neither must the record on its own.
#[tokio::test]
async fn w6_4_cert_status_uri_host_must_equal_cert_iss() {
    let idp = key(1);
    let disc = Mock { primaries: HashMap::from([("example.com".into(), idp.public_key())]), fallback: ("browserid.me".into(), key(2).public_key()), delegates: HashMap::new() };
    let alice = Party { email: "alice@example.com", iss: "example.com", idp: &idp };
    let st = Status::new();
    st.seed("example.com", &idp);

    // Access cert on the broker's list, config cert on its own issuer's.
    let r = verify_access_with_dns(&bundle_with(&alice, &alice, vec![], OWN_LIST, &list_uri("example.com")), AUD, &disc, &[], st.ctx()).await;
    assert_eq!(r.status, "failure", "example.com's access cert must not point at browserid.me's list");
    assert!(r.reason.as_deref().unwrap().contains("access cert status.uri host is not its issuer 'example.com'"), "{:?}", r.reason);

    // Config cert on the broker's list.
    let full = bundle_with(&alice, &alice, vec![], &list_uri("example.com"), OWN_LIST);
    let r = verify_access_with_dns(&full, AUD, &disc, &[], st.ctx()).await;
    assert_eq!(r.status, "failure");
    assert!(r.reason.as_deref().unwrap().contains("config cert status.uri host is not its issuer 'example.com'"), "{:?}", r.reason);

    // …and the same config cert held as a record (operation A).
    let parts: Vec<&str> = full.split('~').collect();
    let r = validate_record_with_dns(&format!("{}~{}", parts[2], parts[3]), AUD, &disc, &[], st.ctx()).await;
    assert_eq!(r.status, "failure");
    assert!(r.reason.as_deref().unwrap().contains("config cert status.uri host is not its issuer 'example.com'"), "{:?}", r.reason);

    // Any other third-party host is equally refused, even with a verified
    // list for it in the cache.
    st.seed("other.example", &key(9));
    let r = verify_access_with_dns(&bundle(&alice, &alice, vec![], Some(&list_uri("other.example"))), AUD, &disc, &[], st.ctx()).await;
    assert_eq!(r.status, "failure");
    assert!(r.reason.as_deref().unwrap().contains("status.uri host is not its issuer"), "{:?}", r.reason);
}

/// A hosted primary (`host=` in its DNSSEC record) publishes no list at its
/// own domain: its certs may point at the delegate host's list, and only
/// that one (§6.3).
#[tokio::test]
async fn w6_4_hosted_primary_may_point_at_its_dnssec_delegate() {
    let tenant_key = key(1);
    let provider_key = key(6);
    let disc = Mock {
        primaries: HashMap::from([("tenant.example".into(), tenant_key.public_key()), ("idp.provider.example".into(), provider_key.public_key())]),
        fallback: ("browserid.me".into(), key(2).public_key()),
        delegates: HashMap::from([("tenant.example".into(), "idp.provider.example".into())]),
    };
    let alice = Party { email: "alice@tenant.example", iss: "tenant.example", idp: &tenant_key };
    let st = Status::new();
    st.seed("idp.provider.example", &provider_key);
    let on_delegate = list_uri("idp.provider.example");
    let r = verify_access_with_dns(&bundle_with(&alice, &alice, vec![], &on_delegate, &on_delegate), AUD, &disc, &[], st.ctx()).await;
    assert_eq!(r.status, "okay", "{:?}", r.reason);

    // The delegation is per issuer: a different provider's list is refused.
    st.seed("idp.other.example", &key(7));
    let elsewhere = list_uri("idp.other.example");
    let r = verify_access_with_dns(&bundle_with(&alice, &alice, vec![], &elsewhere, &on_delegate), AUD, &disc, &[], st.ctx()).await;
    assert_eq!(r.status, "failure");
    assert!(r.reason.as_deref().unwrap().contains("status.uri host is not its issuer 'tenant.example'"), "{:?}", r.reason);
}

// ---------------------------------------------------------------------------
// W6-5 (WS5 W5-5) — the `.well-known` discovery fetch lacks the H1 guard.
// ---------------------------------------------------------------------------

/// `HttpFetcher` (used by `resolve_with_dnssec_key` on every verification of
/// a primary-issued bundle) is a default `reqwest::blocking` client: it
/// follows redirects, does no post-resolution address check, and reads the
/// body uncapped. The target host is the DNS `host=` value, which an
/// attacker who runs a DNSSEC-signed domain chooses. Here a loopback server
/// redirects to a second loopback server, and the fetch returns its JSON.
/// (`allow_http()` is needed to reach loopback without TLS; the production
/// `new()` client shares the redirect policy and address handling, so an
/// `https` first hop redirecting to `http://169.254.169.254/…` is followed.)
#[test]
#[ignore] // AUDIT-2026-11 W6-5: fails today — discovery.rs:15-27,193-202 / verify.rs:25-47 use an unguarded client
fn w6_5_discovery_fetch_refuses_redirects_and_private_hosts() {
    use browserid_core::discovery::SupportDocumentFetcher;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // Accept forever: the fetcher tries https first (a TLS handshake this
    // plain server answers with garbage), then falls back to http.
    fn serve(listener: TcpListener, make: impl Fn() -> String + Send + 'static) {
        std::thread::spawn(move || {
            for sock in listener.incoming() {
                let Ok(mut sock) = sock else { break };
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(make().as_bytes());
            }
        });
    }
    let hop = TcpListener::bind("127.0.0.1:0").unwrap();
    let hop_addr = hop.local_addr().unwrap();
    serve(hop, || {
        let body = r#"{"authentication":"/pwned"}"#;
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    });
    let front = TcpListener::bind("127.0.0.1:0").unwrap();
    let front_addr = front.local_addr().unwrap();
    serve(front, move || {
        format!("HTTP/1.1 302 Found\r\nLocation: http://{hop_addr}/internal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    });

    let r = browserid_verifier::HttpFetcher::allow_http().fetch(&front_addr.to_string());
    assert!(
        r.is_err(),
        "discovery followed a redirect to another host and accepted its document: {:?}",
        r.map(|d| d.authentication)
    );
}
