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
    Assertion, Cap, Holder, KeyPair, PublicKey, Purpose, ScopeEntry, ScopeParams,
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

/// Scripted discovery: `domain → (key, is_primary)`. A no-primary domain
/// resolves to the fallback `browserid.me`'s key, as `FallbackFetcher` does.
struct Mock {
    primaries: HashMap<String, PublicKey>,
    fallback: (String, PublicKey),
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
                serving_host: None,
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
fn bundle(grantee: &Party, grantor: &Party, scopes: Vec<ScopeEntry>, status_uri: Option<&str>) -> String {
    let t = now();
    let access_key = key(3);
    let config_key = key(4);
    let sref = |idx: u64| status_uri.map(|u| StatusRef { uri: u.into(), idx }).or_else(|| own(idx));
    let access = AccessCert::from_claims(
        AccessCertClaims {
            typ: TYP_ACCESS_CERT.into(),
            iss: grantee.iss.into(),
            iat: t - 60,
            exp: t + DAY,
            identity: grantee.email.into(),
            holder: Holder::new("br.main").unwrap(),
            access_key: access_key.public_key(),
            status: sref(7),
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
            status: sref(2),
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
            status: sref(42),
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
    let disc = Mock { primaries: HashMap::from([("example.com".into(), idp.public_key())]), fallback: ("browserid.me".into(), key(2).public_key()) };
    let alice = Party { email: "alice@example.com", iss: "example.com", idp: &idp };
    let st = Status::new();
    let r = verify_access_with_dns(&bundle(&alice, &alice, vec![], None), AUD, &disc, &[], st.ctx()).await;
    assert_eq!(r.status, "okay", "{:?}", r.reason);
    assert_eq!(r.email.as_deref(), Some("alice@example.com"));
}

// ---------------------------------------------------------------------------
// D7 — scope parameters are dropped at the HTTP boundary.
// ---------------------------------------------------------------------------

/// S7's relay rule: a verifier returns scope entries verbatim. The hosted
/// `/verify` response carries `scopes: Vec<String>` only, so the `cap` on a
/// `pay:` entry never reaches an SDK consumer.
#[tokio::test]
#[ignore] // AUDIT-2026-11 D7: fails today — `AccessVerificationResult.scopes` is `Vec<String>` (verify.rs:122, :689)
async fn d7_verify_response_carries_scope_parameters() {
    let idp = key(1);
    let disc = Mock { primaries: HashMap::from([("example.com".into(), idp.public_key())]), fallback: ("browserid.me".into(), key(2).public_key()) };
    let alice = Party { email: "alice@example.com", iss: "example.com", idp: &idp };
    let st = Status::new();
    let r = verify_access_with_dns(&bundle(&alice, &alice, vec![pay_scope()], None), AUD, &disc, &[], st.ctx()).await;
    assert_eq!(r.status, "okay", "{:?}", r.reason);
    let out = serde_json::to_value(&r).unwrap();
    assert_eq!(
        out["scopes"][0]["cap"]["amount"], json!("20.00"),
        "cap must survive the hosted verifier; got {}", out["scopes"]
    );
}

#[tokio::test]
#[ignore] // AUDIT-2026-11 D7: fails today — `RecordValidationResult.scopes` is `Vec<String>` (verify.rs:487, :602)
async fn d7_validate_record_response_carries_scope_parameters() {
    let idp = key(1);
    let disc = Mock { primaries: HashMap::from([("example.com".into(), idp.public_key())]), fallback: ("browserid.me".into(), key(2).public_key()) };
    let alice = Party { email: "alice@example.com", iss: "example.com", idp: &idp };
    let full = bundle(&alice, &alice, vec![pay_scope()], None);
    let parts: Vec<&str> = full.split('~').collect();
    let record = format!("{}~{}", parts[2], parts[3]);
    let st = Status::new();
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
    let disc = Mock { primaries: HashMap::from([("example.com".into(), primary.public_key())]), fallback: ("browserid.me".into(), fallback.public_key()) };
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
    let disc = Mock { primaries: HashMap::new(), fallback: ("browserid.me".into(), fallback.public_key()) };
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
    };
    let agent = Party { email: "agent@a.example", iss: "a.example", idp: &a_idp };
    let st = Status::new();

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
    let idp = key(1);
    let disc = Mock { primaries: HashMap::from([("example.com".into(), idp.public_key())]), fallback: ("browserid.me".into(), key(2).public_key()) };
    let alice = Party { email: "alice@example.com", iss: "example.com", idp: &idp };
    let cache = RwLock::new(HashMap::new());
    let ctx = StatusCtx { own_uri: OWN_LIST.into(), is_own_revoked: &|_| Err("db down".into()), cache: &cache, allow_private_hosts: false };
    let r = verify_access_with_dns(&bundle(&alice, &alice, vec![], None), AUD, &disc, &[], ctx).await;
    assert_eq!(r.status, "failure");
    assert!(r.reason.unwrap().contains("fail-closed"));
}

#[tokio::test]
async fn i9_foreign_status_on_a_private_or_plain_http_host_is_never_fetched() {
    let idp = key(1);
    let disc = Mock { primaries: HashMap::from([("example.com".into(), idp.public_key())]), fallback: ("browserid.me".into(), key(2).public_key()) };
    let alice = Party { email: "alice@example.com", iss: "example.com", idp: &idp };
    for uri in ["https://127.0.0.1:1/list", "http://example.com/list", "https://169.254.169.254/latest/meta-data", "https://[::1]/list"] {
        let st = Status::new();
        let r = verify_access_with_dns(&bundle(&alice, &alice, vec![], Some(uri)), AUD, &disc, &[], st.ctx()).await;
        assert_eq!(r.status, "failure", "{uri}");
        let reason = r.reason.unwrap();
        assert!(reason.contains("status unavailable (fail-closed)"), "{uri}: {reason}");
        assert!(!reason.contains("fetch "), "{uri}: the guard must trip before any request: {reason}");
    }
}
