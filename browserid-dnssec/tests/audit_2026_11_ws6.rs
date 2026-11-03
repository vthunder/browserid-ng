//! Security audit 2026-11, WS6 — DNSSEC fail-closed (threat-model B1,
//! spec §3; WS1 candidate D14).
//!
//! Spec §3: an AD-unset ANSWER means "not a primary → fallback". A transport
//! failure is not an answer: it carries no DNSSEC signal, and reading it as
//! `Insecure` lets a network attacker who can merely block port 853 demote
//! every primary domain to the fallback path.
//!
//! Report: docs/security-audit-2026-11-ws6-core-verifier.md.
//!
//! The resolver here is a loopback port nothing listens on: every attempt
//! fails at TCP connect, so the one-retry budget (D14, Q2 (b)) is exercised
//! without any network.

use browserid_core::DnssecStatus;
use browserid_dnssec::DnsFetcher;

/// A resolver nothing listens on: the TLS connect fails immediately
/// (connection refused on loopback). No DNS answer is ever received.
fn dead_resolver() -> DnsFetcher {
    DnsFetcher::with_resolver("127.0.0.1:1", "dns.google").unwrap()
}

#[tokio::test]
async fn d14_transport_failure_is_not_an_insecure_answer() {
    let r = dead_resolver().lookup("sandmill.org").await;
    assert_ne!(
        r.dnssec_status,
        DnssecStatus::Insecure,
        "a DoT transport failure must hard-reject (Bogus or an error), never demote the domain to fallback"
    );
    assert!(r.record.is_none());
}

/// The same demotion through the verifier-facing resolver: `resolve_idp_key`
/// must not report `NotPrimary` (the fallback signal) when no answer arrived.
#[tokio::test]
async fn d14_resolve_idp_key_does_not_report_not_primary_on_transport_failure() {
    let r = browserid_dnssec::resolve_idp_key(&dead_resolver(), "sandmill.org").await;
    assert!(
        matches!(r, Err(browserid_dnssec::ResolveError::Bogus)),
        "expected a hard reject, got {r:?}"
    );
}

/// The retry is bounded: two connect-refused attempts complete well inside
/// the 2 s budget plus one query timeout — the lookup must not stall.
#[tokio::test]
async fn d14_retry_once_within_budget_then_reject() {
    let started = std::time::Instant::now();
    let r = dead_resolver().lookup("sandmill.org").await;
    assert_eq!(r.dnssec_status, DnssecStatus::Bogus);
    assert!(
        started.elapsed() < browserid_dnssec::dns::TRANSPORT_RETRY_BUDGET + std::time::Duration::from_secs(6),
        "lookup took {:?}", started.elapsed()
    );
}
