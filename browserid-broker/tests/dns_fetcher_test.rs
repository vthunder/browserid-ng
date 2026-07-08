//! DNS fetcher tests
//!
//! Note: Some of these tests use the actual DNS-over-TLS resolver.
//! For unit tests of the response classification logic, see the module tests
//! in src/dns_fetcher.rs; for record parsing, see
//! browserid-core/tests/dns_record_test.rs

use browserid_broker::DnsFetcher;
use browserid_core::DnssecStatus;
use tokio::io::AsyncWriteExt;

/// Test that lookup for non-existent domain returns insecure or secure
/// (depending on whether the NXDOMAIN response is DNSSEC-validated)
#[tokio::test]
async fn test_lookup_nonexistent_returns_valid_status() {
    let fetcher = DnsFetcher::new().unwrap();

    // This domain almost certainly doesn't have a _browserid record
    let result = fetcher.lookup("thisdomain.doesnotexist.invalid").await;

    // Should return insecure (NXDOMAIN without DNSSEC = insecure)
    // or secure (if the resolver validates the NXDOMAIN via DNSSEC)
    assert!(
        result.dnssec_status == DnssecStatus::Insecure
            || result.dnssec_status == DnssecStatus::Secure,
        "Expected Insecure or Secure (NXDOMAIN), got {:?}",
        result.dnssec_status
    );
    assert!(result.record.is_none());
}

/// Test that fetcher can be created with default resolver
#[tokio::test]
async fn test_fetcher_creation() {
    let fetcher = DnsFetcher::new();
    assert!(fetcher.is_ok());
}

/// Test that fetcher can be created with custom DoT resolver
#[tokio::test]
async fn test_custom_resolver_creation() {
    // Cloudflare DNS-over-TLS
    let fetcher = DnsFetcher::with_resolver("1.1.1.1:853", "cloudflare-dns.com");
    assert!(fetcher.is_ok());
}

/// Test that invalid resolver address is rejected
#[test]
fn test_invalid_resolver_address() {
    let fetcher = DnsFetcher::with_resolver("not-an-address", "dns.example");
    assert!(fetcher.is_err());
}

/// Test looking up a domain that likely has DNSSEC (e.g., cloudflare.com)
/// This tests that the AD flag can be detected
#[tokio::test]
async fn test_lookup_dnssec_enabled_domain() {
    let fetcher = DnsFetcher::new().unwrap();

    // cloudflare.com has DNSSEC enabled, so lookups should get AD=true
    // However, they don't have _browserid records, so we expect no record
    let result = fetcher.lookup("cloudflare.com").await;

    // We don't assert on the DNSSEC status here because it depends on
    // the resolver's validation capabilities and network conditions.
    // Just verify we get a valid response.
    assert!(result.record.is_none()); // No _browserid record expected
    println!("cloudflare.com DNSSEC status: {:?}", result.dnssec_status);
}

/// Regression test for the forged-AD attack: a resolver that speaks plain DNS
/// (no TLS) and sets AD=1 must NOT be trusted as Secure. Before the
/// DNS-over-TLS fix, the fetcher sent plaintext UDP and trusted the AD bit,
/// so any on-path attacker could claim DNSSEC validation. Now the TLS
/// handshake fails against a non-TLS server and the lookup degrades to
/// Insecure (broker fallback) — never Secure.
#[tokio::test]
async fn test_forged_ad_over_plaintext_is_not_secure() {
    // A fake "resolver" that accepts TCP and immediately writes a plaintext
    // DNS response with AD=1. It cannot complete a TLS handshake.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            // Length-prefixed (TCP DNS framing) garbage claiming AD=1.
            // Header: id=0, QR=1, AD=1, rcode=0, no records.
            let response: [u8; 12] = [0, 0, 0x80, 0x20, 0, 0, 0, 0, 0, 0, 0, 0];
            let mut framed = vec![0u8, 12];
            framed.extend_from_slice(&response);
            let _ = socket.write_all(&framed).await;
        }
    });

    let fetcher = DnsFetcher::with_resolver(&addr.to_string(), "dns.google").unwrap();
    let result = fetcher.lookup("victim.example").await;

    assert_eq!(
        result.dnssec_status,
        DnssecStatus::Insecure,
        "plaintext server forging AD=1 must not produce Secure"
    );
    assert!(result.record.is_none());
}
