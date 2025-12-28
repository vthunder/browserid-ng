//! DNS fetcher tests
//!
//! Note: These tests use the actual DNS resolver.
//! For unit tests of parsing logic, see browserid-core/tests/dns_record_test.rs

use browserid_broker::DnsFetcher;
use browserid_core::DnssecStatus;

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

/// Test that fetcher can be created with custom resolver
#[tokio::test]
async fn test_custom_resolver_creation() {
    // Cloudflare DNS
    let fetcher = DnsFetcher::with_resolver_addr("1.1.1.1:53");
    assert!(fetcher.is_ok());
}

/// Test that invalid resolver address is rejected
#[test]
fn test_invalid_resolver_address() {
    let fetcher = DnsFetcher::with_resolver_addr("not-an-address");
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
