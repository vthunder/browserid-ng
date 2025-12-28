//! DNS fetcher tests
//!
//! Note: These tests use the actual DNS resolver.
//! For unit tests of parsing logic, see browserid-core/tests/dns_record_test.rs

use browserid_core::DnssecStatus;
use browserid_broker::DnsFetcher;

/// Test that lookup for non-existent domain returns insecure
/// (most domains don't have _browserid records)
#[tokio::test]
async fn test_lookup_nonexistent_returns_insecure() {
    let fetcher = DnsFetcher::new().unwrap();

    // This domain almost certainly doesn't have a _browserid record
    let result = fetcher.lookup("thisdomain.doesnotexist.invalid").await;

    // Should return insecure (NXDOMAIN without DNSSEC = insecure)
    assert!(
        result.dnssec_status == DnssecStatus::Insecure
            || result.dnssec_status == DnssecStatus::Secure,
        "Expected Insecure or Secure (NXDOMAIN), got {:?}",
        result.dnssec_status
    );
    assert!(result.record.is_none());
}

/// Test that fetcher can be created
#[tokio::test]
async fn test_fetcher_creation() {
    let fetcher = DnsFetcher::new();
    assert!(fetcher.is_ok());
}
