//! DNSSEC `_browserid` discovery.
//!
//! Moved to the shared `browserid-dnssec` crate so every verifier roots trust
//! the same way (bean 0p5f). Re-exported here to keep the broker's internal
//! `crate::dns_fetcher::DnsFetcher` paths stable.

pub use browserid_dnssec::DnsFetcher;
