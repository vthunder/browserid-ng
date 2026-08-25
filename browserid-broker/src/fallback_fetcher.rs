//! Moved to the shared `browserid-verifier` crate (bean kozn). This shim keeps
//! the broker's `crate::fallback_fetcher::*` paths stable.

pub use browserid_verifier::discovery::{Discoverer, FallbackFetcher, FallbackResult};
