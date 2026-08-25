//! Moved to the shared `browserid-verifier` crate (bean kozn) so the hosted
//! `/verify` endpoint and in-process RP verification (`browserid-rp`) run the
//! SAME algorithm. This shim keeps the broker's `crate::verifier::*` paths
//! stable.

pub use browserid_verifier::verify::*;
