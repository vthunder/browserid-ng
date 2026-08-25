//! The ONE BrowserID-NG verification implementation (bean kozn).
//!
//! Extracted from `browserid-broker` so the hosted `/verify` endpoint and
//! in-process RP verification (`browserid-rp`) run the SAME algorithm:
//! DNSSEC-rooted discovery (primary / trusted-fallback conformance, hosted
//! primaries via the record's `host=`), the four-object presentation join,
//! two-object record validation, and fail-closed revocation status — own-list
//! checks via a caller hook, foreign lists by authenticated, SSRF-guarded
//! fetch.

pub mod discovery;
pub mod error;
pub mod verify;

pub use discovery::{Discoverer, FallbackFetcher, FallbackResult};
pub use error::VerifierError;
pub use verify::{
    check_foreign_status_fresh, fetch_foreign_status_list, resolve_conformant_key,
    validate_record_with_dns, verify_access_with_dns, AccessVerificationResult, HttpFetcher,
    RecordValidationResult, StatusCtx,
};
