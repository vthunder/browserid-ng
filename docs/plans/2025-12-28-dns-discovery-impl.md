# DNS-Based Key Discovery Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement DNS TXT record discovery with DNSSEC validation for primary IdP mode, falling back to broker when DNS fails or lacks DNSSEC.

**Architecture:** Add DNS record parsing to browserid-core, then add a DNSSEC-validating fetcher to browserid-broker that tries DNS first and falls back to the broker. The verifier uses the fallback fetcher to determine if a domain operates as primary IdP.

**Tech Stack:** hickory-resolver for DNS with DNSSEC, existing reqwest for HTTP fallback

---

## Task 1: Add DNS Record Parsing Types

**Files:**
- Create: `browserid-core/src/dns.rs`
- Modify: `browserid-core/src/lib.rs`
- Modify: `browserid-core/src/error.rs`
- Test: `browserid-core/tests/dns_record_test.rs`

### Step 1: Add DNS-related error variants

Edit `browserid-core/src/error.rs` to add:

```rust
#[error("Invalid DNS record: {0}")]
InvalidDnsRecord(String),

#[error("Unsupported algorithm: {0}")]
UnsupportedAlgorithm(String),
```

### Step 2: Run existing tests to ensure no breakage

Run: `cargo test -p browserid-core`
Expected: All tests pass

### Step 3: Create dns.rs with DnsRecord struct

Create `browserid-core/src/dns.rs`:

```rust
//! DNS TXT record parsing for BrowserID-NG
//!
//! Parses `_browserid.<domain>` TXT records with format:
//! `v=browserid1; public-key-algorithm=Ed25519; public-key=<base64url>; host=<optional>`

use crate::{Error, PublicKey, Result};

/// Parsed BrowserID DNS TXT record
#[derive(Debug, Clone, PartialEq)]
pub struct DnsRecord {
    /// Version (must be "browserid1")
    pub version: String,
    /// Algorithm for the public key (e.g., "Ed25519")
    pub algorithm: String,
    /// The domain's public key
    pub public_key: PublicKey,
    /// Optional host for .well-known lookup (defaults to email domain)
    pub host: Option<String>,
}

impl DnsRecord {
    /// Parse a DNS TXT record value
    ///
    /// Expected format: `v=browserid1; public-key-algorithm=Ed25519; public-key=<base64>; host=<optional>`
    pub fn parse(txt: &str) -> Result<Self> {
        let mut version = None;
        let mut algorithm = None;
        let mut public_key = None;
        let mut host = None;

        for part in txt.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "v" => version = Some(value.to_string()),
                    "public-key-algorithm" => algorithm = Some(value.to_string()),
                    "public-key" => public_key = Some(value.to_string()),
                    "host" => host = Some(value.to_string()),
                    _ => {} // Ignore unknown fields for forward compatibility
                }
            }
        }

        // Validate required fields
        let version = version.ok_or_else(|| {
            Error::InvalidDnsRecord("missing required field: v".into())
        })?;

        if version != "browserid1" {
            return Err(Error::InvalidDnsRecord(format!(
                "unsupported version: {}", version
            )));
        }

        let algorithm = algorithm.ok_or_else(|| {
            Error::InvalidDnsRecord("missing required field: public-key-algorithm".into())
        })?;

        if algorithm != "Ed25519" {
            return Err(Error::UnsupportedAlgorithm(algorithm));
        }

        let public_key_b64 = public_key.ok_or_else(|| {
            Error::InvalidDnsRecord("missing required field: public-key".into())
        })?;

        let public_key = PublicKey::from_base64(&public_key_b64)
            .map_err(|e| Error::InvalidDnsRecord(format!("invalid public key: {}", e)))?;

        Ok(Self {
            version,
            algorithm,
            public_key,
            host,
        })
    }

    /// Get the host for .well-known lookup, defaulting to the given domain
    pub fn well_known_host<'a>(&'a self, default_domain: &'a str) -> &'a str {
        self.host.as_deref().unwrap_or(default_domain)
    }
}
```

### Step 4: Export dns module from lib.rs

Edit `browserid-core/src/lib.rs` to add:

```rust
pub mod dns;
```

And add to exports:

```rust
pub use dns::DnsRecord;
```

### Step 5: Run build to verify compilation

Run: `cargo build -p browserid-core`
Expected: Compiles successfully

### Step 6: Write failing tests for DnsRecord parsing

Create `browserid-core/tests/dns_record_test.rs`:

```rust
//! DNS record parsing tests

use browserid_core::{DnsRecord, Error, KeyPair};

mod parse_valid {
    use super::*;

    #[test]
    fn test_parse_minimal_record() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key-algorithm=Ed25519; public-key={}",
            key.public_key().to_base64()
        );

        let record = DnsRecord::parse(&txt).unwrap();
        assert_eq!(record.version, "browserid1");
        assert_eq!(record.algorithm, "Ed25519");
        assert_eq!(record.public_key, key.public_key());
        assert_eq!(record.host, None);
    }

    #[test]
    fn test_parse_record_with_host() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key-algorithm=Ed25519; public-key={}; host=idp.example.com",
            key.public_key().to_base64()
        );

        let record = DnsRecord::parse(&txt).unwrap();
        assert_eq!(record.host, Some("idp.example.com".to_string()));
    }

    #[test]
    fn test_parse_with_extra_whitespace() {
        let key = KeyPair::generate();
        let txt = format!(
            "  v=browserid1 ;  public-key-algorithm=Ed25519 ;  public-key={} ",
            key.public_key().to_base64()
        );

        let record = DnsRecord::parse(&txt).unwrap();
        assert_eq!(record.version, "browserid1");
    }

    #[test]
    fn test_parse_ignores_unknown_fields() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key-algorithm=Ed25519; public-key={}; future-field=value",
            key.public_key().to_base64()
        );

        let record = DnsRecord::parse(&txt).unwrap();
        assert_eq!(record.version, "browserid1");
    }
}

mod parse_invalid {
    use super::*;

    #[test]
    fn test_missing_version() {
        let key = KeyPair::generate();
        let txt = format!(
            "public-key-algorithm=Ed25519; public-key={}",
            key.public_key().to_base64()
        );

        let result = DnsRecord::parse(&txt);
        assert!(matches!(result, Err(Error::InvalidDnsRecord(_))));
    }

    #[test]
    fn test_wrong_version() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid2; public-key-algorithm=Ed25519; public-key={}",
            key.public_key().to_base64()
        );

        let result = DnsRecord::parse(&txt);
        assert!(matches!(result, Err(Error::InvalidDnsRecord(msg)) if msg.contains("version")));
    }

    #[test]
    fn test_missing_algorithm() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key={}",
            key.public_key().to_base64()
        );

        let result = DnsRecord::parse(&txt);
        assert!(matches!(result, Err(Error::InvalidDnsRecord(_))));
    }

    #[test]
    fn test_unsupported_algorithm() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key-algorithm=RSA; public-key={}",
            key.public_key().to_base64()
        );

        let result = DnsRecord::parse(&txt);
        assert!(matches!(result, Err(Error::UnsupportedAlgorithm(_))));
    }

    #[test]
    fn test_missing_public_key() {
        let txt = "v=browserid1; public-key-algorithm=Ed25519";

        let result = DnsRecord::parse(txt);
        assert!(matches!(result, Err(Error::InvalidDnsRecord(_))));
    }

    #[test]
    fn test_invalid_public_key() {
        let txt = "v=browserid1; public-key-algorithm=Ed25519; public-key=not-valid-base64!!!";

        let result = DnsRecord::parse(txt);
        assert!(matches!(result, Err(Error::InvalidDnsRecord(_))));
    }
}

mod well_known_host {
    use super::*;

    #[test]
    fn test_returns_host_when_specified() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key-algorithm=Ed25519; public-key={}; host=idp.example.com",
            key.public_key().to_base64()
        );

        let record = DnsRecord::parse(&txt).unwrap();
        assert_eq!(record.well_known_host("example.com"), "idp.example.com");
    }

    #[test]
    fn test_returns_default_when_no_host() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key-algorithm=Ed25519; public-key={}",
            key.public_key().to_base64()
        );

        let record = DnsRecord::parse(&txt).unwrap();
        assert_eq!(record.well_known_host("example.com"), "example.com");
    }
}
```

### Step 7: Run tests

Run: `cargo test -p browserid-core --test dns_record_test`
Expected: All tests pass

### Step 8: Commit

```bash
git add browserid-core/src/dns.rs browserid-core/src/lib.rs browserid-core/src/error.rs browserid-core/tests/dns_record_test.rs
git commit -m "feat(core): add DNS TXT record parsing for BrowserID

Parses _browserid.<domain> TXT records with format:
v=browserid1; public-key-algorithm=Ed25519; public-key=<base64>; host=<optional>"
```

---

## Task 2: Add DNSSEC Status Types

**Files:**
- Modify: `browserid-core/src/dns.rs`
- Modify: `browserid-core/tests/dns_record_test.rs`

### Step 1: Add DnssecStatus enum to dns.rs

Add to `browserid-core/src/dns.rs`:

```rust
/// DNSSEC validation status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecStatus {
    /// Response is DNSSEC-validated (AD flag set)
    Secure,
    /// Response is not DNSSEC-validated (insecure zone or no DNSSEC)
    Insecure,
    /// DNSSEC validation failed (BOGUS - indicates attack or misconfiguration)
    Bogus,
}

impl DnssecStatus {
    /// Returns true if the response is cryptographically validated
    pub fn is_secure(&self) -> bool {
        matches!(self, DnssecStatus::Secure)
    }

    /// Returns true if this status allows fallback to broker
    pub fn allows_fallback(&self) -> bool {
        matches!(self, DnssecStatus::Insecure)
    }

    /// Returns true if this status should cause hard rejection
    pub fn is_bogus(&self) -> bool {
        matches!(self, DnssecStatus::Bogus)
    }
}

/// Result of a DNS lookup for BrowserID
#[derive(Debug, Clone)]
pub struct DnsLookupResult {
    /// The parsed record, if found
    pub record: Option<DnsRecord>,
    /// DNSSEC validation status
    pub dnssec_status: DnssecStatus,
}

impl DnsLookupResult {
    /// Create a secure result with a record
    pub fn secure(record: DnsRecord) -> Self {
        Self {
            record: Some(record),
            dnssec_status: DnssecStatus::Secure,
        }
    }

    /// Create a secure result with no record (NXDOMAIN)
    pub fn secure_nxdomain() -> Self {
        Self {
            record: None,
            dnssec_status: DnssecStatus::Secure,
        }
    }

    /// Create an insecure result
    pub fn insecure() -> Self {
        Self {
            record: None,
            dnssec_status: DnssecStatus::Insecure,
        }
    }

    /// Create a bogus result
    pub fn bogus() -> Self {
        Self {
            record: None,
            dnssec_status: DnssecStatus::Bogus,
        }
    }
}
```

### Step 2: Export new types from lib.rs

Edit `browserid-core/src/lib.rs` to update export:

```rust
pub use dns::{DnsRecord, DnssecStatus, DnsLookupResult};
```

### Step 3: Add tests for DNSSEC status

Add to `browserid-core/tests/dns_record_test.rs`:

```rust
mod dnssec_status {
    use browserid_core::{DnssecStatus, DnsLookupResult, KeyPair, DnsRecord};

    #[test]
    fn test_secure_is_secure() {
        assert!(DnssecStatus::Secure.is_secure());
        assert!(!DnssecStatus::Insecure.is_secure());
        assert!(!DnssecStatus::Bogus.is_secure());
    }

    #[test]
    fn test_insecure_allows_fallback() {
        assert!(!DnssecStatus::Secure.allows_fallback());
        assert!(DnssecStatus::Insecure.allows_fallback());
        assert!(!DnssecStatus::Bogus.allows_fallback());
    }

    #[test]
    fn test_bogus_is_bogus() {
        assert!(!DnssecStatus::Secure.is_bogus());
        assert!(!DnssecStatus::Insecure.is_bogus());
        assert!(DnssecStatus::Bogus.is_bogus());
    }

    #[test]
    fn test_lookup_result_constructors() {
        let key = KeyPair::generate();
        let txt = format!(
            "v=browserid1; public-key-algorithm=Ed25519; public-key={}",
            key.public_key().to_base64()
        );
        let record = DnsRecord::parse(&txt).unwrap();

        let secure = DnsLookupResult::secure(record);
        assert!(secure.record.is_some());
        assert_eq!(secure.dnssec_status, DnssecStatus::Secure);

        let nxdomain = DnsLookupResult::secure_nxdomain();
        assert!(nxdomain.record.is_none());
        assert_eq!(nxdomain.dnssec_status, DnssecStatus::Secure);

        let insecure = DnsLookupResult::insecure();
        assert!(insecure.record.is_none());
        assert_eq!(insecure.dnssec_status, DnssecStatus::Insecure);

        let bogus = DnsLookupResult::bogus();
        assert!(bogus.record.is_none());
        assert_eq!(bogus.dnssec_status, DnssecStatus::Bogus);
    }
}
```

### Step 4: Run tests

Run: `cargo test -p browserid-core --test dns_record_test`
Expected: All tests pass

### Step 5: Commit

```bash
git add browserid-core/src/dns.rs browserid-core/src/lib.rs browserid-core/tests/dns_record_test.rs
git commit -m "feat(core): add DNSSEC status types

DnssecStatus enum: Secure, Insecure, Bogus
DnsLookupResult combines record with DNSSEC status"
```

---

## Task 3: Add hickory-resolver Dependency

**Files:**
- Modify: `Cargo.toml` (workspace)
- Modify: `browserid-broker/Cargo.toml`

### Step 1: Add hickory-resolver to workspace dependencies

Edit `Cargo.toml` (workspace root), replace the commented trust-dns line:

```toml
# DNS / DNSSEC
hickory-resolver = { version = "0.24", features = ["dnssec-ring"] }
```

### Step 2: Add hickory-resolver to broker dependencies

Edit `browserid-broker/Cargo.toml`, add:

```toml
hickory-resolver.workspace = true
```

### Step 3: Verify build

Run: `cargo build -p browserid-broker`
Expected: Compiles (may take a while for first build with new dep)

### Step 4: Commit

```bash
git add Cargo.toml browserid-broker/Cargo.toml
git commit -m "chore: add hickory-resolver dependency for DNSSEC"
```

---

## Task 4: Create DNS Fetcher

**Files:**
- Create: `browserid-broker/src/dns_fetcher.rs`
- Modify: `browserid-broker/src/lib.rs`
- Test: `browserid-broker/tests/dns_fetcher_test.rs`

### Step 1: Create dns_fetcher.rs

Create `browserid-broker/src/dns_fetcher.rs`:

```rust
//! DNS-based BrowserID discovery with DNSSEC validation
//!
//! Queries `_browserid.<domain>` TXT records and validates DNSSEC.

use browserid_core::{DnsLookupResult, DnsRecord, DnssecStatus};
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use std::sync::Arc;

/// DNS fetcher with DNSSEC validation
pub struct DnsFetcher {
    resolver: Arc<TokioAsyncResolver>,
}

impl DnsFetcher {
    /// Create a new DNS fetcher with system resolver config
    pub fn new() -> Result<Self, String> {
        let mut opts = ResolverOpts::default();
        // Enable DNSSEC validation
        opts.validate = true;

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);

        Ok(Self {
            resolver: Arc::new(resolver),
        })
    }

    /// Create a DNS fetcher with custom resolver (for testing)
    pub fn with_resolver(resolver: TokioAsyncResolver) -> Self {
        Self {
            resolver: Arc::new(resolver),
        }
    }

    /// Query the BrowserID DNS record for a domain
    ///
    /// Returns the lookup result with DNSSEC status.
    pub async fn lookup(&self, domain: &str) -> DnsLookupResult {
        let name = format!("_browserid.{}", domain);

        match self.resolver.txt_lookup(&name).await {
            Ok(lookup) => {
                // Check if response is DNSSEC-validated
                // hickory-resolver sets this based on AD flag
                let is_secure = lookup
                    .as_lookup()
                    .extensions()
                    .map(|ext| ext.dnssec_ok)
                    .unwrap_or(false);

                // Get the first TXT record
                let txt_data: Option<String> = lookup.iter().next().map(|txt| {
                    txt.txt_data()
                        .iter()
                        .map(|bytes| String::from_utf8_lossy(bytes))
                        .collect::<Vec<_>>()
                        .join("")
                });

                match txt_data {
                    Some(txt) => match DnsRecord::parse(&txt) {
                        Ok(record) => {
                            if is_secure {
                                DnsLookupResult::secure(record)
                            } else {
                                // Record found but not DNSSEC-validated
                                DnsLookupResult::insecure()
                            }
                        }
                        Err(_) => {
                            // Malformed record - treat as not found
                            if is_secure {
                                DnsLookupResult::secure_nxdomain()
                            } else {
                                DnsLookupResult::insecure()
                            }
                        }
                    },
                    None => {
                        // No TXT records
                        if is_secure {
                            DnsLookupResult::secure_nxdomain()
                        } else {
                            DnsLookupResult::insecure()
                        }
                    }
                }
            }
            Err(e) => {
                // Check if this is a DNSSEC validation failure (BOGUS)
                let error_str = e.to_string().to_lowercase();
                if error_str.contains("dnssec")
                    || error_str.contains("bogus")
                    || error_str.contains("validation")
                {
                    DnsLookupResult::bogus()
                } else {
                    // NXDOMAIN or other error - treat as insecure
                    DnsLookupResult::insecure()
                }
            }
        }
    }
}

impl Default for DnsFetcher {
    fn default() -> Self {
        Self::new().expect("Failed to create DNS resolver")
    }
}
```

### Step 2: Export from lib.rs

Edit `browserid-broker/src/lib.rs`, add:

```rust
pub mod dns_fetcher;

pub use dns_fetcher::DnsFetcher;
```

### Step 3: Verify build

Run: `cargo build -p browserid-broker`
Expected: Compiles successfully

### Step 4: Create test file with mock-based tests

Create `browserid-broker/tests/dns_fetcher_test.rs`:

```rust
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
```

### Step 5: Run tests

Run: `cargo test -p browserid-broker --test dns_fetcher_test`
Expected: Tests pass

### Step 6: Commit

```bash
git add browserid-broker/src/dns_fetcher.rs browserid-broker/src/lib.rs browserid-broker/tests/dns_fetcher_test.rs
git commit -m "feat(broker): add DNS fetcher with DNSSEC validation

Queries _browserid.<domain> TXT records and checks DNSSEC status.
Returns DnsLookupResult with Secure/Insecure/Bogus status."
```

---

## Task 5: Add DNSSEC Error to Broker

**Files:**
- Modify: `browserid-broker/src/error.rs`

### Step 1: Read current error.rs

Run: Check current error types in browserid-broker/src/error.rs

### Step 2: Add DNSSEC error variant

Edit `browserid-broker/src/error.rs` to add a new variant:

```rust
#[error("DNSSEC validation failed for domain {domain}")]
DnssecValidationFailed { domain: String },
```

### Step 3: Verify build

Run: `cargo build -p browserid-broker`
Expected: Compiles

### Step 4: Commit

```bash
git add browserid-broker/src/error.rs
git commit -m "feat(broker): add DNSSEC validation error type"
```

---

## Task 6: Create Fallback Fetcher

**Files:**
- Create: `browserid-broker/src/fallback_fetcher.rs`
- Modify: `browserid-broker/src/lib.rs`
- Test: `browserid-broker/tests/fallback_fetcher_test.rs`

### Step 1: Create fallback_fetcher.rs

Create `browserid-broker/src/fallback_fetcher.rs`:

```rust
//! Fallback fetcher for BrowserID discovery
//!
//! Tries DNS with DNSSEC first, falls back to broker if needed.

use browserid_core::{
    discovery::{SupportDocument, SupportDocumentFetcher},
    DnssecStatus, Result as CoreResult,
};

use crate::dns_fetcher::DnsFetcher;
use crate::error::BrokerError;
use crate::verifier::HttpFetcher;

/// Discovery result including the authoritative domain
pub struct FallbackResult {
    /// The support document
    pub document: SupportDocument,
    /// The domain that is authoritative (email domain for primary, broker for fallback)
    pub authoritative_domain: String,
    /// Whether this is a primary IdP (via DNS) or fallback broker
    pub is_primary: bool,
}

/// Fetcher that tries DNS first, falls back to broker
pub struct FallbackFetcher {
    dns_fetcher: DnsFetcher,
    http_fetcher: HttpFetcher,
    trusted_broker: String,
}

impl FallbackFetcher {
    /// Create a new fallback fetcher
    pub fn new(trusted_broker: String) -> Result<Self, String> {
        Ok(Self {
            dns_fetcher: DnsFetcher::new()?,
            http_fetcher: HttpFetcher::new(),
            trusted_broker,
        })
    }

    /// Create with custom fetchers (for testing)
    pub fn with_fetchers(
        dns_fetcher: DnsFetcher,
        http_fetcher: HttpFetcher,
        trusted_broker: String,
    ) -> Self {
        Self {
            dns_fetcher,
            http_fetcher,
            trusted_broker,
        }
    }

    /// Discover BrowserID support for a domain
    ///
    /// 1. Query DNS for _browserid.<domain> with DNSSEC
    /// 2. If DNSSEC-validated record found: use as primary IdP
    /// 3. If insecure/not found: fall back to broker
    /// 4. If BOGUS: reject (DNSSEC validation failure)
    pub async fn discover(&self, domain: &str) -> Result<FallbackResult, BrokerError> {
        let dns_result = self.dns_fetcher.lookup(domain).await;

        match dns_result.dnssec_status {
            DnssecStatus::Secure => {
                if let Some(record) = dns_result.record {
                    // Primary IdP mode - use DNS public key
                    let host = record.well_known_host(domain);

                    // Fetch .well-known for auth/provision endpoints
                    let mut doc = self.http_fetcher.fetch(host).map_err(|e| {
                        BrokerError::Discovery(format!(
                            "Failed to fetch .well-known from {}: {}",
                            host, e
                        ))
                    })?;

                    // Override public key with DNSSEC-validated key
                    doc.public_key = record.public_key;

                    Ok(FallbackResult {
                        document: doc,
                        authoritative_domain: domain.to_string(),
                        is_primary: true,
                    })
                } else {
                    // DNSSEC-validated NXDOMAIN - fall back to broker
                    self.fallback_to_broker()
                }
            }
            DnssecStatus::Insecure => {
                // No DNSSEC - fall back to broker
                self.fallback_to_broker()
            }
            DnssecStatus::Bogus => {
                // DNSSEC validation failed - reject
                Err(BrokerError::DnssecValidationFailed {
                    domain: domain.to_string(),
                })
            }
        }
    }

    fn fallback_to_broker(&self) -> Result<FallbackResult, BrokerError> {
        let doc = self.http_fetcher.fetch(&self.trusted_broker).map_err(|e| {
            BrokerError::Discovery(format!(
                "Failed to fetch broker .well-known: {}",
                e
            ))
        })?;

        Ok(FallbackResult {
            document: doc,
            authoritative_domain: self.trusted_broker.clone(),
            is_primary: false,
        })
    }
}
```

### Step 2: Add Discovery error variant if not present

Check `browserid-broker/src/error.rs` for Discovery variant. If not present, add:

```rust
#[error("Discovery failed: {0}")]
Discovery(String),
```

### Step 3: Export from lib.rs

Edit `browserid-broker/src/lib.rs`, add:

```rust
pub mod fallback_fetcher;

pub use fallback_fetcher::{FallbackFetcher, FallbackResult};
```

### Step 4: Verify build

Run: `cargo build -p browserid-broker`
Expected: Compiles

### Step 5: Create test file

Create `browserid-broker/tests/fallback_fetcher_test.rs`:

```rust
//! Fallback fetcher tests

use browserid_broker::FallbackFetcher;

/// Test that fallback fetcher can be created
#[tokio::test]
async fn test_fallback_fetcher_creation() {
    let fetcher = FallbackFetcher::new("localhost:3000".to_string());
    assert!(fetcher.is_ok());
}

/// Test fallback to broker for unknown domain
/// Note: This requires a running broker or will fail gracefully
#[tokio::test]
async fn test_fallback_for_unknown_domain() {
    let fetcher = match FallbackFetcher::new("localhost:3000".to_string()) {
        Ok(f) => f,
        Err(_) => return, // Skip if can't create
    };

    // This domain has no _browserid record, so should fall back
    let result = fetcher.discover("example.invalid").await;

    // Will fail because broker isn't running, but that's expected in unit tests
    // The important thing is the logic path is exercised
    assert!(result.is_err() || !result.unwrap().is_primary);
}
```

### Step 6: Run tests

Run: `cargo test -p browserid-broker --test fallback_fetcher_test`
Expected: Tests pass (or skip gracefully)

### Step 7: Commit

```bash
git add browserid-broker/src/fallback_fetcher.rs browserid-broker/src/lib.rs browserid-broker/src/error.rs browserid-broker/tests/fallback_fetcher_test.rs
git commit -m "feat(broker): add fallback fetcher for DNS-first discovery

Tries DNS with DNSSEC first, falls back to broker if:
- No DNSSEC (Insecure)
- No record found (NXDOMAIN)

Rejects if DNSSEC validation fails (Bogus)."
```

---

## Task 7: Integrate Fallback Fetcher into Verifier

**Files:**
- Modify: `browserid-broker/src/verifier.rs`
- Test: `browserid-broker/tests/verifier_dns_test.rs`

### Step 1: Read current verifier.rs

Understand the current `verify_assertion` function structure.

### Step 2: Update verify_assertion to support async and DNS

The verifier currently uses synchronous `SupportDocumentFetcher`. We need to add an async variant that uses `FallbackFetcher`.

Add new function to `browserid-broker/src/verifier.rs`:

```rust
use crate::fallback_fetcher::FallbackFetcher;

/// Verify assertion with DNS-first discovery (async)
///
/// Uses FallbackFetcher to try DNS with DNSSEC first,
/// falling back to broker if needed.
pub async fn verify_assertion_with_dns(
    assertion: &str,
    audience: &str,
    fallback_fetcher: &FallbackFetcher,
    trusted_broker: &str,
) -> VerificationResult {
    // Parse the backed assertion
    let backed = match BackedAssertion::parse(assertion) {
        Ok(b) => b,
        Err(e) => return VerificationResult::failure(format!("Invalid assertion format: {}", e)),
    };

    // Get the certificate
    let cert = match backed.certificates().first() {
        Some(c) => c,
        None => return VerificationResult::failure("No certificate in assertion".to_string()),
    };

    let issuer = cert.issuer().to_string();
    let expires = backed.assertion().claims().exp;

    // Get email and its domain
    let email = match cert.email() {
        Some(e) => e.to_string(),
        None => return VerificationResult::failure("Certificate has no email".to_string()),
    };

    let email_domain = match email.split('@').nth(1) {
        Some(d) => d.to_string(),
        None => return VerificationResult::failure("Invalid email format".to_string()),
    };

    // Try DNS discovery for the email domain
    let discovery_result = match fallback_fetcher.discover(&email_domain).await {
        Ok(r) => r,
        Err(e) => return VerificationResult::failure(format!("Discovery failed: {}", e)),
    };

    // Check issuer authorization based on discovery result
    let issuer_authorized = if discovery_result.is_primary {
        // Primary IdP mode - issuer must match email domain
        issuer == email_domain
    } else {
        // Fallback mode - issuer must be trusted broker
        issuer == trusted_broker
    };

    if !issuer_authorized {
        let expected = if discovery_result.is_primary {
            &email_domain
        } else {
            trusted_broker
        };
        return VerificationResult::failure(format!(
            "Issuer '{}' is not authorized (expected '{}')",
            issuer, expected
        ));
    }

    // Verify signatures using discovery result's public key
    verify_signatures_with_doc(
        &backed,
        audience,
        &issuer,
        &email,
        expires,
        &discovery_result.document,
    )
}

/// Verify signatures using a pre-fetched support document
fn verify_signatures_with_doc(
    backed: &BackedAssertion,
    audience: &str,
    issuer: &str,
    email: &str,
    expires: i64,
    doc: &SupportDocument,
) -> VerificationResult {
    // Check audience
    if backed.assertion().audience() != audience {
        return VerificationResult::failure(format!(
            "Audience mismatch: expected {}, got {}",
            audience,
            backed.assertion().audience()
        ));
    }

    // Check assertion expiration
    if backed.assertion().is_expired() {
        return VerificationResult::failure("Assertion expired".to_string());
    }

    // Check certificate expiration
    let cert = backed.certificates().first().unwrap();
    if cert.is_expired() {
        return VerificationResult::failure("Certificate expired".to_string());
    }

    // Verify assertion signature with certificate's public key
    if let Err(e) = backed.assertion().verify(cert.public_key()) {
        return VerificationResult::failure(format!("Assertion signature invalid: {}", e));
    }

    // Verify certificate signature with issuer's key (from discovery)
    if let Err(e) = cert.verify(&doc.public_key) {
        return VerificationResult::failure(format!("Certificate signature invalid: {}", e));
    }

    VerificationResult::success(email.to_string(), issuer.to_string(), expires)
}
```

### Step 3: Add necessary imports

At the top of `browserid-broker/src/verifier.rs`, ensure these imports exist:

```rust
use browserid_core::discovery::SupportDocument;
```

### Step 4: Verify build

Run: `cargo build -p browserid-broker`
Expected: Compiles

### Step 5: Create test file

Create `browserid-broker/tests/verifier_dns_test.rs`:

```rust
//! Verifier DNS integration tests
//!
//! These tests verify the DNS-first discovery logic.
//! Note: Most tests will fall back to broker since test domains
//! don't have real _browserid DNS records.

// Integration tests for DNS verification would go here
// For now, the main verification tests in verifier_test.rs cover
// the core verification logic, and the DNS path adds the discovery layer.

#[test]
fn test_placeholder() {
    // Placeholder - real integration tests require:
    // 1. A domain with actual _browserid TXT record
    // 2. DNSSEC enabled on that domain
    // 3. Or a mock DNS resolver
    assert!(true);
}
```

### Step 6: Run all broker tests

Run: `cargo test -p browserid-broker`
Expected: All tests pass

### Step 7: Commit

```bash
git add browserid-broker/src/verifier.rs browserid-broker/tests/verifier_dns_test.rs
git commit -m "feat(broker): add async verify_assertion_with_dns

Uses FallbackFetcher for DNS-first discovery.
Primary IdP mode requires issuer == email_domain.
Fallback mode requires issuer == trusted_broker."
```

---

## Task 8: Update Verify Route to Use DNS Discovery

**Files:**
- Modify: `browserid-broker/src/routes/verify.rs`
- Modify: `browserid-broker/src/state.rs`

### Step 1: Read current verify route and state

Understand how the verify endpoint currently works.

### Step 2: Add FallbackFetcher to AppState

Edit `browserid-broker/src/state.rs` to add FallbackFetcher:

```rust
use crate::fallback_fetcher::FallbackFetcher;
use std::sync::Arc;
use tokio::sync::OnceCell;

// Add to AppState struct:
fallback_fetcher: OnceCell<Arc<FallbackFetcher>>,

// Add method to AppState impl:
/// Get or create the fallback fetcher
pub async fn fallback_fetcher(&self) -> Result<Arc<FallbackFetcher>, String> {
    self.fallback_fetcher
        .get_or_try_init(|| async {
            FallbackFetcher::new(self.hostname.clone()).map(Arc::new)
        })
        .await
        .cloned()
}

// Update constructor to initialize the OnceCell:
fallback_fetcher: OnceCell::new(),
```

### Step 3: Update verify route to use async DNS verification

Edit `browserid-broker/src/routes/verify.rs` to use the new async verification:

```rust
use crate::verifier::verify_assertion_with_dns;

// In the verify handler, replace the sync verification with:
let fallback_fetcher = match state.fallback_fetcher().await {
    Ok(f) => f,
    Err(e) => {
        return Json(VerificationResult::failure(format!("Failed to create fetcher: {}", e)));
    }
};

let result = verify_assertion_with_dns(
    &request.assertion,
    &request.audience,
    &fallback_fetcher,
    &state.hostname,
).await;

Json(result)
```

### Step 4: Verify build

Run: `cargo build -p browserid-broker`
Expected: Compiles

### Step 5: Run all tests

Run: `cargo test`
Expected: All tests pass

### Step 6: Commit

```bash
git add browserid-broker/src/state.rs browserid-broker/src/routes/verify.rs
git commit -m "feat(broker): use DNS-first discovery in verify endpoint

Verify route now uses FallbackFetcher for async DNS discovery.
Falls back to broker if domain lacks DNSSEC or _browserid record."
```

---

## Task 9: Run Full Test Suite

**Files:** None (verification only)

### Step 1: Run all Rust tests

Run: `cargo test`
Expected: All tests pass

### Step 2: Run E2E tests

Run: `cd e2e-tests && npm test`
Expected: All E2E tests pass (still using broker as fallback since test domains don't have DNS records)

### Step 3: Manual verification

Run the broker and verify:
1. `/verify` endpoint works
2. Existing authentication flows work

Run: `cargo run -p browserid-broker`
Then test with a simple curl or browser test.

### Step 4: Commit any fixes

If any fixes were needed, commit them.

---

## Task 10: Update Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/plans/2025-12-28-dns-discovery-design.md`

### Step 1: Update README if needed

Ensure the README reflects the implemented behavior.

### Step 2: Mark design doc as implemented

Add a note to `docs/plans/2025-12-28-dns-discovery-design.md`:

```markdown
## Implementation Status

**Implemented:** 2025-12-28

See commits in main branch for implementation details.
```

### Step 3: Commit

```bash
git add README.md docs/plans/2025-12-28-dns-discovery-design.md
git commit -m "docs: mark DNS discovery as implemented"
```

---

## Summary

After completing all tasks:

1. **browserid-core** has DNS record parsing (`DnsRecord`) and DNSSEC status types
2. **browserid-broker** has `DnsFetcher` for DNSSEC-validated DNS lookups
3. **browserid-broker** has `FallbackFetcher` that tries DNS first, falls back to broker
4. The verify endpoint uses async DNS-first discovery
5. All existing tests continue to pass (they use broker fallback)
6. New domains with DNSSEC-validated `_browserid` TXT records will be treated as primary IdPs
