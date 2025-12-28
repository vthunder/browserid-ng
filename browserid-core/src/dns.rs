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
