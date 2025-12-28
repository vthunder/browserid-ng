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
    ///
    /// Note: hickory-resolver with validate=true will:
    /// - Return successfully for zones without DNSSEC (insecure)
    /// - Return successfully for properly signed zones (secure)
    /// - Return an error for validation failures (bogus)
    ///
    /// Since most zones don't have DNSSEC, we default to Insecure for
    /// successful queries. The security model relies on the fallback
    /// behavior: insecure zones can use the broker, while bogus zones
    /// are rejected entirely.
    pub async fn lookup(&self, domain: &str) -> DnsLookupResult {
        let name = format!("_browserid.{}", domain);

        match self.resolver.txt_lookup(&name).await {
            Ok(lookup) => {
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
                            // Record found and parsed successfully
                            // Note: We return insecure because hickory-resolver doesn't
                            // expose whether the zone was DNSSEC-signed at the Lookup level.
                            // A future enhancement could use a validating resolver that
                            // exposes the AD (Authenticated Data) flag.
                            DnsLookupResult {
                                record: Some(record),
                                dnssec_status: DnssecStatus::Insecure,
                            }
                        }
                        Err(_) => {
                            // Malformed record - treat as not found
                            DnsLookupResult::insecure()
                        }
                    },
                    None => {
                        // No TXT records
                        DnsLookupResult::insecure()
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
