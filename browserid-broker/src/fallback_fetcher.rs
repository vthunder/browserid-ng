//! Fallback fetcher for BrowserID discovery
//!
//! Tries DNS with DNSSEC first, falls back to broker if needed.

use browserid_core::{
    discovery::{SupportDocument, SupportDocumentFetcher},
    DnssecStatus,
};

use crate::dns_fetcher::DnsFetcher;
use crate::error::BrokerError;
use crate::verifier::HttpFetcher;

/// Wrapper to run sync HTTP fetch in a blocking task
async fn fetch_blocking(host: &str) -> Result<SupportDocument, BrokerError> {
    let host = host.to_string();

    // Run in blocking task since reqwest::blocking::Client isn't Send
    let result = tokio::task::spawn_blocking(move || {
        let fetcher = HttpFetcher::new();
        fetcher.fetch(&host)
    })
    .await
    .map_err(|e| BrokerError::Discovery(format!("Blocking task failed: {}", e)))?;

    result.map_err(|e| BrokerError::Discovery(format!("HTTP fetch failed: {}", e)))
}

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
    trusted_broker: String,
}

impl FallbackFetcher {
    /// Create a new fallback fetcher
    pub fn new(trusted_broker: String) -> Result<Self, String> {
        Ok(Self {
            dns_fetcher: DnsFetcher::new()?,
            trusted_broker,
        })
    }

    /// Create with custom DNS fetcher (for testing)
    pub fn with_dns_fetcher(dns_fetcher: DnsFetcher, trusted_broker: String) -> Self {
        Self {
            dns_fetcher,
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

                    // Fetch .well-known for auth/provision endpoints (via blocking task)
                    let mut doc = fetch_blocking(host).await?;

                    // Override public key with DNSSEC-validated key
                    doc.public_key = record.public_key;

                    Ok(FallbackResult {
                        document: doc,
                        authoritative_domain: domain.to_string(),
                        is_primary: true,
                    })
                } else {
                    // DNSSEC-validated NXDOMAIN - fall back to broker
                    self.fallback_to_broker().await
                }
            }
            DnssecStatus::Insecure => {
                // No DNSSEC - fall back to broker
                self.fallback_to_broker().await
            }
            DnssecStatus::Bogus => {
                // DNSSEC validation failed - reject
                Err(BrokerError::DnssecValidationFailed {
                    domain: domain.to_string(),
                })
            }
        }
    }

    async fn fallback_to_broker(&self) -> Result<FallbackResult, BrokerError> {
        let doc = fetch_blocking(&self.trusted_broker).await?;

        Ok(FallbackResult {
            document: doc,
            authoritative_domain: self.trusted_broker.clone(),
            is_primary: false,
        })
    }
}
