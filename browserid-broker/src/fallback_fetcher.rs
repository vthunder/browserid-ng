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
#[derive(Clone)]
pub struct FallbackResult {
    /// The support document
    pub document: SupportDocument,
    /// The domain that is authoritative (email domain for primary, broker for fallback)
    pub authoritative_domain: String,
    /// Whether this is a primary IdP (via DNS) or fallback broker
    pub is_primary: bool,
}

/// Resolves the authoritative BrowserID support for an email domain.
///
/// Abstracted so the verifier can be exercised with a mock in tests without a
/// live DNS/HTTP round-trip. Production uses [`FallbackFetcher`].
pub trait Discoverer {
    /// Discover the authoritative support document for `domain`.
    fn discover(
        &self,
        domain: &str,
    ) -> impl std::future::Future<Output = Result<FallbackResult, BrokerError>> + Send;
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

    /// Discover BrowserID support for a domain.
    ///
    /// 1. Query DNS for _browserid.<domain> with DNSSEC.
    /// 2. If a DNSSEC-validated record is found: use as primary IdP, taking the
    ///    identity key from the DNSSEC record (never from `.well-known`).
    /// 3. If insecure/not found: fall back to the broker — whose key is ALSO
    ///    resolved via DNSSEC (the broker must publish an authenticated record).
    /// 4. If BOGUS: reject (DNSSEC validation failure).
    ///
    /// `.well-known` is fetched only for endpoint discovery (auth/provision
    /// paths); the trusted key is always the DNSSEC-validated one. There is no
    /// path by which a key served solely via `.well-known` is trusted.
    pub async fn discover(&self, domain: &str) -> Result<FallbackResult, BrokerError> {
        let dns_result = self.dns_fetcher.lookup(domain).await;

        match dns_result.dnssec_status {
            DnssecStatus::Secure => {
                if let Some(record) = dns_result.record {
                    // Primary IdP: identity key comes from the DNSSEC record.
                    let doc = resolve_with_dnssec_key(domain, record).await?;
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

    /// Fall back to the trusted broker. The broker's identity key is resolved
    /// via DNSSEC too — the broker MUST publish an authenticated `_browserid`
    /// record (browserid.me does). A broker without a DNSSEC-validated record
    /// is a hard error, never a well-known downgrade.
    async fn fallback_to_broker(&self) -> Result<FallbackResult, BrokerError> {
        let broker = self.trusted_broker.clone();
        let dns_result = self.dns_fetcher.lookup(&broker).await;

        match dns_result.dnssec_status {
            DnssecStatus::Secure => match dns_result.record {
                Some(record) => {
                    let doc = resolve_with_dnssec_key(&broker, record).await?;
                    Ok(FallbackResult {
                        document: doc,
                        authoritative_domain: broker,
                        is_primary: false,
                    })
                }
                None => Err(BrokerError::Discovery(format!(
                    "trusted broker '{}' publishes no DNSSEC _browserid record",
                    broker
                ))),
            },
            DnssecStatus::Insecure => Err(BrokerError::Discovery(format!(
                "trusted broker '{}' discovery is not DNSSEC-authenticated",
                broker
            ))),
            DnssecStatus::Bogus => Err(BrokerError::DnssecValidationFailed { domain: broker }),
        }
    }
}

/// Fetch `.well-known/browserid` for endpoints, then override the identity key
/// with the DNSSEC-validated one so trust is always rooted in DNSSEC.
async fn resolve_with_dnssec_key(
    domain: &str,
    record: browserid_core::DnsRecord,
) -> Result<SupportDocument, BrokerError> {
    let host = record.well_known_host(domain);
    let mut doc = fetch_blocking(host).await?;
    doc.public_key = Some(record.public_key);
    Ok(doc)
}

impl Discoverer for FallbackFetcher {
    fn discover(
        &self,
        domain: &str,
    ) -> impl std::future::Future<Output = Result<FallbackResult, BrokerError>> + Send {
        FallbackFetcher::discover(self, domain)
    }
}
