//! DNS-based BrowserID discovery with DNSSEC validation
//!
//! Queries `_browserid.<domain>` TXT records and validates DNSSEC.
//!
//! Security model: queries are sent over DNS-over-TLS (RFC 7858) to a trusted
//! validating resolver, with the EDNS DO bit set. Because the channel is
//! authenticated (TLS with WebPKI certificate validation), the resolver's AD
//! (Authenticated Data) flag can be trusted — an on-path attacker cannot forge
//! responses or the AD bit. DNSSEC validation failures surface as SERVFAIL
//! from the validating resolver (RFC 4035 §5.5) and are treated as Bogus,
//! which hard-rejects discovery rather than falling back to the broker.
//!
//! Residual trust: the configured resolver itself (default: Google Public
//! DNS). An attacker who can merely block the TLS connection can force a
//! downgrade to broker fallback (Insecure), but cannot forge a
//! DNSSEC-validated primary IdP record.

use browserid_core::{DnsLookupResult, DnsRecord, DnssecStatus};
use futures_util::StreamExt;
use hickory_client::client::AsyncClient;
use hickory_client::proto::iocompat::AsyncIoTokioAsStd;
use hickory_client::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_client::proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_client::proto::rustls::tls_client_connect;
use hickory_client::proto::xfer::DnsHandle;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::TcpStream as TokioTcpStream;

/// Default DNS-over-TLS resolver address (Google Public DNS)
const DEFAULT_RESOLVER: &str = "8.8.8.8:853";

/// TLS server name for the default resolver's certificate
const DEFAULT_TLS_NAME: &str = "dns.google";

/// Default DNS-over-TLS port
const DEFAULT_DOT_PORT: u16 = 853;

/// Shared rustls config with WebPKI roots, built once
fn tls_client_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));

            Arc::new(
                rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// DNS fetcher with DNSSEC validation over an authenticated channel
///
/// Sends queries with the EDNS DO bit over DNS-over-TLS to a validating
/// resolver and trusts the AD flag only because the transport is
/// authenticated.
pub struct DnsFetcher {
    resolver_addr: SocketAddr,
    tls_name: String,
}

impl DnsFetcher {
    /// Create a new DNS fetcher using Google Public DNS over TLS
    pub fn new() -> Result<Self, String> {
        Self::with_resolver(DEFAULT_RESOLVER, DEFAULT_TLS_NAME)
    }

    /// Create a DNS fetcher with a custom DNS-over-TLS resolver
    ///
    /// `addr` is either an IP (port defaults to 853) or IP:port.
    /// `tls_name` is the hostname the resolver's TLS certificate must match
    /// (e.g., "dns.google" for 8.8.8.8, "cloudflare-dns.com" for 1.1.1.1).
    pub fn with_resolver(addr: &str, tls_name: &str) -> Result<Self, String> {
        let resolver_addr = if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
            socket_addr
        } else if let Ok(ip) = addr.parse::<IpAddr>() {
            SocketAddr::new(ip, DEFAULT_DOT_PORT)
        } else {
            return Err(format!("Invalid resolver address: {}", addr));
        };

        if tls_name.is_empty() {
            return Err("TLS server name must not be empty".to_string());
        }

        Ok(Self {
            resolver_addr,
            tls_name: tls_name.to_string(),
        })
    }

    /// Create a fresh client connection for a single query
    async fn connect(&self) -> Result<AsyncClient, String> {
        let (stream, sender) = tls_client_connect::<AsyncIoTokioAsStd<TokioTcpStream>>(
            self.resolver_addr,
            self.tls_name.clone(),
            tls_client_config(),
        );

        let (client, bg) =
            AsyncClient::with_timeout(stream, sender, Duration::from_secs(5), None)
                .await
                .map_err(|e| format!("Failed to connect to DNS-over-TLS resolver: {}", e))?;

        // Spawn the background task - it will complete when the query is done
        tokio::spawn(bg);

        Ok(client)
    }

    /// Query the BrowserID DNS record for a domain
    ///
    /// Returns the lookup result with DNSSEC status based on the AD flag,
    /// received over the authenticated DoT channel.
    ///
    /// - AD flag set (Secure) -> Domain operates as primary IdP
    /// - AD flag not set (Insecure) -> Fall back to broker
    /// - SERVFAIL (Bogus, DNSSEC validation failure at the resolver) -> Reject
    pub async fn lookup(&self, domain: &str) -> DnsLookupResult {
        let name_str = format!("_browserid.{}.", domain);

        // Parse the domain name
        let name = match Name::from_str(&name_str) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("Invalid domain name {}: {}", domain, e);
                return DnsLookupResult::insecure();
            }
        };

        // Create fresh client connection for this query
        let client = match self.connect().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to get DNS client: {}", e);
                return DnsLookupResult::insecure();
            }
        };

        // Build query with EDNS and DO bit for DNSSEC
        let mut query = Query::new();
        query.set_name(name.clone());
        query.set_query_type(RecordType::TXT);
        query.set_query_class(DNSClass::IN);

        // Build message with EDNS options
        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query(query);

        // Add EDNS with DO bit set - this requests DNSSEC validation
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true); // Set DO bit
        edns.set_max_payload(4096);
        message.set_edns(edns);

        tracing::debug!("Querying {} via DoT with EDNS DO=true", name_str);

        // Send the message over the authenticated channel
        let mut response_stream = client.send(message);
        let response = match response_stream.next().await {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
                // Transport-level failure (timeout, TLS error, connection
                // reset). The channel is authenticated, so this carries no
                // DNSSEC signal — treat as insecure and fall back to broker.
                tracing::debug!("DNS lookup failed for {}: {}", domain, e);
                return DnsLookupResult::insecure();
            }
            None => {
                tracing::debug!("No DNS response for {}", domain);
                return DnsLookupResult::insecure();
            }
        };

        classify_response(&response, domain)
    }
}

/// Classify a DNS response into a BrowserID lookup result
///
/// Separated from transport so the security-critical decision logic is unit
/// testable with constructed messages.
fn classify_response(response: &Message, domain: &str) -> DnsLookupResult {
    match response.response_code() {
        ResponseCode::NoError | ResponseCode::NXDomain => {}
        ResponseCode::ServFail => {
            // A validating resolver signals DNSSEC validation failure as
            // SERVFAIL (RFC 4035 §5.5). Hard-reject: this is either an attack
            // or a misconfigured zone, and both must not fall back silently.
            tracing::warn!(
                "SERVFAIL from validating resolver for {} - treating as DNSSEC Bogus",
                domain
            );
            return DnsLookupResult::bogus();
        }
        other => {
            tracing::warn!("Unexpected response code {} for {}", other, domain);
            return DnsLookupResult::insecure();
        }
    }

    // Check the AD (Authenticated Data) flag. The resolver validated the
    // DNSSEC chain, and we trust the flag because the channel is TLS.
    let is_secure = response.authentic_data();

    tracing::debug!(
        "DNS response for {}: rcode={}, AD={}, answers={}",
        domain,
        response.response_code(),
        is_secure,
        response.answers().len()
    );

    // Parse TXT records from the response
    let mut txt_data: Option<String> = None;

    for record in response.answers() {
        if let Some(RData::TXT(txt)) = record.data() {
            // Concatenate all character strings in the TXT record
            let combined: String = txt
                .txt_data()
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes))
                .collect::<Vec<_>>()
                .join("");

            txt_data = Some(combined);
            break; // Use the first TXT record
        }
    }

    match txt_data {
        Some(txt) => match DnsRecord::parse(&txt) {
            Ok(record) => {
                // Record found and parsed successfully
                let dnssec_status = if is_secure {
                    DnssecStatus::Secure
                } else {
                    DnssecStatus::Insecure
                };

                tracing::info!(
                    "Found BrowserID record for {} (DNSSEC: {:?})",
                    domain,
                    dnssec_status
                );

                DnsLookupResult {
                    record: Some(record),
                    dnssec_status,
                }
            }
            Err(e) => {
                // Malformed record - treat as not found
                tracing::warn!("Malformed BrowserID record for {}: {}", domain, e);
                if is_secure {
                    DnsLookupResult::secure_nxdomain()
                } else {
                    DnsLookupResult::insecure()
                }
            }
        },
        None => {
            // No TXT records found
            if is_secure {
                DnsLookupResult::secure_nxdomain()
            } else {
                DnsLookupResult::insecure()
            }
        }
    }
}

impl Default for DnsFetcher {
    fn default() -> Self {
        Self::new().expect("Failed to create DNS fetcher")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_client::proto::rr::rdata::TXT;
    use hickory_client::proto::rr::Record;

    #[test]
    fn test_fetcher_creation() {
        let fetcher = DnsFetcher::new();
        assert!(fetcher.is_ok());
    }

    #[test]
    fn test_custom_resolver() {
        let fetcher = DnsFetcher::with_resolver("1.1.1.1:853", "cloudflare-dns.com");
        assert!(fetcher.is_ok());
    }

    #[test]
    fn test_custom_resolver_default_port() {
        let fetcher = DnsFetcher::with_resolver("1.1.1.1", "cloudflare-dns.com").unwrap();
        assert_eq!(fetcher.resolver_addr.port(), DEFAULT_DOT_PORT);
    }

    #[test]
    fn test_invalid_resolver() {
        let fetcher = DnsFetcher::with_resolver("not-an-address", "dns.example");
        assert!(fetcher.is_err());
    }

    #[test]
    fn test_empty_tls_name_rejected() {
        let fetcher = DnsFetcher::with_resolver("1.1.1.1", "");
        assert!(fetcher.is_err());
    }

    // --- classify_response: the security-critical decision logic ---

    fn valid_txt() -> String {
        let key = browserid_core::KeyPair::generate();
        format!(
            "v=browserid1; public-key-algorithm=Ed25519; public-key={}",
            key.public_key().to_base64()
        )
    }

    fn response(code: ResponseCode, ad: bool, txt: Option<&str>) -> Message {
        let mut message = Message::new();
        message.set_message_type(MessageType::Response);
        message.set_response_code(code);
        message.set_authentic_data(ad);

        if let Some(txt) = txt {
            let name = Name::from_str("_browserid.example.com.").unwrap();
            let rdata = RData::TXT(TXT::new(vec![txt.to_string()]));
            message.add_answer(Record::from_rdata(name, 300, rdata));
        }

        message
    }

    #[test]
    fn test_servfail_is_bogus_not_fallback() {
        // A validating resolver returns SERVFAIL on DNSSEC validation failure.
        // This must hard-reject (Bogus), never fall back to the broker.
        let result = classify_response(&response(ResponseCode::ServFail, false, None), "example.com");
        assert_eq!(result.dnssec_status, DnssecStatus::Bogus);
        assert!(result.record.is_none());
    }

    #[test]
    fn test_ad_flag_with_record_is_secure() {
        let result = classify_response(
            &response(ResponseCode::NoError, true, Some(&valid_txt())),
            "example.com",
        );
        assert_eq!(result.dnssec_status, DnssecStatus::Secure);
        assert!(result.record.is_some());
    }

    #[test]
    fn test_no_ad_flag_with_record_is_insecure() {
        let result = classify_response(
            &response(ResponseCode::NoError, false, Some(&valid_txt())),
            "example.com",
        );
        assert_eq!(result.dnssec_status, DnssecStatus::Insecure);
    }

    #[test]
    fn test_nxdomain_with_ad_is_secure_nxdomain() {
        let result = classify_response(&response(ResponseCode::NXDomain, true, None), "example.com");
        assert_eq!(result.dnssec_status, DnssecStatus::Secure);
        assert!(result.record.is_none());
    }

    #[test]
    fn test_nxdomain_without_ad_is_insecure() {
        let result = classify_response(&response(ResponseCode::NXDomain, false, None), "example.com");
        assert_eq!(result.dnssec_status, DnssecStatus::Insecure);
    }

    #[test]
    fn test_refused_is_insecure_not_bogus() {
        let result = classify_response(&response(ResponseCode::Refused, true, None), "example.com");
        assert_eq!(result.dnssec_status, DnssecStatus::Insecure);
    }
}
