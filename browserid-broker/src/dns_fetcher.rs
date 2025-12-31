//! DNS-based BrowserID discovery with DNSSEC validation
//!
//! Queries `_browserid.<domain>` TXT records and validates DNSSEC.
//! Uses hickory-client with EDNS DO bit to get AD flag from validating resolver.

use browserid_core::{DnsLookupResult, DnsRecord, DnssecStatus};
use futures_util::StreamExt;
use hickory_client::client::AsyncClient;
use hickory_client::proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_client::proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_client::proto::xfer::DnsHandle;
use hickory_client::udp::UdpClientStream;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Default DNS resolver address (Google Public DNS)
const DEFAULT_RESOLVER: &str = "8.8.8.8";

/// DNS fetcher with DNSSEC validation using hickory-client
///
/// This implementation uses hickory-client to query DNS with the EDNS DO bit set,
/// which causes validating resolvers like Google DNS (8.8.8.8) to return the
/// AD (Authenticated Data) flag if DNSSEC validation succeeded.
pub struct DnsFetcher {
    resolver_addr: SocketAddr,
    /// Cached client connection (lazily initialized)
    client: Arc<Mutex<Option<AsyncClient>>>,
}

impl DnsFetcher {
    /// Create a new DNS fetcher with Google Public DNS resolver
    pub fn new() -> Result<Self, String> {
        Self::with_resolver_addr(DEFAULT_RESOLVER)
    }

    /// Create a DNS fetcher with a custom resolver address
    /// Accepts either just IP (e.g., "8.8.8.8") or IP:port (e.g., "8.8.8.8:53")
    pub fn with_resolver_addr(addr: &str) -> Result<Self, String> {
        // Try parsing as SocketAddr first (with port), then as just IP
        let resolver_addr = if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
            socket_addr
        } else if let Ok(ip) = addr.parse::<IpAddr>() {
            SocketAddr::new(ip, 53) // Default port
        } else {
            return Err(format!("Invalid resolver address: {}", addr));
        };

        Ok(Self {
            resolver_addr,
            client: Arc::new(Mutex::new(None)),
        })
    }

    /// Get or create an async client connection
    async fn get_client(&self) -> Result<AsyncClient, String> {
        let mut client_guard = self.client.lock().await;

        // If we have a cached client, clone it
        if let Some(ref client) = *client_guard {
            return Ok(client.clone());
        }

        // Create a new UDP client stream with timeout
        let stream = UdpClientStream::<UdpSocket>::with_timeout(
            self.resolver_addr,
            Duration::from_secs(5),
        );

        // Connect the client
        let (client, bg) = AsyncClient::connect(stream)
            .await
            .map_err(|e| format!("Failed to connect to DNS resolver: {}", e))?;

        // Spawn the background task to handle responses
        tokio::spawn(bg);

        // Cache the client for future use
        *client_guard = Some(client.clone());

        Ok(client)
    }

    /// Query the BrowserID DNS record for a domain
    ///
    /// Returns the lookup result with DNSSEC status based on the AD flag.
    ///
    /// - AD flag set (Secure) -> Domain operates as primary IdP
    /// - AD flag not set (Insecure) -> Fall back to broker
    /// - DNSSEC validation failure (Bogus) -> Reject
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

        // Get client connection
        let mut client = match self.get_client().await {
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

        tracing::debug!("Querying {} with EDNS DO=true", name_str);

        // Send the custom message with DO bit
        let mut response_stream = client.send(message);
        let response = match response_stream.next().await {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
                let error_str = e.to_string().to_lowercase();

                // Check if this is a DNSSEC validation failure (BOGUS)
                if error_str.contains("dnssec")
                    || error_str.contains("bogus")
                    || error_str.contains("validation")
                    || error_str.contains("rrsig")
                {
                    tracing::warn!("DNSSEC validation failed for {}: {}", domain, e);
                    return DnsLookupResult::bogus();
                }

                // NXDOMAIN or other error - treat as insecure
                tracing::debug!("DNS lookup failed for {}: {}", domain, e);
                return DnsLookupResult::insecure();
            }
            None => {
                tracing::debug!("No DNS response for {}", domain);
                return DnsLookupResult::insecure();
            }
        };

        // Check the AD (Authenticated Data) flag
        // This flag indicates the resolver has validated the DNSSEC chain
        let is_secure = response.authentic_data();

        tracing::debug!(
            "DNS response for {}: AD={}, answers={}",
            domain,
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
}

impl Default for DnsFetcher {
    fn default() -> Self {
        Self::new().expect("Failed to create DNS fetcher")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetcher_creation() {
        let fetcher = DnsFetcher::new();
        assert!(fetcher.is_ok());
    }

    #[test]
    fn test_custom_resolver() {
        let fetcher = DnsFetcher::with_resolver_addr("1.1.1.1:53");
        assert!(fetcher.is_ok());
    }

    #[test]
    fn test_invalid_resolver() {
        let fetcher = DnsFetcher::with_resolver_addr("not-an-address");
        assert!(fetcher.is_err());
    }
}
