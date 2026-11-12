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
//! DNS). A **transport failure** — the resolver unreachable, a TLS or
//! connect error, a timeout, no response, an unexpected rcode — carries no
//! DNSSEC signal and is indistinguishable from an attack, so it is a hard
//! reject (`Bogus`), never `Insecure` (spec §3, audit 2026-11 D14): an
//! attacker who can block port 853 must not be able to demote a primary
//! domain to the fallback path. One retry is made within a short budget
//! ([`TRANSPORT_RETRY_BUDGET`]) before giving up.

use browserid_core::{DnsLookupResult, DnsRecord, DnssecStatus};
use futures_util::StreamExt;
use hickory_client::client::Client;
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_client::proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_client::proto::rustls::tls_client_connect;
use hickory_client::proto::xfer::DnsHandle;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Default DNS-over-TLS resolver address (Google Public DNS)
const DEFAULT_RESOLVER: &str = "8.8.8.8:853";

/// TLS server name for the default resolver's certificate
const DEFAULT_TLS_NAME: &str = "dns.google";

/// Default DNS-over-TLS port
const DEFAULT_DOT_PORT: u16 = 853;

/// Budget within which a failed DoT exchange is retried once (audit
/// 2026-11 Q2 (b): "retry once with a short budget, then hard reject").
/// The retry is attempted only while this much time has not yet elapsed
/// since the first attempt began; each attempt is still bounded by the
/// client's own query timeout.
pub const TRANSPORT_RETRY_BUDGET: Duration = Duration::from_secs(2);

/// Env switch for deterministic test runs: every `_browserid` lookup answers
/// as an authenticated NXDOMAIN (so discovery takes the fallback path)
/// without touching the network. Test suites and the release-candidate
/// pipeline set it so a public resolver's hiccup can never decide a run.
/// The name is deliberately alarming: it disables DNSSEC discovery. The
/// broker refuses to start with it set on a non-local domain.
pub const OFFLINE_DNS_ENV: &str = "BROWSERID_INSECURE_OFFLINE_DNS_FOR_TESTS";

/// Whether [`OFFLINE_DNS_ENV`] is set to `1` (read once per process).
pub fn offline_for_tests() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        let on = std::env::var(OFFLINE_DNS_ENV).map(|v| v == "1").unwrap_or(false);
        if on {
            tracing::warn!("{OFFLINE_DNS_ENV}=1: DNSSEC discovery is OFF, every domain reads as having no _browserid record (tests only)");
        }
        on
    })
}

/// Shared rustls config with WebPKI roots, built once
fn tls_client_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let root_store = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            Arc::new(
                rustls::ClientConfig::builder()
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
#[derive(Clone)]
pub struct DnsFetcher {
    resolver_addr: SocketAddr,
    tls_name: String,
    /// Only the default resolver ([`DnsFetcher::new`]) honours the offline
    /// test switch; one built for an explicit resolver is a test of the
    /// resolver itself and always talks to it.
    honor_offline_switch: bool,
}

impl DnsFetcher {
    /// Create a new DNS fetcher using Google Public DNS over TLS
    pub fn new() -> Result<Self, String> {
        let mut f = Self::with_resolver(DEFAULT_RESOLVER, DEFAULT_TLS_NAME)?;
        f.honor_offline_switch = true;
        Ok(f)
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
            honor_offline_switch: false,
        })
    }

    /// Create a fresh client connection for a single query
    async fn connect(&self) -> Result<Client, String> {
        let (stream, sender) = tls_client_connect(
            self.resolver_addr,
            self.tls_name.clone(),
            tls_client_config(),
            TokioRuntimeProvider::new(),
        );

        let (client, bg) =
            Client::with_timeout(stream, sender, Duration::from_secs(5), None)
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
    /// - Transport failure (no answer at all, after one retry within
    ///   [`TRANSPORT_RETRY_BUDGET`]) -> Reject (Bogus). An unanswered query
    ///   is not an "insecure" answer (spec §3, audit 2026-11 D14).
    pub async fn lookup(&self, domain: &str) -> DnsLookupResult {
        if self.honor_offline_switch && offline_for_tests() {
            tracing::debug!("offline DNS (tests): _browserid.{} answers as an authenticated NXDOMAIN", domain);
            return DnsLookupResult::secure_nxdomain();
        }
        let name_str = format!("_browserid.{}.", domain);

        // Parse the domain name. Not a transport failure, but not an answer
        // either: nothing was asked, so nothing may be read as "not a primary".
        let name = match Name::from_str(&name_str) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("Invalid domain name {}: {}", domain, e);
                return DnsLookupResult::bogus();
            }
        };

        let started = std::time::Instant::now();
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.exchange(&name, &name_str).await {
                Ok(response) => return classify_response(&response, domain),
                Err(e) if attempt == 1 && started.elapsed() < TRANSPORT_RETRY_BUDGET => {
                    tracing::debug!("DoT lookup for {} failed ({}); retrying once", domain, e);
                }
                Err(e) => {
                    // Transport-level failure (connect, TLS, timeout, reset, no
                    // response). The channel carries no DNSSEC signal, and an
                    // attacker who can block it must not be able to demote the
                    // domain to the fallback path: hard reject.
                    tracing::warn!(
                        "DoT lookup for {} failed after {} attempt(s): {} - treating as Bogus (transport failure is a hard reject)",
                        domain, attempt, e
                    );
                    return DnsLookupResult::bogus();
                }
            }
        }
    }

    /// One DoT exchange for the `_browserid` TXT record: fresh connection,
    /// EDNS DO query, first response. `Err` is a transport failure.
    async fn exchange(&self, name: &Name, name_str: &str) -> Result<Message, String> {
        // Create fresh client connection for this query
        let client = self.connect().await?;

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
        match response_stream.next().await {
            Some(Ok(r)) => Ok(r.into()),
            Some(Err(e)) => Err(format!("DNS lookup failed: {e}")),
            None => Err("no DNS response".to_string()),
        }
    }

    /// Does `domain` publish a usable MX record — and which host takes its
    /// mail? Step 3 of the claim-time authority hierarchy (browserid-ng-tsqk):
    /// a no-primary, no-handle domain may only take the SMTP verification
    /// loop if it actually accepts mail. The returned exchange host
    /// (preferred MX, lowercased, no trailing dot) additionally lets the
    /// broker recognize provider-hosted mail domains (e.g. Google Workspace's
    /// `aspmx.l.google.com`) and offer an OIDC proof of the same mailbox.
    ///
    /// `Ok(Some(host))`/`Ok(None)` are definitive answers; `Err` is a
    /// transport failure carrying no signal, and the caller decides how to
    /// degrade (the authority checker fails open). No DNSSEC requirement
    /// here — SMTP itself offers none, so demanding it of the routing
    /// decision would protect nothing.
    pub async fn lookup_mx(&self, domain: &str) -> Result<Option<String>, String> {
        let name = Name::from_str(&format!("{}.", domain))
            .map_err(|e| format!("invalid domain {domain}: {e}"))?;
        let client = self.connect().await?;

        let mut query = Query::new();
        query.set_name(name);
        query.set_query_type(RecordType::MX);
        query.set_query_class(DNSClass::IN);

        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query(query);

        let mut response_stream = client.send(message);
        let response = match response_stream.next().await {
            Some(Ok(r)) => r,
            Some(Err(e)) => return Err(format!("MX lookup failed for {domain}: {e}")),
            None => return Err(format!("no MX response for {domain}")),
        };
        classify_mx_response(&response)
    }
}

/// Interpret an MX response into the preferred (lowest-preference) usable
/// exchange host. NXDomain and an empty answer are the definitive "does not
/// accept mail" (`None`); a null MX (`MX 0 .`, RFC 7505) is the domain
/// *saying* it accepts no mail and counts the same way. Anything that is not
/// a definitive answer is an error, never a silent `None` — refusing a claim
/// wants a real "no", not a resolver hiccup.
fn classify_mx_response(response: &Message) -> Result<Option<String>, String> {
    match response.response_code() {
        ResponseCode::NoError | ResponseCode::NXDomain => {}
        other => return Err(format!("MX query answered {other}")),
    }
    Ok(response
        .answers()
        .iter()
        .filter_map(|record| match record.data() {
            RData::MX(mx) if !mx.exchange().is_root() => Some(mx),
            _ => None,
        })
        .min_by_key(|mx| mx.preference())
        .map(|mx| {
            mx.exchange()
                .to_utf8()
                .trim_end_matches('.')
                .to_ascii_lowercase()
        }))
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
            // REFUSED, NOTIMP, FORMERR, …: the resolver did not answer the
            // question. No DNSSEC signal → not "insecure"; hard reject, like a
            // transport failure (audit 2026-11 D14).
            tracing::warn!("Unexpected response code {} for {} - treating as Bogus", other, domain);
            return DnsLookupResult::bogus();
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

    // Collect the BrowserID candidate TXT records at `_browserid.<domain>`.
    // Filter by the `v=browserid1` version tag rather than taking the first TXT
    // (audit M5): a zone may legitimately carry other TXT records at this name,
    // and blindly picking the first one would either miss a valid record or, if
    // it happened to be ours, ignore a second conflicting one.
    let candidates: Vec<String> = response
        .answers()
        .iter()
        .filter_map(|record| match record.data() {
            RData::TXT(txt) => {
                let combined: String = txt
                    .txt_data()
                    .iter()
                    .map(|bytes| String::from_utf8_lossy(bytes))
                    .collect::<Vec<_>>()
                    .join("");
                combined
                    .trim_start()
                    .starts_with("v=browserid")
                    .then_some(combined)
            }
            _ => None,
        })
        .collect();

    // More than one BrowserID record is an ambiguous/misconfigured (or tampered)
    // zone. On a DNSSEC-secure answer this is Bogus — hard-reject rather than
    // non-deterministically pick one and silently demote the domain.
    if candidates.len() > 1 {
        tracing::warn!(
            "Multiple BrowserID records for {} ({} found)",
            domain,
            candidates.len()
        );
        return if is_secure {
            DnsLookupResult::bogus()
        } else {
            DnsLookupResult::insecure()
        };
    }

    match candidates.into_iter().next() {
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
                // A BrowserID record is PRESENT but malformed. If it is
                // DNSSEC-signed this is Bogus (audit M5): treating it as
                // NXDOMAIN would demote a primary domain to the broker fallback,
                // rejecting the domain's own legitimately-issued presentations.
                tracing::warn!("Malformed BrowserID record for {}: {}", domain, e);
                if is_secure {
                    DnsLookupResult::bogus()
                } else {
                    DnsLookupResult::insecure()
                }
            }
        },
        None => {
            // No BrowserID record present — a genuine "not a primary" signal.
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

    /// Response carrying several TXT records at `_browserid.example.com`.
    fn response_multi(code: ResponseCode, ad: bool, txts: &[&str]) -> Message {
        let mut message = Message::new();
        message.set_message_type(MessageType::Response);
        message.set_response_code(code);
        message.set_authentic_data(ad);
        let name = Name::from_str("_browserid.example.com.").unwrap();
        for txt in txts {
            let rdata = RData::TXT(TXT::new(vec![txt.to_string()]));
            message.add_answer(Record::from_rdata(name.clone(), 300, rdata));
        }
        message
    }

    // --- classify_mx_response: step 3 of the authority hierarchy ---

    fn mx_response(code: ResponseCode, exchanges: &[&str]) -> Message {
        use hickory_client::proto::rr::rdata::MX;
        let mut message = Message::new();
        message.set_message_type(MessageType::Response);
        message.set_response_code(code);
        let name = Name::from_str("example.com.").unwrap();
        for (i, ex) in exchanges.iter().enumerate() {
            let rdata = RData::MX(MX::new(i as u16, Name::from_str(ex).unwrap()));
            message.add_answer(Record::from_rdata(name.clone(), 300, rdata));
        }
        message
    }

    #[test]
    fn mx_present_yields_the_preferred_exchange() {
        assert_eq!(
            classify_mx_response(&mx_response(ResponseCode::NoError, &["mx.example.com."])),
            Ok(Some("mx.example.com".to_string()))
        );
        // Lowest preference wins (mx_response assigns preference by index),
        // and the host comes back lowercased without the trailing dot.
        assert_eq!(
            classify_mx_response(&mx_response(
                ResponseCode::NoError,
                &["ASPMX.L.GOOGLE.COM.", "alt1.aspmx.l.google.com."]
            )),
            Ok(Some("aspmx.l.google.com".to_string()))
        );
    }

    #[test]
    fn mx_absent_and_nxdomain_are_definitively_false() {
        assert_eq!(classify_mx_response(&mx_response(ResponseCode::NoError, &[])), Ok(None));
        assert_eq!(classify_mx_response(&mx_response(ResponseCode::NXDomain, &[])), Ok(None));
    }

    /// RFC 7505: `MX 0 .` is the domain declaring it accepts no mail — that
    /// is a "no", not a usable exchange.
    #[test]
    fn null_mx_reads_as_no_mail() {
        assert_eq!(classify_mx_response(&mx_response(ResponseCode::NoError, &["."])), Ok(None));
        // …but a null MX alongside a real one does not mask it.
        assert_eq!(
            classify_mx_response(&mx_response(ResponseCode::NoError, &[".", "mx.example.com."])),
            Ok(Some("mx.example.com".to_string()))
        );
    }

    /// A resolver failure is not a definitive "no mail" — it must surface as
    /// an error so the authority checker can fail open instead of refusing
    /// legitimate claims during an outage.
    #[test]
    fn mx_servfail_is_an_error_not_a_no() {
        assert!(classify_mx_response(&mx_response(ResponseCode::ServFail, &[])).is_err());
        assert!(classify_mx_response(&mx_response(ResponseCode::Refused, &[])).is_err());
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
    fn test_malformed_signed_record_is_bogus_not_nxdomain() {
        // A BrowserID record is present (v=browserid1 tag) but malformed, and the
        // answer is DNSSEC-secure. This must hard-reject (Bogus), NOT demote to
        // the broker fallback via secure_nxdomain (audit M5).
        let result = classify_response(
            &response(ResponseCode::NoError, true, Some("v=browserid1; public-key=not-valid")),
            "example.com",
        );
        assert_eq!(result.dnssec_status, DnssecStatus::Bogus);
        assert!(result.record.is_none());
    }

    #[test]
    fn test_multiple_browserid_records_signed_is_bogus() {
        // Two BrowserID records at _browserid is ambiguous/tampered; on a secure
        // answer, reject rather than non-deterministically pick one (audit M5).
        let result = classify_response(
            &response_multi(ResponseCode::NoError, true, &[&valid_txt(), &valid_txt()]),
            "example.com",
        );
        assert_eq!(result.dnssec_status, DnssecStatus::Bogus);
    }

    #[test]
    fn test_non_browserid_txt_alongside_record_is_ignored() {
        // An unrelated TXT record at the same name must not shadow the real
        // BrowserID record (previously the first-TXT-wins scan could miss it).
        let result = classify_response(
            &response_multi(
                ResponseCode::NoError,
                true,
                &["some-other-txt=hello", &valid_txt()],
            ),
            "example.com",
        );
        assert_eq!(result.dnssec_status, DnssecStatus::Secure);
        assert!(result.record.is_some());
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

    /// REFUSED (and any other non-answer rcode) is not an answer: it must
    /// hard-reject, never demote the domain to the fallback path (audit
    /// 2026-11 D14; this flips the pre-audit expectation).
    #[test]
    fn test_refused_is_bogus_not_insecure() {
        for code in [ResponseCode::Refused, ResponseCode::NotImp, ResponseCode::FormErr] {
            let result = classify_response(&response(code, true, None), "example.com");
            assert_eq!(result.dnssec_status, DnssecStatus::Bogus, "{code}");
            assert!(result.record.is_none());
        }
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    /// Live DoT lookup against the default resolver — run with
    /// `cargo test -p browserid-dnssec -- --ignored` to validate the
    /// transport stack after dependency upgrades (audit L11: hickory 0.25 /
    /// rustls 0.23). sandmill.org publishes a signed _browserid record, so a
    /// working stack returns Secure with a record.
    #[tokio::test]
    #[ignore]
    async fn live_dot_lookup_secure_primary() {
        let fetcher = DnsFetcher::new().unwrap();
        let result = fetcher.lookup("sandmill.org").await;
        assert_eq!(result.dnssec_status, DnssecStatus::Secure, "{result:?}");
        assert!(result.record.is_some(), "{result:?}");
    }
}
