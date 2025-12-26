//! Assertion verification for BrowserID-NG
//!
//! Provides HTTP-based domain discovery and assertion verification.

use browserid_core::{
    discovery::{DiscoveryConfig, SupportDocument, SupportDocumentFetcher},
    BackedAssertion, Error as CoreError, Result as CoreResult,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// HTTP-based support document fetcher
pub struct HttpFetcher {
    client: Client,
    require_https: bool,
}

impl HttpFetcher {
    /// Create a new HTTP fetcher
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            require_https: true,
        }
    }

    /// Create a fetcher that allows HTTP (for testing/local development)
    pub fn allow_http() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            require_https: false,
        }
    }
}

impl SupportDocumentFetcher for HttpFetcher {
    fn fetch(&self, domain: &str) -> CoreResult<SupportDocument> {
        // Try HTTPS first, then HTTP if allowed
        let https_url = format!("https://{}/.well-known/browserid", domain);
        let http_url = format!("http://{}/.well-known/browserid", domain);

        let response = self.client.get(&https_url).send();

        let response = match response {
            Ok(r) if r.status().is_success() => r,
            _ if !self.require_https => {
                // Try HTTP as fallback
                self.client.get(&http_url).send().map_err(|e| {
                    CoreError::DiscoveryFailed {
                        domain: domain.to_string(),
                        reason: format!("HTTP request failed: {}", e),
                    }
                })?
            }
            Ok(r) => {
                return Err(CoreError::DiscoveryFailed {
                    domain: domain.to_string(),
                    reason: format!("HTTP error: {}", r.status()),
                });
            }
            Err(e) => {
                return Err(CoreError::DiscoveryFailed {
                    domain: domain.to_string(),
                    reason: format!("HTTPS request failed: {}", e),
                });
            }
        };

        if !response.status().is_success() {
            return Err(CoreError::DiscoveryFailed {
                domain: domain.to_string(),
                reason: format!("HTTP error: {}", response.status()),
            });
        }

        let doc: SupportDocument = response.json().map_err(|e| CoreError::DiscoveryFailed {
            domain: domain.to_string(),
            reason: format!("Invalid JSON: {}", e),
        })?;

        Ok(doc)
    }
}

/// Result of assertion verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether verification succeeded
    pub status: String,

    /// The verified email address (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// The issuing domain (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// Expiration timestamp (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<i64>,

    /// Error reason (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl VerificationResult {
    /// Create a successful verification result
    pub fn success(email: String, issuer: String, expires: i64) -> Self {
        Self {
            status: "okay".to_string(),
            email: Some(email),
            issuer: Some(issuer),
            expires: Some(expires),
            reason: None,
        }
    }

    /// Create a failed verification result
    pub fn failure(reason: String) -> Self {
        Self {
            status: "failure".to_string(),
            email: None,
            issuer: None,
            expires: None,
            reason: Some(reason),
        }
    }
}

/// Verify a backed identity assertion
///
/// Implements fallback broker support per original Persona logic:
/// 1. If issuer == trusted_broker (HOSTNAME), accept (fallback case)
/// 2. If issuer == email domain, accept (native IdP)
/// 3. If email domain delegates to issuer, accept (explicit delegation)
/// 4. Otherwise, reject
///
/// # Arguments
/// * `assertion` - The backed assertion string (certificate~assertion)
/// * `audience` - The expected audience (relying party origin)
/// * `trusted_broker` - The hostname of the trusted fallback broker
/// * `fetcher` - Implementation for fetching support documents
pub fn verify_assertion(
    assertion: &str,
    audience: &str,
    trusted_broker: &str,
    fetcher: &impl SupportDocumentFetcher,
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

    // Discovery config
    let config = DiscoveryConfig::default();

    // Per original Persona logic, check issuer authorization:
    // 1. issuer == trusted_broker (HOSTNAME) -> accept
    // 2. issuer == email_domain -> accept
    // 3. email_domain delegates to issuer -> accept
    // 4. otherwise -> reject

    let issuer_authorized = if issuer == trusted_broker {
        // Case 1: Issuer is the trusted fallback broker
        true
    } else if issuer == email_domain {
        // Case 2: Issuer matches email domain (native IdP)
        true
    } else {
        // Case 3: Check if email domain explicitly delegates to issuer
        match browserid_core::discovery::discover(&email_domain, fetcher, &config) {
            Ok(result) => {
                // Check if the authoritative domain (end of delegation chain) is the issuer
                result.domain == issuer
            }
            Err(_) => false, // No support document = no delegation
        }
    };

    if !issuer_authorized {
        return VerificationResult::failure(format!(
            "Issuer '{}' is not authorized to issue certificates for emails from '{}'",
            issuer, email_domain
        ));
    }

    // Issuer is authorized - now verify the cryptographic signatures
    verify_signatures(&backed, audience, &issuer, &email, expires, fetcher, &config)
}

/// Verify the cryptographic signatures in the assertion
fn verify_signatures(
    backed: &BackedAssertion,
    audience: &str,
    issuer: &str,
    email: &str,
    expires: i64,
    fetcher: &impl SupportDocumentFetcher,
    config: &DiscoveryConfig,
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

    // Fetch the issuer's (fallback broker's) public key
    let issuer_key = match browserid_core::discovery::discover(issuer, fetcher, config) {
        Ok(result) => result.document.public_key,
        Err(e) => {
            return VerificationResult::failure(format!(
                "Failed to discover issuer {}: {}",
                issuer, e
            ))
        }
    };

    // Verify certificate signature with issuer's key
    if let Err(e) = cert.verify(&issuer_key) {
        return VerificationResult::failure(format!("Certificate signature invalid: {}", e));
    }

    VerificationResult::success(email.to_string(), issuer.to_string(), expires)
}
