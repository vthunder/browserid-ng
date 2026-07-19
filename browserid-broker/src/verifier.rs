//! Access-presentation verification for BrowserID-NG (device-cert model)
//!
//! Provides HTTP-based domain discovery and DNSSEC-rooted verification of the
//! 4-object `access_cert~assertion~warrant~config_cert` presentation.

use browserid_core::{
    discovery::{SupportDocument, SupportDocumentFetcher},
    Error as CoreError, Result as CoreResult,
};
use reqwest::blocking::Client;
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

// ===========================================================================
// Device-cert model verification (DC Phase 6) — the 4-object presentation
// `access_cert ~ assertion ~ warrant ~ config_cert`, DNSSEC-rooted with the
// SAME primary/fallback conformance as `verify_assertion_with_dns`.
// ===========================================================================

/// Result of verifying a device-cert access presentation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AccessVerificationResult {
    pub status: String, // "okay" | "failure"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AccessVerificationResult {
    fn fail(reason: impl Into<String>) -> Self {
        Self { status: "failure".into(), email: None, subject: None, scopes: None, issuer: None, reason: Some(reason.into()) }
    }
}

/// Verify a device-cert `access_cert~assertion~warrant~config_cert` bundle.
///
/// Enforces conformance: the access cert AND config cert must be issued by the
/// identity's own IdP (a primary for a primary domain; an accepted fallback for a
/// no-primary domain). Because `AccessPresentation::verify` is sync and both certs
/// share one `iss`, we resolve that single issuer key up front (async) and hand it
/// to the sync join.
///
/// NOTE (P6 hardening TODO): the three status refs returned by the core verify are
/// not yet fetched fail-closed here — foreign status-list fetch (`StatusCache`)
/// lands with the warrant registry (P4). Revocation is therefore not yet enforced.
pub async fn verify_access_with_dns(
    presentation: &str,
    audience: &str,
    discoverer: &impl crate::fallback_fetcher::Discoverer,
    accepted_fallbacks: &[String],
) -> AccessVerificationResult {
    use browserid_core::device::{AccessPresentation, Subject};

    let pres = match AccessPresentation::parse(presentation) {
        Ok(p) => p,
        Err(e) => return AccessVerificationResult::fail(format!("parse: {e}")),
    };
    let ac = pres.access_cert.claims();
    let email = ac.identity.clone();
    let iss = ac.iss.clone();
    let email_domain = match email.split('@').nth(1) {
        Some(d) => d.to_string(),
        None => return AccessVerificationResult::fail("identity is not an email"),
    };

    let email_disc = match discoverer.discover(&email_domain).await {
        Ok(r) => r,
        Err(e) => return AccessVerificationResult::fail(format!("discovery failed: {e}")),
    };

    // Same conformance rule as the classic path.
    let key_doc = if email_disc.is_primary {
        if iss != email_domain {
            return AccessVerificationResult::fail(format!(
                "issuer '{iss}' is not authorized for primary domain '{email_domain}'"
            ));
        }
        email_disc.document
    } else {
        if !accepted_fallbacks.iter().any(|f| f == &iss) {
            return AccessVerificationResult::fail(format!("issuer '{iss}' is not an accepted fallback"));
        }
        if iss == email_disc.authoritative_domain {
            email_disc.document
        } else {
            match discoverer.discover(&iss).await {
                Ok(r) => r.document,
                Err(e) => return AccessVerificationResult::fail(format!("fallback discovery failed: {e}")),
            }
        }
    };
    let idp_key = match key_doc.public_key {
        Some(k) => k,
        None => return AccessVerificationResult::fail("issuer has no key"),
    };

    match pres.verify(audience, |req_iss| {
        if req_iss == iss {
            Ok(idp_key.clone())
        } else {
            Err(browserid_core::Error::InvalidProvisioning(format!("issuer '{req_iss}' not authoritative")))
        }
    }) {
        Ok(v) => AccessVerificationResult {
            status: "okay".into(),
            email: Some(v.email),
            subject: Some(match v.subject { Subject::User => "user".into(), Subject::Agent => "agent".into() }),
            scopes: Some(v.scopes),
            issuer: Some(v.issuer),
            reason: None,
        },
        Err(e) => AccessVerificationResult::fail(e.to_string()),
    }
}
