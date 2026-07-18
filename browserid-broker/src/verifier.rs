//! Assertion verification for BrowserID-NG
//!
//! Provides HTTP-based domain discovery and assertion verification.

use browserid_core::{
    discovery::{SupportDocument, SupportDocumentFetcher},
    BackedAssertion, Error as CoreError, Result as CoreResult,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::fallback_fetcher::Discoverer;

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

/// Agent attribution in a verification result (spec §5.3 step 5)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResult {
    /// The delegator this agent acts for
    pub parent: String,
    /// Scopes the delegator's warrant grants at this audience
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
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

    /// Agent attribution — present iff the presentation was an agent's
    /// (agent certificate + verified warrant)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentResult>,

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
            agent: None,
            reason: None,
        }
    }

    /// Attach agent attribution to a successful result
    pub fn with_agent(mut self, parent: String, scopes: Vec<String>) -> Self {
        self.agent = Some(AgentResult { parent, scopes });
        self
    }

    /// Create a failed verification result
    pub fn failure(reason: String) -> Self {
        Self {
            status: "failure".to_string(),
            email: None,
            issuer: None,
            expires: None,
            agent: None,
            reason: Some(reason),
        }
    }
}

/// Verify a backed identity assertion, with the issuer's identity key resolved
/// SOLELY via DNSSEC (browserid-ng-28uc). There is no `.well-known`-only key
/// trust and therefore no downgrade: a domain is a primary IdP only if it
/// publishes an authenticated `_browserid` DNSSEC record; otherwise the only
/// acceptable issuer is the trusted broker (which is itself DNSSEC-rooted).
///
/// `.well-known` is still consulted, but only for endpoint discovery — never as
/// a source of trusted keys.
///
/// # Arguments
/// * `assertion` - The backed assertion string (certificate~assertion)
/// * `audience` - The expected audience (relying party origin)
/// * `discoverer` - DNSSEC-first discovery (production: `FallbackFetcher`)
/// * `accepted_fallbacks` - the fallback-IdP issuer domains the RP accepts for
///   no-primary emails (spec §8.1). Primaries are always accepted regardless.
///   Pass `&[<this broker's domain>]` for the default (broker-only) policy.
pub async fn verify_assertion_with_dns(
    assertion: &str,
    audience: &str,
    discoverer: &impl Discoverer,
    accepted_fallbacks: &[String],
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

    // Discover the email domain (DNSSEC-first) to decide primary vs fallback.
    let email_disc = match discoverer.discover(&email_domain).await {
        Ok(r) => r,
        Err(e) => return VerificationResult::failure(format!("Discovery failed: {}", e)),
    };

    // Authorize the issuer and resolve the key document to verify against.
    let key_doc = if email_disc.is_primary {
        // Primary domain: only its own primary may vouch for it — no fallback
        // override. (Primaries are always accepted; §8.1's set is the no-primary
        // path only.)
        if issuer != email_domain {
            return VerificationResult::failure(format!(
                "Issuer '{}' is not authorized for primary domain '{}'",
                issuer, email_domain
            ));
        }
        email_disc.document
    } else {
        // No primary: the issuer must be a fallback IdP the RP accepts (§8.1).
        if !accepted_fallbacks.iter().any(|f| f == &issuer) {
            return VerificationResult::failure(format!(
                "Issuer '{}' is not an accepted fallback",
                issuer
            ));
        }
        // The accepted fallback's identity key is resolved via ITS OWN DNSSEC
        // record — reusing the broker doc we already fetched when the issuer is
        // that broker, else discovering the issuer directly.
        if issuer == email_disc.authoritative_domain {
            email_disc.document
        } else {
            match discoverer.discover(&issuer).await {
                Ok(r) => r.document,
                Err(e) => {
                    return VerificationResult::failure(format!(
                        "Discovery of accepted fallback '{}' failed: {}",
                        issuer, e
                    ))
                }
            }
        }
    };

    verify_signatures_with_doc(&backed, audience, &issuer, &email, expires, &key_doc)
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
    let issuer_key = match &doc.public_key {
        Some(key) => key,
        None => {
            return VerificationResult::failure(format!(
                "Issuer {} published no public key",
                issuer
            ))
        }
    };
    if let Err(e) = cert.verify(issuer_key) {
        return VerificationResult::failure(format!("Certificate signature invalid: {}", e));
    }

    // Agent presentation (spec §5.3): the warrant is load-bearing. Parse
    // already rejects an agent cert without one; verify it against the same
    // issuer key (delegator and agent share one IdP — identity-domain rule)
    // and surface the attribution.
    if cert.is_agent() {
        let warrant = match backed.warrant() {
            Some(w) => w,
            None => {
                return VerificationResult::failure(
                    "Agent certificate requires a warrant".to_string(),
                )
            }
        };
        return match warrant.verify_for(cert, audience, issuer_key) {
            Ok(scopes) => {
                let parent = cert.agent_parent().unwrap_or_default().to_string();
                VerificationResult::success(email.to_string(), issuer.to_string(), expires)
                    .with_agent(parent, scopes)
            }
            Err(e) => VerificationResult::failure(format!("Warrant invalid: {}", e)),
        };
    }

    VerificationResult::success(email.to_string(), issuer.to_string(), expires)
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
