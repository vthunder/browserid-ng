//! Domain discovery for BrowserID-NG
//!
//! A domain's identity key is discovered from its authenticated `_browserid`
//! DNSSEC record — the sole root of trust (browserid-ng-28uc). The
//! `/.well-known/browserid` support document is still fetched, but only for
//! endpoint discovery (authentication/provisioning paths); it is never a source
//! of trusted keys. This module models the support-document shape and parsing;
//! DNSSEC lookup + key resolution live in the broker's DNS/fallback fetchers.

use serde::{Deserialize, Serialize};

use crate::{PublicKey, Result};

/// A domain's BrowserID support document
///
/// Published at `https://<domain>/.well-known/browserid`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportDocument {
    /// The domain's public key for verifying certificates
    ///
    /// `None` for a delegation document, which carries no key of its own.
    #[serde(rename = "public-key", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,

    /// Path to the authentication page
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<String>,

    /// Path to the provisioning page
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioning: Option<String>,

    /// Delegation to another domain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,

    // --- Device-cert conformance (docs/design/browserid-end-to-end-flow.md) ---
    /// Path to the batch device-cert issuance API (session/interactive-authed):
    /// issues the user (authentication) + config (authorization) device certs.
    #[serde(rename = "device-cert", skip_serializing_if = "Option::is_none")]
    pub device_cert: Option<String>,

    /// Path to the headless access-cert mint API (the device cert is the
    /// credential — this is what lets agents mint with no browser).
    #[serde(rename = "access-cert", skip_serializing_if = "Option::is_none")]
    pub access_cert: Option<String>,

    /// Path to the browser-facing device-authorization page. The login dialog
    /// opens it in a popup with `#email=…&device_pubkey=…&config_pubkey=…&
    /// return_origin=…`; the page authenticates the user first-party, calls the
    /// domain's own device-cert API for those pubkeys, and posts
    /// `{type:'browserid:device_certs', device_cert, config_cert}` back to
    /// `window.opener` (targetOrigin = return_origin), then closes.
    #[serde(rename = "device-authorization", skip_serializing_if = "Option::is_none")]
    pub device_authorization: Option<String>,

    /// Path to the device-authorization page's AGENT mode (merged
    /// provisioning): the broker's approval page opens it with
    /// `#agent_email=…&agent_pubkey=…&holder=…` to have this IdP sign a
    /// NAMED-agent device cert (an identity differing from the session's, e.g.
    /// a `+tag` sub-address). Absent = named agents unsupported here; as-you
    /// agents need no support (they are indistinguishable from devices).
    #[serde(rename = "agent-device-authorization", skip_serializing_if = "Option::is_none")]
    pub agent_device_authorization: Option<String>,
}

impl SupportDocument {
    /// Create a new support document with just a public key
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            public_key: Some(public_key),
            authentication: None,
            provisioning: None,
            authority: None,
            device_cert: None,
            access_cert: None,
            device_authorization: None,
            agent_device_authorization: None,
        }
    }

    /// Set the authentication path
    pub fn with_authentication(mut self, path: impl Into<String>) -> Self {
        self.authentication = Some(path.into());
        self
    }

    /// Set the provisioning path
    pub fn with_provisioning(mut self, path: impl Into<String>) -> Self {
        self.provisioning = Some(path.into());
        self
    }

    /// Set the device-cert issuance API path
    pub fn with_device_cert(mut self, path: impl Into<String>) -> Self {
        self.device_cert = Some(path.into());
        self
    }

    /// Set the headless access-cert mint API path
    pub fn with_access_cert(mut self, path: impl Into<String>) -> Self {
        self.access_cert = Some(path.into());
        self
    }

    /// Set the browser-facing device-authorization page path
    pub fn with_device_authorization(mut self, path: impl Into<String>) -> Self {
        self.device_authorization = Some(path.into());
        self
    }

    pub fn with_agent_device_authorization(mut self, path: impl Into<String>) -> Self {
        self.agent_device_authorization = Some(path.into());
        self
    }

    /// Create a delegation document
    pub fn delegate(authority: impl Into<String>) -> Self {
        Self {
            public_key: None,
            authentication: None,
            provisioning: None,
            authority: Some(authority.into()),
            device_cert: None,
            access_cert: None,
            device_authorization: None,
            agent_device_authorization: None,
        }
    }

    /// Check if this is a delegation
    pub fn is_delegation(&self) -> bool {
        self.authority.is_some()
    }
}

/// Configuration for domain discovery
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Maximum number of delegation hops to follow
    pub max_delegation_depth: usize,

    /// Whether to require HTTPS
    pub require_https: bool,

    /// Fallback broker domain for domains without native support
    pub fallback_broker: Option<String>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            max_delegation_depth: 5,
            require_https: true,
            fallback_broker: None,
        }
    }
}

/// Trait for fetching support documents
///
/// This allows different implementations:
/// - HTTP fetcher (production)
/// - Mock fetcher (testing)
/// - DNSSEC-verified fetcher (future)
pub trait SupportDocumentFetcher {
    /// Fetch the support document for a domain
    fn fetch(&self, domain: &str) -> Result<SupportDocument>;
}

/// Result of domain discovery
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    /// The resolved domain (after following delegations)
    pub domain: String,

    /// The support document
    pub document: SupportDocument,

    /// The delegation chain followed (if any)
    pub delegation_chain: Vec<String>,
}

/// Discover BrowserID support for a domain
pub fn discover<F: SupportDocumentFetcher>(
    domain: &str,
    fetcher: &F,
    config: &DiscoveryConfig,
) -> Result<DiscoveryResult> {
    let mut current_domain = domain.to_string();
    let mut delegation_chain = Vec::new();
    let mut visited = std::collections::HashSet::new();

    for _ in 0..config.max_delegation_depth {
        let doc = fetcher.fetch(&current_domain)?;

        if let Some(ref authority) = doc.authority {
            // Check for self-delegation
            if authority == &current_domain {
                return Err(crate::Error::DiscoveryFailed {
                    domain: domain.to_string(),
                    reason: format!(
                        "Circular reference in delegating authority: {} > {}",
                        current_domain, authority
                    ),
                });
            }

            // Check for circular reference
            if visited.contains(authority) || authority == domain {
                let chain_str = delegation_chain.join(" > ");
                return Err(crate::Error::DiscoveryFailed {
                    domain: domain.to_string(),
                    reason: format!(
                        "Circular reference in delegating authority: {} > {}",
                        chain_str, authority
                    ),
                });
            }

            // Follow delegation
            visited.insert(current_domain.clone());
            delegation_chain.push(current_domain.clone());
            current_domain = authority.clone();
        } else {
            // Found final document
            return Ok(DiscoveryResult {
                domain: current_domain,
                document: doc,
                delegation_chain,
            });
        }
    }

    // Build the chain string for the error message
    let mut chain_parts = delegation_chain.clone();
    chain_parts.push(current_domain);
    let chain_str = chain_parts.join(" > ");

    Err(crate::Error::DiscoveryFailed {
        domain: domain.to_string(),
        reason: format!("Too many hops while delegating authority: {}", chain_str),
    })
}

/// Extract domain from email address
pub fn domain_from_email(email: &str) -> Option<&str> {
    email.split('@').nth(1)
}

/// Build the well-known URL for a domain
pub fn well_known_url(domain: &str, https: bool) -> String {
    let scheme = if https { "https" } else { "http" };
    format!("{}://{}/.well-known/browserid", scheme, domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;
    use std::collections::HashMap;

    struct MockFetcher {
        documents: HashMap<String, SupportDocument>,
    }

    impl SupportDocumentFetcher for MockFetcher {
        fn fetch(&self, domain: &str) -> Result<SupportDocument> {
            self.documents.get(domain).cloned().ok_or_else(|| {
                crate::Error::DiscoveryFailed {
                    domain: domain.to_string(),
                    reason: "not found".into(),
                }
            })
        }
    }

    #[test]
    fn test_discover_direct() {
        let key = KeyPair::generate();
        let mut fetcher = MockFetcher {
            documents: HashMap::new(),
        };
        fetcher.documents.insert(
            "example.com".to_string(),
            SupportDocument::new(key.public_key())
                .with_authentication("/auth")
                .with_provisioning("/provision"),
        );

        let config = DiscoveryConfig::default();
        let result = discover("example.com", &fetcher, &config).unwrap();

        assert_eq!(result.domain, "example.com");
        assert!(result.delegation_chain.is_empty());
        assert_eq!(result.document.authentication, Some("/auth".to_string()));
    }

    #[test]
    fn test_discover_with_delegation() {
        let key = KeyPair::generate();
        let mut fetcher = MockFetcher {
            documents: HashMap::new(),
        };

        // example.com delegates to idp.example.net
        fetcher
            .documents
            .insert("example.com".to_string(), SupportDocument::delegate("idp.example.net"));

        fetcher.documents.insert(
            "idp.example.net".to_string(),
            SupportDocument::new(key.public_key()),
        );

        let config = DiscoveryConfig::default();
        let result = discover("example.com", &fetcher, &config).unwrap();

        assert_eq!(result.domain, "idp.example.net");
        assert_eq!(result.delegation_chain, vec!["example.com"]);
    }

    #[test]
    fn test_domain_from_email() {
        assert_eq!(domain_from_email("alice@example.com"), Some("example.com"));
        assert_eq!(domain_from_email("bob@sub.example.org"), Some("sub.example.org"));
        assert_eq!(domain_from_email("invalid"), None);
    }

    #[test]
    fn test_support_document_serialization() {
        let key = KeyPair::generate();
        let doc = SupportDocument::new(key.public_key())
            .with_authentication("/browserid/auth")
            .with_provisioning("/browserid/provision");

        let json = serde_json::to_string_pretty(&doc).unwrap();
        println!("{}", json);

        let parsed: SupportDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.authentication, Some("/browserid/auth".to_string()));
    }
}
