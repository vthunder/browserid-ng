//! Domain discovery for BrowserID-NG
//!
//! Discovers domain support by fetching `/.well-known/browserid`

use serde::{Deserialize, Serialize};

use crate::{PublicKey, Result};

/// A domain's BrowserID support document
///
/// Published at `https://<domain>/.well-known/browserid`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportDocument {
    /// The domain's public key for verifying certificates
    #[serde(rename = "public-key")]
    pub public_key: PublicKey,

    /// Path to the authentication page
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<String>,

    /// Path to the provisioning page
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioning: Option<String>,

    /// Delegation to another domain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,

    /// Whether this domain has explicitly disabled BrowserID support
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
}

impl SupportDocument {
    /// Create a new support document with just a public key
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            authentication: None,
            provisioning: None,
            authority: None,
            disabled: false,
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

    /// Create a delegation document
    pub fn delegate(authority: impl Into<String>) -> Self {
        Self {
            public_key: PublicKey::from_bytes(&[0u8; 32]).unwrap(), // placeholder
            authentication: None,
            provisioning: None,
            authority: Some(authority.into()),
            disabled: false,
        }
    }

    /// Create a disabled support document
    pub fn disabled() -> Self {
        Self {
            public_key: PublicKey::from_bytes(&[0u8; 32]).unwrap(), // placeholder
            authentication: None,
            provisioning: None,
            authority: None,
            disabled: true,
        }
    }

    /// Check if this domain has disabled BrowserID support
    pub fn is_disabled(&self) -> bool {
        self.disabled
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

        // Check if domain has disabled BrowserID support
        if doc.disabled {
            return Err(crate::Error::DiscoveryFailed {
                domain: domain.to_string(),
                reason: format!("{} has disabled BrowserID support", current_domain),
            });
        }

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
