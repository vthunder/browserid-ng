//! Access-presentation verification for BrowserID-NG (device-cert model)
//!
//! Provides HTTP-based domain discovery and DNSSEC-rooted verification of the
//! 4-object `access_cert~assertion~warrant~config_cert` presentation.

use browserid_core::{
    discovery::{SupportDocument, SupportDocumentFetcher},
    Error as CoreError, Result as CoreResult, StatusListToken, StatusRef,
};
use reqwest::blocking::Client;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
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
    /// The ACTING identity — the warrant's grantee (== the access-cert
    /// identity). Equals `email` for an as-you presentation; differs when an
    /// agent acted on the attributed identity's behalf. RPs get both names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grantee: Option<String>,
    /// The opaque holder id the presentation carried (which of the user's
    /// things acted). Advisory; the old user/agent subject axis is gone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AccessVerificationResult {
    fn fail(reason: impl Into<String>) -> Self {
        Self { status: "failure".into(), email: None, grantee: None, holder: None, scopes: None, issuer: None, reason: Some(reason.into()) }
    }
}

/// Where a verifier resolves revocation status (core §6.4) — all three
/// checks fail-closed.
///
/// A ref whose `uri` is this deployment's **own** status list is checked
/// authoritatively against the local store (no network, no staleness). Any
/// other ref is a **foreign** list: fetched over HTTPS, bound to its
/// publishing authority (the list's `iss` claim MUST be the URI's host, and
/// the signature MUST verify under that domain's discovered key), and cached
/// while fresh. An unreachable, stale, or unverifiable list rejects the
/// presentation — "cannot prove unrevoked" is a failure, per spec §6.4.
pub struct StatusCtx<'a> {
    /// This deployment's own status-list URI
    /// (`browserid_registrar::consent::status_list_uri`)
    pub own_uri: String,
    /// Authoritative local check: is `idx` revoked on our own list?
    pub is_own_revoked: &'a (dyn Fn(u64) -> Result<bool, String> + Send + Sync),
    /// Cache of verified foreign list tokens, keyed by URI (see
    /// `AppState::status_lists`)
    pub cache: &'a RwLock<HashMap<String, StatusListToken>>,
}

fn status_http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build status HTTP client")
    })
}

/// The list's signer must be the URI's own host — the credential's issuer
/// chose the URI, and a list served there is only authoritative if signed by
/// that host's key (else a compromised host could serve someone else's
/// all-clear list).
fn uri_matches_issuer(uri: &str, iss: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(uri) else { return false };
    let Some(host) = u.host_str() else { return false };
    match u.port() {
        Some(p) => format!("{host}:{p}") == iss,
        None => host == iss,
    }
}

/// Check a foreign status ref fail-closed: `Ok(revoked)`, or `Err` when the
/// check cannot be made (which the caller MUST treat as a rejection).
async fn check_foreign_status(
    r: &StatusRef,
    discoverer: &impl crate::fallback_fetcher::Discoverer,
    cache: &RwLock<HashMap<String, StatusListToken>>,
) -> Result<bool, String> {
    // Fresh cached list → answer without network. (Scoped: the guard must not
    // live across an await.)
    {
        let lists = cache.read().unwrap();
        if let Some(tok) = lists.get(&r.uri) {
            if tok.is_fresh(0) {
                return Ok(tok.is_revoked(r.idx));
            }
        }
    }

    let body = status_http()
        .get(&r.uri)
        .send()
        .await
        .and_then(|resp| resp.error_for_status())
        .map_err(|e| format!("fetch {}: {e}", r.uri))?
        .text()
        .await
        .map_err(|e| format!("read {}: {e}", r.uri))?;
    let token = StatusListToken::parse(body.trim()).map_err(|e| e.to_string())?;

    let iss = token.claims().iss.clone();
    if !uri_matches_issuer(&r.uri, &iss) {
        return Err(format!("list at {} signed by non-authoritative issuer '{iss}'", r.uri));
    }
    let disc = discoverer
        .discover(&iss)
        .await
        .map_err(|e| format!("status issuer discovery '{iss}': {e}"))?;
    let key = disc
        .document
        .public_key
        .ok_or_else(|| format!("status issuer '{iss}' has no key"))?;
    token.verify(&key, &r.uri).map_err(|e| e.to_string())?;
    if !token.is_fresh(0) {
        return Err(format!("status list {} is stale", r.uri));
    }

    let revoked = token.is_revoked(r.idx);
    cache.write().unwrap().insert(r.uri.clone(), token);
    Ok(revoked)
}

/// Resolve the published IdP key for `iss`, enforcing that `iss` is
/// authoritative for `domain`: a primary domain must be served by its own
/// `iss == domain`; a no-primary domain must name an accepted fallback. This
/// is the conformance rule applied independently to each identity in a
/// presentation — the grantee (access cert) under its domain, and the grantor
/// (config cert) under its own, which need not be the same IdP.
async fn resolve_conformant_key(
    discoverer: &impl crate::fallback_fetcher::Discoverer,
    accepted_fallbacks: &[String],
    domain: &str,
    iss: &str,
) -> Result<browserid_core::PublicKey, String> {
    let disc = discoverer
        .discover(domain)
        .await
        .map_err(|e| format!("discovery failed: {e}"))?;
    let key_doc = if disc.is_primary {
        if iss != domain {
            return Err(format!("issuer '{iss}' is not authorized for primary domain '{domain}'"));
        }
        disc.document
    } else {
        if !accepted_fallbacks.iter().any(|f| f == iss) {
            return Err(format!("issuer '{iss}' is not an accepted fallback"));
        }
        if iss == disc.authoritative_domain {
            disc.document
        } else {
            discoverer
                .discover(iss)
                .await
                .map_err(|e| format!("fallback discovery failed: {e}"))?
                .document
        }
    };
    key_doc.public_key.ok_or_else(|| "issuer has no key".to_string())
}

/// Verify a device-cert `access_cert~assertion~warrant~config_cert` bundle.
///
/// Enforces conformance: the access cert AND config cert must each be issued
/// by their own identity's IdP (a primary for a primary domain; an accepted
/// fallback for a no-primary domain). The two issuers may differ — an
/// on-behalf-of warrant attributes to the GRANTOR (the config cert's
/// identity), whose IdP is not necessarily the grantee's — so both are
/// resolved up front and handed to the sync join.
///
/// Revocation (core §6.4): after the cryptographic join, the three status
/// refs (access cert, config cert, warrant) are checked **fail-closed**
/// through `status` — own-list refs against the local store, foreign refs by
/// authenticated fetch. A revoked bit or an uncheckable ref rejects.
pub async fn verify_access_with_dns(
    presentation: &str,
    audience: &str,
    discoverer: &impl crate::fallback_fetcher::Discoverer,
    accepted_fallbacks: &[String],
    status: StatusCtx<'_>,
) -> AccessVerificationResult {
    use browserid_core::device::AccessPresentation;

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

    // The GRANTOR's issuer — the config cert's — which may differ from the
    // grantee's (an on-behalf-of warrant where the actor and the identity it
    // speaks for live at different IdPs: e.g. an `@sandmill.org` agent posting
    // as an `@bsky.browserid.me` handle). `AccessPresentation::verify` asks the
    // resolver for BOTH issuers separately; resolving only the access cert's,
    // as this path once did, rejected every cross-issuer bundle — including an
    // IdP's own certs — as "not authoritative".
    let cc_iss = pres.config_cert.claims().iss.clone();
    let grantor = pres.warrant.claims().grantor.clone();
    let grantor_domain = match grantor.split('@').nth(1) {
        Some(d) => d.to_string(),
        None => return AccessVerificationResult::fail("warrant grantor is not an email"),
    };

    let access_key =
        match resolve_conformant_key(discoverer, accepted_fallbacks, &email_domain, &iss).await {
            Ok(k) => k,
            Err(e) => return AccessVerificationResult::fail(e),
        };
    // Reuse only when the grantor is the SAME identity domain under the SAME
    // issuer; otherwise resolve the grantor's IdP with the same conformance
    // rule applied to the grantor's domain.
    let config_key = if cc_iss == iss && grantor_domain == email_domain {
        access_key.clone()
    } else {
        match resolve_conformant_key(discoverer, accepted_fallbacks, &grantor_domain, &cc_iss).await
        {
            Ok(k) => k,
            Err(e) => return AccessVerificationResult::fail(e),
        }
    };

    let v = match pres.verify(audience, |req_iss| {
        if req_iss == iss {
            Ok(access_key.clone())
        } else if req_iss == cc_iss {
            Ok(config_key.clone())
        } else {
            Err(browserid_core::Error::InvalidProvisioning(format!("issuer '{req_iss}' not authoritative")))
        }
    }) {
        Ok(v) => v,
        Err(e) => return AccessVerificationResult::fail(e.to_string()),
    };

    // Three fail-closed status authorities (§6.4, §6.2 step 8).
    for (label, r) in [
        ("access cert", &v.access_status),
        ("config cert", &v.config_status),
        ("warrant", &v.warrant_status),
    ] {
        let Some(r) = r else { continue };
        let revoked = if r.uri == status.own_uri {
            (status.is_own_revoked)(r.idx)
        } else {
            check_foreign_status(r, discoverer, status.cache).await
        };
        match revoked {
            Ok(false) => {}
            Ok(true) => return AccessVerificationResult::fail(format!("{label} revoked")),
            Err(e) => {
                return AccessVerificationResult::fail(format!(
                    "{label} status unavailable (fail-closed): {e}"
                ))
            }
        }
    }

    AccessVerificationResult {
        status: "okay".into(),
        email: Some(v.email),
        grantee: Some(v.grantee),
        holder: Some(v.holder.as_str().to_string()),
        scopes: Some(v.scopes),
        issuer: Some(v.issuer),
        reason: None,
    }
}
