//! Claim-time authority hierarchy for no-primary domains (browserid-ng-tsqk).
//!
//! Before the fallback issues for a domain it must decide **which proof it
//! will demand**. For a domain with no DNSSEC-validated `_browserid` record
//! (that case is a primary — we do not issue at all), the precedence is:
//!
//! 1. a *resolved* atproto handle binding → prove ownership via atproto OAuth
//! 2. an MX record → prove ownership via the SMTP verification loop
//! 3. otherwise → refuse the claim
//!
//! This is a **claim-routing rule, not a verification rule**: RPs never
//! evaluate it, and the verifier is untouched. It is re-derived on every
//! issuance — no pinning — because whoever can publish `_atproto` for a name
//! can already redirect its MX, so pinning would buy detection rather than
//! prevention while blocking legitimate migrations.
//!
//! The atproto presence check is delegated to the bsky bridge's
//! `/idp/resolve` endpoint (the bridge is the atproto specialist and a
//! trusted internal component of the fallback; see
//! `docs/plans/2026-07-30-handle-identities-and-the-authority-hierarchy.md`).
//! Both probes fail open on *transport* failure — an unreachable bridge
//! reads as "not a handle" and an unanswerable MX query as "accepts mail" —
//! so an outage degrades to today's behavior instead of locking every
//! sign-in out. A *definitive* empty answer is not an outage and does gate.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::dns_fetcher::DnsFetcher;

/// How long a hierarchy answer for a domain may be reused. Matches the
/// bridge's resolve-cache bound so no claim decision rests on a binding
/// older than the atproto side would itself accept.
pub const AUTHORITY_CACHE_SECONDS: u64 = 600;

/// Timeout for one probe of the bridge's resolve endpoint. The bridge does
/// real resolution work (DoH + a well-known fetch) on a cold domain, so this
/// is generous — but bounded, because `address_info` sits on the dialog's
/// critical path.
const BRIDGE_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The proof method the hierarchy demands for a no-primary domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecondaryAuthority {
    /// The domain is a resolved atproto handle binding: ownership is proven
    /// via atproto OAuth at the bridge, and the proven party owns every
    /// label at the domain.
    Atproto {
        /// The DID the handle resolved to when the decision was made.
        did: String,
    },
    /// The domain accepts mail: ownership of one local part is proven via
    /// the SMTP verification loop.
    Smtp,
    /// No proof method exists — the claim is refused.
    Unprovable,
}

/// How the checker answers "is this domain a resolved handle binding?".
pub enum HandleProbe {
    /// Ask the bsky bridge's `GET /idp/resolve?domain=` endpoint.
    Bridge { url: String, http: reqwest::Client },
    /// Tests: a fixed domain → DID map.
    Static(HashMap<String, String>),
    /// The atproto lane is off: every domain reads as not-a-handle.
    Disabled,
}

/// How the checker answers "does this domain accept mail?".
pub enum MxProbe {
    /// A real MX lookup over the authenticated DoT channel.
    Dns(DnsFetcher),
    /// Tests: the set of domains that have MX.
    Static(HashSet<String>),
    /// The MX gate is off: every domain reads as accepting mail.
    Off,
}

/// Runs steps 2–4 of the hierarchy (step 1, the DNSSEC `_browserid` check,
/// is the existing primary discovery in `fallback_fetcher`). Answers are
/// cached per domain for [`AUTHORITY_CACHE_SECONDS`] — the probes are
/// network round-trips and `address_info` runs on every keystroke-debounced
/// email entry, so an uncached check on that path is not acceptable.
pub struct AuthorityChecker {
    handles: HandleProbe,
    mx: MxProbe,
    /// Where the dialog sends the user to claim a handle identity, when the
    /// atproto lane is live (the bridge's claim page).
    claim_url: Option<String>,
    cache: RwLock<HashMap<String, (SecondaryAuthority, Instant)>>,
}

impl AuthorityChecker {
    pub fn new(handles: HandleProbe, mx: MxProbe) -> Self {
        let claim_url = match &handles {
            HandleProbe::Bridge { url, .. } => {
                Some(format!("{}/idp/claim", url.trim_end_matches('/')))
            }
            _ => None,
        };
        Self {
            handles,
            mx,
            claim_url,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Both probes off: identical behavior to before the hierarchy existed
    /// (everything reads as SMTP-provable). The default for unit tests and
    /// the explicit opt-out for deployments.
    pub fn disabled() -> Self {
        Self::new(HandleProbe::Disabled, MxProbe::Off)
    }

    /// Tests: fixed answers plus a fixed claim URL.
    pub fn fixed(
        handles: HashMap<String, String>,
        mx: HashSet<String>,
        claim_url: Option<String>,
    ) -> Self {
        let mut checker = Self::new(HandleProbe::Static(handles), MxProbe::Static(mx));
        checker.claim_url = claim_url;
        checker
    }

    /// The bridge claim page for the atproto lane, if one is configured.
    pub fn claim_url(&self) -> Option<String> {
        self.claim_url.clone()
    }

    /// Steps 2–4 of the hierarchy for a domain already known to have no
    /// primary. Never errors: outages degrade (see module docs) rather than
    /// failing the caller.
    pub async fn no_primary_authority(&self, domain: &str) -> SecondaryAuthority {
        let domain = domain.to_ascii_lowercase();

        // Local dev domains are never probed — no DNS, no bridge; they keep
        // the SMTP loop (which dev runs with a console/mock sender anyway).
        if domain.starts_with("localhost") || domain.starts_with("127.") {
            return SecondaryAuthority::Smtp;
        }

        if let Some((authority, at)) = self.cache.read().unwrap().get(&domain).cloned() {
            if at.elapsed() < Duration::from_secs(AUTHORITY_CACHE_SECONDS) {
                return authority;
            }
        }

        let authority = if let Some(did) = self.handle_did(&domain).await {
            SecondaryAuthority::Atproto { did }
        } else if self.has_mx(&domain).await {
            SecondaryAuthority::Smtp
        } else {
            SecondaryAuthority::Unprovable
        };

        self.cache
            .write()
            .unwrap()
            .insert(domain, (authority.clone(), Instant::now()));
        authority
    }

    /// Step 2: a binding that *resolves* — both atproto resolution methods,
    /// DNS wins on conflict, mandatory bidirectional `alsoKnownAs` check.
    /// All of that lives in the bridge; here it is one HTTP question. `None`
    /// covers "not a handle", "cannot tell right now", and "lane disabled"
    /// alike: a binding we cannot resolve is not one we may rely on, and the
    /// hierarchy falls through to MX.
    async fn handle_did(&self, domain: &str) -> Option<String> {
        match &self.handles {
            HandleProbe::Disabled => None,
            HandleProbe::Static(map) => map.get(domain).cloned(),
            HandleProbe::Bridge { url, http } => {
                let resp = http
                    .get(format!("{}/idp/resolve", url.trim_end_matches('/')))
                    .query(&[("domain", domain)])
                    .timeout(BRIDGE_PROBE_TIMEOUT)
                    .send()
                    .await
                    .and_then(|r| r.error_for_status())
                    .map_err(|e| {
                        tracing::warn!(%domain, "bridge resolve probe failed: {e}");
                    })
                    .ok()?;
                let body: serde_json::Value = resp.json().await.ok()?;
                if body.get("valid").and_then(|v| v.as_bool()) != Some(true) {
                    return None;
                }
                body.get("did").and_then(|d| d.as_str()).map(str::to_string)
            }
        }
    }

    /// Step 3: does the domain accept mail? Presence of a usable MX record,
    /// per the design — the RFC 5321 implicit-MX fallback is deliberately
    /// not honored as a proof route.
    async fn has_mx(&self, domain: &str) -> bool {
        match &self.mx {
            MxProbe::Off => true,
            MxProbe::Static(set) => set.contains(domain),
            MxProbe::Dns(fetcher) => match fetcher.lookup_mx(domain).await {
                Ok(present) => present,
                Err(e) => {
                    tracing::warn!(%domain, "MX probe failed ({e}); failing open");
                    true
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checker(
        handles: &[(&str, &str)],
        mx: &[&str],
    ) -> AuthorityChecker {
        AuthorityChecker::fixed(
            handles
                .iter()
                .map(|(d, did)| (d.to_string(), did.to_string()))
                .collect(),
            mx.iter().map(|d| d.to_string()).collect(),
            Some("https://bridge.test/idp/claim".into()),
        )
    }

    /// The precedence order itself: a resolved handle binding outranks MX
    /// even when both exist (the documented A/B conflation decision), MX
    /// carries a plain mail domain, and a domain with neither is refused.
    #[tokio::test]
    async fn the_hierarchy_orders_atproto_over_smtp_over_refusal() {
        let c = checker(
            &[("dan.bsky.social", "did:plc:dan"), ("both.example", "did:plc:both")],
            &["gmail.com", "both.example"],
        );
        assert_eq!(
            c.no_primary_authority("dan.bsky.social").await,
            SecondaryAuthority::Atproto { did: "did:plc:dan".into() }
        );
        assert_eq!(
            c.no_primary_authority("both.example").await,
            SecondaryAuthority::Atproto { did: "did:plc:both".into() }
        );
        assert_eq!(c.no_primary_authority("gmail.com").await, SecondaryAuthority::Smtp);
        assert_eq!(
            c.no_primary_authority("no-proof.example").await,
            SecondaryAuthority::Unprovable
        );
    }

    #[tokio::test]
    async fn domains_are_case_insensitive() {
        let c = checker(&[("dan.bsky.social", "did:plc:dan")], &[]);
        assert!(matches!(
            c.no_primary_authority("Dan.BSKY.Social").await,
            SecondaryAuthority::Atproto { .. }
        ));
    }

    /// Local dev domains never hit a probe: a broker on localhost must keep
    /// working with no network and no bridge.
    #[tokio::test]
    async fn localhost_is_always_smtp() {
        let c = checker(&[], &[]);
        assert_eq!(c.no_primary_authority("localhost:3000").await, SecondaryAuthority::Smtp);
        assert_eq!(c.no_primary_authority("127.0.0.1:3000").await, SecondaryAuthority::Smtp);
        // …while a real domain with no proof is still refused.
        assert_eq!(c.no_primary_authority("x.example").await, SecondaryAuthority::Unprovable);
    }

    /// The opt-out preserves pre-hierarchy behavior exactly.
    #[tokio::test]
    async fn disabled_checker_reads_everything_as_smtp() {
        let c = AuthorityChecker::disabled();
        assert_eq!(c.no_primary_authority("anything.example").await, SecondaryAuthority::Smtp);
        assert_eq!(c.claim_url(), None);
    }

    /// The claim URL is derived from the bridge base, since that is where
    /// the dialog must send the user for the atproto proof.
    #[test]
    fn bridge_probe_derives_the_claim_url() {
        let c = AuthorityChecker::new(
            HandleProbe::Bridge {
                url: "https://bsky.browserid.me/".into(),
                http: reqwest::Client::new(),
            },
            MxProbe::Off,
        );
        assert_eq!(c.claim_url().as_deref(), Some("https://bsky.browserid.me/idp/claim"));
    }

    /// Answers are cached: mutating the world behind the probe within the
    /// TTL does not change the answer, which is what keeps the probes off
    /// the per-request critical path.
    #[tokio::test]
    async fn answers_are_cached_per_domain() {
        let c = checker(&[("d.example", "did:plc:d")], &[]);
        assert!(matches!(
            c.no_primary_authority("d.example").await,
            SecondaryAuthority::Atproto { .. }
        ));
        // Swap the probe out from under the checker; the cached answer holds.
        let cached = std::mem::take(&mut *c.cache.write().unwrap());
        let c = AuthorityChecker {
            handles: HandleProbe::Disabled,
            mx: MxProbe::Static(HashSet::new()),
            claim_url: None,
            cache: RwLock::new(cached),
        };
        assert!(matches!(
            c.no_primary_authority("d.example").await,
            SecondaryAuthority::Atproto { .. }
        ));
    }
}
