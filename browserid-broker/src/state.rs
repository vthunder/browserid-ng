//! Application state for the broker

use std::collections::HashMap;
use std::sync::Arc;

use browserid_core::KeyPair;
use tokio::sync::{OnceCell, RwLock};

use crate::email::EmailSender;
use crate::fallback_fetcher::FallbackFetcher;
use crate::store::{SessionStore, UserStore};

/// Mock primary IdP configuration for testing
#[derive(Debug, Clone)]
pub struct MockPrimaryIdp {
    /// Authentication URL path (e.g., "/browserid/auth")
    pub auth_path: String,
    /// Provisioning URL path (e.g., "/browserid/provision")
    pub prov_path: String,
    /// Base URL for the IdP (e.g., "http://localhost:4000")
    pub base_url: String,
}

/// Shared application state
pub struct AppState<U: UserStore, S: SessionStore, E: EmailSender> {
    /// The broker's signing keypair
    pub keypair: KeyPair,
    /// The broker's domain (e.g., "localhost:3000")
    pub domain: String,
    /// User and email storage
    pub user_store: Arc<U>,
    /// Session storage
    pub session_store: Arc<S>,
    /// Email sender
    pub email_sender: Arc<E>,
    /// Lazy-initialized fallback fetcher for DNS-first discovery
    pub fallback_fetcher: OnceCell<Arc<FallbackFetcher>>,
    /// Mock primary IdPs for testing (domain -> config)
    pub mock_primary_idps: RwLock<HashMap<String, MockPrimaryIdp>>,
    /// Whether headless agent provisioning (`/agent/*` + API-key management)
    /// is enabled on this deployment (l8lw). Off by default; the dedicated
    /// agent IdP deployment turns it on.
    pub agent_provisioning_enabled: bool,
    /// Per-user cap on active (non-revoked) agent identities — the sybil
    /// limit that replaces SMTP friction for headless issuance
    pub max_agent_identities_per_user: usize,
    /// Whether the `/wsapi/test/*` helper routes are mounted. These expose raw
    /// verification codes and mock-IdP controls, so they are an account-takeover
    /// primitive in production and MUST stay off there. Off by default; only
    /// dev/test (no real SMTP) turns it on.
    pub test_endpoints_enabled: bool,
    /// Per-address throttle for outbound verification/reset emails: address
    /// (lowercased) -> time of the last send. Bounds email-bombing and code
    /// spam server-side (the client cooldown is only a UX hint).
    pub email_send_times: RwLock<HashMap<String, chrono::DateTime<chrono::Utc>>>,
    /// Origin of the separate static marketing site (e.g.
    /// `https://www.browserid.me`), when the origin split is deployed. When set,
    /// the broker (auth/issuer origin) redirects the public marketing routes
    /// (`/` and the guestbook page) there, keeping keystore/cookies/wsapi on this
    /// origin only. Unset locally → the broker still serves those pages itself.
    pub marketing_url: Option<String>,
    /// Server-side product analytics (the auth-origin funnel). Disabled unless
    /// `POSTHOG_TOKEN` is set. No analytics JS runs on the auth origin; the
    /// funnel is emitted from handlers, PII-safe. See `crate::analytics`.
    pub analytics: crate::analytics::Analytics,
    /// FedCM silent-auto-login consent (browserid-ng-mhyp): session id -> the RP
    /// origins the user opted into SILENT auto-login for. Server-side enforcement:
    /// `/fedcm/assertion` refuses an *auto-selected* (silent) assertion unless the
    /// (session, RP) pair is present. An *interactive* FedCM selection records it;
    /// RP logout (`/fedcm/reset`) clears it. Ephemeral (in-memory) — a restart
    /// forces re-opt-in, which is safe.
    pub fedcm_autologin: RwLock<HashMap<String, std::collections::HashSet<String>>>,
    /// Test override for the registrar's foreign-IdP key discovery (external
    /// warrant requests, §6.6). Production leaves this `None` and gets the
    /// DNSSEC-rooted fallback fetcher.
    pub issuer_resolver_override: Option<Arc<dyn browserid_registrar::IssuerKeyResolver>>,
    /// The one attestor domain whose handle attestations
    /// `complete_handle_claim` accepts (browserid-ng-tsqk) — the bsky
    /// bridge's host, derived from `ATPROTO_BRIDGE_URL`. `None` disables the
    /// route.
    pub handle_attestor: Option<String>,
    /// Test override for the attestor's signing key. Production resolves it
    /// via DNSSEC primary discovery of the attestor domain.
    pub handle_attestor_key_override: Option<browserid_core::PublicKey>,
    /// Redeemed attestation `jti`s, kept until their `exp` (replay guard).
    /// std RwLock: never held across an await.
    pub used_attestation_jtis: std::sync::RwLock<HashMap<String, i64>>,
    /// Claim-time authority hierarchy for no-primary domains
    /// (browserid-ng-tsqk): which proof — atproto OAuth, the SMTP loop, or
    /// none — the fallback demands before issuing. Defaults to disabled
    /// (everything reads as SMTP-provable, the pre-hierarchy behavior);
    /// `main.rs` wires the real bridge + MX probes.
    pub authority: crate::authority::AuthorityChecker,
    /// Cache of verified **foreign** status-list tokens (core §6.4), keyed by
    /// list URI. Populated/refreshed by the fail-closed status check in
    /// `verifier::verify_access_with_dns`; own-list refs never land here
    /// (they are checked authoritatively against the store). std RwLock:
    /// never held across an await.
    pub foreign_status_lists: std::sync::RwLock<HashMap<String, browserid_core::StatusListToken>>,
    /// Per-client-IP password-login throttle (bean ytjn): fixed-window failed-
    /// attempt counts on `/wsapi/authenticate_user`, keyed by client IP so a
    /// brute-forcer is throttled without letting anyone lock out a victim
    /// account. Auto-resets each window (no permanent lockout). std RwLock:
    /// never held across an await.
    pub login_attempts: std::sync::RwLock<HashMap<String, (std::time::Instant, u32)>>,
    /// Hosted-primary tenant key sealing (bean g5qt). `None` = the keystore
    /// secret is not configured; tenant onboarding is refused, everything
    /// else is unaffected.
    pub tenant_keystore: Option<crate::tenant_keys::KeystoreKey>,
    /// Host serving the hosted-primary §7 surface — what tenants' DNS
    /// records name in `host=` (e.g. `idp.browserid.me`; the broker's own
    /// host locally). Used to build the tenant support doc's absolute
    /// status URIs and the generated DNS record text.
    pub idp_host: String,
    /// OIDC claim ceremony (browserid-ng-qer8): claim a Google-hosted
    /// mailbox by signing in with Google instead of a mailed code. `None`
    /// (no `OIDC_GOOGLE_CLIENT_ID/SECRET`) keeps the whole bridge inert —
    /// `/oidc/*` refuses and `address_info` never advertises the ceremony.
    pub oidc: Option<crate::oidc::OidcRuntime>,
}

/// Default per-user agent identity quota
pub const DEFAULT_AGENT_QUOTA: usize = 50;

/// Minimum spacing between verification/reset emails to one address.
pub const EMAIL_SEND_COOLDOWN_SECS: i64 = 300;

impl<U: UserStore, S: SessionStore, E: EmailSender> AppState<U, S, E> {
    pub fn new(
        keypair: KeyPair,
        domain: String,
        user_store: U,
        session_store: S,
        email_sender: E,
    ) -> Self {
        let domain_for_idp = domain.clone();
        Self {
            keypair,
            domain,
            user_store: Arc::new(user_store),
            session_store: Arc::new(session_store),
            email_sender: Arc::new(email_sender),
            fallback_fetcher: OnceCell::new(),
            mock_primary_idps: RwLock::new(HashMap::new()),
            agent_provisioning_enabled: false,
            max_agent_identities_per_user: DEFAULT_AGENT_QUOTA,
            test_endpoints_enabled: false,
            email_send_times: RwLock::new(HashMap::new()),
            marketing_url: None,
            analytics: crate::analytics::Analytics::disabled(),
            fedcm_autologin: RwLock::new(HashMap::new()),
            issuer_resolver_override: None,
            handle_attestor: None,
            handle_attestor_key_override: None,
            used_attestation_jtis: std::sync::RwLock::new(HashMap::new()),
            authority: crate::authority::AuthorityChecker::disabled(),
            foreign_status_lists: std::sync::RwLock::new(HashMap::new()),
            login_attempts: std::sync::RwLock::new(HashMap::new()),
            tenant_keystore: None,
            idp_host: domain_for_idp,
            oidc: None,
        }
    }

    /// Create AppState with pre-wrapped Arc stores (useful for testing)
    pub fn new_with_arcs(
        keypair: KeyPair,
        domain: String,
        user_store: Arc<U>,
        session_store: Arc<S>,
        email_sender: Arc<E>,
    ) -> Self {
        let domain_for_idp = domain.clone();
        Self {
            keypair,
            domain,
            user_store,
            session_store,
            email_sender,
            fallback_fetcher: OnceCell::new(),
            mock_primary_idps: RwLock::new(HashMap::new()),
            agent_provisioning_enabled: false,
            max_agent_identities_per_user: DEFAULT_AGENT_QUOTA,
            test_endpoints_enabled: false,
            email_send_times: RwLock::new(HashMap::new()),
            marketing_url: None,
            analytics: crate::analytics::Analytics::disabled(),
            fedcm_autologin: RwLock::new(HashMap::new()),
            issuer_resolver_override: None,
            handle_attestor: None,
            handle_attestor_key_override: None,
            used_attestation_jtis: std::sync::RwLock::new(HashMap::new()),
            authority: crate::authority::AuthorityChecker::disabled(),
            foreign_status_lists: std::sync::RwLock::new(HashMap::new()),
            login_attempts: std::sync::RwLock::new(HashMap::new()),
            tenant_keystore: None,
            idp_host: domain_for_idp,
            oidc: None,
        }
    }

    /// Register a mock primary IdP for testing
    pub async fn register_mock_primary_idp(&self, domain: String, config: MockPrimaryIdp) {
        self.mock_primary_idps.write().await.insert(domain, config);
    }

    /// Get mock primary IdP config if registered
    pub async fn get_mock_primary_idp(&self, domain: &str) -> Option<MockPrimaryIdp> {
        self.mock_primary_idps.read().await.get(domain).cloned()
    }

    /// Clear all mock primary IdPs
    pub async fn clear_mock_primary_idps(&self) {
        self.mock_primary_idps.write().await.clear();
    }

    /// Remove a specific mock primary IdP by domain
    pub async fn remove_mock_primary_idp(&self, domain: &str) -> bool {
        self.mock_primary_idps
            .write()
            .await
            .remove(domain)
            .is_some()
    }

    /// Get or create the fallback fetcher
    pub async fn fallback_fetcher(&self) -> Result<Arc<FallbackFetcher>, String> {
        self.fallback_fetcher
            .get_or_try_init(|| async {
                FallbackFetcher::new(self.domain.clone()).map(Arc::new)
            })
            .await
            .cloned()
    }

    /// Get the fallback fetcher if already initialized (does not create one)
    ///
    /// This is useful for contexts where you want to use DNS discovery if available,
    /// but don't want to trigger the (potentially blocking) initialization.
    pub fn get_fallback_fetcher(&self) -> Option<Arc<FallbackFetcher>> {
        self.fallback_fetcher.get().cloned()
    }

    /// Rate-limit an outbound email of kind `scope` (e.g. "new_account",
    /// "reset", "add_email") to one per [`EMAIL_SEND_COOLDOWN_SECS`] per address.
    /// Keyed per-scope so a legitimate cross-kind sequence (sign up, then reset)
    /// isn't blocked, while resends of the *same* kind are. On success records
    /// the send; returns `Err(seconds_remaining)` if the caller must wait.
    /// Enforced server-side so it can't be bypassed by reloading the page.
    pub async fn throttle_email(&self, email: &str, scope: &str) -> Result<(), i64> {
        let key = format!("{scope}\u{0}{}", email.to_lowercase());
        let now = chrono::Utc::now();
        let mut times = self.email_send_times.write().await;
        if let Some(last) = times.get(&key) {
            let elapsed = (now - *last).num_seconds();
            if elapsed < EMAIL_SEND_COOLDOWN_SECS {
                return Err(EMAIL_SEND_COOLDOWN_SECS - elapsed);
            }
        }
        times.insert(key, now);
        times.retain(|_, t| (now - *t).num_seconds() < EMAIL_SEND_COOLDOWN_SECS); // bound memory
        Ok(())
    }

    /// Forget all send-throttle entries for an address (any scope) — e.g. on
    /// account cancellation, so a legitimate re-registration isn't blocked.
    pub async fn clear_email_throttle(&self, email: &str) {
        let suffix = format!("\u{0}{}", email.to_lowercase());
        self.email_send_times
            .write()
            .await
            .retain(|k, _| !k.ends_with(&suffix));
    }
}

/// Type alias for the default in-memory state
pub type InMemoryAppState = AppState<
    crate::store::InMemoryUserStore,
    crate::store::InMemorySessionStore,
    crate::email::ConsoleEmailSender,
>;

#[cfg(test)]
mod throttle_tests {
    use super::*;
    use crate::email::ConsoleEmailSender;
    use crate::store::{InMemorySessionStore, InMemoryUserStore};
    use browserid_core::KeyPair;

    fn state() -> InMemoryAppState {
        AppState::new(
            KeyPair::generate(),
            "localhost".into(),
            InMemoryUserStore::new(),
            InMemorySessionStore::new(),
            ConsoleEmailSender::new(),
        )
    }

    #[tokio::test]
    async fn throttle_blocks_second_send_per_address() {
        let s = state();
        assert!(s.throttle_email("a@b.com", "reset").await.is_ok()); // first is allowed
        let blocked = s.throttle_email("A@B.com", "reset").await; // same address+scope (case-insensitive)
        assert!(matches!(blocked, Err(secs) if secs > 0 && secs <= EMAIL_SEND_COOLDOWN_SECS));
        assert!(s.throttle_email("other@b.com", "reset").await.is_ok()); // a different address is independent
        assert!(s.throttle_email("a@b.com", "new_account").await.is_ok()); // different scope, same address: independent
        s.clear_email_throttle("a@b.com").await; // clearing (e.g. cancel) re-opens every scope
        assert!(s.throttle_email("a@b.com", "reset").await.is_ok());
    }
}
