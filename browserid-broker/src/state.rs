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
}

impl<U: UserStore, S: SessionStore, E: EmailSender> AppState<U, S, E> {
    pub fn new(
        keypair: KeyPair,
        domain: String,
        user_store: U,
        session_store: S,
        email_sender: E,
    ) -> Self {
        Self {
            keypair,
            domain,
            user_store: Arc::new(user_store),
            session_store: Arc::new(session_store),
            email_sender: Arc::new(email_sender),
            fallback_fetcher: OnceCell::new(),
            mock_primary_idps: RwLock::new(HashMap::new()),
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
        Self {
            keypair,
            domain,
            user_store,
            session_store,
            email_sender,
            fallback_fetcher: OnceCell::new(),
            mock_primary_idps: RwLock::new(HashMap::new()),
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
}

/// Type alias for the default in-memory state
pub type InMemoryAppState = AppState<
    crate::store::InMemoryUserStore,
    crate::store::InMemorySessionStore,
    crate::email::ConsoleEmailSender,
>;
