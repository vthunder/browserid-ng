//! Application state for the broker

use std::sync::Arc;

use browserid_core::KeyPair;
use tokio::sync::OnceCell;

use crate::email::EmailSender;
use crate::fallback_fetcher::FallbackFetcher;
use crate::store::{SessionStore, UserStore};

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
        }
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
