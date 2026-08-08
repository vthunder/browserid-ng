//! BrowserID-NG Fallback Broker
//!
//! A fallback identity provider for domains that don't implement
//! native BrowserID support. Similar to Mozilla's login.persona.org.

pub mod analytics;
pub mod authority;
pub mod config;
pub mod crypto;
pub mod dns_fetcher;
pub mod email;
pub mod error;
pub mod fallback_fetcher;
pub mod registrar_glue;
pub mod routes;
pub mod state;
pub mod store;
pub mod tenant_keys;
pub mod verifier;

pub use config::{load_or_generate_keypair, Config};
pub use dns_fetcher::DnsFetcher;
pub use email::{ConsoleEmailSender, EmailSender, SmtpConfig, SmtpEmailSender};
pub use fallback_fetcher::{Discoverer, FallbackFetcher, FallbackResult};
pub use state::AppState;
pub use store::{
    EmailType, InMemorySessionStore, InMemoryUserStore, SessionStore, SqliteStore, UserStore,
};
