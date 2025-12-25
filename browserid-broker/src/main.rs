//! BrowserID-NG Fallback Broker
//!
//! A fallback identity provider for domains that don't implement
//! native BrowserID support. Similar to Mozilla's login.persona.org.

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod routes;
mod state;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "browserid_broker=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("BrowserID-NG Broker starting...");

    // TODO: Load config
    // TODO: Initialize state
    // TODO: Set up routes
    // TODO: Start server

    tracing::info!("Broker not yet implemented");

    Ok(())
}
