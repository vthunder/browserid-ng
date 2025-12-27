//! BrowserID-NG Fallback Broker
//!
//! A fallback identity provider for domains that don't implement
//! native BrowserID support. Similar to Mozilla's login.persona.org.

use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use browserid_broker::{
    load_or_generate_keypair, routes, AppState, Config, ConsoleEmailSender, EmailSender,
    SmtpConfig, SmtpEmailSender, SqliteStore,
};

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

    // Load configuration
    let config = Config::from_env();
    tracing::info!(?config, "Loaded configuration");

    // Load or generate keypair
    let keypair = load_or_generate_keypair(&config.key_file)?;
    tracing::info!(
        public_key = %keypair.public_key().to_base64(),
        "Loaded keypair"
    );

    // Open SQLite database
    let store = SqliteStore::open(&config.database_path)?;
    let store = Arc::new(store);
    tracing::info!(path = %config.database_path, "Opened database");

    // Create email sender (SMTP if configured, otherwise console)
    let email_sender: Box<dyn EmailSender> = if let Some(smtp_config) = SmtpConfig::from_env() {
        tracing::info!("Using SMTP email sender");
        Box::new(
            SmtpEmailSender::new(smtp_config)
                .map_err(|e| anyhow::anyhow!("Failed to create SMTP sender: {}", e))?,
        )
    } else {
        tracing::info!("Using console email sender (set SMTP_HOST to enable real emails)");
        Box::new(ConsoleEmailSender::new())
    };

    // Create app state
    let state = Arc::new(AppState::new(
        keypair,
        config.domain.clone(),
        store.clone(),
        store.clone(),
        email_sender,
    ));

    // Determine static files path (relative to workspace root or package root)
    let static_path = if std::path::Path::new("browserid-broker/static").exists() {
        "browserid-broker/static"
    } else {
        "static"
    };

    // Create router
    let app = routes::create_router_with_static_path(state, static_path);

    // Start server
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("Broker listening on http://{}", addr);
    tracing::info!("Support document at http://{}/.well-known/browserid", config.domain);

    axum::serve(listener, app).await?;

    Ok(())
}
