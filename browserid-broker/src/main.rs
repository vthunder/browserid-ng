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
    // Check if SMTP should be disabled (e.g., for testing)
    // This must be checked BEFORE loading .env to prevent .env from overriding
    let disable_smtp = std::env::var("DISABLE_SMTP").is_ok();

    // Load .env file if present (before reading any config)
    if let Err(e) = dotenvy::dotenv() {
        if !matches!(e, dotenvy::Error::Io(_)) {
            // Only warn if it's not a "file not found" error
            eprintln!("Warning: Failed to load .env file: {}", e);
        }
    }

    // Clear SMTP config if DISABLE_SMTP was set before .env loaded
    if disable_smtp {
        std::env::remove_var("SMTP_HOST");
    }

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
    let mut state = AppState::new(
        keypair,
        config.domain.clone(),
        store.clone(),
        store.clone(),
        email_sender,
    );

    // Headless agent provisioning (l8lw): off unless explicitly enabled —
    // intended for the dedicated agent-IdP deployment (agents.browserid.me)
    state.agent_provisioning_enabled = std::env::var("AGENT_PROVISIONING")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    // The /wsapi/test/* helper routes (raw verification codes, mock IdP) are an
    // account-takeover primitive — only ever mount them for local/dev (no real
    // SMTP), NEVER in production.
    state.test_endpoints_enabled = disable_smtp;
    if state.test_endpoints_enabled {
        tracing::warn!("test endpoints (/wsapi/test/*) ENABLED — dev only, never production");
    }
    // Origin split: when a separate static marketing site is deployed, point the
    // public marketing routes (`/`, guestbook page) at it. Keystore/cookies/wsapi
    // stay on this (auth/issuer) origin only. Unset → broker serves them locally.
    state.marketing_url = std::env::var("MARKETING_URL")
        .ok()
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty());
    if let Some(url) = &state.marketing_url {
        tracing::info!(marketing_url = %url, "Origin split: marketing routes redirect to marketing site");
    }
    // Hosted-primary tenancy (bean g5qt). `IDP_HOST` is the host tenants name
    // in their DNSSEC `host=` (a dedicated origin, e.g. idp.browserid.me);
    // defaults to the broker's own domain when unset (shared origin — fine for
    // local/test). `TENANT_KEYSTORE_KEY` (64 hex chars) seals custodial tenant
    // private keys at rest; absent → tenant onboarding is refused.
    if let Some(h) = std::env::var("IDP_HOST").ok().filter(|s| !s.trim().is_empty()) {
        state.idp_host = h.trim().to_string();
    }
    match std::env::var("TENANT_KEYSTORE_KEY") {
        Ok(v) if !v.trim().is_empty() => {
            match browserid_broker::tenant_keys::KeystoreKey::from_env_value(&v) {
                Ok(k) => {
                    state.tenant_keystore = Some(k);
                    tracing::info!(idp_host = %state.idp_host, "Hosted-primary tenancy enabled");
                }
                Err(e) => tracing::error!("TENANT_KEYSTORE_KEY invalid, tenancy disabled: {e}"),
            }
        }
        _ => {}
    }
    // Server-side product analytics (auth-origin funnel). Enabled iff POSTHOG_TOKEN set.
    state.analytics = browserid_broker::analytics::Analytics::from_env();
    if state.analytics.enabled() {
        tracing::info!("PostHog server-side analytics enabled");
    }
    if let Some(quota) = std::env::var("AGENT_MAX_IDENTITIES")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        state.max_agent_identities_per_user = quota;
    }
    if state.agent_provisioning_enabled {
        tracing::info!(
            quota = state.max_agent_identities_per_user,
            "Agent provisioning enabled"
        );
    }
    // Claim-time authority hierarchy probes (browserid-ng-tsqk). On by
    // default; both fail open on transport errors, so an offline dev broker
    // behaves as before. ATPROTO_BRIDGE_URL="" disables the atproto lane,
    // MX_GATE=0 the MX gate.
    {
        use browserid_broker::authority::{AuthorityChecker, HandleProbe, MxProbe};
        let bridge_url = std::env::var("ATPROTO_BRIDGE_URL")
            .unwrap_or_else(|_| "https://bsky.browserid.me".to_string());
        let handles = if bridge_url.trim().is_empty() {
            HandleProbe::Disabled
        } else {
            HandleProbe::Bridge {
                url: bridge_url.trim().to_string(),
                http: reqwest::Client::new(),
            }
        };
        // Default the MX gate off wherever SMTP is disabled (dev/e2e): those
        // brokers stage addresses at fake domains — and example.com in
        // particular publishes a null MX (RFC 7505), which the gate rightly
        // reads as "accepts no mail".
        let mx_gate_on = std::env::var("MX_GATE")
            .map(|v| v != "0")
            .unwrap_or(!disable_smtp);
        let mx = if mx_gate_on {
            match browserid_broker::DnsFetcher::new() {
                Ok(f) => MxProbe::Dns(f),
                Err(e) => {
                    tracing::warn!("MX gate disabled — DNS fetcher unavailable: {e}");
                    MxProbe::Off
                }
            }
        } else {
            MxProbe::Off
        };
        // The same bridge that answers the presence probe is the one whose
        // attestations complete_handle_claim accepts.
        state.handle_attestor = bridge_url
            .trim()
            .strip_prefix("https://")
            .or_else(|| bridge_url.trim().strip_prefix("http://"))
            .map(|rest| rest.split('/').next().unwrap_or(rest).to_string())
            .filter(|h| !h.is_empty());
        state.authority = AuthorityChecker::new(handles, mx);
        tracing::info!(
            atproto_lane = state.authority.claim_url().as_deref().unwrap_or("disabled"),
            mx_gate = mx_gate_on,
            "claim-time authority hierarchy configured"
        );
    }

    let state = Arc::new(state);

    // Warm the DNS fallback fetcher at startup: auth_with_assertion uses the
    // non-initializing accessor, so a cold start otherwise fails the first
    // primary login with "DNS discovery not configured" until /verify has
    // initialized it (bean 888v).
    match state.fallback_fetcher().await {
        Ok(_) => tracing::info!("DNS fallback fetcher initialized"),
        Err(e) => tracing::warn!("DNS fallback fetcher init failed (primary login degraded): {e}"),
    }

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
