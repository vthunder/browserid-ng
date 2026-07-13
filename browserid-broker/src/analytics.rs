//! Server-side product analytics — the funnel for the AUTH origin.
//!
//! The auth/issuer origin (browserid.me) runs NO analytics JS: any script there
//! could reach the keystore, session cookie, and wsapi. Instead we emit the
//! onboarding/conversion funnel from the axum handlers directly to PostHog,
//! server-to-server. Events are:
//!   - authoritative (server-observed, un-blockable, un-spoofable),
//!   - PII-safe: we never send raw emails, verification codes, or client IPs —
//!     users are keyed by an opaque, stable hash of their email.
//!
//! The marketing origin's website analytics is separate (client-side, locked
//! down) — see `marketing/analytics.js`. The two aren't stitched: this is the
//! server funnel, that is anonymous visitor traffic.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Fire-and-forget PostHog capture client. Disabled unless `POSTHOG_TOKEN` is set,
/// so local/dev/test emit nothing.
#[derive(Clone)]
pub struct Analytics {
    client: reqwest::Client,
    token: Option<String>,
    endpoint: String,
}

impl Analytics {
    /// Disabled instance (no token) — the default for tests and local runs.
    pub fn disabled() -> Self {
        Self {
            client: reqwest::Client::new(),
            token: None,
            endpoint: default_endpoint(),
        }
    }

    /// Build from the environment: `POSTHOG_TOKEN` (project token, `phc_…`) and
    /// optional `POSTHOG_HOST` (defaults to us ingestion).
    pub fn from_env() -> Self {
        let token = std::env::var("POSTHOG_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let endpoint = std::env::var("POSTHOG_HOST")
            .ok()
            .map(|s| s.trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(default_endpoint);
        Self {
            client: reqwest::Client::new(),
            token,
            endpoint,
        }
    }

    pub fn enabled(&self) -> bool {
        self.token.is_some()
    }

    /// Emit an event without blocking the request. Spawns onto the runtime; any
    /// delivery error is logged, never surfaced to the caller. `distinct_id`
    /// must already be opaque (see [`distinct_id_for_email`]).
    pub fn capture(&self, event: &str, distinct_id: String, mut properties: Value) {
        let Some(token) = self.token.clone() else {
            return;
        };
        if !properties.is_object() {
            properties = json!({});
        }
        if let Some(obj) = properties.as_object_mut() {
            obj.insert("$lib".into(), json!("browserid-broker"));
            obj.insert("source".into(), json!("server"));
        }
        let body = json!({
            "api_key": token,
            "event": event,
            "distinct_id": distinct_id,
            "properties": properties,
        });
        let url = format!("{}/capture/", self.endpoint);
        let client = self.client.clone();
        let event = event.to_string();
        tokio::spawn(async move {
            match client.post(&url).json(&body).send().await {
                Ok(r) if r.status().is_success() => {}
                Ok(r) => tracing::warn!(status = %r.status(), %event, "posthog capture non-2xx"),
                Err(e) => tracing::warn!(error = %e, %event, "posthog capture failed"),
            }
        });
    }
}

fn default_endpoint() -> String {
    "https://us.i.posthog.com".to_string()
}

/// Opaque, stable per-user id derived from an email — so the funnel can follow a
/// user across steps without the raw address ever leaving the process. Not
/// reversible; case/whitespace-normalized so the same address always maps alike.
pub fn distinct_id_for_email(email: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(email.trim().to_lowercase().as_bytes());
    let digest = hasher.finalize();
    let mut s = String::from("u_");
    for b in &digest[..12] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The email's domain (lowercased) — safe, useful funnel segmentation
/// ("gmail.com" vs "acme.com") without being personally identifying.
pub fn email_domain(email: &str) -> Option<String> {
    email.rsplit_once('@').map(|(_, d)| d.trim().to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_id_is_stable_case_insensitive_and_opaque() {
        let a = distinct_id_for_email("Alice.Test@Example.COM");
        let b = distinct_id_for_email("  alice.test@example.com ");
        assert_eq!(a, b, "same address (normalized) → same id");
        assert!(a.starts_with("u_"));
        assert!(!a.to_lowercase().contains("alice"), "id must not reveal the email");
        assert_ne!(a, distinct_id_for_email("bob@example.com"));
    }

    #[test]
    fn email_domain_lowercased() {
        assert_eq!(email_domain("Foo@Bar.COM").as_deref(), Some("bar.com"));
        assert_eq!(email_domain("nope").as_deref(), None);
    }

    #[test]
    fn disabled_capture_is_noop() {
        // No token → capture must not panic and must be a no-op (no runtime needed).
        Analytics::disabled().capture("x", "u_1".into(), serde_json::json!({}));
        assert!(!Analytics::disabled().enabled());
    }
}
