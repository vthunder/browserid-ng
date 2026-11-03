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

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Environment variable holding the per-deployment secret that salts the
/// PostHog distinct id (audit 2026-11 Q13).
pub const ID_SALT_ENV: &str = "POSTHOG_ID_SALT";

/// Fire-and-forget PostHog capture client. Disabled unless `POSTHOG_TOKEN` is set,
/// so local/dev/test emit nothing.
///
/// `client` exists only when a token does: constructing a `reqwest::Client`
/// blocks ~11s in macOS system-proxy detection (hyper-util
/// `Matcher::from_system`), and every test builds an `AppState` with a
/// disabled Analytics — an unused client here once cost the broker suite
/// ~10 minutes of pure idle (bean 7g2q).
#[derive(Clone)]
pub struct Analytics {
    client: Option<reqwest::Client>,
    token: Option<String>,
    endpoint: String,
    /// Per-deployment secret for the distinct id (`POSTHOG_ID_SALT`). `None`
    /// keeps the historical unsalted `sha256(email)` id, which anyone with
    /// PostHog access and an email guess can confirm; production warns at
    /// startup when it is missing (see `main.rs`).
    salt: Option<Vec<u8>>,
}

impl Analytics {
    /// Disabled instance (no token, no client) — the default for tests and
    /// local runs.
    pub fn disabled() -> Self {
        Self {
            client: None,
            token: None,
            endpoint: default_endpoint(),
            salt: None,
        }
    }

    /// Build from the environment: `POSTHOG_TOKEN` (project token, `phc_…`),
    /// optional `POSTHOG_HOST` (defaults to us ingestion) and optional
    /// `POSTHOG_ID_SALT` (per-deployment secret; unset = unsalted ids).
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
        // no_proxy: skip platform proxy detection (the ~11s macOS stall). If a
        // deployment ever needs an egress proxy, this becomes a config knob.
        let client = token.as_ref().map(|_| {
            reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("analytics reqwest client")
        });
        let salt = std::env::var(ID_SALT_ENV)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(String::into_bytes);
        Self {
            client,
            token,
            endpoint,
            salt,
        }
    }

    pub fn enabled(&self) -> bool {
        self.token.is_some()
    }

    /// True when a `POSTHOG_ID_SALT` is configured, i.e. distinct ids are
    /// keyed under a deployment secret rather than a bare hash.
    pub fn salted(&self) -> bool {
        self.salt.is_some()
    }

    /// The distinct id for an email under this deployment's salt. Every
    /// capture site goes through here so the choice of salt lives in one
    /// place; see [`distinct_id_for_email`] for the derivation.
    pub fn distinct_id(&self, email: &str) -> String {
        distinct_id_for_email(email, self.salt.as_deref())
    }

    /// Emit an event without blocking the request. Spawns onto the runtime; any
    /// delivery error is logged, never surfaced to the caller. `distinct_id`
    /// must already be opaque (see [`distinct_id_for_email`]).
    pub fn capture(&self, event: &str, distinct_id: String, mut properties: Value) {
        let (Some(token), Some(client)) = (self.token.clone(), self.client.clone()) else {
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
///
/// With a salt the id is `u_<HMAC-SHA256(salt, email)[:12]>`: without the
/// deployment secret nobody can confirm an address's membership from the
/// PostHog side (audit 2026-11 Q13). Without a salt it is the historical
/// `u_<sha256(email)[:12]>`, kept so existing dashboards still join; the two
/// never collide in practice and a deployment that turns the salt on
/// accepts that older ids do not join.
pub fn distinct_id_for_email(email: &str, salt: Option<&[u8]>) -> String {
    let normalized = email.trim().to_lowercase();
    let digest: Vec<u8> = match salt {
        Some(key) => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(normalized.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        None => Sha256::digest(normalized.as_bytes()).to_vec(),
    };
    let mut s = String::from("u_");
    for b in &digest[..12] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The email's domain (lowercased) — safe, useful funnel segmentation
/// ("gmail.com" vs "acme.com") without being personally identifying.
pub fn email_domain(email: &str) -> Option<String> {
    browserid_core::identity::email_domain(email).map(|d| d.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_id_is_stable_case_insensitive_and_opaque() {
        for salt in [None, Some(b"deployment-secret".as_slice())] {
            let a = distinct_id_for_email("Alice.Test@Example.COM", salt);
            let b = distinct_id_for_email("  alice.test@example.com ", salt);
            assert_eq!(a, b, "same address (normalized) → same id");
            assert!(a.starts_with("u_"));
            assert_eq!(a.len(), 2 + 24);
            assert!(!a.to_lowercase().contains("alice"), "id must not reveal the email");
            assert_ne!(a, distinct_id_for_email("bob@example.com", salt));
        }
    }

    #[test]
    fn distinct_id_changes_with_the_salt_and_is_stable_for_one_salt() {
        // Audit 2026-11 Q13: the id is keyed under the deployment secret.
        let unsalted = distinct_id_for_email("alice@example.com", None);
        let s1 = distinct_id_for_email("alice@example.com", Some(b"secret-one"));
        let s1_again = distinct_id_for_email("alice@example.com", Some(b"secret-one"));
        let s2 = distinct_id_for_email("alice@example.com", Some(b"secret-two"));
        assert_eq!(s1, s1_again, "one secret → one stable id");
        assert_ne!(s1, s2, "a different secret → a different id");
        assert_ne!(s1, unsalted, "a salted id is not the bare hash");
        // Unset salt keeps the historical derivation so existing ids still join.
        let mut h = Sha256::new();
        h.update(b"alice@example.com");
        let legacy = format!("u_{}", h.finalize()[..12].iter().map(|b| format!("{b:02x}")).collect::<String>());
        assert_eq!(unsalted, legacy);
    }

    #[test]
    fn analytics_distinct_id_uses_its_salt() {
        let mut a = Analytics::disabled();
        assert!(!a.salted());
        assert_eq!(a.distinct_id("x@example.com"), distinct_id_for_email("x@example.com", None));
        a.salt = Some(b"k".to_vec());
        assert!(a.salted());
        assert_eq!(a.distinct_id("x@example.com"), distinct_id_for_email("x@example.com", Some(b"k")));
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
