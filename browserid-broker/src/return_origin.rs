//! Accepted `return_origin` values for the device-authorization ceremony
//! (fallback-idp-api-v1 §3.1, bean qze7).
//!
//! The ceremony authenticates the USER, never the wallet: any page that opens
//! the page with its own keys would otherwise receive a victim-identity config
//! cert bound to those keys. So the issuer delivers only to:
//!
//! - a loopback origin (`http://127.0.0.1:*`, `http://[::1]:*`,
//!   `http://localhost:*`) — always;
//! - a custom-scheme origin (any non-http(s) scheme) — always;
//! - an http(s) origin on the issuer's configured trusted-wallet list, or
//!   the issuer's own origin (its first-party dialog).
//!
//! The first two can only be received by code already running on the user's
//! machine. The third is deployment policy. Enforced HERE, on the issuance
//! endpoint, as well as in the page, so a page regression cannot reopen it.

/// Reason string the endpoints and the page agree on.
pub const REFUSAL: &str = "return_origin_not_allowed";

/// Default trusted web wallets for a fresh deployment (override with
/// `TRUSTED_WALLET_ORIGINS`, comma-separated; empty string = trust none).
pub const DEFAULT_TRUSTED: &[&str] = &["https://browserid.me"];

/// Parse a comma-separated origin list from the environment.
pub fn from_env() -> Vec<String> {
    match std::env::var("TRUSTED_WALLET_ORIGINS") {
        Ok(v) => v
            .split(',')
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Err(_) => DEFAULT_TRUSTED.iter().map(|s| s.to_string()).collect(),
    }
}

/// Is `raw` an origin the issuer will deliver certs to? `own` is the
/// issuer's own origin (always accepted); `trusted` the configured list.
pub fn is_accepted(raw: &str, own: &str, trusted: &[String]) -> bool {
    // A single trailing slash is the bare-origin form some URL APIs emit.
    let raw = raw.trim().strip_suffix('/').unwrap_or(raw.trim());
    let Some((scheme, rest)) = raw.split_once("://") else { return false };
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return false;
    }
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        // A custom scheme: only an installed handler receives it. Require an
        // origin shape (no path) so `return_url` same-origin checks stay sane.
        return !rest.is_empty() && !rest.contains('/');
    }
    // http(s): must be a bare origin — no path, query or fragment.
    if rest.is_empty() || rest.contains('/') || rest.contains('?') || rest.contains('#') || rest.contains('@') {
        return false;
    }
    let host = rest.rsplit_once(':').map(|(h, _)| h).unwrap_or(rest);
    let host = if rest.starts_with('[') {
        rest.split(']').next().map(|h| format!("{h}]")).unwrap_or_default()
    } else {
        host.to_string()
    };
    if matches!(host.to_ascii_lowercase().as_str(), "127.0.0.1" | "[::1]" | "localhost") {
        return true;
    }
    // Own origin: the issuer's host is the issuer's under either scheme
    // (dev runs it over plain http; a non-TLS impostor cannot hold the host).
    let own_host = own.split_once("://").map(|(_, h)| h).unwrap_or(own).trim_end_matches('/');
    if rest.eq_ignore_ascii_case(own_host) {
        return true;
    }
    let norm = format!("{scheme}://{}", rest.to_ascii_lowercase());
    trusted.iter().any(|t| t.trim_end_matches('/').eq_ignore_ascii_case(&norm))
}

/// Is `url` on the origin `origin` (scheme and authority equal, case-
/// insensitively)? The §4.2 same-origin rule between `return_url` and
/// `return_origin`; a custom-scheme origin compares as `scheme://rest`.
pub fn same_origin(url: &str, origin: &str) -> bool {
    let origin = origin.trim().trim_end_matches('/');
    let Some((scheme, rest)) = url.trim().split_once("://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let url_origin = format!("{}://{}", scheme.to_ascii_lowercase(), authority);
    if url_origin.eq_ignore_ascii_case(origin) {
        return true;
    }
    // Default ports: `https://h:443` == `https://h`, `http://h:80` == `http://h`.
    let strip = |o: &str| -> String {
        let o = o.to_ascii_lowercase();
        match o.split_once("://") {
            Some(("https", h)) => format!("https://{}", h.strip_suffix(":443").unwrap_or(h)),
            Some(("http", h)) => format!("http://{}", h.strip_suffix(":80").unwrap_or(h)),
            _ => o,
        }
    };
    strip(&url_origin) == strip(origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_origin_rule() {
        assert!(same_origin("https://wallet.example/cb#x", "https://wallet.example"));
        assert!(same_origin("https://WALLET.example:443/cb", "https://wallet.example/"));
        assert!(same_origin("mingo://wallet", "mingo://wallet"));
        assert!(same_origin("http://127.0.0.1:4321/done?x=1", "http://127.0.0.1:4321"));
        assert!(!same_origin("https://wallet.example.evil.example/cb", "https://wallet.example"));
        assert!(!same_origin("https://wallet.example@evil.example/cb", "https://wallet.example"));
        assert!(!same_origin("http://wallet.example/cb", "https://wallet.example"));
        assert!(!same_origin("https://evil.example/?u=https://wallet.example", "https://wallet.example"));
    }

    fn t(raw: &str) -> bool {
        is_accepted(raw, "https://idp.example", &["https://wallet.example".to_string()])
    }

    #[test]
    fn loopback_always() {
        assert!(t("http://127.0.0.1:4321"));
        assert!(t("http://localhost"));
        assert!(t("http://LOCALHOST:8080"));
        assert!(t("http://[::1]:9"));
        assert!(!t("http://127.0.0.1.evil.example"));
        assert!(!t("http://localhost.evil.example"));
    }

    #[test]
    fn custom_scheme_always() {
        assert!(t("mingo://wallet"));
        assert!(t("com.example.wallet://callback"));
        assert!(!t("mingo://wallet/path"));
        assert!(!t("://x"));
        assert!(!t("no scheme"));
    }

    #[test]
    fn https_only_when_trusted_or_own() {
        assert!(t("https://idp.example"));
        assert!(t("http://idp.example"));
        assert!(!t("https://idp.example.evil.example"));
        assert!(t("https://wallet.example"));
        assert!(t("https://WALLET.example/"));
        assert!(!t("https://evil.example"));
        assert!(!t("https://wallet.example.evil.example"));
        assert!(!t("https://wallet.example/path"));
        assert!(!t("https://wallet.example@evil.example"));
        assert!(!t("https://evil.example?x=https://wallet.example"));
    }

    #[test]
    fn env_parsing() {
        assert_eq!(DEFAULT_TRUSTED, &["https://browserid.me"]);
    }
}
