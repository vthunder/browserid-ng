//! Wire contract for agent → RP API authentication (l8lw Phase 2).
//!
//! A non-browser client needs a non-browser auth path. The RP opts into one
//! small thing: a token-exchange endpoint where a browserid assertion is
//! swapped for the RP's own bearer token (RFC 7521-shaped; the RP still
//! learns just "an email"). Discovery is in-band and self-describing:
//!
//! ```text
//! GET /data
//! → 401 WWW-Authenticate: BrowserID realm="api", audience="https://api.example.com",
//!       token_endpoint="https://api.example.com/token"
//!
//! POST /token   grant_type=urn:x-browserid:grant-type:assertion&assertion=<cert~assertion>
//! → 200 {"access_token":"…","token_type":"Bearer","expires_in":3600}
//! ```
//!
//! The RP names its own `audience` (the agent never guesses what to sign
//! for) and its own `token_endpoint`. Out-of-band discovery reuses RFC 8414
//! (`.well-known/oauth-authorization-server`) with the same grant type —
//! see the `browserid-rp` crate.

use serde::{Deserialize, Serialize};

/// The `WWW-Authenticate` scheme name
pub const CHALLENGE_SCHEME: &str = "BrowserID";

/// The token-exchange grant type (RFC 7521 assertion-grant shape)
pub const GRANT_TYPE_ASSERTION: &str = "urn:x-browserid:grant-type:assertion";

/// A `WWW-Authenticate: BrowserID …` challenge: everything an agent needs to
/// authenticate to an API it has never seen before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpChallenge {
    /// Optional human-readable realm
    pub realm: Option<String>,
    /// The exact audience assertions must be signed for. Usually the API
    /// origin, but the RP may name a stable logical id instead.
    pub audience: String,
    /// Absolute URL of the RP's token-exchange endpoint
    pub token_endpoint: String,
}

impl RpChallenge {
    pub fn new(audience: impl Into<String>, token_endpoint: impl Into<String>) -> Self {
        Self {
            realm: None,
            audience: audience.into(),
            token_endpoint: token_endpoint.into(),
        }
    }

    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(realm.into());
        self
    }

    /// Render as a `WWW-Authenticate` header value
    pub fn to_header_value(&self) -> String {
        let mut parts = Vec::new();
        if let Some(realm) = &self.realm {
            parts.push(format!("realm=\"{}\"", realm));
        }
        parts.push(format!("audience=\"{}\"", self.audience));
        parts.push(format!("token_endpoint=\"{}\"", self.token_endpoint));
        format!("{} {}", CHALLENGE_SCHEME, parts.join(", "))
    }

    /// Parse a `WWW-Authenticate` header value. Returns `None` when the
    /// scheme is not `BrowserID` or required params are missing. Quoted
    /// param values must not contain literal `"` (none of ours can).
    pub fn parse(header_value: &str) -> Option<Self> {
        let rest = header_value.trim().strip_prefix(CHALLENGE_SCHEME)?;
        // Scheme must be followed by whitespace (not e.g. "BrowserIDx")
        if !rest.starts_with(char::is_whitespace) {
            return None;
        }

        let mut realm = None;
        let mut audience = None;
        let mut token_endpoint = None;

        for param in split_params(rest) {
            let (key, value) = param.split_once('=')?;
            let value = value.trim().trim_matches('"').to_string();
            match key.trim() {
                "realm" => realm = Some(value),
                "audience" => audience = Some(value),
                "token_endpoint" => token_endpoint = Some(value),
                _ => {} // ignore unknown params (forward compatibility)
            }
        }

        Some(Self {
            realm,
            audience: audience?,
            token_endpoint: token_endpoint?,
        })
    }
}

/// Split `key="value", key2="value2"` on commas outside quotes
fn split_params(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                parts.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(s[start..].trim());
    parts.retain(|p| !p.is_empty());
    parts
}

/// Body of a token-exchange request (form- or JSON-encoded POST)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    /// The backed assertion (`cert~assertion`)
    pub assertion: String,
}

impl TokenRequest {
    pub fn new(assertion: impl Into<String>) -> Self {
        Self {
            grant_type: GRANT_TYPE_ASSERTION.to_string(),
            assertion: assertion.into(),
        }
    }
}

/// Successful token-exchange response (OAuth-shaped)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    /// Always `Bearer`
    pub token_type: String,
    /// Seconds until the token expires
    pub expires_in: i64,
    /// The verified email — extra response member; RPs may omit it
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// OAuth-shaped error response from a token endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_roundtrip() {
        let challenge = RpChallenge::new("https://api.example.com", "https://api.example.com/token")
            .with_realm("api");
        let header = challenge.to_header_value();
        assert_eq!(
            header,
            "BrowserID realm=\"api\", audience=\"https://api.example.com\", token_endpoint=\"https://api.example.com/token\""
        );
        assert_eq!(RpChallenge::parse(&header).unwrap(), challenge);
    }

    #[test]
    fn challenge_parse_without_realm_and_with_unknown_params() {
        let parsed = RpChallenge::parse(
            "BrowserID audience=\"aud\", token_endpoint=\"http://t\", nonce=\"xyz\"",
        )
        .unwrap();
        assert_eq!(parsed.realm, None);
        assert_eq!(parsed.audience, "aud");
        assert_eq!(parsed.token_endpoint, "http://t");
    }

    #[test]
    fn challenge_parse_rejects_other_schemes_and_missing_params() {
        assert!(RpChallenge::parse("Bearer realm=\"x\"").is_none());
        assert!(RpChallenge::parse("BrowserIDx audience=\"a\", token_endpoint=\"t\"").is_none());
        assert!(RpChallenge::parse("BrowserID realm=\"x\"").is_none());
        assert!(RpChallenge::parse("BrowserID audience=\"a\"").is_none());
    }
}
