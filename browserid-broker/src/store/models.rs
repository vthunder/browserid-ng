//! Data models for broker storage

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Type of pending verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationType {
    /// New account creation
    NewAccount,
    /// Adding email to existing account
    AddEmail,
    /// Password reset
    PasswordReset,
}

/// Type of email (how it was added to the account)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailType {
    /// Email verified through a primary IdP
    Primary,
    /// Email verified through the broker (secondary flow)
    Secondary,
    /// Agent identity minted headlessly via an API key (l8lw). Attribution to
    /// the human lives in `parent_email`; agent-ness is issuer-side metadata
    /// only, never protocol-visible.
    Agent,
}

impl EmailType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EmailType::Primary => "primary",
            EmailType::Secondary => "secondary",
            EmailType::Agent => "agent",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "primary" => Some(EmailType::Primary),
            "secondary" => Some(EmailType::Secondary),
            "agent" => Some(EmailType::Agent),
            _ => None,
        }
    }
}

/// Unique user identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub u64);

/// Unique session identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

/// A user account
#[derive(Debug, Clone)]
pub struct User {
    pub id: UserId,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
}

/// An email address associated with a user
#[derive(Debug, Clone)]
pub struct Email {
    pub email: String,
    pub user_id: UserId,
    pub verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
    /// How this email was added (primary IdP or secondary broker flow)
    pub email_type: EmailType,
    /// How this email was last used (for tracking type transitions)
    pub last_used_as: EmailType,
    /// For a *subordinate/derived* identity (e.g. a minted `<handle>@issuer`), the
    /// parent email in the same account that controls it. Private account metadata
    /// — set via `set_parent_email`, never exposed publicly (mingo-cm8z). `None`
    /// for ordinary identities.
    pub parent_email: Option<String>,
}

/// A pending email verification
#[derive(Debug, Clone)]
pub struct PendingVerification {
    pub secret: String,
    pub email: String,
    /// None for new account creation, Some for adding email to existing account or password reset
    pub user_id: Option<UserId>,
    /// Password hash for new account creation
    pub password_hash: Option<String>,
    /// Type of verification (new account, add email, password reset)
    pub verification_type: VerificationType,
    pub created_at: DateTime<Utc>,
}

/// A per-user API key: the standing credential an agent uses to (re-)mint
/// certificates headlessly (l8lw). The secret itself is never stored — only
/// its SHA-256 hash. Scoped to minting certs for agent identities on the
/// owning account; revocation is soft (re-mints fail, certs age out ≤24h).
#[derive(Debug, Clone)]
pub struct ApiKey {
    pub id: u64,
    pub user_id: UserId,
    /// SHA-256 of the secret, hex-encoded
    pub key_hash: String,
    /// Human label ("ci-bot")
    pub name: String,
    /// Attribution root: the human email agent identities minted with this
    /// key chain to (becomes their `parent_email`)
    pub parent_email: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ApiKey {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// A user session
#[derive(Debug, Clone)]
pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub csrf_token: String,
    pub created_at: DateTime<Utc>,
}
