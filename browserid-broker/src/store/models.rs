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
    /// Agent identity minted via the delegation chain. Attribution to the
    /// human lives in `parent_email` and — since spec v0.4 — is also
    /// protocol-visible: these identities get typed agent certificates with
    /// an `agent.parent` claim.
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

/// A registered provisioning certificate (tdxf, spec v0.2). The broker holds
/// only public data: the delegation bundle `U_cert~P_cert` the user's identity
/// key signed in-browser, plus the provisioning public key `P_pub` it delegates
/// to. The broker never sees `P_priv` (the "API key"). Endorsement is granted
/// only for a registered, unrevoked cert; revoking one starves future
/// endorsements so agents age out within a cert TTL (≤24h).
#[derive(Debug, Clone)]
pub struct ProvisioningCertRecord {
    pub id: u64,
    pub user_id: UserId,
    /// The delegating identity (`P_cert.iss` == `U_cert` email)
    pub delegator_email: String,
    /// P_pub, base64 — the registry lookup key at endorse time
    pub provisioning_pub: String,
    /// The full `U_cert~P_cert` delegation bundle
    pub bundle: String,
    /// Human label ("ci-bot")
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_endorsed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ProvisioningCertRecord {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// A pending warrant consent request (agent spec §6, v0.4). Created by an
/// agent's `warrant` request against a registered provisioning cert; resolved
/// by the delegator on the consent page, which signs the warrant client-side
/// with the identity key (the broker never holds it). The audience and scopes
/// live here only while the request is open — the record is deleted on
/// delivery, so the registrar retains no record of where warrants apply
/// (§6.4 privacy rule).
#[derive(Debug, Clone)]
pub struct WarrantRequestRecord {
    /// High-entropy opaque code — the poll credential (single delivery)
    pub code: String,
    /// The delegator's account
    pub user_id: UserId,
    pub delegator_email: String,
    /// The agent identity the warrant is for (`<name>@<idp-domain>`)
    pub agent_email: String,
    /// Label of the provisioning cert that raised the request (display)
    pub label: String,
    /// The requested grants — one per RP audience, each with its own scopes
    /// (audiences verbatim from RP challenges). Approval yields one
    /// single-audience warrant per grant.
    pub grants: Vec<WarrantGrantItem>,
    pub status: WarrantRequestStatus,
    /// The signed warrant JWSs (one per grant, same order), present once
    /// approved
    pub warrants: Option<Vec<String>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_polled_at: Option<DateTime<Utc>>,
}

/// One grant inside a pending warrant request
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WarrantGrantItem {
    pub audience: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarrantRequestStatus {
    Pending,
    Approved,
    Denied,
}

impl WarrantRequestStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            WarrantRequestStatus::Pending => "pending",
            WarrantRequestStatus::Approved => "approved",
            WarrantRequestStatus::Denied => "denied",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(WarrantRequestStatus::Pending),
            "approved" => Some(WarrantRequestStatus::Approved),
            "denied" => Some(WarrantRequestStatus::Denied),
            _ => None,
        }
    }
}

impl WarrantRequestRecord {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
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
