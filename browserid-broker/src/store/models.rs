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
    /// USER-CHOSEN display name for an agent identity (Flow I step 2, eywc) —
    /// the name permission cards open with. INTERNAL: shown only to the
    /// owning account, never published or served to agents/RPs (bean tmk8).
    /// `None` for non-agent emails and agents named before display names
    /// existed.
    pub display_name: Option<String>,
    /// PUBLIC byline for an agent identity (bean tmk8): what services display
    /// next to this identity's actions (e.g. the guestbook name column).
    /// Consented as public at pairing or set at /account. Deliberately never
    /// backfilled from `display_name`. `None` = services fall back to the
    /// email local-part.
    pub public_name: Option<String>,
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

/// A pending warrant consent request (agent spec §6, v0.4). Created by an
/// agent's `warrant` request against a registered provisioning cert; resolved
/// by the delegator on the consent page, which signs the warrants client-side
/// with the identity key (the broker never holds it). The row is the poll
/// *code* — single delivery, deleted on handover. The issued warrants
/// themselves persist in [`WarrantRecord`]s (jipx).
#[derive(Debug, Clone)]
pub struct WarrantRequestRecord {
    /// High-entropy opaque code — the poll credential (single delivery)
    pub code: String,
    /// The delegator's account
    pub user_id: UserId,
    pub delegator_email: String,
    /// The agent identity the warrant is for (`<name>@<idp-domain>`)
    pub agent_email: String,
    /// The agent's opaque holder id (from its device cert) — consent binds the
    /// warrant to it (`<id>`) or its namespace (`<ns>.*`).
    pub holder: String,
    /// Label of the provisioning cert that raised the request (display)
    pub label: String,
    /// The request's GRANTOR pin, normalized (t1jp): `*` = approver's choice;
    /// a concrete email = pinned (approve/deny only).
    pub grantor: String,
    /// The agent's own account of why it wants this (eywc) — displayed
    /// quoted and marked unverified.
    pub message: Option<String>,
    /// The requested grants — one per RP audience, each with its own scopes
    /// (audiences verbatim from RP challenges). Approval yields one
    /// single-audience warrant per grant.
    pub grants: Vec<WarrantGrantItem>,
    pub status: WarrantRequestStatus,
    /// The signed warrant JWSs (one per grant, same order), present once
    /// approved
    pub warrants: Option<Vec<String>>,
    /// External request (agent spec §6.6): raised by a foreign-IdP service
    /// agent, not a registered provisioning credential. Redirect-tied —
    /// excluded from the pending inbox — and rate-limited per delegator.
    pub external: bool,
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
    /// Status index allocated for this grant (egr7) — the consent page
    /// embeds it in the warrant it signs
    #[serde(default)]
    pub status_idx: Option<u64>,
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

/// A registered warrant (jipx): the delegator's own record of a grant they
/// signed — one agent at one audience. Kept per account (shown only to the
/// delegator's session), upserted on (user, agent, audience) so a reissue
/// replaces its predecessor. The substrate for per-warrant revocation once
/// status lists (egr7) land.
#[derive(Debug, Clone)]
pub struct WarrantRecord {
    pub id: u64,
    pub user_id: UserId,
    pub delegator_email: String,
    pub agent_email: String,
    pub audience: String,
    pub scopes: Vec<String>,
    /// The signed warrant JWS
    pub warrant: String,
    /// The warrant's status index (from its `status` claim), when it has one
    pub status_idx: Option<u64>,
    /// Device-cert-model holder matcher (`*` / `<ns>.*` / `<id>`), when this
    /// warrant came from the device-cert model. `None` for legacy warrants.
    pub holder: Option<String>,
    /// The config (authorization) device cert JWS that signed this warrant, in
    /// the device-cert model (DC Phase 4). `None` for legacy warrants.
    pub config_cert: Option<String>,
    pub signed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A namespace registry row (holder-authorization model): a user-organized
/// bucket of holders (`browsers` / `agents` / `services` / …). `prefix` is the
/// stored random dot-prefix every holder in the namespace shares (`<prefix>.…`),
/// so a `<prefix>.*` warrant matches the whole namespace; `label` is the
/// user-facing name, editable without touching the opaque prefix.
#[derive(Debug, Clone)]
pub struct Namespace {
    pub name: String,
    pub prefix: String,
    pub label: String,
}

/// A durable record of an IdP-signed device cert or config cert issued via
/// `/device/issue` (DC Phase 3/4). Persisted so the certs are listable and
/// revocable: revoking flips the cert's status bit (shared status-list index
/// space, egr7), which the RP-side verifier checks fail-closed.
#[derive(Debug, Clone)]
pub struct DeviceCertRecord {
    pub id: u64,
    pub user_id: UserId,
    /// Emails (or single-`*` globs) the cert authorizes (JSON array on disk)
    pub identities: Vec<String>,
    /// "authentication" | "authorization"
    pub purpose: String,
    /// The broker-assigned opaque holder id (`<ns>.<id>`) this device acts as.
    pub holder: String,
    /// The device (or config) public key, base64 — UNIQUE registry key
    pub pubkey: String,
    /// Issuing IdP domain
    pub iss: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    /// The cert's status-list index (its revocation bit), when it has one
    pub status_idx: Option<u64>,
}

impl DeviceCertRecord {
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
