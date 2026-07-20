//! Registrar-owned records. User accounts belong to the host (IdP/broker);
//! the registrar refers to them by an opaque `u64` id.

use chrono::{DateTime, Utc};

/// A pending warrant consent request (agent spec §6, v0.4). Created by an
/// agent's `warrant` request against a registered provisioning cert; resolved
/// by the delegator on the consent page, which signs the warrants client-side
/// with the identity key (the registrar never holds it). The row is the poll
/// *code* — single delivery, deleted on handover. The issued warrants
/// themselves persist in [`WarrantRecord`]s (jipx).
#[derive(Debug, Clone)]
pub struct WarrantRequestRecord {
    /// High-entropy opaque code — the poll credential (single delivery)
    pub code: String,
    /// The delegator's account
    pub user_id: u64,
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
    /// External request (§6.6): raised by a service agent certified by a
    /// foreign IdP, not by a registered provisioning credential. External
    /// rows are redirect-tied — reachable only via their `/consent/<code>`
    /// link, never listed in the pending inbox — and rate-limited per
    /// delegator.
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

/// A durable record of an IdP-signed device/config cert (DC Phase 3/4).
/// Persisted so certs are listable and revocable; revoking flips the cert's
/// status bit (shared status-list index space, egr7).
#[derive(Debug, Clone)]
pub struct DeviceCertRecord {
    pub id: u64,
    pub user_id: u64,
    /// Emails (or single-`*` globs) the cert authorizes
    pub identities: Vec<String>,
    /// "authentication" | "authorization"
    pub purpose: String,
    /// The broker-assigned opaque holder id (`<ns>.<id>`) this cert acts as.
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

/// A registered warrant (jipx): the delegator's own record of a grant they
/// signed — one agent at one audience. Kept per account (shown only to the
/// delegator's session), upserted on (user, agent, audience) so a reissue
/// replaces its predecessor. The substrate for per-warrant revocation (egr7).
#[derive(Debug, Clone)]
pub struct WarrantRecord {
    pub id: u64,
    pub user_id: u64,
    pub delegator_email: String,
    pub agent_email: String,
    pub audience: String,
    pub scopes: Vec<String>,
    /// The signed warrant JWS
    pub warrant: String,
    /// The warrant's status index (from its `status` claim), when it has one
    pub status_idx: Option<u64>,
    /// Device-cert-model holder matcher (`*` / `<ns>.*` / `<id>`)
    pub holder: Option<String>,
    /// The config (authorization) device cert JWS that signed this warrant —
    /// presented alongside it in the 4-object bundle
    pub config_cert: Option<String>,
    pub signed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
