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

/// How the broker verified ownership of a secondary identity
/// (browserid-ng-tsqk, the claim-time authority hierarchy). Recorded at
/// claim time and enforced from stored state, never re-derived per request:
/// an SMTP proof covers exactly one mailbox, an atproto proof covers every
/// label at the handle domain. Meaningless for primary/agent identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofMethod {
    /// The email verification loop proved the specific mailbox.
    Smtp,
    /// An atproto handle attestation proved the whole domain.
    Atproto,
    /// The mailbox provider's OIDC sign-in proved the specific mailbox
    /// (browserid-ng-qer8). Per-mailbox scope, exactly like `Smtp` — the
    /// `proof_subject` is `<iss>#<sub>` (the stable provider account id).
    Oidc,
}

impl ProofMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProofMethod::Smtp => "smtp",
            ProofMethod::Atproto => "atproto",
            ProofMethod::Oidc => "oidc",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "smtp" => Some(ProofMethod::Smtp),
            "atproto" => Some(ProofMethod::Atproto),
            "oidc" => Some(ProofMethod::Oidc),
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
    /// How the broker verified this identity (browserid-ng-tsqk). Every
    /// pre-hierarchy email is grandfathered as `Smtp` by the migration
    /// default, which the pre-flight confirmed is accurate for all
    /// production identities.
    pub proof: ProofMethod,
    /// The subject that held the proof — for `Atproto`, the DID the handle
    /// resolved to at claim time. What lets a cold re-claim distinguish
    /// "same holder signing in" from "the handle changed hands".
    pub proof_subject: Option<String>,
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
    /// Which consent flow this row belongs to (spec §7.5): "agent" |
    /// "connection" | "authoring". The registrar owns the semantics; the
    /// store carries it opaquely.
    pub kind: String,
    /// Record-request extras (challenge/proof state, client descriptor,
    /// binding.id) as one opaque JSON blob. `None` on agent rows.
    pub meta: Option<String>,
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
    /// Where the consent page sends the browser after a successful approval
    /// (the OAuth authorization-code lane). Origin-validated by the registrar
    /// at request time — never a caller-controlled redirect.
    pub return_url: Option<String>,
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
    /// Authoring ceremony rows (spec §7.5): the row's grantee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grantee: Option<String>,
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
    /// Connection records (spec §5): the record's broker-minted `binding.id`.
    /// Folded into the upsert key so two connections to the same audience
    /// stay distinct rows (§6.6 invariant 5).
    pub binding_id: Option<String>,
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
    /// The cert's status-list URI — WHICH revocation authority `status_idx`
    /// indexes into (the broker's own list, a hosted tenant's list, or a
    /// foreign IdP's). Without it revocation flips a bit on the wrong list
    /// (bean pbzn). None on legacy rows (treated as the broker's own list).
    pub status_uri: Option<String>,
    /// The cert's status-list index (its revocation bit), when it has one
    pub status_idx: Option<u64>,
    /// The proof class ("smtp"/"oidc"/"atproto") the identity was verified
    /// under when this cert was issued — the registry mirror of the cert's
    /// `prov` claim (x5c3). Lets a provenance change revoke the EXACT stale
    /// set (auth + config, all browsers) instead of one presented cert at a
    /// time. Legacy rows read "smtp" (migration default — historically true).
    pub prov: String,
}

impl DeviceCertRecord {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// How a session was established (epic browserid-ng-shyj). The level gates
/// capability — which credentials the session may mint — not lifetime: both
/// levels share the same 30-day TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLevel {
    /// Established by an E1/E2 proof (primary presentation, OIDC/Google or
    /// bsky bridge claim) or an emailed code — no account password shown.
    Lightweight,
    /// The account password was presented (login, update, first set).
    Full,
}

impl SessionLevel {
    /// Stable storage/wire token ("lightweight" / "full").
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionLevel::Lightweight => "lightweight",
            SessionLevel::Full => "full",
        }
    }

    /// Parse a stored token. Unknown values map to `Lightweight` — the
    /// least-privileged level — so a bad row can never grant password powers.
    pub fn parse(s: &str) -> SessionLevel {
        match s {
            "full" => SessionLevel::Full,
            _ => SessionLevel::Lightweight,
        }
    }
}

/// A user session
#[derive(Debug, Clone)]
pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub csrf_token: String,
    pub created_at: DateTime<Utc>,
    /// How this session was established — Full (password) or Lightweight
    /// (E1/E2 proof). Every creation site must decide (browserid-ng-ca29).
    pub level: SessionLevel,
}

/// Lifecycle of a hosted-primary tenant domain (bean g5qt).
///
/// `PendingDns` from onboarding until the domain's DNSSEC `_browserid`
/// record carrying this tenant's public key validates; `Active` while the
/// broker issues for the domain; `Suspended` stops issuance without
/// deleting anything (the DNS record is the tenant-side kill switch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    PendingDns,
    Active,
    Suspended,
}

impl TenantStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TenantStatus::PendingDns => "pending_dns",
            TenantStatus::Active => "active",
            TenantStatus::Suspended => "suspended",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending_dns" => Some(TenantStatus::PendingDns),
            "active" => Some(TenantStatus::Active),
            "suspended" => Some(TenantStatus::Suspended),
            _ => None,
        }
    }
}

/// Managed-identity policy for a tenant (spec §4.7). Stored as one JSON blob
/// so vocabulary can evolve without migrations. `enabled` gates everything:
/// when true, device certs are stamped `managed: true` and the mint applies
/// current policy to every access cert.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManagementPolicy {
    pub enabled: bool,
    /// Per-audience posture: the mint requires the access request to name its
    /// audience and scopes the cert to it (used-set visibility). Default off =
    /// broad posture (uniform allowlist, RP-blind mint).
    #[serde(default)]
    pub per_audience: bool,
    /// Allowed audiences (cleartext here, admin-managed; hashed on the wire).
    /// Empty = allow all.
    #[serde(default)]
    pub audiences: Vec<String>,
    /// Allowed warrant scopes. None = unrestricted.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Max warrant TTL in seconds. None = unrestricted. Legacy single knob:
    /// when `access_cert_ttl` is absent it also bounds the access-cert
    /// validity (backward compat for policies saved before the split).
    #[serde(default)]
    pub max_ttl: Option<i64>,
    /// Device-cert validity in seconds — how long a signed-in device stays
    /// signed in. None = the default (90 days).
    #[serde(default)]
    pub device_cert_ttl: Option<i64>,
    /// Access-cert validity in seconds — how long each site credential lasts
    /// before it's silently reissued. None = `max_ttl`, else the default (24h).
    #[serde(default)]
    pub access_cert_ttl: Option<i64>,
    /// base64url salt for audience hashing; generated when the policy is first
    /// saved.
    #[serde(default)]
    pub salt: String,
}

/// A hosted-primary tenant: a domain browserid.me issues for under a
/// custodial per-tenant key. The private key is sealed at rest
/// (`crate::tenant_keys`); `public_key` is the base64url raw Ed25519 point
/// that must appear in the domain's `_browserid` DNSSEC record.
#[derive(Debug, Clone)]
pub struct Tenant {
    pub id: u64,
    pub domain: String,
    pub public_key: String,
    pub private_key_sealed: String,
    pub status: TenantStatus,
    /// Allow mailbox-proof self-claims for unrostered local parts (post-MVP;
    /// stored so the policy exists from day one).
    pub self_claim: bool,
    /// The browserid account that onboarded this domain. It controls the
    /// domain (it did the DNS) and always retains console access, even when
    /// the admin-of-record is a domain-local email not yet on the account.
    pub owner_user_id: Option<UserId>,
    /// Admin-of-record identity (becomes first admin at activation). Either an
    /// existing identity the owner holds, or an email at this domain.
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    /// Managed-identity policy (spec §4.7); None = never configured.
    pub management: Option<ManagementPolicy>,
}

/// State of one roster entry. Disabled blocks login and minting; certs
/// already issued age out (access certs ≤24h).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RosterState {
    Active,
    Disabled,
}

impl RosterState {
    pub fn as_str(&self) -> &'static str {
        match self {
            RosterState::Active => "active",
            RosterState::Disabled => "disabled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(RosterState::Active),
            "disabled" => Some(RosterState::Disabled),
            _ => None,
        }
    }
}

/// An admin-managed user at a tenant domain. Authoritative for its local
/// part: while a roster entry exists, mailbox self-claim for the address is
/// refused. `password_hash` is admin-set (bcrypt); `must_change_password`
/// forces a change on first interactive login.
#[derive(Debug, Clone)]
pub struct RosterEntry {
    pub tenant_id: u64,
    pub local_part: String,
    pub password_hash: String,
    pub state: RosterState,
    pub must_change_password: bool,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}
