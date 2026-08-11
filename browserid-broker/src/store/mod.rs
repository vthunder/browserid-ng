//! Storage abstractions for the broker

pub mod memory;
pub mod models;
pub mod sqlite;

pub use memory::{InMemorySessionStore, InMemoryUserStore};
pub use models::*;
pub use sqlite::SqliteStore;

use crate::error::BrokerError;
use std::collections::HashMap;

/// Result type for store operations
pub type StoreResult<T> = Result<T, BrokerError>;

/// Trait for user and email storage
pub trait UserStore: Send + Sync {
    /// Create a new user with the given password hash
    fn create_user(&self, password_hash: &str) -> StoreResult<UserId>;

    /// Create a user without a password (for primary-only users)
    fn create_user_no_password(&self) -> StoreResult<UserId>;

    /// Get a user by ID
    fn get_user(&self, user_id: UserId) -> StoreResult<Option<User>>;

    /// Get a user by email address
    fn get_user_by_email(&self, email: &str) -> StoreResult<Option<User>>;

    /// Add an email to a user's account
    fn add_email(&self, user_id: UserId, email: &str, verified: bool) -> StoreResult<()>;

    /// Add email with type tracking
    fn add_email_with_type(
        &self,
        user_id: UserId,
        email: &str,
        verified: bool,
        email_type: EmailType,
    ) -> StoreResult<()>;

    /// List all emails for a user
    fn list_emails(&self, user_id: UserId) -> StoreResult<Vec<Email>>;

    /// Mark an email as verified
    fn verify_email(&self, email: &str) -> StoreResult<()>;

    /// Remove an email from a user's account
    fn remove_email(&self, user_id: UserId, email: &str) -> StoreResult<()>;

    /// Reassign an existing email to `to_user_id`, moving it off whatever account
    /// currently owns it — per-email transfer on proof of ownership (Persona
    /// semantics). Errors with `EmailNotFound` if the email doesn't exist.
    /// Callers are responsible for deleting a former account left with no emails.
    fn transfer_email(&self, email: &str, to_user_id: UserId) -> StoreResult<()>;

    /// Set (or clear) an email's parent — the controlling identity for a
    /// subordinate/derived email (mingo-cm8z). Private account metadata; callers
    /// must ensure both emails belong to the same account. `None` clears it.
    fn set_parent_email(&self, email: &str, parent_email: Option<&str>) -> StoreResult<()>;

    /// Set (or clear) an email's USER-CHOSEN display name (Flow I step 2,
    /// eywc) — only meaningful for agent identities today. `None` clears it.
    /// INTERNAL: never published; see `Email::display_name`.
    fn set_email_display_name(&self, email: &str, display_name: Option<&str>) -> StoreResult<()>;

    /// Set (or clear) an email's PUBLIC byline (bean tmk8) — what services
    /// display next to this identity's actions. `None` clears it (services
    /// fall back to the email local-part).
    fn set_email_public_name(&self, email: &str, public_name: Option<&str>) -> StoreResult<()>;

    /// Record how ownership of this identity was proven (browserid-ng-tsqk).
    /// Emails default to `smtp` on insert; the handle-attestation route
    /// flips its identities to `atproto`.
    fn set_email_proof(
        &self,
        email: &str,
        proof: ProofMethod,
        subject: Option<&str>,
    ) -> StoreResult<()>;

    /// Store a pending verification
    fn create_pending(&self, pending: PendingVerification) -> StoreResult<()>;

    /// Get a pending verification by secret
    fn get_pending(&self, secret: &str) -> StoreResult<Option<PendingVerification>>;

    /// Delete a pending verification
    fn delete_pending(&self, secret: &str) -> StoreResult<()>;

    /// Delete expired pending verifications (older than given duration)
    fn cleanup_expired_pending(&self, max_age_minutes: i64) -> StoreResult<u64>;

    /// Update a user's password hash
    fn update_password(&self, user_id: UserId, password_hash: &str) -> StoreResult<()>;

    /// Check if there's a pending password reset for an email
    fn has_pending_reset(&self, email: &str) -> StoreResult<bool>;

    /// Delete a user and all their associated data (emails, pending verifications)
    fn delete_user(&self, user_id: UserId) -> StoreResult<()>;

    /// Get pending verification by email and type
    fn get_pending_by_email(
        &self,
        email: &str,
        verification_type: VerificationType,
    ) -> StoreResult<Option<PendingVerification>>;

    /// Update email's last_used_as when type changes
    fn update_email_last_used(&self, email: &str, email_type: EmailType) -> StoreResult<()>;

    /// Get email record by address
    fn get_email(&self, email: &str) -> StoreResult<Option<Email>>;

    /// Check if user has a password set (non-empty password_hash)
    fn has_password(&self, user_id: UserId) -> StoreResult<bool>;

    /// Set password for a user (for transition cases)
    fn set_password(&self, user_id: UserId, password_hash: &str) -> StoreResult<()>;

    /// Clear an email's verified flag — used to revoke agent identities
    /// (re-mints then fail the ordinary verified check; certs age out)
    fn unverify_email(&self, email: &str) -> StoreResult<()>;

    // --- Warrant consent requests (agent spec §6, v0.4) ---

    /// Store a new pending warrant consent request
    fn create_warrant_request(&self, req: WarrantRequestRecord) -> StoreResult<()>;

    /// Look up a warrant request by its poll code
    fn get_warrant_request(&self, code: &str) -> StoreResult<Option<WarrantRequestRecord>>;

    /// List a user's open (pending, unexpired) warrant requests, for the
    /// consent page
    fn list_pending_warrant_requests(&self, user_id: UserId)
        -> StoreResult<Vec<WarrantRequestRecord>>;

    /// Resolve a pending request: approve with the signed warrant JWSs (one
    /// per grant, in grant order), or deny with `None`. Scoped to the owning
    /// user; errors with `WarrantRequestNotFound` if absent, another user's,
    /// or not pending.
    fn respond_warrant_request(
        &self,
        user_id: UserId,
        code: &str,
        warrants: Option<&[String]>,
    ) -> StoreResult<()>;

    /// Record a poll (rate-limiting input), returning the previous
    /// last_polled_at
    fn touch_warrant_poll(&self, code: &str) -> StoreResult<Option<chrono::DateTime<chrono::Utc>>>;

    /// Delete a warrant request (single delivery / cleanup) — removes the
    /// audience and scope data entirely
    fn delete_warrant_request(&self, code: &str) -> StoreResult<()>;

    /// Drop expired warrant requests
    fn cleanup_expired_warrant_requests(&self) -> StoreResult<u64>;

    // --- Warrant registry (jipx) ---

    /// Record (or replace — upsert on user/agent/audience) an issued warrant
    fn upsert_warrant(&self, record: WarrantRecord) -> StoreResult<()>;

    /// The account's registered warrants, newest first
    fn list_warrants(&self, user_id: UserId) -> StoreResult<Vec<WarrantRecord>>;

    /// Remove a warrant record (the signed JWS an agent holds stays valid
    /// until expiry — this only forgets the registry row). Scoped to the
    /// owning user; errors with `WarrantRequestNotFound` if absent.
    fn delete_warrant(&self, user_id: UserId, warrant_id: u64) -> StoreResult<()>;

    // --- Status entries (egr7): the revocation bitmap's index space ---

    /// Get (or allocate) the status index for `(kind, subject)` — e.g.
    /// ("identity", email) or ("warrant", composite grant key). Stable across
    /// re-mints/reissues so one bit covers every outstanding credential.
    fn get_or_allocate_status(&self, kind: &str, subject: &str) -> StoreResult<u64>;

    /// Flip the revocation bit for `(kind, subject)`. Ok(false) if no entry.
    fn set_status_revoked(&self, kind: &str, subject: &str) -> StoreResult<bool>;

    /// Flip the revocation bit by index. Ok(false) if no entry.
    fn set_status_revoked_idx(&self, idx: u64) -> StoreResult<bool>;

    /// Clear the revocation bit by index (reactivate) — used when a subject is
    /// RE-authorized after a prior revoke (the status subject/index is stable, so
    /// a fresh grant must un-revoke the shared bit). Ok(false) if no entry.
    fn set_status_active_idx(&self, idx: u64) -> StoreResult<bool>;

    /// Whether an index is revoked (issuer-local authoritative check)
    fn is_status_revoked_idx(&self, idx: u64) -> StoreResult<bool>;

    /// All revoked indices plus the current max index (bitmap capacity)
    fn revoked_status_indices(&self) -> StoreResult<(Vec<u64>, u64)>;

    // --- Device certs (DC Phase 3/4): durable, revocable IdP-signed certs ---

    /// Persist an issued device/config cert (upsert on its pubkey). Returns
    /// the row id.
    fn insert_device_cert(&self, rec: DeviceCertRecord) -> StoreResult<u64>;

    /// Look up a device cert by its public key (base64)
    fn get_device_cert_by_pubkey(&self, pubkey: &str) -> StoreResult<Option<DeviceCertRecord>>;

    /// List a user's device certs (active and revoked)
    fn list_device_certs(&self, user_id: UserId) -> StoreResult<Vec<DeviceCertRecord>>;

    /// Soft-revoke a device cert. Scoped to the owning user; errors with
    /// `DeviceCertNotFound` if it doesn't exist or belongs to someone else.
    fn revoke_device_cert(&self, user_id: UserId, cert_id: u64) -> StoreResult<()>;

    /// Forget a holder: delete the user's device-cert rows carrying this
    /// holder id (revocation bits are the CALLER's job first — deletion alone
    /// does not invalidate live certs) plus its label. Returns the number of
    /// cert rows removed. A holder id is baked into its signed certs, so
    /// "removing a device" = revoke + forget; the device can always sign in
    /// again, which simply records a fresh entry.
    fn forget_holder(&self, user_id: UserId, holder: &str) -> StoreResult<u64>;

    // --- Holder moves (account-driven re-organization) ---

    /// Record a PERMANENT redirect `old_holder → new_holder` (upsert on the
    /// old id). The move revokes the old certs up front (caller's job); the
    /// redirect makes every later path converge on the target: the device
    /// re-issues under it, and a stale client supplying the old holder is
    /// redirected at issuance.
    fn set_holder_move(&self, user_id: UserId, old_holder: &str, new_holder: &str) -> StoreResult<()>;

    /// Where `holder` points now, following the redirect chain to its end
    /// (bounded). `None` when the holder was never moved.
    fn resolve_holder_move(&self, user_id: UserId, holder: &str) -> StoreResult<Option<String>>;

    /// All of the user's redirects as `(old_holder, new_holder)` pairs.
    fn list_holder_moves(&self, user_id: UserId) -> StoreResult<Vec<(String, String)>>;

    // --- Holder namespaces (holder-authorization model) ---

    /// Return the stored random prefix for this user's namespace `name`
    /// (`browsers` / `agents` / `services` / …), creating the namespace with a
    /// fresh random prefix on first use. The prefix is persisted (not derived)
    /// so a future re-categorize can rotate it. Every holder the broker assigns
    /// under this namespace is `<prefix>.<random>`.
    fn get_or_create_namespace(&self, user_id: UserId, name: &str) -> StoreResult<String>;

    /// Adopt `new_prefix` as the namespace's prefix — but only while the
    /// namespace is UNUSED (no recorded device-cert holder carries its current
    /// prefix). Covers the cold first sign-in, where the cert was issued before
    /// a session existed to hand out the account prefix: the account-creating
    /// login adopts the cert's prefix so the holder lands in `browsers` instead
    /// of orphaning. Returns whether the namespace now uses `new_prefix`.
    fn adopt_namespace_prefix(
        &self,
        user_id: UserId,
        name: &str,
        new_prefix: &str,
    ) -> StoreResult<bool>;

    /// List this user's namespaces (name, stored prefix, friendly label).
    fn list_namespaces(&self, user_id: UserId) -> StoreResult<Vec<Namespace>>;

    /// Rename a namespace's friendly label (leaves the opaque prefix untouched,
    /// so existing holders + `<prefix>.*` warrants keep matching).
    fn set_namespace_label(&self, user_id: UserId, name: &str, label: &str) -> StoreResult<()>;

    /// Create a namespace with a fresh random prefix. No-op/`Ok` if it exists.
    fn create_namespace(&self, user_id: UserId, name: &str, label: &str) -> StoreResult<()>;

    /// Delete a namespace. Refused (`PolicyRefused`) if any of this user's
    /// device-cert holders still live under its prefix (block non-empty).
    fn delete_namespace(&self, user_id: UserId, name: &str) -> StoreResult<()>;

    /// Set the friendly label for one opaque holder id (the logical-slot name,
    /// e.g. "Main Laptop"). Upserts.
    fn set_holder_label(&self, user_id: UserId, holder_id: &str, label: &str) -> StoreResult<()>;

    /// This user's holder-id → friendly-label map (holders without a row are
    /// simply absent; the caller supplies a default).
    fn get_holder_labels(&self, user_id: UserId) -> StoreResult<HashMap<String, String>>;

    // --- Hosted-primary tenants (bean g5qt) ---

    /// Create a tenant in `PendingDns` with a freshly generated custodial
    /// keypair (public b64url, private sealed by `crate::tenant_keys`).
    /// `owner_user_id` is the onboarding account (retains console access);
    /// `created_by` is the admin-of-record identity. Errors with
    /// `TenantExists` if the domain already has a tenant row.
    fn create_tenant(
        &self,
        domain: &str,
        public_key: &str,
        private_key_sealed: &str,
        owner_user_id: Option<UserId>,
        created_by: &str,
    ) -> StoreResult<Tenant>;

    /// Revoke every broker-issued device cert (and, via the shared status
    /// bit, the access certs derived from it) for identities at `domain`.
    /// Flips each cert's revocation bit in the broker's own status list and
    /// stamps `revoked_at`. Used when a domain that browserid already knew is
    /// verified as a tenant, so prior fallback credentials stop working.
    /// Returns the number of device-cert rows revoked. Certs issued by the
    /// domain's previous external IdP are not in this registry and are not
    /// affected (the DNS key change retires those).
    fn revoke_domain_device_certs(&self, domain: &str) -> StoreResult<u64>;

    /// Look up a tenant by domain (exact, lowercase).
    fn get_tenant(&self, domain: &str) -> StoreResult<Option<Tenant>>;

    /// Tenants this identity onboarded or administers.
    fn list_tenants_for(&self, identity: &str) -> StoreResult<Vec<Tenant>>;

    /// Flip a tenant's status. Activation (→`Active`) stamps `activated_at`
    /// once and seats `created_by` as the first admin.
    fn set_tenant_status(&self, domain: &str, status: TenantStatus) -> StoreResult<()>;

    /// Save the tenant's managed-identity policy (spec §4.7).
    fn set_tenant_management(&self, domain: &str, policy: &ManagementPolicy) -> StoreResult<()>;

    /// Revoke EVERY credential on the tenant's status list (device, config,
    /// and access certs alike) — the enable-management transition: everyone
    /// re-logs in and comes back with marked certs. Returns bits set.
    fn tenant_status_revoke_all(&self, tenant_id: u64) -> StoreResult<u64>;

    /// Revoke one slot on a tenant's status list by INDEX (the registry rows
    /// carry (status_uri, idx); forget/remove routes revocation to the right
    /// authority — bean pbzn).
    fn tenant_status_revoke_idx(&self, tenant_id: u64, idx: u64) -> StoreResult<bool>;

    /// Delete a tenant and everything scoped to it — admins, roster, status
    /// index space. The tenant's certs (signed under a key that now vanishes)
    /// die once the DNS record is removed or re-onboarded; this only forgets
    /// the broker-side rows so the domain can be onboarded fresh. No-op if the
    /// domain has no tenant.
    fn delete_tenant(&self, domain: &str) -> StoreResult<()>;

    /// Whether `identity` administers `domain`'s tenant.
    fn is_tenant_admin(&self, domain: &str, identity: &str) -> StoreResult<bool>;

    /// Add an admin identity to a tenant (idempotent).
    fn add_tenant_admin(&self, domain: &str, identity: &str, added_by: &str) -> StoreResult<()>;

    /// Remove an admin identity from a tenant. Ok(false) if it wasn't one.
    /// Policy (self-removal, last-admin floor) is the ROUTE's job — the store
    /// just forgets the row.
    fn remove_tenant_admin(&self, domain: &str, identity: &str) -> StoreResult<bool>;

    /// List a tenant's admin identities.
    fn list_tenant_admins(&self, domain: &str) -> StoreResult<Vec<String>>;

    /// Create a roster entry (admin-set bcrypt hash). `must_change` forces a
    /// password change on the user's first interactive login — set when an
    /// admin provisions someone else with a temporary password, cleared when
    /// the eventual user chose the password themselves (onboarding). Errors
    /// with `RosterEntryExists` for a duplicate local part.
    fn create_roster_entry(
        &self,
        tenant_id: u64,
        local_part: &str,
        password_hash: &str,
        must_change: bool,
        created_by: &str,
    ) -> StoreResult<()>;

    /// Look up one roster entry.
    fn get_roster_entry(&self, tenant_id: u64, local_part: &str) -> StoreResult<Option<RosterEntry>>;

    /// All roster entries for a tenant.
    fn list_roster(&self, tenant_id: u64) -> StoreResult<Vec<RosterEntry>>;

    /// Enable/disable a roster entry. Ok(false) if absent.
    fn set_roster_state(&self, tenant_id: u64, local_part: &str, state: RosterState) -> StoreResult<bool>;

    /// Admin password reset: new hash + `must_change_password` back on.
    /// The user's own change (`must_change` false) also lands here.
    fn set_roster_password(
        &self,
        tenant_id: u64,
        local_part: &str,
        password_hash: &str,
        must_change: bool,
    ) -> StoreResult<bool>;

    /// Stamp a successful interactive login.
    fn touch_roster_login(&self, tenant_id: u64, local_part: &str) -> StoreResult<()>;

    // --- Tenant status lists: per-tenant revocation index space ---

    /// Get (or allocate, starting at 1) the status index for `subject` on
    /// this tenant's list. Index 0 is never allocated (list sentinel).
    fn tenant_status_allocate(&self, tenant_id: u64, subject: &str) -> StoreResult<u64>;

    /// Flip the revocation bit for a subject on the tenant's list.
    fn tenant_status_revoke(&self, tenant_id: u64, subject: &str) -> StoreResult<bool>;

    /// Whether a tenant-list index is revoked.
    fn tenant_status_is_revoked(&self, tenant_id: u64, idx: u64) -> StoreResult<bool>;

    /// Revoked indices + max index for building the tenant's signed list.
    fn tenant_status_snapshot(&self, tenant_id: u64) -> StoreResult<(Vec<u64>, u64)>;
}

/// Trait for session storage
pub trait SessionStore: Send + Sync {
    /// Create a new session for a user
    fn create(&self, user_id: UserId) -> StoreResult<Session>;

    /// Get a session by ID
    fn get(&self, session_id: &SessionId) -> StoreResult<Option<Session>>;

    /// Delete a session
    fn delete(&self, session_id: &SessionId) -> StoreResult<()>;

    /// Delete **all** sessions for a user; returns the number removed. Used to
    /// evict every live session on a credential change (password update/reset),
    /// so recovering an account also cuts off an attacker's session (audit H2).
    fn delete_by_user(&self, user_id: UserId) -> StoreResult<u64>;
}
