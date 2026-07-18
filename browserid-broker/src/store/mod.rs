//! Storage abstractions for the broker

pub mod memory;
pub mod models;
pub mod sqlite;

pub use memory::{InMemorySessionStore, InMemoryUserStore};
pub use models::*;
pub use sqlite::SqliteStore;

use crate::error::BrokerError;

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

    /// Register a provisioning certificate (tdxf, spec v0.2). Stores only
    /// public data: the delegation bundle and its `P_pub`.
    fn register_provisioning_cert(
        &self,
        user_id: UserId,
        delegator_email: &str,
        provisioning_pub: &str,
        bundle: &str,
        label: &str,
    ) -> StoreResult<ProvisioningCertRecord>;

    /// Look up a registered provisioning cert by its `P_pub` (endorse path)
    fn get_provisioning_cert_by_pub(
        &self,
        provisioning_pub: &str,
    ) -> StoreResult<Option<ProvisioningCertRecord>>;

    /// List a user's registered provisioning certs (active and revoked)
    fn list_provisioning_certs(&self, user_id: UserId) -> StoreResult<Vec<ProvisioningCertRecord>>;

    /// Count a user's active (unrevoked) provisioning certs — account-level
    /// policy input at endorse time
    fn count_active_provisioning_certs(&self, user_id: UserId) -> StoreResult<usize>;

    /// Soft-revoke a provisioning cert. Scoped to the owning user; errors with
    /// `ProvisioningCertNotFound` if it doesn't exist or belongs to someone else.
    fn revoke_provisioning_cert(&self, user_id: UserId, cert_id: u64) -> StoreResult<()>;

    /// Update a cert's last_endorsed_at to now (audit trail)
    fn touch_provisioning_cert(&self, cert_id: u64) -> StoreResult<()>;

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
}

/// Trait for session storage
pub trait SessionStore: Send + Sync {
    /// Create a new session for a user
    fn create(&self, user_id: UserId) -> StoreResult<Session>;

    /// Get a session by ID
    fn get(&self, session_id: &SessionId) -> StoreResult<Option<Session>>;

    /// Delete a session
    fn delete(&self, session_id: &SessionId) -> StoreResult<()>;
}
