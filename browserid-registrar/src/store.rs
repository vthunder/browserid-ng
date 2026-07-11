//! Registrar storage trait. The host (broker, or a self-hosting IdP)
//! provides the persistence; the registrar owns the semantics.

use crate::error::RegistrarError;
use crate::models::{ProvisioningCertRecord, WarrantRecord, WarrantRequestRecord};

pub type StoreResult<T> = Result<T, RegistrarError>;

/// The registrar's tables: provisioning-cert registry, pending warrant
/// consent requests, the warrant registry, and the revocation-status index
/// space. User ids are the host's account ids, opaque to the registrar.
pub trait RegistrarStore: Send + Sync {
    // --- Provisioning-cert registry (tdxf, spec v0.2) ---

    /// Register a provisioning certificate. Stores only public data: the
    /// delegation bundle and its `P_pub`.
    fn register_provisioning_cert(
        &self,
        user_id: u64,
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
    fn list_provisioning_certs(&self, user_id: u64) -> StoreResult<Vec<ProvisioningCertRecord>>;

    /// Count a user's active (unrevoked) provisioning certs — account-level
    /// policy input at endorse time
    fn count_active_provisioning_certs(&self, user_id: u64) -> StoreResult<usize>;

    /// Soft-revoke a provisioning cert. Scoped to the owning user; errors
    /// with `ProvisioningCertNotFound` if it doesn't exist or belongs to
    /// someone else.
    fn revoke_provisioning_cert(&self, user_id: u64, cert_id: u64) -> StoreResult<()>;

    /// Update a cert's last_endorsed_at to now (audit trail)
    fn touch_provisioning_cert(&self, cert_id: u64) -> StoreResult<()>;

    // --- Warrant consent requests (agent spec §6, v0.4) ---

    /// Store a new pending warrant consent request
    fn create_warrant_request(&self, req: WarrantRequestRecord) -> StoreResult<()>;

    /// Look up a warrant request by its poll code
    fn get_warrant_request(&self, code: &str) -> StoreResult<Option<WarrantRequestRecord>>;

    /// List a user's open (pending, unexpired) warrant requests, for the
    /// consent page
    fn list_pending_warrant_requests(&self, user_id: u64)
        -> StoreResult<Vec<WarrantRequestRecord>>;

    /// Resolve a pending request: approve with the signed warrant JWSs (one
    /// per grant, in grant order), or deny with `None`. Scoped to the owning
    /// user; errors with `WarrantRequestNotFound` if absent, another user's,
    /// or not pending.
    fn respond_warrant_request(
        &self,
        user_id: u64,
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
    fn list_warrants(&self, user_id: u64) -> StoreResult<Vec<WarrantRecord>>;

    /// Remove a warrant record (the signed JWS an agent holds stays valid
    /// until expiry — this only forgets the registry row). Scoped to the
    /// owning user; errors with `WarrantRequestNotFound` if absent.
    fn delete_warrant(&self, user_id: u64, warrant_id: u64) -> StoreResult<()>;

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
}
