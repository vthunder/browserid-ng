//! Account membership: what happens when an identity LEAVES an account
//! (registry-api-v1 §4.1 rule 3) and when it RETURNS within the hold.
//!
//! One implementation for every trigger — transfer, takeover, detach,
//! delete — reached by the cookie lane directly and by the registry API
//! through `RegistrarHost`. Leaving suspends the identity's data on the
//! account, never its keys:
//!
//! - the identity is remembered on the account as suspended (a
//!   `SuspendedIdentity` row); the `emails` row itself moves with the
//!   identity or goes away;
//! - its derived agent rows stay on the account, marked suspended;
//! - the status bits of its warrants and of its agents' certs are set,
//!   stamped with `"<user>:<identity>"` so a return clears exactly those
//!   and leaves explicit revokes alone;
//! - a `notice` is filed in the account's inbox;
//! - certs, sessions and the other identities are untouched.
//!
//! After the hold, `sweep_holds` drops the frozen records, and an account
//! with no identity left is dropped with them.

use chrono::{DateTime, Duration, Utc};

use crate::error::BrokerError;
use crate::store::{
    EmailType, StoreResult, SuspendedIdentity, UserId, UserStore, WarrantRequestRecord,
    WarrantRequestStatus,
};

/// The hold (§4.1: RECOMMENDED 30 days).
pub const HOLD_DAYS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaveReason {
    Transferred,
    TakenOver,
    Detached,
    Deleted,
}

impl LeaveReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            LeaveReason::Transferred => "transferred",
            LeaveReason::TakenOver => "taken_over",
            LeaveReason::Detached => "detached",
            LeaveReason::Deleted => "deleted",
        }
    }
}

/// What a leave did, for callers and tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LeaveReport {
    pub agents_suspended: usize,
    pub bits_set: usize,
    pub already_suspended: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepReport {
    pub identities_dropped: usize,
    pub agents_dropped: usize,
    pub warrants_dropped: u64,
    pub accounts_dropped: usize,
}

/// The stamp a suspension leaves on the bits it sets.
pub fn stamp(user_id: UserId, identity: &str) -> String {
    format!("{}:{}", user_id.0, identity.to_lowercase())
}

fn derived_agents<U: UserStore>(store: &U, user_id: UserId, identity: &str) -> StoreResult<Vec<String>> {
    Ok(store
        .list_emails(user_id)?
        .into_iter()
        .filter(|e| {
            e.email_type == EmailType::Agent
                && e.parent_email.as_deref().map_or(false, |p| p.eq_ignore_ascii_case(identity))
        })
        .map(|e| e.email)
        .collect())
}

fn file_notice<U: UserStore>(
    store: &U,
    user_id: UserId,
    identity: &str,
    reason: &str,
    at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> StoreResult<()> {
    let meta = serde_json::json!({
        "challenge": "",
        "notice": { "identity": identity, "reason": reason, "at": at.to_rfc3339() }
    });
    store.create_warrant_request(WarrantRequestRecord {
        code: crate::crypto::generate_salt_b64(),
        kind: "notice".to_string(),
        meta: Some(meta.to_string()),
        user_id,
        delegator_email: identity.to_string(),
        agent_email: String::new(),
        holder: String::new(),
        label: String::new(),
        grantor: String::new(),
        message: None,
        grants: Vec::new(),
        status: WarrantRequestStatus::Pending,
        warrants: None,
        external: false,
        return_url: None,
        created_at: at,
        expires_at,
        last_polled_at: None,
    })
}

/// `identity` leaves `user_id`'s account. The `emails` row is NOT moved or
/// removed here — the caller transfers it (`transfer_email`) or removes it
/// (`remove_email`) as the trigger requires; this records the hold and
/// freezes the account's records for the identity. Idempotent: an identity
/// already on hold here reports `already_suspended` and changes nothing.
pub fn identity_leaves<U: UserStore>(
    store: &U,
    user_id: UserId,
    identity: &str,
    reason: LeaveReason,
) -> StoreResult<LeaveReport> {
    let identity = identity.to_lowercase();
    if store.get_suspended_identity(user_id, &identity)?.is_some() {
        return Ok(LeaveReport { already_suspended: true, ..Default::default() });
    }
    let now = Utc::now();
    let hold_until = now + Duration::days(HOLD_DAYS);
    let by = stamp(user_id, &identity);
    let mut report = LeaveReport::default();

    // Derived agents go with their parent: rows stay, marked suspended.
    let agents = derived_agents(store, user_id, &identity)?;
    for a in &agents {
        store.set_email_suspension(a, Some((now, hold_until)))?;
    }
    report.agents_suspended = agents.len();

    // Warrants the identity (or its agents) signed as grantor.
    let mut grantors: Vec<String> = agents.clone();
    grantors.push(identity.clone());
    for w in store.list_warrants(user_id)? {
        if grantors.iter().any(|g| g.eq_ignore_ascii_case(&w.delegator_email)) {
            if let Some(idx) = w.status_idx {
                if store.mark_status_suspended_idx(idx, &by)? {
                    report.bits_set += 1;
                }
            }
        }
    }
    // The agents' own certs.
    for c in store.list_device_certs(user_id)? {
        if c.revoked_at.is_none()
            && c.identities.iter().any(|i| agents.iter().any(|a| a.eq_ignore_ascii_case(i)))
        {
            if let Some(idx) = c.status_idx {
                if store.mark_status_suspended_idx(idx, &by)? {
                    report.bits_set += 1;
                }
            }
        }
    }

    store.insert_suspended_identity(SuspendedIdentity {
        user_id,
        email: identity.clone(),
        suspended_at: now,
        hold_until,
        reason: reason.as_str().to_string(),
    })?;
    file_notice(store, user_id, &identity, "left", now, hold_until)?;
    Ok(report)
}

/// `identity` returns to `user_id`'s account within the hold. The caller
/// has already put the `emails` row back on the account. Clears the
/// suspension and every bit it set; bits set by an explicit revoke stay.
pub fn identity_returns<U: UserStore>(store: &U, user_id: UserId, identity: &str) -> StoreResult<u64> {
    let identity = identity.to_lowercase();
    if store.get_suspended_identity(user_id, &identity)?.is_none() {
        return Err(BrokerError::EmailNotFound);
    }
    for a in derived_agents(store, user_id, &identity)? {
        store.set_email_suspension(&a, None)?;
    }
    let cleared = store.clear_status_suspended_by(&stamp(user_id, &identity))?;
    store.delete_suspended_identity(user_id, &identity)?;
    let now = Utc::now();
    file_notice(store, user_id, &identity, "returned", now, now + Duration::days(HOLD_DAYS))?;
    Ok(cleared)
}

/// Move `identity` from `from` to `to` (transfer or takeover): the leave
/// cascade at `from`, then the row moves. If `to` had the identity on hold,
/// that is a return and its records are restored.
pub fn transfer_out<U: UserStore>(
    store: &U,
    from: UserId,
    to: UserId,
    identity: &str,
    reason: LeaveReason,
) -> StoreResult<LeaveReport> {
    let report = identity_leaves(store, from, identity, reason)?;
    store.transfer_email(identity, to)?;
    if store.get_suspended_identity(to, identity)?.is_some() {
        identity_returns(store, to, identity)?;
    }
    Ok(report)
}

/// Detach: the leave cascade, then the row is removed — nobody holds the
/// identity until a fresh attach does.
pub fn detach<U: UserStore>(store: &U, user_id: UserId, identity: &str) -> StoreResult<LeaveReport> {
    let report = identity_leaves(store, user_id, identity, LeaveReason::Detached)?;
    store.remove_email(user_id, identity)?;
    Ok(report)
}

/// Drop what the hold kept, for every hold that has ended: the identity's
/// frozen records and its suspended agents, then the account itself when
/// nothing is left on it. Cheap when nothing has expired; call it
/// opportunistically.
pub fn sweep_holds<U: UserStore>(store: &U, now: DateTime<Utc>) -> StoreResult<SweepReport> {
    let mut report = SweepReport::default();
    for hold in store.list_expired_holds(now)? {
        let user_id = hold.user_id;
        let agents = derived_agents(store, user_id, &hold.email)?;
        for a in &agents {
            report.warrants_dropped += store.delete_warrants_by_grantor(user_id, a)?;
            for c in store.list_device_certs(user_id)? {
                if c.identities.iter().any(|i| i.eq_ignore_ascii_case(a)) {
                    store.delete_device_cert(user_id, c.id)?;
                }
            }
            store.remove_email(user_id, a)?;
            report.agents_dropped += 1;
        }
        report.warrants_dropped += store.delete_warrants_by_grantor(user_id, &hold.email)?;
        store.delete_suspended_identity(user_id, &hold.email)?;
        report.identities_dropped += 1;

        let nothing_left = store.list_emails(user_id)?.is_empty()
            && store.list_suspended_identities(user_id)?.is_empty();
        if nothing_left {
            store.delete_warrant_requests_for_user(user_id)?;
            store.delete_user(user_id)?;
            report.accounts_dropped += 1;
        }
    }
    Ok(report)
}

/// The account's roster as the registry reports it (§4.5): active
/// identities, then those on hold. Derived agents are not roster entries.
pub fn roster<U: UserStore>(store: &U, user_id: UserId) -> StoreResult<Vec<(String, &'static str)>> {
    let mut out: Vec<(String, &'static str)> = store
        .list_emails(user_id)?
        .into_iter()
        .filter(|e| e.email_type != EmailType::Agent)
        .map(|e| (e.email, "active"))
        .collect();
    for s in store.list_suspended_identities(user_id)? {
        out.push((s.email, "suspended"));
    }
    Ok(out)
}
