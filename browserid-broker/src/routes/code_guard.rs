//! Brute-force guard for the wsapi 6-digit verification codes (security audit
//! C1). The `complete_*` endpoints historically looked a pending record up by
//! the code alone, across the whole 900k code space, with no attempt limit — so
//! an unauthenticated attacker could walk the space within a code's 15-minute
//! window and hit *some* account (or, after triggering a reset for a known
//! email, that specific account).
//!
//! This module binds a completion to its target **email** and burns the pending
//! record after [`MAX_VERIFY_ATTEMPTS`] wrong guesses — the same defense the
//! fallback IdP path already applies (`fallback_idp.rs`), so a code can only be
//! guessed ~5 times per target per window. The attempt counter is in-memory and
//! single-instance, matching the app's other throttles (email send, fallback
//! verify); a restart only resets counters, and codes still expire in 15 min.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::error::BrokerError;
use crate::store::{PendingVerification, UserStore, VerificationType};

/// Wrong-code attempts before a code is burned.
const MAX_VERIFY_ATTEMPTS: u32 = 5;

/// Codes are valid this long (mirrors the per-endpoint expiry checks).
const CODE_TTL_MINUTES: i64 = 15;

/// `"{type}:{normalized-email}"` -> wrong-attempt count for the live code.
static VERIFY_ATTEMPTS: LazyLock<Mutex<HashMap<String, u32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn attempt_key(vtype: VerificationType, email: &str) -> String {
    format!("{:?}:{}", vtype, email.to_lowercase())
}

/// Verify a submitted code against the pending record for `(email, vtype)`,
/// enforcing the attempt cap. On success the caller receives the pending record
/// and is responsible for consuming it (`delete_pending(&pending.secret)`).
///
/// Failure modes all return an opaque [`BrokerError::InvalidVerificationCode`]
/// (or `VerificationExpired`) so a caller cannot distinguish "no such pending"
/// from "wrong code" — no oracle beyond what enumeration already leaks. A wrong
/// guess increments the counter and, at the cap, deletes the pending record so
/// the remaining code space cannot be walked.
pub fn verify_pending_code<U: UserStore>(
    store: &U,
    email: &str,
    vtype: VerificationType,
    submitted_code: &str,
) -> Result<PendingVerification, BrokerError> {
    let key = attempt_key(vtype, email);

    let pending = match store.get_pending_by_email(email, vtype)? {
        Some(p) => p,
        None => {
            // Nothing to burn, but still count so a per-email spray is bounded.
            record_wrong(&key, None, store);
            return Err(BrokerError::InvalidVerificationCode);
        }
    };

    // Expired → consume the record and clear the counter (fresh code resets).
    let age = chrono::Utc::now() - pending.created_at;
    if age.num_minutes() > CODE_TTL_MINUTES {
        store.delete_pending(&pending.secret)?;
        VERIFY_ATTEMPTS.lock().unwrap().remove(&key);
        return Err(BrokerError::VerificationExpired);
    }

    if pending.secret == submitted_code.trim() {
        VERIFY_ATTEMPTS.lock().unwrap().remove(&key);
        Ok(pending)
    } else {
        record_wrong(&key, Some(&pending.secret), store);
        Err(BrokerError::InvalidVerificationCode)
    }
}

/// Increment the wrong-attempt counter for `key`; at the cap, burn the pending
/// record (if one exists) and reset the counter.
fn record_wrong<U: UserStore>(key: &str, secret: Option<&str>, store: &U) {
    let mut attempts = VERIFY_ATTEMPTS.lock().unwrap();
    let n = attempts.entry(key.to_string()).or_insert(0);
    *n += 1;
    if *n >= MAX_VERIFY_ATTEMPTS {
        if let Some(secret) = secret {
            let _ = store.delete_pending(secret);
        }
        attempts.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{InMemoryUserStore, PendingVerification};

    fn pending(email: &str, code: &str) -> PendingVerification {
        PendingVerification {
            secret: code.to_string(),
            email: email.to_string(),
            user_id: None,
            password_hash: Some("x".to_string()),
            verification_type: VerificationType::NewAccount,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn wrong_code_burns_after_max_attempts() {
        let store = InMemoryUserStore::new();
        // Unique email so the shared static counter doesn't collide with siblings.
        let email = "burn-test@example.com";
        store.create_pending(pending(email, "123456")).unwrap();

        // MAX_VERIFY_ATTEMPTS wrong guesses; each fails, the last one burns.
        for _ in 0..MAX_VERIFY_ATTEMPTS {
            assert!(verify_pending_code(&store, email, VerificationType::NewAccount, "000000").is_err());
        }
        // Record is gone: even the CORRECT code no longer works.
        assert!(store
            .get_pending_by_email(email, VerificationType::NewAccount)
            .unwrap()
            .is_none());
        assert!(verify_pending_code(&store, email, VerificationType::NewAccount, "123456").is_err());
    }

    #[test]
    fn correct_code_succeeds_and_resets_counter() {
        let store = InMemoryUserStore::new();
        let email = "ok-test@example.com";
        store.create_pending(pending(email, "654321")).unwrap();

        // A few wrong tries, then the right one still works (under the cap).
        assert!(verify_pending_code(&store, email, VerificationType::NewAccount, "111111").is_err());
        let ok = verify_pending_code(&store, email, VerificationType::NewAccount, "654321");
        assert!(ok.is_ok());
        assert_eq!(ok.unwrap().secret, "654321");
    }
}
