//! In-memory storage implementations

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use chrono::Utc;
use uuid::Uuid;

use super::{
    Email, EmailType, PendingVerification, Session, SessionId, SessionStore, StoreResult, User,
    UserId, UserStore, VerificationType,
};
use crate::error::BrokerError;

/// In-memory user store
pub struct InMemoryUserStore {
    users: RwLock<HashMap<UserId, User>>,
    emails: RwLock<HashMap<String, Email>>,
    pending: RwLock<HashMap<String, PendingVerification>>,
    next_user_id: AtomicU64,
}

impl InMemoryUserStore {
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            emails: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            next_user_id: AtomicU64::new(1),
        }
    }

    /// Set the verified_at timestamp for an email (for testing purposes)
    pub fn set_verified_at(
        &self,
        email: &str,
        verified_at: chrono::DateTime<chrono::Utc>,
    ) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let mut emails = self.emails.write().unwrap();
        if let Some(email_record) = emails.get_mut(&normalized) {
            email_record.verified_at = Some(verified_at);
            Ok(())
        } else {
            Err(BrokerError::EmailNotFound)
        }
    }
}

impl Default for InMemoryUserStore {
    fn default() -> Self {
        Self::new()
    }
}

impl UserStore for InMemoryUserStore {
    fn create_user(&self, password_hash: &str) -> StoreResult<UserId> {
        let id = UserId(self.next_user_id.fetch_add(1, Ordering::SeqCst));
        let user = User {
            id,
            password_hash: password_hash.to_string(),
            created_at: Utc::now(),
        };
        self.users.write().unwrap().insert(id, user);
        Ok(id)
    }

    fn create_user_no_password(&self) -> StoreResult<UserId> {
        // Use empty string as sentinel for "no password"
        self.create_user("")
    }

    fn get_user(&self, user_id: UserId) -> StoreResult<Option<User>> {
        Ok(self.users.read().unwrap().get(&user_id).cloned())
    }

    fn get_user_by_email(&self, email: &str) -> StoreResult<Option<User>> {
        let normalized = email.to_lowercase();
        let emails = self.emails.read().unwrap();
        if let Some(email_record) = emails.get(&normalized) {
            return self.get_user(email_record.user_id);
        }
        Ok(None)
    }

    fn add_email(&self, user_id: UserId, email: &str, verified: bool) -> StoreResult<()> {
        // Default to secondary type for backwards compatibility
        self.add_email_with_type(user_id, email, verified, EmailType::Secondary)
    }

    fn add_email_with_type(
        &self,
        user_id: UserId,
        email: &str,
        verified: bool,
        email_type: EmailType,
    ) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let mut emails = self.emails.write().unwrap();
        if emails.contains_key(&normalized) {
            return Err(BrokerError::EmailAlreadyExists);
        }
        emails.insert(
            normalized.clone(),
            Email {
                email: normalized, // Store normalized (lowercase) email
                user_id,
                verified,
                verified_at: if verified { Some(Utc::now()) } else { None },
                email_type,
                last_used_as: email_type,
            },
        );
        Ok(())
    }

    fn list_emails(&self, user_id: UserId) -> StoreResult<Vec<Email>> {
        let emails = self.emails.read().unwrap();
        Ok(emails
            .values()
            .filter(|e| e.user_id == user_id)
            .cloned()
            .collect())
    }

    fn verify_email(&self, email: &str) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let mut emails = self.emails.write().unwrap();
        if let Some(email_record) = emails.get_mut(&normalized) {
            email_record.verified = true;
            email_record.verified_at = Some(Utc::now());
            Ok(())
        } else {
            Err(BrokerError::EmailNotFound)
        }
    }

    fn remove_email(&self, user_id: UserId, email: &str) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let mut emails = self.emails.write().unwrap();
        if let Some(email_record) = emails.get(&normalized) {
            if email_record.user_id != user_id {
                return Err(BrokerError::EmailNotFound);
            }
            emails.remove(&normalized);
            Ok(())
        } else {
            Err(BrokerError::EmailNotFound)
        }
    }

    fn create_pending(&self, pending: PendingVerification) -> StoreResult<()> {
        self.pending
            .write()
            .unwrap()
            .insert(pending.secret.clone(), pending);
        Ok(())
    }

    fn get_pending(&self, secret: &str) -> StoreResult<Option<PendingVerification>> {
        Ok(self.pending.read().unwrap().get(secret).cloned())
    }

    fn delete_pending(&self, secret: &str) -> StoreResult<()> {
        self.pending.write().unwrap().remove(secret);
        Ok(())
    }

    fn cleanup_expired_pending(&self, max_age_minutes: i64) -> StoreResult<u64> {
        let cutoff = Utc::now() - chrono::Duration::minutes(max_age_minutes);
        let mut pending = self.pending.write().unwrap();
        let before = pending.len();
        pending.retain(|_, p| p.created_at > cutoff);
        Ok((before - pending.len()) as u64)
    }

    fn update_password(&self, user_id: UserId, password_hash: &str) -> StoreResult<()> {
        let mut users = self.users.write().unwrap();
        if let Some(user) = users.get_mut(&user_id) {
            user.password_hash = password_hash.to_string();
            Ok(())
        } else {
            Err(BrokerError::UserNotFound)
        }
    }

    fn has_pending_reset(&self, email: &str) -> StoreResult<bool> {
        let pending = self.pending.read().unwrap();
        Ok(pending.values().any(|p| {
            p.email == email && p.verification_type == VerificationType::PasswordReset
        }))
    }

    fn delete_user(&self, user_id: UserId) -> StoreResult<()> {
        // Delete user
        self.users.write().unwrap().remove(&user_id);

        // Delete all emails for this user
        self.emails
            .write()
            .unwrap()
            .retain(|_, e| e.user_id != user_id);

        // Delete pending verifications for this user
        self.pending
            .write()
            .unwrap()
            .retain(|_, p| p.user_id != Some(user_id));

        Ok(())
    }

    fn get_pending_by_email(
        &self,
        email: &str,
        verification_type: VerificationType,
    ) -> StoreResult<Option<PendingVerification>> {
        let normalized = email.to_lowercase();
        let pending = self.pending.read().unwrap();
        Ok(pending
            .values()
            .find(|p| p.email.to_lowercase() == normalized && p.verification_type == verification_type)
            .cloned())
    }

    fn update_email_last_used(&self, email: &str, email_type: EmailType) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let mut emails = self.emails.write().unwrap();
        if let Some(email_record) = emails.get_mut(&normalized) {
            email_record.last_used_as = email_type;
            Ok(())
        } else {
            Err(BrokerError::EmailNotFound)
        }
    }

    fn get_email(&self, email: &str) -> StoreResult<Option<Email>> {
        let normalized = email.to_lowercase();
        let emails = self.emails.read().unwrap();
        Ok(emails.get(&normalized).cloned())
    }

    fn has_password(&self, user_id: UserId) -> StoreResult<bool> {
        let users = self.users.read().unwrap();
        if let Some(user) = users.get(&user_id) {
            // User has a password if password_hash is non-empty
            Ok(!user.password_hash.is_empty())
        } else {
            Ok(false)
        }
    }

    fn set_password(&self, user_id: UserId, password_hash: &str) -> StoreResult<()> {
        // Delegate to update_password which has the same behavior
        self.update_password(user_id, password_hash)
    }
}

/// In-memory session store
pub struct InMemorySessionStore {
    sessions: RwLock<HashMap<SessionId, Session>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore for InMemorySessionStore {
    fn create(&self, user_id: UserId) -> StoreResult<Session> {
        let session = Session {
            id: SessionId(Uuid::new_v4().to_string()),
            user_id,
            csrf_token: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
        };
        self.sessions
            .write()
            .unwrap()
            .insert(session.id.clone(), session.clone());
        Ok(session)
    }

    fn get(&self, session_id: &SessionId) -> StoreResult<Option<Session>> {
        Ok(self.sessions.read().unwrap().get(session_id).cloned())
    }

    fn delete(&self, session_id: &SessionId) -> StoreResult<()> {
        self.sessions.write().unwrap().remove(session_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_user_and_email() {
        let store = InMemoryUserStore::new();

        let user_id = store.create_user("hashed_password").unwrap();
        store.add_email(user_id, "test@example.com", false).unwrap();

        let user = store.get_user_by_email("test@example.com").unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().id, user_id);
    }

    #[test]
    fn test_verify_email() {
        let store = InMemoryUserStore::new();

        let user_id = store.create_user("hashed_password").unwrap();
        store.add_email(user_id, "test@example.com", false).unwrap();

        let emails = store.list_emails(user_id).unwrap();
        assert!(!emails[0].verified);

        store.verify_email("test@example.com").unwrap();

        let emails = store.list_emails(user_id).unwrap();
        assert!(emails[0].verified);
    }

    #[test]
    fn test_session_lifecycle() {
        let store = InMemorySessionStore::new();

        let session = store.create(UserId(1)).unwrap();
        assert!(store.get(&session.id).unwrap().is_some());

        store.delete(&session.id).unwrap();
        assert!(store.get(&session.id).unwrap().is_none());
    }
}
