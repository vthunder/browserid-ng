//! In-memory storage implementations

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use chrono::Utc;
use uuid::Uuid;

use super::{
    Email, EmailType, PendingVerification, ProvisioningCertRecord, Session, SessionId, WarrantRecord, WarrantRequestRecord, WarrantRequestStatus,
    SessionStore, StoreResult, User, UserId, UserStore, VerificationType,
};
use crate::error::BrokerError;

/// In-memory user store
pub struct InMemoryUserStore {
    users: RwLock<HashMap<UserId, User>>,
    emails: RwLock<HashMap<String, Email>>,
    pending: RwLock<HashMap<String, PendingVerification>>,
    prov_certs: RwLock<HashMap<u64, ProvisioningCertRecord>>,
    warrant_requests: RwLock<HashMap<String, WarrantRequestRecord>>,
    warrant_records: RwLock<HashMap<u64, WarrantRecord>>,
    next_warrant_id: AtomicU64,
    next_user_id: AtomicU64,
    next_prov_cert_id: AtomicU64,
}

impl InMemoryUserStore {
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            emails: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            prov_certs: RwLock::new(HashMap::new()),
            warrant_requests: RwLock::new(HashMap::new()),
            warrant_records: RwLock::new(HashMap::new()),
            next_warrant_id: AtomicU64::new(1),
            next_user_id: AtomicU64::new(1),
            next_prov_cert_id: AtomicU64::new(1),
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
                parent_email: None,
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

    fn transfer_email(&self, email: &str, to_user_id: UserId) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let mut emails = self.emails.write().unwrap();
        match emails.get_mut(&normalized) {
            Some(rec) => {
                rec.user_id = to_user_id;
                Ok(())
            }
            None => Err(BrokerError::EmailNotFound),
        }
    }

    fn set_parent_email(&self, email: &str, parent_email: Option<&str>) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let mut emails = self.emails.write().unwrap();
        match emails.get_mut(&normalized) {
            Some(rec) => {
                rec.parent_email = parent_email.map(|p| p.to_lowercase());
                Ok(())
            }
            None => Err(BrokerError::EmailNotFound),
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

    fn unverify_email(&self, email: &str) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let mut emails = self.emails.write().unwrap();
        match emails.get_mut(&normalized) {
            Some(rec) => {
                rec.verified = false;
                rec.verified_at = None;
                Ok(())
            }
            None => Err(BrokerError::EmailNotFound),
        }
    }

    fn register_provisioning_cert(
        &self,
        user_id: UserId,
        delegator_email: &str,
        provisioning_pub: &str,
        bundle: &str,
        label: &str,
    ) -> StoreResult<ProvisioningCertRecord> {
        let rec = ProvisioningCertRecord {
            id: self.next_prov_cert_id.fetch_add(1, Ordering::SeqCst),
            user_id,
            delegator_email: delegator_email.to_lowercase(),
            provisioning_pub: provisioning_pub.to_string(),
            bundle: bundle.to_string(),
            label: label.to_string(),
            created_at: Utc::now(),
            last_endorsed_at: None,
            revoked_at: None,
        };
        self.prov_certs.write().unwrap().insert(rec.id, rec.clone());
        Ok(rec)
    }

    fn get_provisioning_cert_by_pub(
        &self,
        provisioning_pub: &str,
    ) -> StoreResult<Option<ProvisioningCertRecord>> {
        let certs = self.prov_certs.read().unwrap();
        Ok(certs
            .values()
            .find(|c| c.provisioning_pub == provisioning_pub)
            .cloned())
    }

    fn list_provisioning_certs(&self, user_id: UserId) -> StoreResult<Vec<ProvisioningCertRecord>> {
        let certs = self.prov_certs.read().unwrap();
        let mut result: Vec<ProvisioningCertRecord> =
            certs.values().filter(|c| c.user_id == user_id).cloned().collect();
        result.sort_by_key(|c| c.id);
        Ok(result)
    }

    fn count_active_provisioning_certs(&self, user_id: UserId) -> StoreResult<usize> {
        let certs = self.prov_certs.read().unwrap();
        Ok(certs
            .values()
            .filter(|c| c.user_id == user_id && c.is_active())
            .count())
    }

    fn revoke_provisioning_cert(&self, user_id: UserId, cert_id: u64) -> StoreResult<()> {
        let mut certs = self.prov_certs.write().unwrap();
        match certs.get_mut(&cert_id) {
            Some(c) if c.user_id == user_id => {
                if c.revoked_at.is_none() {
                    c.revoked_at = Some(Utc::now());
                }
                Ok(())
            }
            _ => Err(BrokerError::ProvisioningCertNotFound),
        }
    }

    fn touch_provisioning_cert(&self, cert_id: u64) -> StoreResult<()> {
        let mut certs = self.prov_certs.write().unwrap();
        match certs.get_mut(&cert_id) {
            Some(c) => {
                c.last_endorsed_at = Some(Utc::now());
                Ok(())
            }
            None => Err(BrokerError::ProvisioningCertNotFound),
        }
    }

    fn create_warrant_request(&self, req: WarrantRequestRecord) -> StoreResult<()> {
        self.warrant_requests
            .write()
            .unwrap()
            .insert(req.code.clone(), req);
        Ok(())
    }

    fn get_warrant_request(&self, code: &str) -> StoreResult<Option<WarrantRequestRecord>> {
        Ok(self.warrant_requests.read().unwrap().get(code).cloned())
    }

    fn list_pending_warrant_requests(
        &self,
        user_id: UserId,
    ) -> StoreResult<Vec<WarrantRequestRecord>> {
        let reqs = self.warrant_requests.read().unwrap();
        let mut result: Vec<WarrantRequestRecord> = reqs
            .values()
            .filter(|r| {
                r.user_id == user_id
                    && r.status == WarrantRequestStatus::Pending
                    && !r.is_expired()
            })
            .cloned()
            .collect();
        result.sort_by_key(|r| r.created_at);
        Ok(result)
    }

    fn respond_warrant_request(
        &self,
        user_id: UserId,
        code: &str,
        warrants: Option<&[String]>,
    ) -> StoreResult<()> {
        let mut reqs = self.warrant_requests.write().unwrap();
        match reqs.get_mut(code) {
            Some(r)
                if r.user_id == user_id
                    && r.status == WarrantRequestStatus::Pending
                    && !r.is_expired() =>
            {
                match warrants {
                    Some(w) => {
                        r.status = WarrantRequestStatus::Approved;
                        r.warrants = Some(w.to_vec());
                    }
                    None => r.status = WarrantRequestStatus::Denied,
                }
                Ok(())
            }
            _ => Err(BrokerError::WarrantRequestNotFound),
        }
    }

    fn touch_warrant_poll(
        &self,
        code: &str,
    ) -> StoreResult<Option<chrono::DateTime<Utc>>> {
        let mut reqs = self.warrant_requests.write().unwrap();
        match reqs.get_mut(code) {
            Some(r) => {
                let prev = r.last_polled_at;
                r.last_polled_at = Some(Utc::now());
                Ok(prev)
            }
            None => Err(BrokerError::WarrantRequestNotFound),
        }
    }

    fn delete_warrant_request(&self, code: &str) -> StoreResult<()> {
        self.warrant_requests.write().unwrap().remove(code);
        Ok(())
    }

    fn cleanup_expired_warrant_requests(&self) -> StoreResult<u64> {
        let mut reqs = self.warrant_requests.write().unwrap();
        let before = reqs.len();
        reqs.retain(|_, r| !r.is_expired());
        Ok((before - reqs.len()) as u64)
    }

    fn upsert_warrant(&self, mut record: WarrantRecord) -> StoreResult<()> {
        let mut records = self.warrant_records.write().unwrap();
        // Replace any existing row for the same (user, agent, audience).
        records.retain(|_, r| {
            !(r.user_id == record.user_id
                && r.agent_email == record.agent_email
                && r.audience == record.audience)
        });
        record.id = self.next_warrant_id.fetch_add(1, Ordering::SeqCst);
        records.insert(record.id, record);
        Ok(())
    }

    fn list_warrants(&self, user_id: UserId) -> StoreResult<Vec<WarrantRecord>> {
        let records = self.warrant_records.read().unwrap();
        let mut out: Vec<WarrantRecord> =
            records.values().filter(|r| r.user_id == user_id).cloned().collect();
        out.sort_by(|a, b| b.signed_at.cmp(&a.signed_at));
        Ok(out)
    }

    fn delete_warrant(&self, user_id: UserId, warrant_id: u64) -> StoreResult<()> {
        let mut records = self.warrant_records.write().unwrap();
        match records.get(&warrant_id) {
            Some(r) if r.user_id == user_id => {
                records.remove(&warrant_id);
                Ok(())
            }
            _ => Err(BrokerError::WarrantRequestNotFound),
        }
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
