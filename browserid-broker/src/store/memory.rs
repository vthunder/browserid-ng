//! In-memory storage implementations

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use chrono::Utc;
use uuid::Uuid;

use super::{
    ApiTokenRecord, DeviceCertRecord, Email, EmailType, ManagementPolicy, Namespace, PendingVerification, ProofMethod, RosterEntry,
    RosterState, Session, SessionId, SessionLevel, WarrantRecord, WarrantRequestRecord, WarrantRequestStatus,
    SessionStore, StoreResult, Tenant, TenantStatus, User, UserId, UserStore, VerificationType,
};
use crate::error::BrokerError;

/// In-memory user store
pub struct InMemoryUserStore {
    users: RwLock<HashMap<UserId, User>>,
    emails: RwLock<HashMap<String, Email>>,
    pending: RwLock<HashMap<String, PendingVerification>>,
    warrant_requests: RwLock<HashMap<String, WarrantRequestRecord>>,
    warrant_records: RwLock<HashMap<u64, WarrantRecord>>,
    next_warrant_id: AtomicU64,
    /// (kind, subject) -> (idx, revoked)
    status_entries: RwLock<HashMap<(String, String), (u64, bool)>>,
    next_status_idx: AtomicU64,
    next_user_id: AtomicU64,
    device_certs: RwLock<HashMap<u64, DeviceCertRecord>>,
    next_device_cert_id: AtomicU64,
    /// (user_id, namespace name) -> (stored random prefix, friendly label)
    namespaces: RwLock<HashMap<(UserId, String), (String, String)>>,
    /// (user_id, holder_id) -> friendly label
    holder_labels: RwLock<HashMap<(UserId, String), String>>,
    holder_moves: RwLock<HashMap<(UserId, String), String>>,
    /// domain -> tenant (bean g5qt)
    tenants: RwLock<HashMap<String, Tenant>>,
    next_tenant_id: AtomicU64,
    /// (tenant_id) -> admin identities
    tenant_admins: RwLock<HashMap<u64, Vec<String>>>,
    /// (tenant_id, local_part) -> roster entry
    tenant_roster: RwLock<HashMap<(u64, String), RosterEntry>>,
    /// (tenant_id, subject) -> (idx, revoked); per-tenant idx allocation
    tenant_status: RwLock<HashMap<(u64, String), (u64, bool)>>,
    /// email -> when a VISIBLE bridge ceremony last proved it (lrhe)
    interactive_proofs: RwLock<HashMap<String, chrono::DateTime<Utc>>>,
    /// token_hash -> registry API token record (registry-api-v1 §3.1)
    api_tokens: RwLock<HashMap<String, ApiTokenRecord>>,
}

impl InMemoryUserStore {
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            emails: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            warrant_requests: RwLock::new(HashMap::new()),
            warrant_records: RwLock::new(HashMap::new()),
            next_warrant_id: AtomicU64::new(1),
            status_entries: RwLock::new(HashMap::new()),
            next_status_idx: AtomicU64::new(1),
            next_user_id: AtomicU64::new(1),
            device_certs: RwLock::new(HashMap::new()),
            next_device_cert_id: AtomicU64::new(1),
            namespaces: RwLock::new(HashMap::new()),
            holder_labels: RwLock::new(HashMap::new()),
            holder_moves: RwLock::new(HashMap::new()),
            tenants: RwLock::new(HashMap::new()),
            next_tenant_id: AtomicU64::new(1),
            tenant_admins: RwLock::new(HashMap::new()),
            tenant_roster: RwLock::new(HashMap::new()),
            tenant_status: RwLock::new(HashMap::new()),
            interactive_proofs: RwLock::new(HashMap::new()),
            api_tokens: RwLock::new(HashMap::new()),
        }
    }

    /// Set the verified_at timestamp for an email (for testing purposes).
    /// The trait method [`UserStore::set_email_verified_at`] delegates here.
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
                display_name: None,
                public_name: None,
                proof: ProofMethod::Smtp,
                proof_subject: None,
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

    fn set_email_verified_at(
        &self,
        email: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> StoreResult<()> {
        self.set_verified_at(email, at)
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

    fn set_email_display_name(&self, email: &str, display_name: Option<&str>) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let mut emails = self.emails.write().unwrap();
        match emails.get_mut(&normalized) {
            Some(rec) => {
                rec.display_name = display_name.map(str::to_string);
                Ok(())
            }
            None => Err(BrokerError::EmailNotFound),
        }
    }

    fn set_email_proof(
        &self,
        email: &str,
        proof: ProofMethod,
        subject: Option<&str>,
    ) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let mut emails = self.emails.write().unwrap();
        let record = emails.get_mut(&normalized).ok_or(BrokerError::EmailNotFound)?;
        record.proof = proof;
        record.proof_subject = subject.map(str::to_string);
        Ok(())
    }

    fn set_email_public_name(&self, email: &str, public_name: Option<&str>) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let mut emails = self.emails.write().unwrap();
        match emails.get_mut(&normalized) {
            Some(rec) => {
                rec.public_name = public_name.map(str::to_string);
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

    fn set_email_interactive_proof_now(&self, email: &str) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        if !self.emails.read().unwrap().contains_key(&normalized) {
            return Err(BrokerError::EmailNotFound);
        }
        self.interactive_proofs
            .write()
            .unwrap()
            .insert(normalized, Utc::now());
        Ok(())
    }

    fn email_interactive_proof_at(
        &self,
        email: &str,
    ) -> StoreResult<Option<chrono::DateTime<Utc>>> {
        Ok(self
            .interactive_proofs
            .read()
            .unwrap()
            .get(&email.to_lowercase())
            .cloned())
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

    fn update_warrant_request(&self, rec: &WarrantRequestRecord) -> StoreResult<()> {
        let mut reqs = self.warrant_requests.write().unwrap();
        match reqs.get_mut(&rec.code) {
            Some(r) if r.status == WarrantRequestStatus::Pending => {
                *r = rec.clone();
                Ok(())
            }
            _ => Err(BrokerError::WarrantRequestNotFound),
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
        // Replace any existing row for the same grant identity —
        // (user, agent, audience, scopes): same-audience grants that differ
        // only in scopes coexist (e85i).
        // Connection records fold their binding.id into the grant identity so
        // two connections to the same audience stay distinct rows.
        let key = |scopes: &[String], binding: &Option<String>| match binding {
            Some(id) => format!("{}:{id}", browserid_registrar::scope_fingerprint(scopes)),
            None => browserid_registrar::scope_fingerprint(scopes),
        };
        let fp = key(&record.scopes, &record.binding_id);
        records.retain(|_, r| {
            !(r.user_id == record.user_id
                && r.agent_email == record.agent_email
                && r.audience == record.audience
                && key(&r.scopes, &r.binding_id) == fp)
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

    fn create_api_token(&self, rec: ApiTokenRecord) -> StoreResult<()> {
        self.api_tokens.write().unwrap().insert(rec.token_hash.clone(), rec);
        Ok(())
    }

    fn get_api_token(&self, token_hash: &str) -> StoreResult<Option<ApiTokenRecord>> {
        Ok(self.api_tokens.read().unwrap().get(token_hash).cloned())
    }

    fn cleanup_expired_api_tokens(&self) -> StoreResult<u64> {
        let now = Utc::now();
        let mut tokens = self.api_tokens.write().unwrap();
        let before = tokens.len();
        tokens.retain(|_, r| r.expires_at > now);
        Ok((before - tokens.len()) as u64)
    }

    fn get_or_allocate_status(&self, kind: &str, subject: &str) -> StoreResult<u64> {
        let mut entries = self.status_entries.write().unwrap();
        let key = (kind.to_string(), subject.to_string());
        if let Some((idx, _)) = entries.get(&key) {
            return Ok(*idx);
        }
        let idx = self.next_status_idx.fetch_add(1, Ordering::SeqCst);
        entries.insert(key, (idx, false));
        Ok(idx)
    }

    fn set_status_revoked(&self, kind: &str, subject: &str) -> StoreResult<bool> {
        let mut entries = self.status_entries.write().unwrap();
        match entries.get_mut(&(kind.to_string(), subject.to_string())) {
            Some(e) => {
                e.1 = true;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn set_status_revoked_idx(&self, idx: u64) -> StoreResult<bool> {
        let mut entries = self.status_entries.write().unwrap();
        for e in entries.values_mut() {
            if e.0 == idx {
                e.1 = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn set_status_active_idx(&self, idx: u64) -> StoreResult<bool> {
        let mut entries = self.status_entries.write().unwrap();
        for e in entries.values_mut() {
            if e.0 == idx {
                e.1 = false;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn is_status_revoked_idx(&self, idx: u64) -> StoreResult<bool> {
        Ok(self
            .status_entries
            .read()
            .unwrap()
            .values()
            .any(|(i, revoked)| *i == idx && *revoked))
    }

    fn revoked_status_indices(&self) -> StoreResult<(Vec<u64>, u64)> {
        let entries = self.status_entries.read().unwrap();
        let revoked = entries.values().filter(|(_, r)| *r).map(|(i, _)| *i).collect();
        let max = entries.values().map(|(i, _)| *i).max().unwrap_or(0);
        Ok((revoked, max))
    }

    fn insert_device_cert(&self, mut rec: DeviceCertRecord) -> StoreResult<u64> {
        let mut certs = self.device_certs.write().unwrap();
        // Upsert on pubkey: replace any existing row for the same key.
        if let Some(existing_id) = certs
            .values()
            .find(|c| c.pubkey == rec.pubkey)
            .map(|c| c.id)
        {
            rec.id = existing_id;
        } else {
            rec.id = self.next_device_cert_id.fetch_add(1, Ordering::SeqCst);
        }
        certs.insert(rec.id, rec.clone());
        Ok(rec.id)
    }

    fn get_device_cert_by_pubkey(&self, pubkey: &str) -> StoreResult<Option<DeviceCertRecord>> {
        let certs = self.device_certs.read().unwrap();
        Ok(certs.values().find(|c| c.pubkey == pubkey).cloned())
    }

    fn list_device_certs(&self, user_id: UserId) -> StoreResult<Vec<DeviceCertRecord>> {
        let certs = self.device_certs.read().unwrap();
        let mut out: Vec<DeviceCertRecord> =
            certs.values().filter(|c| c.user_id == user_id).cloned().collect();
        out.sort_by_key(|c| c.id);
        Ok(out)
    }

    fn revoke_device_cert(&self, user_id: UserId, cert_id: u64) -> StoreResult<()> {
        let mut certs = self.device_certs.write().unwrap();
        match certs.get_mut(&cert_id) {
            Some(c) if c.user_id == user_id => {
                if c.revoked_at.is_none() {
                    c.revoked_at = Some(Utc::now());
                }
                Ok(())
            }
            _ => Err(BrokerError::DeviceCertNotFound),
        }
    }

    fn forget_holder(&self, user_id: UserId, holder: &str) -> StoreResult<u64> {
        let mut certs = self.device_certs.write().unwrap();
        let ids: Vec<u64> = certs
            .values()
            .filter(|c| c.user_id == user_id && c.holder == holder)
            .map(|c| c.id)
            .collect();
        for id in &ids {
            certs.remove(id);
        }
        self.holder_labels
            .write()
            .unwrap()
            .remove(&(user_id, holder.to_string()));
        Ok(ids.len() as u64)
    }

    fn set_holder_move(&self, user_id: UserId, old_holder: &str, new_holder: &str) -> StoreResult<()> {
        self.holder_moves
            .write()
            .unwrap()
            .insert((user_id, old_holder.to_string()), new_holder.to_string());
        Ok(())
    }

    fn resolve_holder_move(&self, user_id: UserId, holder: &str) -> StoreResult<Option<String>> {
        let moves = self.holder_moves.read().unwrap();
        let mut current = holder.to_string();
        let mut hops = 0;
        while let Some(next) = moves.get(&(user_id, current.clone())) {
            current = next.clone();
            hops += 1;
            if hops > 8 {
                break; // defensive: never loop on a malformed chain
            }
        }
        Ok(if current == holder { None } else { Some(current) })
    }

    fn list_holder_moves(&self, user_id: UserId) -> StoreResult<Vec<(String, String)>> {
        Ok(self
            .holder_moves
            .read()
            .unwrap()
            .iter()
            .filter(|((u, _), _)| *u == user_id)
            .map(|((_, old), new)| (old.clone(), new.clone()))
            .collect())
    }

    fn get_or_create_namespace(&self, user_id: UserId, name: &str) -> StoreResult<String> {
        let mut ns = self.namespaces.write().unwrap();
        let (prefix, _label) = ns
            .entry((user_id, name.to_string()))
            .or_insert_with(|| (crate::crypto::generate_namespace_prefix(), title_case(name)));
        Ok(prefix.clone())
    }

    fn adopt_namespace_prefix(
        &self,
        user_id: UserId,
        name: &str,
        new_prefix: &str,
    ) -> StoreResult<bool> {
        let mut ns = self.namespaces.write().unwrap();
        let (prefix, _label) = ns
            .entry((user_id, name.to_string()))
            .or_insert_with(|| (crate::crypto::generate_namespace_prefix(), title_case(name)));
        if prefix == new_prefix {
            return Ok(true);
        }
        // Only adopt while unused (no recorded holder under the current prefix).
        let want = format!("{prefix}.");
        let in_use = self
            .device_certs
            .read()
            .unwrap()
            .values()
            .any(|c| c.user_id == user_id && c.holder.starts_with(&want));
        if in_use {
            return Ok(false);
        }
        *prefix = new_prefix.to_string();
        Ok(true)
    }

    fn list_namespaces(&self, user_id: UserId) -> StoreResult<Vec<Namespace>> {
        let ns = self.namespaces.read().unwrap();
        let mut out: Vec<Namespace> = ns
            .iter()
            .filter(|((uid, _), _)| *uid == user_id)
            .map(|((_, name), (prefix, label))| Namespace {
                name: name.clone(),
                prefix: prefix.clone(),
                label: label.clone(),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn set_namespace_label(&self, user_id: UserId, name: &str, label: &str) -> StoreResult<()> {
        let mut ns = self.namespaces.write().unwrap();
        match ns.get_mut(&(user_id, name.to_string())) {
            Some((_, l)) => {
                *l = label.to_string();
                Ok(())
            }
            None => Err(BrokerError::PolicyRefused("no such namespace".into())),
        }
    }

    fn create_namespace(&self, user_id: UserId, name: &str, label: &str) -> StoreResult<()> {
        let mut ns = self.namespaces.write().unwrap();
        ns.entry((user_id, name.to_string()))
            .or_insert_with(|| (crate::crypto::generate_namespace_prefix(), label.to_string()));
        Ok(())
    }

    fn delete_namespace(&self, user_id: UserId, name: &str) -> StoreResult<()> {
        let prefix = {
            let ns = self.namespaces.read().unwrap();
            match ns.get(&(user_id, name.to_string())) {
                Some((p, _)) => p.clone(),
                None => return Err(BrokerError::PolicyRefused("no such namespace".into())),
            }
        };
        let in_use = self
            .device_certs
            .read()
            .unwrap()
            .values()
            .any(|r| r.user_id == user_id && r.holder.starts_with(&format!("{prefix}.")));
        if in_use {
            return Err(BrokerError::PolicyRefused(
                "namespace is not empty — revoke its holders first".into(),
            ));
        }
        self.namespaces.write().unwrap().remove(&(user_id, name.to_string()));
        Ok(())
    }

    fn set_holder_label(&self, user_id: UserId, holder_id: &str, label: &str) -> StoreResult<()> {
        self.holder_labels
            .write()
            .unwrap()
            .insert((user_id, holder_id.to_string()), label.to_string());
        Ok(())
    }

    fn get_holder_labels(&self, user_id: UserId) -> StoreResult<HashMap<String, String>> {
        Ok(self
            .holder_labels
            .read()
            .unwrap()
            .iter()
            .filter(|((uid, _), _)| *uid == user_id)
            .map(|((_, hid), label)| (hid.clone(), label.clone()))
            .collect())
    }

    // --- Hosted-primary tenants (bean g5qt) ---

    fn create_tenant(
        &self,
        domain: &str,
        public_key: &str,
        private_key_sealed: &str,
        owner_user_id: Option<UserId>,
        created_by: &str,
    ) -> StoreResult<Tenant> {
        let mut tenants = self.tenants.write().unwrap();
        if tenants.contains_key(domain) {
            return Err(BrokerError::TenantExists);
        }
        let tenant = Tenant {
            id: self.next_tenant_id.fetch_add(1, Ordering::SeqCst),
            domain: domain.to_string(),
            public_key: public_key.to_string(),
            private_key_sealed: private_key_sealed.to_string(),
            status: TenantStatus::PendingDns,
            self_claim: false,
            owner_user_id,
            created_by: created_by.to_string(),
            created_at: Utc::now(),
            activated_at: None,
            management: None,
        };
        tenants.insert(domain.to_string(), tenant.clone());
        Ok(tenant)
    }

    fn get_tenant(&self, domain: &str) -> StoreResult<Option<Tenant>> {
        Ok(self.tenants.read().unwrap().get(domain).cloned())
    }

    fn list_tenants_for(&self, identity: &str) -> StoreResult<Vec<Tenant>> {
        let admins = self.tenant_admins.read().unwrap();
        let mut out: Vec<Tenant> = self
            .tenants
            .read()
            .unwrap()
            .values()
            .filter(|t| {
                t.created_by == identity
                    || admins.get(&t.id).is_some_and(|a| a.iter().any(|i| i == identity))
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(out)
    }

    fn set_tenant_status(&self, domain: &str, status: TenantStatus) -> StoreResult<()> {
        let mut tenants = self.tenants.write().unwrap();
        let tenant = tenants.get_mut(domain).ok_or(BrokerError::TenantNotFound)?;
        tenant.status = status;
        if status == TenantStatus::Active {
            tenant.activated_at.get_or_insert_with(Utc::now);
            let mut admins = self.tenant_admins.write().unwrap();
            let list = admins.entry(tenant.id).or_default();
            if !list.iter().any(|i| *i == tenant.created_by) {
                list.push(tenant.created_by.clone());
            }
        }
        Ok(())
    }

    fn set_tenant_management(&self, domain: &str, policy: &ManagementPolicy) -> StoreResult<()> {
        let mut tenants = self.tenants.write().unwrap();
        let t = tenants.get_mut(domain).ok_or(BrokerError::TenantNotFound)?;
        t.management = Some(policy.clone());
        Ok(())
    }

    fn tenant_status_revoke_all(&self, tenant_id: u64) -> StoreResult<u64> {
        let mut status = self.tenant_status.write().unwrap();
        let mut n = 0;
        for ((tid, _), (_, revoked)) in status.iter_mut() {
            if *tid == tenant_id && !*revoked {
                *revoked = true;
                n += 1;
            }
        }
        Ok(n)
    }

    fn tenant_status_revoke_idx(&self, tenant_id: u64, idx: u64) -> StoreResult<bool> {
        let mut status = self.tenant_status.write().unwrap();
        for ((tid, _), (i, revoked)) in status.iter_mut() {
            if *tid == tenant_id && *i == idx {
                let was = *revoked;
                *revoked = true;
                return Ok(!was || true);
            }
        }
        Ok(false)
    }

    fn delete_tenant(&self, domain: &str) -> StoreResult<()> {
        let Some(tenant) = self.tenants.write().unwrap().remove(domain) else {
            return Ok(());
        };
        self.tenant_admins.write().unwrap().remove(&tenant.id);
        self.tenant_roster
            .write()
            .unwrap()
            .retain(|(tid, _), _| *tid != tenant.id);
        self.tenant_status
            .write()
            .unwrap()
            .retain(|(tid, _), _| *tid != tenant.id);
        Ok(())
    }

    fn revoke_domain_device_certs(&self, domain: &str) -> StoreResult<u64> {
        let suffix = format!("@{}", domain.to_lowercase());
        let mut certs = self.device_certs.write().unwrap();
        let mut status = self.status_entries.write().unwrap();
        let mut count = 0u64;
        for cert in certs.values_mut() {
            if cert.revoked_at.is_some() {
                continue;
            }
            if !cert
                .identities
                .iter()
                .any(|i| i.to_lowercase().ends_with(&suffix))
            {
                continue;
            }
            cert.revoked_at = Some(Utc::now());
            if let Some(idx) = cert.status_idx {
                for (_, (i, revoked)) in status.iter_mut() {
                    if *i == idx {
                        *revoked = true;
                    }
                }
            }
            count += 1;
        }
        Ok(count)
    }

    fn revoke_user_stale_class_certs(
        &self,
        user_id: UserId,
        email: &str,
        current_class: &str,
    ) -> StoreResult<u64> {
        let target = email.to_lowercase();
        let mut certs = self.device_certs.write().unwrap();
        let mut status = self.status_entries.write().unwrap();
        let mut count = 0u64;
        for cert in certs.values_mut() {
            if cert.user_id != user_id || cert.revoked_at.is_some() || cert.prov == current_class {
                continue;
            }
            if !cert.identities.iter().any(|i| i.to_lowercase() == target) {
                continue;
            }
            cert.revoked_at = Some(Utc::now());
            if let Some(idx) = cert.status_idx {
                for (_, (i, revoked)) in status.iter_mut() {
                    if *i == idx {
                        *revoked = true;
                    }
                }
            }
            count += 1;
        }
        Ok(count)
    }

    fn revoke_user_certs_for_email(&self, user_id: UserId, email: &str) -> StoreResult<u64> {
        let target = email.to_lowercase();
        let mut certs = self.device_certs.write().unwrap();
        let mut status = self.status_entries.write().unwrap();
        let mut count = 0u64;
        for cert in certs.values_mut() {
            if cert.user_id != user_id || cert.revoked_at.is_some() {
                continue;
            }
            if !cert.identities.iter().any(|i| i.to_lowercase() == target) {
                continue;
            }
            cert.revoked_at = Some(Utc::now());
            if let Some(idx) = cert.status_idx {
                for (_, (i, revoked)) in status.iter_mut() {
                    if *i == idx {
                        *revoked = true;
                    }
                }
            }
            count += 1;
        }
        Ok(count)
    }

    fn is_tenant_admin(&self, domain: &str, identity: &str) -> StoreResult<bool> {
        let Some(tenant) = self.tenants.read().unwrap().get(domain).cloned() else {
            return Ok(false);
        };
        Ok(self
            .tenant_admins
            .read()
            .unwrap()
            .get(&tenant.id)
            .is_some_and(|a| a.iter().any(|i| i == identity)))
    }

    fn add_tenant_admin(&self, domain: &str, identity: &str, _added_by: &str) -> StoreResult<()> {
        let tenant = self
            .tenants
            .read()
            .unwrap()
            .get(domain)
            .cloned()
            .ok_or(BrokerError::TenantNotFound)?;
        let mut admins = self.tenant_admins.write().unwrap();
        let list = admins.entry(tenant.id).or_default();
        if !list.iter().any(|i| i == identity) {
            list.push(identity.to_string());
        }
        Ok(())
    }

    fn remove_tenant_admin(&self, domain: &str, identity: &str) -> StoreResult<bool> {
        let tenant = self
            .tenants
            .read()
            .unwrap()
            .get(domain)
            .cloned()
            .ok_or(BrokerError::TenantNotFound)?;
        let mut admins = self.tenant_admins.write().unwrap();
        let Some(list) = admins.get_mut(&tenant.id) else {
            return Ok(false);
        };
        let before = list.len();
        list.retain(|i| i != identity);
        Ok(list.len() < before)
    }

    fn list_tenant_admins(&self, domain: &str) -> StoreResult<Vec<String>> {
        let Some(tenant) = self.tenants.read().unwrap().get(domain).cloned() else {
            return Ok(Vec::new());
        };
        Ok(self
            .tenant_admins
            .read()
            .unwrap()
            .get(&tenant.id)
            .cloned()
            .unwrap_or_default())
    }

    fn create_roster_entry(
        &self,
        tenant_id: u64,
        local_part: &str,
        password_hash: &str,
        must_change: bool,
        created_by: &str,
    ) -> StoreResult<()> {
        let mut roster = self.tenant_roster.write().unwrap();
        let key = (tenant_id, local_part.to_string());
        if roster.contains_key(&key) {
            return Err(BrokerError::RosterEntryExists);
        }
        roster.insert(
            key,
            RosterEntry {
                tenant_id,
                local_part: local_part.to_string(),
                password_hash: password_hash.to_string(),
                state: RosterState::Active,
                must_change_password: must_change,
                created_by: created_by.to_string(),
                created_at: Utc::now(),
                last_login_at: None,
            },
        );
        Ok(())
    }

    fn get_roster_entry(&self, tenant_id: u64, local_part: &str) -> StoreResult<Option<RosterEntry>> {
        Ok(self
            .tenant_roster
            .read()
            .unwrap()
            .get(&(tenant_id, local_part.to_string()))
            .cloned())
    }

    fn list_roster(&self, tenant_id: u64) -> StoreResult<Vec<RosterEntry>> {
        let mut out: Vec<RosterEntry> = self
            .tenant_roster
            .read()
            .unwrap()
            .values()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.local_part.cmp(&b.local_part));
        Ok(out)
    }

    fn set_roster_state(&self, tenant_id: u64, local_part: &str, state: RosterState) -> StoreResult<bool> {
        let mut roster = self.tenant_roster.write().unwrap();
        match roster.get_mut(&(tenant_id, local_part.to_string())) {
            Some(entry) => {
                entry.state = state;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn set_roster_password(
        &self,
        tenant_id: u64,
        local_part: &str,
        password_hash: &str,
        must_change: bool,
    ) -> StoreResult<bool> {
        let mut roster = self.tenant_roster.write().unwrap();
        match roster.get_mut(&(tenant_id, local_part.to_string())) {
            Some(entry) => {
                entry.password_hash = password_hash.to_string();
                entry.must_change_password = must_change;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn touch_roster_login(&self, tenant_id: u64, local_part: &str) -> StoreResult<()> {
        if let Some(entry) = self
            .tenant_roster
            .write()
            .unwrap()
            .get_mut(&(tenant_id, local_part.to_string()))
        {
            entry.last_login_at = Some(Utc::now());
        }
        Ok(())
    }

    fn tenant_status_allocate(&self, tenant_id: u64, subject: &str) -> StoreResult<u64> {
        let mut entries = self.tenant_status.write().unwrap();
        let key = (tenant_id, subject.to_string());
        if let Some((idx, _)) = entries.get(&key) {
            return Ok(*idx);
        }
        let next = entries
            .iter()
            .filter(|((tid, _), _)| *tid == tenant_id)
            .map(|(_, (idx, _))| *idx)
            .max()
            .unwrap_or(0)
            + 1;
        entries.insert(key, (next, false));
        Ok(next)
    }

    fn tenant_status_revoke(&self, tenant_id: u64, subject: &str) -> StoreResult<bool> {
        let mut entries = self.tenant_status.write().unwrap();
        match entries.get_mut(&(tenant_id, subject.to_string())) {
            Some((_, revoked)) => {
                *revoked = true;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn tenant_status_is_revoked(&self, tenant_id: u64, idx: u64) -> StoreResult<bool> {
        Ok(self
            .tenant_status
            .read()
            .unwrap()
            .iter()
            .any(|((tid, _), (i, revoked))| *tid == tenant_id && *i == idx && *revoked))
    }

    fn tenant_status_snapshot(&self, tenant_id: u64) -> StoreResult<(Vec<u64>, u64)> {
        let entries = self.tenant_status.read().unwrap();
        let mut revoked = Vec::new();
        let mut max = 0;
        for ((tid, _), (idx, is_revoked)) in entries.iter() {
            if *tid != tenant_id {
                continue;
            }
            max = max.max(*idx);
            if *is_revoked {
                revoked.push(*idx);
            }
        }
        Ok((revoked, max))
    }
}

/// Title-case a namespace name for its default label ("browsers" → "Browsers").
fn title_case(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
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
    fn create(&self, user_id: UserId, level: SessionLevel) -> StoreResult<Session> {
        let session = Session {
            id: SessionId(Uuid::new_v4().to_string()),
            user_id,
            csrf_token: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            level,
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

    fn delete_by_user(&self, user_id: UserId) -> StoreResult<u64> {
        let mut sessions = self.sessions.write().unwrap();
        let before = sessions.len();
        sessions.retain(|_, s| s.user_id != user_id);
        Ok((before - sessions.len()) as u64)
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

        let session = store.create(UserId(1), SessionLevel::Full).unwrap();
        assert!(store.get(&session.id).unwrap().is_some());

        store.delete(&session.id).unwrap();
        assert!(store.get(&session.id).unwrap().is_none());
    }
}
