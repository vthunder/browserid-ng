//! Glue between the broker and the extracted `browserid-registrar` component
//! (1pnf). The broker runs IdP + registrar in one process: its stores back
//! both roles (one sqlite schema), and its sessions authenticate the
//! registrar's browser surface.
//!
//! `RegistrarStore` is implemented by delegating to the broker's `UserStore`
//! methods — same tables, converting the id/error types at the boundary. A
//! self-hosting IdP (e.g. mingo-idp) implements `RegistrarStore` directly
//! instead.

use std::sync::Arc;

use browserid_registrar::host::{AgentIdentity, AuthedUser, RegistrarHost};
use browserid_registrar::models as reg;
use browserid_registrar::{RegistrarError, RegistrarStore};
use tower_cookies::Cookies;

use crate::error::BrokerError;
use crate::store::{EmailType, SessionStore, UserId, UserStore};

fn to_reg_err(e: BrokerError) -> RegistrarError {
    match e {
        BrokerError::WarrantRequestNotFound => RegistrarError::WarrantRequestNotFound,
        BrokerError::DeviceCertNotFound => RegistrarError::DeviceCertNotFound,
        BrokerError::NotAuthenticated => RegistrarError::NotAuthenticated,
        BrokerError::ValidationError(m) => RegistrarError::ValidationError(m),
        other => RegistrarError::Internal(other.to_string()),
    }
}

fn to_reg_grant(g: crate::store::WarrantGrantItem) -> reg::WarrantGrantItem {
    reg::WarrantGrantItem {
        audience: g.audience,
        scopes: g.scopes,
        status_idx: g.status_idx,
    }
}

fn from_reg_grant(g: reg::WarrantGrantItem) -> crate::store::WarrantGrantItem {
    crate::store::WarrantGrantItem {
        audience: g.audience,
        scopes: g.scopes,
        status_idx: g.status_idx,
    }
}

fn to_reg_status(s: crate::store::WarrantRequestStatus) -> reg::WarrantRequestStatus {
    match s {
        crate::store::WarrantRequestStatus::Pending => reg::WarrantRequestStatus::Pending,
        crate::store::WarrantRequestStatus::Approved => reg::WarrantRequestStatus::Approved,
        crate::store::WarrantRequestStatus::Denied => reg::WarrantRequestStatus::Denied,
    }
}

fn from_reg_status(s: reg::WarrantRequestStatus) -> crate::store::WarrantRequestStatus {
    match s {
        reg::WarrantRequestStatus::Pending => crate::store::WarrantRequestStatus::Pending,
        reg::WarrantRequestStatus::Approved => crate::store::WarrantRequestStatus::Approved,
        reg::WarrantRequestStatus::Denied => crate::store::WarrantRequestStatus::Denied,
    }
}

fn to_reg_request(r: crate::store::WarrantRequestRecord) -> reg::WarrantRequestRecord {
    reg::WarrantRequestRecord {
        code: r.code,
        user_id: r.user_id.0,
        delegator_email: r.delegator_email,
        agent_email: r.agent_email,
        holder: r.holder,
        label: r.label,
        grants: r.grants.into_iter().map(to_reg_grant).collect(),
        status: to_reg_status(r.status),
        warrants: r.warrants,
        external: r.external,
        created_at: r.created_at,
        expires_at: r.expires_at,
        last_polled_at: r.last_polled_at,
    }
}

fn from_reg_request(r: reg::WarrantRequestRecord) -> crate::store::WarrantRequestRecord {
    crate::store::WarrantRequestRecord {
        code: r.code,
        user_id: UserId(r.user_id),
        delegator_email: r.delegator_email,
        agent_email: r.agent_email,
        holder: r.holder,
        label: r.label,
        grants: r.grants.into_iter().map(from_reg_grant).collect(),
        status: from_reg_status(r.status),
        warrants: r.warrants,
        external: r.external,
        created_at: r.created_at,
        expires_at: r.expires_at,
        last_polled_at: r.last_polled_at,
    }
}

fn to_reg_warrant(w: crate::store::WarrantRecord) -> reg::WarrantRecord {
    reg::WarrantRecord {
        id: w.id,
        user_id: w.user_id.0,
        delegator_email: w.delegator_email,
        agent_email: w.agent_email,
        audience: w.audience,
        scopes: w.scopes,
        warrant: w.warrant,
        status_idx: w.status_idx,
        holder: w.holder,
        config_cert: w.config_cert,
        signed_at: w.signed_at,
        expires_at: w.expires_at,
    }
}

fn from_reg_warrant(w: reg::WarrantRecord) -> crate::store::WarrantRecord {
    crate::store::WarrantRecord {
        id: w.id,
        user_id: UserId(w.user_id),
        delegator_email: w.delegator_email,
        agent_email: w.agent_email,
        audience: w.audience,
        scopes: w.scopes,
        warrant: w.warrant,
        status_idx: w.status_idx,
        holder: w.holder,
        config_cert: w.config_cert,
        signed_at: w.signed_at,
        expires_at: w.expires_at,
    }
}

fn to_reg_device_cert(c: crate::store::DeviceCertRecord) -> reg::DeviceCertRecord {
    reg::DeviceCertRecord {
        id: c.id,
        user_id: c.user_id.0,
        identities: c.identities,
        purpose: c.purpose,
        holder: c.holder,
        pubkey: c.pubkey,
        iss: c.iss,
        issued_at: c.issued_at,
        expires_at: c.expires_at,
        revoked_at: c.revoked_at,
        status_idx: c.status_idx,
    }
}

fn from_reg_device_cert(c: reg::DeviceCertRecord) -> crate::store::DeviceCertRecord {
    crate::store::DeviceCertRecord {
        id: c.id,
        user_id: UserId(c.user_id),
        identities: c.identities,
        purpose: c.purpose,
        holder: c.holder,
        pubkey: c.pubkey,
        iss: c.iss,
        issued_at: c.issued_at,
        expires_at: c.expires_at,
        revoked_at: c.revoked_at,
        status_idx: c.status_idx,
    }
}

/// Adapts any broker `UserStore` into the registrar's store.
pub struct BrokerRegistrarStore<U> {
    pub user_store: Arc<U>,
}

impl<U: UserStore> RegistrarStore for BrokerRegistrarStore<U> {
    fn create_warrant_request(&self, req: reg::WarrantRequestRecord) -> Result<(), RegistrarError> {
        UserStore::create_warrant_request(self.user_store.as_ref(), from_reg_request(req))
            .map_err(to_reg_err)
    }

    fn get_warrant_request(
        &self,
        code: &str,
    ) -> Result<Option<reg::WarrantRequestRecord>, RegistrarError> {
        UserStore::get_warrant_request(self.user_store.as_ref(), code)
            .map(|o| o.map(to_reg_request))
            .map_err(to_reg_err)
    }

    fn list_pending_warrant_requests(
        &self,
        user_id: u64,
    ) -> Result<Vec<reg::WarrantRequestRecord>, RegistrarError> {
        UserStore::list_pending_warrant_requests(self.user_store.as_ref(), UserId(user_id))
            .map(|v| v.into_iter().map(to_reg_request).collect())
            .map_err(to_reg_err)
    }

    fn respond_warrant_request(
        &self,
        user_id: u64,
        code: &str,
        warrants: Option<&[String]>,
    ) -> Result<(), RegistrarError> {
        UserStore::respond_warrant_request(self.user_store.as_ref(), UserId(user_id), code, warrants)
            .map_err(to_reg_err)
    }

    fn touch_warrant_poll(
        &self,
        code: &str,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, RegistrarError> {
        UserStore::touch_warrant_poll(self.user_store.as_ref(), code).map_err(to_reg_err)
    }

    fn delete_warrant_request(&self, code: &str) -> Result<(), RegistrarError> {
        UserStore::delete_warrant_request(self.user_store.as_ref(), code).map_err(to_reg_err)
    }

    fn cleanup_expired_warrant_requests(&self) -> Result<u64, RegistrarError> {
        UserStore::cleanup_expired_warrant_requests(self.user_store.as_ref()).map_err(to_reg_err)
    }

    fn upsert_warrant(&self, record: reg::WarrantRecord) -> Result<(), RegistrarError> {
        UserStore::upsert_warrant(self.user_store.as_ref(), from_reg_warrant(record))
            .map_err(to_reg_err)
    }

    fn list_warrants(&self, user_id: u64) -> Result<Vec<reg::WarrantRecord>, RegistrarError> {
        UserStore::list_warrants(self.user_store.as_ref(), UserId(user_id))
            .map(|v| v.into_iter().map(to_reg_warrant).collect())
            .map_err(to_reg_err)
    }

    fn delete_warrant(&self, user_id: u64, warrant_id: u64) -> Result<(), RegistrarError> {
        UserStore::delete_warrant(self.user_store.as_ref(), UserId(user_id), warrant_id)
            .map_err(to_reg_err)
    }

    fn get_or_allocate_status(&self, kind: &str, subject: &str) -> Result<u64, RegistrarError> {
        UserStore::get_or_allocate_status(self.user_store.as_ref(), kind, subject)
            .map_err(to_reg_err)
    }

    fn get_or_create_namespace(&self, user_id: u64, name: &str) -> Result<String, RegistrarError> {
        UserStore::get_or_create_namespace(self.user_store.as_ref(), UserId(user_id), name)
            .map_err(to_reg_err)
    }

    fn set_status_revoked(&self, kind: &str, subject: &str) -> Result<bool, RegistrarError> {
        UserStore::set_status_revoked(self.user_store.as_ref(), kind, subject).map_err(to_reg_err)
    }

    fn set_status_revoked_idx(&self, idx: u64) -> Result<bool, RegistrarError> {
        UserStore::set_status_revoked_idx(self.user_store.as_ref(), idx).map_err(to_reg_err)
    }

    fn set_status_active_idx(&self, idx: u64) -> Result<bool, RegistrarError> {
        UserStore::set_status_active_idx(self.user_store.as_ref(), idx).map_err(to_reg_err)
    }

    fn is_status_revoked_idx(&self, idx: u64) -> Result<bool, RegistrarError> {
        UserStore::is_status_revoked_idx(self.user_store.as_ref(), idx).map_err(to_reg_err)
    }

    fn revoked_status_indices(&self) -> Result<(Vec<u64>, u64), RegistrarError> {
        UserStore::revoked_status_indices(self.user_store.as_ref()).map_err(to_reg_err)
    }

    fn insert_device_cert(&self, rec: reg::DeviceCertRecord) -> Result<u64, RegistrarError> {
        UserStore::insert_device_cert(self.user_store.as_ref(), from_reg_device_cert(rec))
            .map_err(to_reg_err)
    }

    fn get_device_cert_by_pubkey(
        &self,
        pubkey: &str,
    ) -> Result<Option<reg::DeviceCertRecord>, RegistrarError> {
        UserStore::get_device_cert_by_pubkey(self.user_store.as_ref(), pubkey)
            .map(|o| o.map(to_reg_device_cert))
            .map_err(to_reg_err)
    }

    fn list_device_certs(&self, user_id: u64) -> Result<Vec<reg::DeviceCertRecord>, RegistrarError> {
        UserStore::list_device_certs(self.user_store.as_ref(), UserId(user_id))
            .map(|v| v.into_iter().map(to_reg_device_cert).collect())
            .map_err(to_reg_err)
    }

    fn revoke_device_cert(&self, user_id: u64, cert_id: u64) -> Result<(), RegistrarError> {
        UserStore::revoke_device_cert(self.user_store.as_ref(), UserId(user_id), cert_id)
            .map_err(to_reg_err)
    }
}

/// The broker's sessions + accounts, seen through the registrar's eyes.
pub struct BrokerRegistrarHost<U, S> {
    pub user_store: Arc<U>,
    pub session_store: Arc<S>,
    /// The domain agent handles are minted under (`<name>@<domain>`).
    pub domain: String,
    /// Per-account cap on agent identities.
    pub max_agent_identities: usize,
}

impl<U: UserStore, S: SessionStore> RegistrarHost for BrokerRegistrarHost<U, S> {
    fn resolve_session(&self, cookies: &Cookies) -> Option<AuthedUser> {
        crate::routes::session::get_session_from_cookies(cookies, self.session_store.as_ref())
            .map(|s| AuthedUser {
                user_id: s.user_id.0,
                csrf_token: s.csrf_token,
            })
    }

    fn record_agent_device_cert(
        &self,
        user_id: u64,
        identity: &str,
        holder: &str,
        pubkey: &str,
        iss: &str,
        issued_at: i64,
        expires_at: i64,
        status_idx: Option<u64>,
        label: Option<&str>,
    ) {
        let ts = |secs: i64| {
            chrono::DateTime::from_timestamp(secs, 0).unwrap_or_else(chrono::Utc::now)
        };
        let rec = crate::store::DeviceCertRecord {
            id: 0,
            user_id: UserId(user_id),
            identities: vec![identity.to_string()],
            purpose: "authentication".to_string(),
            holder: holder.to_string(),
            pubkey: pubkey.to_string(),
            iss: iss.to_string(),
            issued_at: ts(issued_at),
            expires_at: ts(expires_at),
            revoked_at: None,
            status_idx,
        };
        if let Err(e) = self.user_store.insert_device_cert(rec) {
            tracing::warn!("recording agent device cert failed: {e}");
        }
        if let Some(label) = label.map(str::trim).filter(|l| !l.is_empty()) {
            let label: String = label.chars().take(64).collect();
            if let Err(e) = self.user_store.set_holder_label(UserId(user_id), holder, &label) {
                tracing::warn!("labeling agent holder failed: {e}");
            }
        }
    }

    fn owns_verified_email(&self, user_id: u64, email: &str) -> Result<bool, RegistrarError> {
        Ok(self
            .user_store
            .list_emails(UserId(user_id))
            .map_err(to_reg_err)?
            .iter()
            .any(|e| e.email.eq_ignore_ascii_case(email) && e.verified))
    }

    fn user_for_verified_email(&self, email: &str) -> Result<Option<u64>, RegistrarError> {
        Ok(self
            .user_store
            .get_email(email)
            .map_err(to_reg_err)?
            .filter(|e| e.verified)
            .map(|e| e.user_id.0))
    }

    fn agent_identities(&self, user_id: u64) -> Result<Vec<AgentIdentity>, RegistrarError> {
        Ok(self
            .user_store
            .list_emails(UserId(user_id))
            .map_err(to_reg_err)?
            .into_iter()
            .filter(|e| e.email_type == EmailType::Agent)
            .map(|e| AgentIdentity {
                email: e.email,
                parent_email: e.parent_email,
            })
            .collect())
    }

    fn reserve_agent_names(
        &self,
        user_id: u64,
        delegator: &str,
        names: &[String],
    ) -> Result<(), RegistrarError> {
        // Pre-scan: any handle owned by another account (or a non-agent) is taken.
        let mut taken = Vec::new();
        for name in names {
            let email = browserid_registrar::agent_identity_email(delegator, name);
            if let Some(rec) = self.user_store.get_email(&email).map_err(to_reg_err)? {
                if rec.user_id.0 != user_id || rec.email_type != EmailType::Agent {
                    taken.push(name.clone());
                }
            }
        }
        if !taken.is_empty() {
            return Err(RegistrarError::NamesTaken(taken));
        }
        // Quota: count existing active agent identities + the new ones to create.
        let existing = self.user_store.list_emails(UserId(user_id)).map_err(to_reg_err)?;
        let active = existing
            .iter()
            .filter(|e| e.email_type == EmailType::Agent && e.verified)
            .count();
        let new_count = names
            .iter()
            .filter(|name| {
                let email = browserid_registrar::agent_identity_email(delegator, name);
                !existing.iter().any(|e| e.email.eq_ignore_ascii_case(&email))
            })
            .count();
        if active + new_count > self.max_agent_identities {
            return Err(RegistrarError::PolicyRefused(
                "agent identity quota exceeded for this account".into(),
            ));
        }
        // Create the handles that don't exist yet, parented to the delegator.
        for name in names {
            let email = browserid_registrar::agent_identity_email(delegator, name);
            if self.user_store.get_email(&email).map_err(to_reg_err)?.is_none() {
                self.user_store
                    .add_email_with_type(UserId(user_id), &email, true, EmailType::Agent)
                    .map_err(to_reg_err)?;
                self.user_store
                    .set_parent_email(&email, Some(delegator))
                    .map_err(to_reg_err)?;
            }
        }
        Ok(())
    }
}

/// Foreign-IdP key discovery for external warrant requests (§6.6), backed by
/// the broker's DNSSEC-rooted [`FallbackFetcher`]. A foreign domain without
/// DNSSEC resolves to the fallback broker's key — the same rooting rule as
/// everywhere else — so a cert its claimed issuer didn't sign can never pass.
pub struct BrokerIssuerResolver {
    pub fetcher: Arc<crate::fallback_fetcher::FallbackFetcher>,
}

impl browserid_registrar::IssuerKeyResolver for BrokerIssuerResolver {
    fn resolve_issuer_key<'a>(
        &'a self,
        domain: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<browserid_core::PublicKey, RegistrarError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let result = self.fetcher.discover(domain).await.map_err(|e| {
                RegistrarError::ValidationError(format!(
                    "issuer discovery failed for '{domain}': {e}"
                ))
            })?;
            result.document.public_key.ok_or_else(|| {
                RegistrarError::ValidationError(format!(
                    "no identity key published for '{domain}'"
                ))
            })
        })
    }
}

#[cfg(test)]
mod reserve_tests {
    use super::*;
    use crate::store::memory::{InMemorySessionStore, InMemoryUserStore};

    fn host(max: usize) -> (BrokerRegistrarHost<InMemoryUserStore, InMemorySessionStore>, u64, u64) {
        let us = Arc::new(InMemoryUserStore::new());
        let u1 = us.create_user("x").unwrap().0;
        let u2 = us.create_user("y").unwrap().0;
        let h = BrokerRegistrarHost {
            user_store: us,
            session_store: Arc::new(InMemorySessionStore::new()),
            domain: "browserid.me".into(),
            max_agent_identities: max,
        };
        (h, u1, u2)
    }

    #[test]
    fn reserve_creates_locks_and_is_idempotent() {
        let (h, u1, u2) = host(10);
        h.reserve_agent_names(u1, "alice@browserid.me", &["bot".into()]).unwrap();
        // idempotent for the owner
        h.reserve_agent_names(u1, "alice@browserid.me", &["bot".into()]).unwrap();
        // the identity now exists, parented to the delegator
        let rec = h.user_store.get_email("bot@browserid.me").unwrap().unwrap();
        assert_eq!(rec.email_type, EmailType::Agent);
        assert_eq!(rec.parent_email.as_deref(), Some("alice@browserid.me"));
        // another account cannot take it
        match h.reserve_agent_names(u2, "bob@browserid.me", &["bot".into()]) {
            Err(RegistrarError::NamesTaken(v)) => assert_eq!(v, vec!["bot".to_string()]),
            other => panic!("expected NamesTaken, got {other:?}"),
        }
    }

    #[test]
    fn reserve_enforces_quota() {
        let (h, u1, _) = host(1);
        h.reserve_agent_names(u1, "alice@browserid.me", &["a".into()]).unwrap();
        match h.reserve_agent_names(u1, "alice@browserid.me", &["b".into()]) {
            Err(RegistrarError::PolicyRefused(_)) => {}
            other => panic!("expected PolicyRefused, got {other:?}"),
        }
    }

    // The name is the full local-part (no translation): `<name>@<owner-domain>`.
    // For fallback owners the names are sub-addresses (`alice+shared`), so two
    // different owners' handles cannot collide.
    #[test]
    fn reserve_uses_name_at_owner_domain_scoped_per_owner() {
        let (h, u1, u2) = host(10);
        h.reserve_agent_names(u1, "alice@gmail.com", &["alice+shared".into()]).unwrap();
        let rec = h.user_store.get_email("alice+shared@gmail.com").unwrap().unwrap();
        assert_eq!(rec.email_type, EmailType::Agent);
        assert_eq!(rec.parent_email.as_deref(), Some("alice@gmail.com"));
        // A different owner's sub-address does not collide.
        h.reserve_agent_names(u2, "bob@gmail.com", &["bob+shared".into()]).unwrap();
        assert!(h.user_store.get_email("bob+shared@gmail.com").unwrap().is_some());
        // Idempotent for the owner.
        h.reserve_agent_names(u1, "alice@gmail.com", &["alice+shared".into()]).unwrap();
    }
}
