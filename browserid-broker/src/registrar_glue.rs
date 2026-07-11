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
        BrokerError::ProvisioningCertNotFound => RegistrarError::ProvisioningCertNotFound,
        BrokerError::WarrantRequestNotFound => RegistrarError::WarrantRequestNotFound,
        BrokerError::NotAuthenticated => RegistrarError::NotAuthenticated,
        BrokerError::ValidationError(m) => RegistrarError::ValidationError(m),
        other => RegistrarError::Internal(other.to_string()),
    }
}

fn to_reg_cert(c: crate::store::ProvisioningCertRecord) -> reg::ProvisioningCertRecord {
    reg::ProvisioningCertRecord {
        id: c.id,
        user_id: c.user_id.0,
        delegator_email: c.delegator_email,
        provisioning_pub: c.provisioning_pub,
        bundle: c.bundle,
        label: c.label,
        created_at: c.created_at,
        last_endorsed_at: c.last_endorsed_at,
        revoked_at: c.revoked_at,
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
        label: r.label,
        grants: r.grants.into_iter().map(to_reg_grant).collect(),
        status: to_reg_status(r.status),
        warrants: r.warrants,
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
        label: r.label,
        grants: r.grants.into_iter().map(from_reg_grant).collect(),
        status: from_reg_status(r.status),
        warrants: r.warrants,
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
        signed_at: w.signed_at,
        expires_at: w.expires_at,
    }
}

/// Adapts any broker `UserStore` into the registrar's store.
pub struct BrokerRegistrarStore<U> {
    pub user_store: Arc<U>,
}

impl<U: UserStore> RegistrarStore for BrokerRegistrarStore<U> {
    fn register_provisioning_cert(
        &self,
        user_id: u64,
        delegator_email: &str,
        provisioning_pub: &str,
        bundle: &str,
        label: &str,
    ) -> Result<reg::ProvisioningCertRecord, RegistrarError> {
        UserStore::register_provisioning_cert(
            self.user_store.as_ref(),
            UserId(user_id),
            delegator_email,
            provisioning_pub,
            bundle,
            label,
        )
        .map(to_reg_cert)
        .map_err(to_reg_err)
    }

    fn get_provisioning_cert_by_pub(
        &self,
        provisioning_pub: &str,
    ) -> Result<Option<reg::ProvisioningCertRecord>, RegistrarError> {
        UserStore::get_provisioning_cert_by_pub(self.user_store.as_ref(), provisioning_pub)
            .map(|o| o.map(to_reg_cert))
            .map_err(to_reg_err)
    }

    fn list_provisioning_certs(
        &self,
        user_id: u64,
    ) -> Result<Vec<reg::ProvisioningCertRecord>, RegistrarError> {
        UserStore::list_provisioning_certs(self.user_store.as_ref(), UserId(user_id))
            .map(|v| v.into_iter().map(to_reg_cert).collect())
            .map_err(to_reg_err)
    }

    fn count_active_provisioning_certs(&self, user_id: u64) -> Result<usize, RegistrarError> {
        UserStore::count_active_provisioning_certs(self.user_store.as_ref(), UserId(user_id))
            .map_err(to_reg_err)
    }

    fn revoke_provisioning_cert(&self, user_id: u64, cert_id: u64) -> Result<(), RegistrarError> {
        UserStore::revoke_provisioning_cert(self.user_store.as_ref(), UserId(user_id), cert_id)
            .map_err(to_reg_err)
    }

    fn touch_provisioning_cert(&self, cert_id: u64) -> Result<(), RegistrarError> {
        UserStore::touch_provisioning_cert(self.user_store.as_ref(), cert_id).map_err(to_reg_err)
    }

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

    fn set_status_revoked(&self, kind: &str, subject: &str) -> Result<bool, RegistrarError> {
        UserStore::set_status_revoked(self.user_store.as_ref(), kind, subject).map_err(to_reg_err)
    }

    fn set_status_revoked_idx(&self, idx: u64) -> Result<bool, RegistrarError> {
        UserStore::set_status_revoked_idx(self.user_store.as_ref(), idx).map_err(to_reg_err)
    }

    fn is_status_revoked_idx(&self, idx: u64) -> Result<bool, RegistrarError> {
        UserStore::is_status_revoked_idx(self.user_store.as_ref(), idx).map_err(to_reg_err)
    }

    fn revoked_status_indices(&self) -> Result<(Vec<u64>, u64), RegistrarError> {
        UserStore::revoked_status_indices(self.user_store.as_ref()).map_err(to_reg_err)
    }
}

/// The broker's sessions + accounts, seen through the registrar's eyes.
pub struct BrokerRegistrarHost<U, S> {
    pub user_store: Arc<U>,
    pub session_store: Arc<S>,
}

impl<U: UserStore, S: SessionStore> RegistrarHost for BrokerRegistrarHost<U, S> {
    fn resolve_session(&self, cookies: &Cookies) -> Option<AuthedUser> {
        crate::routes::session::get_session_from_cookies(cookies, self.session_store.as_ref())
            .map(|s| AuthedUser {
                user_id: s.user_id.0,
                csrf_token: s.csrf_token,
            })
    }

    fn owns_verified_email(&self, user_id: u64, email: &str) -> Result<bool, RegistrarError> {
        Ok(self
            .user_store
            .list_emails(UserId(user_id))
            .map_err(to_reg_err)?
            .iter()
            .any(|e| e.email.eq_ignore_ascii_case(email) && e.verified))
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
}
