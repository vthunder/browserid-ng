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

use browserid_registrar::host::{AgentIdentity, AuthedUser, KnownAgent, RegistrarHost};
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
        BrokerError::PolicyRefused(m) => RegistrarError::PolicyRefused(m),
        other => RegistrarError::Internal(other.to_string()),
    }
}

fn to_reg_grant(g: crate::store::WarrantGrantItem) -> reg::WarrantGrantItem {
    reg::WarrantGrantItem {
        audience: g.audience,
        scopes: g.scopes,
        status_idx: g.status_idx,
        grantee: g.grantee,
    }
}

fn from_reg_grant(g: reg::WarrantGrantItem) -> crate::store::WarrantGrantItem {
    crate::store::WarrantGrantItem {
        audience: g.audience,
        scopes: g.scopes,
        status_idx: g.status_idx,
        grantee: g.grantee,
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
        kind: reg::RequestKind::from_str(&r.kind).unwrap_or(reg::RequestKind::Agent),
        meta: r.meta.as_deref().and_then(|m| serde_json::from_str(m).ok()),
        user_id: r.user_id.0,
        delegator_email: r.delegator_email,
        agent_email: r.agent_email,
        holder: r.holder,
        label: r.label,
        grantor: r.grantor,
        message: r.message,
        grants: r.grants.into_iter().map(to_reg_grant).collect(),
        status: to_reg_status(r.status),
        warrants: r.warrants,
        external: r.external,
        return_url: r.return_url,
        created_at: r.created_at,
        expires_at: r.expires_at,
        last_polled_at: r.last_polled_at,
    }
}

fn from_reg_request(r: reg::WarrantRequestRecord) -> crate::store::WarrantRequestRecord {
    crate::store::WarrantRequestRecord {
        code: r.code,
        kind: r.kind.as_str().to_string(),
        meta: r.meta.as_ref().and_then(|m| serde_json::to_string(m).ok()),
        user_id: UserId(r.user_id),
        delegator_email: r.delegator_email,
        agent_email: r.agent_email,
        holder: r.holder,
        label: r.label,
        grantor: r.grantor,
        message: r.message,
        grants: r.grants.into_iter().map(from_reg_grant).collect(),
        status: from_reg_status(r.status),
        warrants: r.warrants,
        external: r.external,
        return_url: r.return_url,
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
        binding_id: w.binding_id,
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
        binding_id: w.binding_id,
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
        status_uri: c.status_uri,
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
        status_uri: c.status_uri,
        status_idx: c.status_idx,
        // Registrar-recorded agent certs are broker-vouched (smtp class).
        prov: "smtp".to_string(),
    }
}

fn to_reg_api_token(t: crate::store::ApiTokenRecord) -> reg::ApiTokenRecord {
    reg::ApiTokenRecord {
        token_hash: t.token_hash,
        user_id: t.user_id.0,
        proof_key: t.proof_key,
        cert_status_uri: t.cert_status_uri,
        cert_status_idx: t.cert_status_idx,
        scope: t.scope,
        created_at: t.created_at,
        expires_at: t.expires_at,
    }
}

fn from_reg_api_token(t: reg::ApiTokenRecord) -> crate::store::ApiTokenRecord {
    crate::store::ApiTokenRecord {
        token_hash: t.token_hash,
        user_id: UserId(t.user_id),
        proof_key: t.proof_key,
        cert_status_uri: t.cert_status_uri,
        cert_status_idx: t.cert_status_idx,
        scope: t.scope,
        created_at: t.created_at,
        expires_at: t.expires_at,
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

    fn update_warrant_request(&self, rec: &reg::WarrantRequestRecord) -> Result<(), RegistrarError> {
        UserStore::update_warrant_request(self.user_store.as_ref(), &from_reg_request(rec.clone()))
            .map_err(to_reg_err)
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

    fn create_api_token(&self, rec: reg::ApiTokenRecord) -> Result<(), RegistrarError> {
        UserStore::create_api_token(self.user_store.as_ref(), from_reg_api_token(rec))
            .map_err(to_reg_err)
    }

    fn get_api_token(&self, token_hash: &str) -> Result<Option<reg::ApiTokenRecord>, RegistrarError> {
        UserStore::get_api_token(self.user_store.as_ref(), token_hash)
            .map(|o| o.map(to_reg_api_token))
            .map_err(to_reg_err)
    }

    fn cleanup_expired_api_tokens(&self) -> Result<u64, RegistrarError> {
        UserStore::cleanup_expired_api_tokens(self.user_store.as_ref()).map_err(to_reg_err)
    }

    fn get_or_allocate_status(&self, kind: &str, subject: &str) -> Result<u64, RegistrarError> {
        UserStore::get_or_allocate_status(self.user_store.as_ref(), kind, subject)
            .map_err(to_reg_err)
    }

    fn get_or_create_namespace(&self, user_id: u64, name: &str) -> Result<String, RegistrarError> {
        UserStore::get_or_create_namespace(self.user_store.as_ref(), UserId(user_id), name)
            .map_err(to_reg_err)
    }

    fn adopt_namespace_prefix(&self, user_id: u64, name: &str, new_prefix: &str) -> Result<bool, RegistrarError> {
        UserStore::adopt_namespace_prefix(self.user_store.as_ref(), UserId(user_id), name, new_prefix)
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

    fn list_namespaces(&self, user_id: u64) -> Result<Vec<reg::NamespaceRecord>, RegistrarError> {
        UserStore::list_namespaces(self.user_store.as_ref(), UserId(user_id))
            .map(|v| {
                v.into_iter()
                    .map(|n| reg::NamespaceRecord { name: n.name, prefix: n.prefix, label: n.label })
                    .collect()
            })
            .map_err(to_reg_err)
    }

    fn create_namespace(&self, user_id: u64, name: &str, label: &str) -> Result<(), RegistrarError> {
        UserStore::create_namespace(self.user_store.as_ref(), UserId(user_id), name, label)
            .map_err(to_reg_err)
    }

    fn set_namespace_label(
        &self,
        user_id: u64,
        name: &str,
        label: &str,
    ) -> Result<(), RegistrarError> {
        UserStore::set_namespace_label(self.user_store.as_ref(), UserId(user_id), name, label)
            .map_err(to_reg_err)
    }

    fn delete_namespace(&self, user_id: u64, name: &str) -> Result<(), RegistrarError> {
        UserStore::delete_namespace(self.user_store.as_ref(), UserId(user_id), name)
            .map_err(to_reg_err)
    }

    fn get_holder_labels(
        &self,
        user_id: u64,
    ) -> Result<std::collections::HashMap<String, String>, RegistrarError> {
        UserStore::get_holder_labels(self.user_store.as_ref(), UserId(user_id)).map_err(to_reg_err)
    }

    fn set_holder_label(
        &self,
        user_id: u64,
        holder_id: &str,
        label: &str,
    ) -> Result<(), RegistrarError> {
        UserStore::set_holder_label(self.user_store.as_ref(), UserId(user_id), holder_id, label)
            .map_err(to_reg_err)
    }

    fn set_holder_move(
        &self,
        user_id: u64,
        old_holder: &str,
        new_holder: &str,
    ) -> Result<(), RegistrarError> {
        UserStore::set_holder_move(self.user_store.as_ref(), UserId(user_id), old_holder, new_holder)
            .map_err(to_reg_err)
    }

    fn resolve_holder_move(
        &self,
        user_id: u64,
        holder: &str,
    ) -> Result<Option<String>, RegistrarError> {
        UserStore::resolve_holder_move(self.user_store.as_ref(), UserId(user_id), holder)
            .map_err(to_reg_err)
    }

    fn list_holder_moves(&self, user_id: u64) -> Result<Vec<(String, String)>, RegistrarError> {
        UserStore::list_holder_moves(self.user_store.as_ref(), UserId(user_id)).map_err(to_reg_err)
    }

    fn forget_holder(&self, user_id: u64, holder: &str) -> Result<u64, RegistrarError> {
        UserStore::forget_holder(self.user_store.as_ref(), UserId(user_id), holder)
            .map_err(to_reg_err)
    }
}

/// The broker's sessions + accounts, seen through the registrar's eyes.
pub struct BrokerRegistrarHost<U, S> {
    pub user_store: Arc<U>,
    pub session_store: Arc<S>,
    /// The domain agent handles are minted under (`<name>@<domain>`).
    pub domain: String,
    /// The hosted-IdP host (tenant status lists live under its `/status/`).
    pub idp_host: String,
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
            // Agent certs recorded here are broker-issued (the registrar's
            // provisioning path) — their bits live on the broker's own list.
            status_uri: status_idx
                .map(|_| browserid_registrar::consent::status_list_uri(&self.domain)),
            status_idx,
            prov: "smtp".to_string(),
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

    fn set_agent_display_name(&self, user_id: u64, agent_email: &str, name: &str) {
        let name = name.trim();
        if name.is_empty() {
            return;
        }
        let name: String = name.chars().take(64).collect();
        // Only name identities this account actually owns — best-effort.
        match self.user_store.get_email(agent_email) {
            Ok(Some(rec)) if rec.user_id.0 == user_id => {
                if let Err(e) = self.user_store.set_email_display_name(agent_email, Some(&name)) {
                    tracing::warn!("setting agent display name failed: {e}");
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("setting agent display name failed: {e}"),
        }
    }

    fn set_agent_public_name(&self, user_id: u64, agent_email: &str, name: &str) {
        let name = name.trim();
        if name.is_empty() {
            return;
        }
        let name: String = name.chars().take(64).collect();
        // Only name identities this account actually owns — best-effort.
        match self.user_store.get_email(agent_email) {
            Ok(Some(rec)) if rec.user_id.0 == user_id => {
                if let Err(e) = self.user_store.set_email_public_name(agent_email, Some(&name)) {
                    tracing::warn!("setting agent public name failed: {e}");
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("setting agent public name failed: {e}"),
        }
    }

    fn known_agent(
        &self,
        user_id: u64,
        agent_email: &str,
    ) -> Result<Option<KnownAgent>, RegistrarError> {
        // Known = an identity on this account (a minted agent, or the user
        // themself for an as-you agent), or a recorded device cert / external
        // service entry covering the identity. Anything else is a stranger.
        let email_rec = self
            .user_store
            .get_email(agent_email)
            .map_err(to_reg_err)?
            .filter(|e| e.user_id.0 == user_id);
        let cert_created: Option<chrono::DateTime<chrono::Utc>> = self
            .user_store
            .list_device_certs(UserId(user_id))
            .map_err(to_reg_err)?
            .into_iter()
            .filter(|c| c.identities.iter().any(|i| i.eq_ignore_ascii_case(agent_email)))
            .map(|c| c.issued_at)
            .min();
        if email_rec.is_none() && cert_created.is_none() {
            return Ok(None);
        }
        Ok(Some(KnownAgent {
            display_name: email_rec.as_ref().and_then(|e| e.display_name.clone()),
            created_at: cert_created.or(email_rec.and_then(|e| e.verified_at)),
        }))
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

    fn account_for_presented_identity(&self, email: &str) -> Result<u64, RegistrarError> {
        // Token-lane account resolution (registry-api-v1 §3.1): the caller
        // PROVED the identity with a full presentation. Existing owner wins
        // (same rule as the cookie lane's no-session path); otherwise a fresh
        // account holding exactly this identity — never linking or transfer,
        // which are session ceremonies with no token-lane analogue.
        if let Some(rec) = self.user_store.get_email(email).map_err(to_reg_err)? {
            return Ok(rec.user_id.0);
        }
        let user_id = self.user_store.create_user_no_password().map_err(to_reg_err)?;
        self.user_store
            .add_email_with_type(user_id, email, true, EmailType::Primary)
            .map_err(to_reg_err)?;
        Ok(user_id.0)
    }

    fn revoke_hosted_status(&self, uri: &str, idx: u64) -> Result<bool, RegistrarError> {
        // A hosted tenant's list? (`…/status/<domain>` on our idp host — the
        // broker hosts those lists too, so their bits are ours to flip.)
        let prefix = format!(
            "{}/status/",
            browserid_registrar::consent::public_origin(&self.idp_host)
        );
        let Some(domain) = uri.strip_prefix(&prefix) else {
            return Ok(false);
        };
        match self.user_store.get_tenant(&domain.to_lowercase()).map_err(to_reg_err)? {
            Some(tenant) => {
                self.user_store.tenant_status_revoke_idx(tenant.id, idx).map_err(to_reg_err)?;
                Ok(true)
            }
            None => Ok(false),
        }
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

    fn resolve_issuer<'a>(
        &'a self,
        domain: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<browserid_registrar::ResolvedIssuer, RegistrarError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let result = self.fetcher.discover(domain).await.map_err(|e| {
                RegistrarError::ValidationError(format!(
                    "issuer discovery failed for '{domain}': {e}"
                ))
            })?;
            let key = result.document.public_key.clone().ok_or_else(|| {
                RegistrarError::ValidationError(format!(
                    "no identity key published for '{domain}'"
                ))
            })?;
            Ok(browserid_registrar::ResolvedIssuer {
                key,
                // The `host=` of the domain's validated `_browserid` record
                // (hosted primaries, g5qt) — same trust root as the key.
                serving_host: result.serving_host.clone(),
            })
        })
    }
}

/// The broker's core §6 verification stack behind the registry API token
/// lane (registry-api-v1 §3): the exact `verify_access_with_dns` call the
/// cookie sibling `auth_with_presentation` makes — same audience (the
/// broker's own public origin), same accepted fallback, same fail-closed
/// status context — plus the per-call status re-check token-authed
/// endpoints run on the bound config cert.
pub struct BrokerPresentationVerifier<U: UserStore, S: SessionStore, E: crate::email::EmailSender>
{
    pub state: Arc<crate::state::AppState<U, S, E>>,
}

impl<U, S, E> browserid_registrar::api::PresentationVerifier for BrokerPresentationVerifier<U, S, E>
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
    E: crate::email::EmailSender + 'static,
{
    fn verify_presentation<'a>(
        &'a self,
        presentation: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<browserid_registrar::api::VerifiedPresentation, String>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let state = &self.state;
            let fetcher = state
                .fallback_fetcher()
                .await
                .map_err(|e| format!("DNS discovery not configured: {e}"))?;
            let audience = browserid_registrar::consent::public_origin(&state.domain);
            let accepted = vec![state.domain.clone()];
            let is_own_revoked =
                |idx: u64| state.user_store.is_status_revoked_idx(idx).map_err(|e| e.to_string());
            let status = crate::verifier::StatusCtx {
                own_uri: browserid_registrar::consent::status_list_uri(&state.domain),
                is_own_revoked: &is_own_revoked,
                cache: &state.foreign_status_lists,
                allow_private_hosts: !crate::routes::session::cookie_secure(&state.domain),
            };
            let result = crate::verifier::verify_access_with_dns(
                presentation,
                &audience,
                fetcher.as_ref(),
                &accepted,
                status,
            )
            .await;
            if result.status != "okay" {
                return Err(result.reason.unwrap_or_else(|| "verification failed".into()));
            }
            Ok(browserid_registrar::api::VerifiedPresentation {
                email: result.email.ok_or("no email in presentation")?,
                grantee: result.grantee.ok_or("no grantee in presentation")?,
                issuer: result.issuer.ok_or("no issuer in presentation")?,
                holder: result.holder.unwrap_or_default(),
                scopes: result.scopes.unwrap_or_default(),
            })
        })
    }

    fn check_status_ref<'a>(
        &'a self,
        uri: &'a str,
        idx: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + 'a>>
    {
        Box::pin(async move {
            let state = &self.state;
            // Same authority routing as record_device_cert: our own list is
            // authoritative locally; a hosted tenant's list lives under the
            // idp host's /status/<domain>; anything else is a foreign list,
            // fetched and verified fail-closed.
            let own_uri = browserid_registrar::consent::status_list_uri(&state.domain);
            if uri == own_uri {
                return state.user_store.is_status_revoked_idx(idx).map_err(|e| e.to_string());
            }
            let idp_status_prefix = format!(
                "{}/status/",
                browserid_registrar::consent::public_origin(&state.idp_host)
            );
            if let Some(tenant) = uri
                .strip_prefix(&idp_status_prefix)
                .and_then(|d| state.user_store.get_tenant(&d.to_lowercase()).ok().flatten())
            {
                return state
                    .user_store
                    .tenant_status_is_revoked(tenant.id, idx)
                    .map_err(|e| e.to_string());
            }
            let fetcher = state
                .fallback_fetcher()
                .await
                .map_err(|e| format!("DNS discovery not configured: {e}"))?;
            let r = browserid_core::StatusRef { uri: uri.to_string(), idx };
            crate::verifier::check_foreign_status_fresh(
                &r,
                fetcher.as_ref(),
                &state.foreign_status_lists,
                !crate::routes::session::cookie_secure(&state.domain),
            )
            .await
            .map_err(|e| e.to_string())
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
            idp_host: "idp.browserid.me".into(),
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
