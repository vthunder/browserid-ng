//! Headless agent provisioning (l8lw)
//!
//! Two route families, both gated on `state.agent_provisioning_enabled`:
//!
//! - `/wsapi/agent_keys*` — browser-side API-key management (session + CSRF
//!   gated). A key materializes the human→agent attribution link as a
//!   revocable row and is the agent's standing re-mint credential.
//! - `/agent/*` — agent-side REST provisioning (`Authorization: Bearer
//!   bidk_…`). An agent generates its own keypair, POSTs the public half, and
//!   gets back an agent identity (`<name>@<broker host>`) plus a certificate.
//!   Re-mints go through the same shared issuance path as `/wsapi/cert_key`.
//!
//! Agent identities are ordinary emails (`email_type = 'agent'`,
//! `parent_email` = attribution root); RPs verify the resulting certs as
//! plain browserid and never learn "agent". Soft revocation only: revoking a
//! key or identity stops re-mints and outstanding certs age out (≤24h).

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::Json;
use base64::Engine;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{ApiKey, EmailType, Session, SessionStore, UserStore};

use super::cert::{issue_certificate, PublicKeyJson};

/// API-key secret prefix (greppability for secret scanners)
const API_KEY_PREFIX: &str = "bidk_";

fn hash_api_key(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

fn generate_api_key_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!(
        "{}{}",
        API_KEY_PREFIX,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Agent identity local-part: 1–32 chars of [a-z0-9-], no leading/trailing '-'
fn valid_agent_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

fn generate_agent_name() -> String {
    let mut bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!(
        "agent-{}",
        bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    )
}

/// Session + CSRF gate for the browser-side key-management endpoints. New
/// state-changing routes enforce CSRF from day one (see bean y2ho for the
/// legacy routes).
fn require_session_csrf<S: SessionStore>(
    cookies: &Cookies,
    session_store: &S,
    csrf: &str,
) -> Result<Session, BrokerError> {
    let session = super::session::get_session_from_cookies(cookies, session_store)
        .ok_or(BrokerError::NotAuthenticated)?;
    if session.csrf_token != csrf {
        return Err(BrokerError::InvalidCsrf);
    }
    Ok(session)
}

fn require_enabled<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
) -> Result<(), BrokerError> {
    if state.agent_provisioning_enabled {
        Ok(())
    } else {
        Err(BrokerError::AgentProvisioningDisabled)
    }
}

/// Authenticate a `/agent/*` request: Bearer token → hash → active key row.
/// Touches `last_used_at` on success (audit trail).
fn authenticate_api_key<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    headers: &HeaderMap,
) -> Result<ApiKey, BrokerError> {
    require_enabled(state)?;
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(BrokerError::InvalidApiKey)?;
    let key = state
        .user_store
        .get_api_key_by_hash(&hash_api_key(token))?
        .ok_or(BrokerError::InvalidApiKey)?;
    if !key.is_active() {
        return Err(BrokerError::InvalidApiKey);
    }
    state.user_store.touch_api_key(key.id)?;
    Ok(key)
}

// ===========================================================================
// Browser-side: API-key management (/wsapi/*)
// ===========================================================================

#[derive(Serialize)]
pub struct AgentKeyInfo {
    pub id: u64,
    pub name: String,
    pub parent_email: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

#[derive(Serialize)]
pub struct ListAgentKeysResponse {
    pub success: bool,
    pub keys: Vec<AgentKeyInfo>,
}

/// GET /wsapi/agent_keys — list the session user's API keys (never secrets)
pub async fn list_agent_keys<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Result<Json<ListAgentKeysResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    require_enabled(&state)?;
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;

    let keys = state
        .user_store
        .list_api_keys(session.user_id)?
        .into_iter()
        .map(|k| AgentKeyInfo {
            id: k.id,
            name: k.name,
            parent_email: k.parent_email,
            created_at: k.created_at,
            last_used_at: k.last_used_at,
            revoked: k.revoked_at.is_some(),
        })
        .collect();

    Ok(Json(ListAgentKeysResponse { success: true, keys }))
}

#[derive(Deserialize)]
pub struct CreateAgentKeyRequest {
    pub csrf: String,
    pub name: String,
    /// Attribution root for identities minted with this key; must be a
    /// verified, non-agent email on the session user's account
    pub parent_email: String,
}

#[derive(Serialize)]
pub struct CreateAgentKeyResponse {
    pub success: bool,
    pub id: u64,
    pub name: String,
    /// The secret — returned exactly once, never stored or shown again
    pub api_key: String,
}

/// POST /wsapi/create_agent_key
pub async fn create_agent_key<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<CreateAgentKeyRequest>,
) -> Result<Json<CreateAgentKeyResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    require_enabled(&state)?;
    let session = require_session_csrf(&cookies, state.session_store.as_ref(), &req.csrf)?;

    let name = req.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(BrokerError::ValidationError(
            "key name must be 1-64 characters".to_string(),
        ));
    }

    // The attribution root must be a verified email the user owns, and must
    // itself be a human identity (chaining agents to agents would let one
    // leaked key mint an unattributable tree).
    let parent = state
        .user_store
        .get_email(&req.parent_email)?
        .ok_or(BrokerError::EmailNotFound)?;
    if parent.user_id != session.user_id {
        return Err(BrokerError::EmailNotFound);
    }
    if !parent.verified {
        return Err(BrokerError::EmailNotVerified);
    }
    if parent.email_type == EmailType::Agent {
        return Err(BrokerError::ValidationError(
            "parent_email cannot be an agent identity".to_string(),
        ));
    }

    let secret = generate_api_key_secret();
    let key = state.user_store.create_api_key(
        session.user_id,
        name,
        &parent.email,
        &hash_api_key(&secret),
    )?;

    Ok(Json(CreateAgentKeyResponse {
        success: true,
        id: key.id,
        name: key.name,
        api_key: secret,
    }))
}

#[derive(Deserialize)]
pub struct RevokeAgentKeyRequest {
    pub csrf: String,
    pub id: u64,
}

#[derive(Serialize)]
pub struct SuccessResponse {
    pub success: bool,
}

/// POST /wsapi/revoke_agent_key
pub async fn revoke_agent_key<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<RevokeAgentKeyRequest>,
) -> Result<Json<SuccessResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    require_enabled(&state)?;
    let session = require_session_csrf(&cookies, state.session_store.as_ref(), &req.csrf)?;
    state.user_store.revoke_api_key(session.user_id, req.id)?;
    Ok(Json(SuccessResponse { success: true }))
}

// ===========================================================================
// Agent-side: REST provisioning (/agent/*, Bearer-key gated)
// ===========================================================================

#[derive(Deserialize)]
pub struct CreateIdentityRequest {
    pub pubkey: PublicKeyJson,
    /// Desired local-part; server-generated when omitted
    pub name: Option<String>,
}

#[derive(Serialize)]
pub struct CreateIdentityResponse {
    pub success: bool,
    pub email: String,
    pub cert: String,
}

/// POST /agent/identities — mint (or idempotently re-provision) an agent
/// identity and issue a certificate for the presented pubkey
pub async fn create_identity<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: HeaderMap,
    Json(req): Json<CreateIdentityRequest>,
) -> Result<Json<CreateIdentityResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let key = authenticate_api_key(&state, &headers)?;

    let name = match &req.name {
        Some(n) => {
            let n = n.trim().to_lowercase();
            if !valid_agent_name(&n) {
                return Err(BrokerError::ValidationError(
                    "name must be 1-32 chars of [a-z0-9-], not starting/ending with '-'"
                        .to_string(),
                ));
            }
            n
        }
        None => generate_agent_name(),
    };
    // The identity's domain must equal the cert issuer (state.domain) exactly
    // — core chain verification requires issuer == email domain, and for
    // agent identities this broker is the authoritative primary. (In dev,
    // with a port in the domain, that yields e.g. `bot@localhost:3000`.)
    let email = format!("{}@{}", name, state.domain);

    let record = match state.user_store.get_email(&email)? {
        // Restart case: the identity already exists on this account — treat
        // create as a re-mint so agents don't need create-vs-remint logic.
        Some(rec) if rec.user_id == key.user_id && rec.email_type == EmailType::Agent => {
            if !rec.verified {
                // Revocation sticks; a revoked name cannot be silently revived
                return Err(BrokerError::EmailNotVerified);
            }
            rec
        }
        Some(_) => return Err(BrokerError::EmailAlreadyExists),
        None => {
            // Quota counts active identities — the attribution-based sybil limit
            let active = state
                .user_store
                .list_emails(key.user_id)?
                .iter()
                .filter(|e| e.email_type == EmailType::Agent && e.verified)
                .count();
            if active >= state.max_agent_identities_per_user {
                return Err(BrokerError::QuotaExceeded);
            }

            state
                .user_store
                .add_email_with_type(key.user_id, &email, true, EmailType::Agent)?;
            state
                .user_store
                .set_parent_email(&email, Some(&key.parent_email))?;
            state
                .user_store
                .get_email(&email)?
                .ok_or_else(|| BrokerError::Internal("identity vanished after insert".into()))?
        }
    };

    let cert = issue_certificate(&state.domain, &state.keypair, &record, &req.pubkey, false)?;

    tracing::info!(email = %record.email, parent = %key.parent_email, key_id = key.id,
        "Provisioned agent identity");

    Ok(Json(CreateIdentityResponse {
        success: true,
        email: record.email,
        cert,
    }))
}

#[derive(Serialize)]
pub struct AgentIdentityInfo {
    pub email: String,
    pub parent_email: Option<String>,
    /// false once revoked (re-mints will fail)
    pub active: bool,
    pub verified_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct ListIdentitiesResponse {
    pub success: bool,
    pub identities: Vec<AgentIdentityInfo>,
}

/// GET /agent/identities — list the account's agent identities
pub async fn list_identities<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: HeaderMap,
) -> Result<Json<ListIdentitiesResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let key = authenticate_api_key(&state, &headers)?;

    let identities = state
        .user_store
        .list_emails(key.user_id)?
        .into_iter()
        .filter(|e| e.email_type == EmailType::Agent)
        .map(|e| AgentIdentityInfo {
            email: e.email,
            parent_email: e.parent_email,
            active: e.verified,
            verified_at: e.verified_at,
        })
        .collect();

    Ok(Json(ListIdentitiesResponse {
        success: true,
        identities,
    }))
}

#[derive(Deserialize)]
pub struct AgentCertRequest {
    pub email: String,
    pub pubkey: PublicKeyJson,
    #[serde(default)]
    pub ephemeral: bool,
}

#[derive(Serialize)]
pub struct AgentCertResponse {
    pub success: bool,
    pub cert: String,
}

/// POST /agent/cert — re-mint a certificate for an existing agent identity.
/// The presented pubkey is what gets certified: the API key is the root
/// credential, so the agent keypair may rotate freely.
pub async fn agent_cert<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: HeaderMap,
    Json(req): Json<AgentCertRequest>,
) -> Result<Json<AgentCertResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let key = authenticate_api_key(&state, &headers)?;
    let record = owned_agent_email(&state, &key, &req.email)?;
    let cert = issue_certificate(
        &state.domain,
        &state.keypair,
        &record,
        &req.pubkey,
        req.ephemeral,
    )?;
    Ok(Json(AgentCertResponse { success: true, cert }))
}

#[derive(Deserialize)]
pub struct RevokeIdentityRequest {
    pub email: String,
}

/// POST /agent/identities/revoke — disable an agent identity. Re-mints fail
/// from now on; outstanding certs age out within their TTL.
pub async fn revoke_identity<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: HeaderMap,
    Json(req): Json<RevokeIdentityRequest>,
) -> Result<Json<SuccessResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let key = authenticate_api_key(&state, &headers)?;
    let record = owned_agent_email(&state, &key, &req.email)?;
    state.user_store.unverify_email(&record.email)?;
    tracing::info!(email = %record.email, key_id = key.id, "Revoked agent identity");
    Ok(Json(SuccessResponse { success: true }))
}

/// Resolve `email` to an agent identity owned by the API key's account.
/// Non-agent emails are invisible to `/agent/*` (an API key must never be
/// able to act on the human's own identities).
fn owned_agent_email<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    key: &ApiKey,
    email: &str,
) -> Result<crate::store::Email, BrokerError> {
    let record = state
        .user_store
        .get_email(email)?
        .ok_or(BrokerError::EmailNotFound)?;
    if record.user_id != key.user_id || record.email_type != EmailType::Agent {
        return Err(BrokerError::EmailNotFound);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_secret_shape_and_hash() {
        let s = generate_api_key_secret();
        assert!(s.starts_with(API_KEY_PREFIX));
        assert_eq!(hash_api_key(&s).len(), 64);
        assert_ne!(generate_api_key_secret(), s);
    }

    #[test]
    fn agent_name_validation() {
        assert!(valid_agent_name("checkpoint-attestor"));
        assert!(valid_agent_name("a"));
        assert!(valid_agent_name("agent-01"));
        assert!(!valid_agent_name(""));
        assert!(!valid_agent_name("-agent"));
        assert!(!valid_agent_name("agent-"));
        assert!(!valid_agent_name("Agent"));
        assert!(!valid_agent_name("a b"));
        assert!(!valid_agent_name(&"x".repeat(33)));
        assert!(valid_agent_name(&generate_agent_name()));
    }
}
