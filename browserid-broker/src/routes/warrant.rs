//! Warrant consent flow (agent spec §6, v0.4).
//!
//! Warrants are requested, not configured: an agent that hits an RP's
//! `WWW-Authenticate` challenge raises a **consent request** here (its
//! registrar), the delegator approves on the consent page — which signs the
//! warrant client-side with the identity key held in this origin — and the
//! agent polls the result (RFC 8628 shape).
//!
//! The pending request (the poll code) is single-delivery and deleted on
//! handover; the issued warrants are retained in the per-delegator warrant
//! registry (§6.4 as revised by jipx) — the delegator's own reviewable
//! record, and the substrate for per-warrant revocation (egr7).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use browserid_core::provisioning::Action;
use browserid_core::Warrant;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{
    SessionStore, UserStore, WarrantGrantItem, WarrantRecord, WarrantRequestRecord,
    WarrantRequestStatus,
};

/// Pending consent requests expire unapproved after this long
const REQUEST_VALIDITY_SECONDS: i64 = 900;
/// Minimum seconds between polls of one code
const POLL_INTERVAL_SECONDS: i64 = 5;

fn public_origin(domain: &str) -> String {
    if domain.starts_with("localhost") || domain.starts_with("127.") {
        format!("http://{domain}")
    } else {
        format!("https://{domain}")
    }
}

fn new_code() -> String {
    // ≥128-bit single-delivery bearer (spec §6.4); 32 bytes to be generous.
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!(
        "wrq_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

// ===========================================================================
// Agent-facing: POST /warrant/request + /warrant/poll
// ===========================================================================

#[derive(Deserialize)]
pub struct WarrantRequestBody {
    pub request_bundle: String,
}

#[derive(Serialize)]
pub struct WarrantRequestResponse {
    pub success: bool,
    pub code: String,
    pub verification_uri: String,
    pub expires_in: i64,
    pub interval: i64,
}

/// POST /warrant/request — an agent (holding a registered provisioning
/// credential) asks its delegator to approve a warrant for one RP audience.
/// Verified exactly like `/provision/endorse`: the signed bundle against the
/// registry; the registry is the gate.
pub async fn request<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<WarrantRequestBody>,
) -> Result<Json<WarrantRequestResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    if !state.agent_provisioning_enabled {
        return Err(BrokerError::AgentProvisioningDisabled);
    }
    // Opportunistic sweep so expired rows don't accumulate.
    let _ = state.user_store.cleanup_expired_warrant_requests();

    let bundle = browserid_core::RequestBundle::parse(&req.request_bundle)
        .map_err(|e| BrokerError::InvalidProvisioningRequest(e.to_string()))?;

    // Registry gate (same as endorse): registered + unrevoked, request signed
    // by P_priv and fresh.
    let p_pub = bundle.provisioning_cert().public_key().to_base64();
    let rec = state
        .user_store
        .get_provisioning_cert_by_pub(&p_pub)?
        .ok_or(BrokerError::ProvisioningCertNotFound)?;
    if !rec.is_active() {
        return Err(BrokerError::PolicyRefused(
            "provisioning certificate revoked".into(),
        ));
    }
    let request = bundle.request();
    request
        .verify(bundle.provisioning_cert().public_key())
        .map_err(|e| {
            BrokerError::InvalidProvisioningRequest(format!("bad request signature: {e}"))
        })?;
    if request.is_expired() {
        return Err(BrokerError::InvalidProvisioningRequest(
            "request expired".into(),
        ));
    }
    let claims = request.claims();
    if claims.action != Action::Warrant {
        return Err(BrokerError::InvalidProvisioningRequest(
            "request action must be 'warrant'".into(),
        ));
    }
    if claims.domain != state.domain {
        return Err(BrokerError::InvalidProvisioningRequest(
            "request domain does not target this registrar".into(),
        ));
    }
    let name = claims.name.as_deref().ok_or_else(|| {
        BrokerError::InvalidProvisioningRequest("warrant request requires a name".into())
    })?;
    if !bundle.provisioning_cert().constraint().authorizes(name) {
        return Err(BrokerError::PolicyRefused(format!(
            "'{name}' is not authorized by this key's constraint"
        )));
    }
    let grants = claims.warrant_grants.clone().unwrap_or_default();
    if grants.is_empty() || grants.len() > browserid_core::MAX_WARRANT_GRANTS {
        return Err(BrokerError::InvalidProvisioningRequest(format!(
            "warrant request must carry 1..={} grants",
            browserid_core::MAX_WARRANT_GRANTS
        )));
    }
    let mut seen_auds: Vec<&str> = Vec::new();
    for g in &grants {
        if g.aud.is_empty() || g.aud.contains('*') || g.aud.len() > 512 {
            return Err(BrokerError::InvalidProvisioningRequest(
                "each grant audience must be one exact identifier".into(),
            ));
        }
        if seen_auds.contains(&g.aud.as_str()) {
            return Err(BrokerError::InvalidProvisioningRequest(
                "duplicate grant audiences".into(),
            ));
        }
        seen_auds.push(&g.aud);
        let scopes = g.scopes.as_deref().unwrap_or_default();
        if scopes.len() > 32 || scopes.iter().any(|s| s.len() > 64) {
            return Err(BrokerError::InvalidProvisioningRequest(
                "too many / too long scopes".into(),
            ));
        }
    }

    // The agent's identity domain is the domain of the IdP that roots the
    // delegator (identity-domain rule) — the registered U_cert's issuer.
    // (For a broker-rooted `alice@gmail.com`, that's the broker's domain,
    // not gmail.com.)
    let idp_domain = rec
        .bundle
        .split_once('~')
        .and_then(|(u, _)| browserid_core::Certificate::parse(u).ok())
        .map(|u| u.issuer().to_string())
        .ok_or_else(|| BrokerError::Internal("registered bundle has no parseable U_cert".into()))?;
    let agent_email = format!("{name}@{idp_domain}");

    let code = new_code();
    let now = Utc::now();
    state.user_store.create_warrant_request(WarrantRequestRecord {
        code: code.clone(),
        user_id: rec.user_id,
        delegator_email: rec.delegator_email.clone(),
        agent_email,
        label: rec.label.clone(),
        grants: grants
            .into_iter()
            .map(|g| WarrantGrantItem {
                audience: g.aud,
                scopes: g.scopes.unwrap_or_default(),
            })
            .collect(),
        status: WarrantRequestStatus::Pending,
        warrants: None,
        created_at: now,
        expires_at: now + Duration::seconds(REQUEST_VALIDITY_SECONDS),
        last_polled_at: None,
    })?;

    tracing::info!(delegator = %rec.delegator_email, "created warrant consent request");
    Ok(Json(WarrantRequestResponse {
        success: true,
        verification_uri: format!("{}/consent/{}", public_origin(&state.domain), code),
        code,
        expires_in: REQUEST_VALIDITY_SECONDS,
        interval: POLL_INTERVAL_SECONDS,
    }))
}

#[derive(Deserialize)]
pub struct PollBody {
    pub code: String,
}

/// POST /warrant/poll — the agent's pickup. Single delivery: the row (and
/// with it the audience/scope data) is deleted the moment the warrant — or
/// the denial — is handed over.
pub async fn poll<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<PollBody>,
) -> Response
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    if !state.agent_provisioning_enabled {
        return BrokerError::AgentProvisioningDisabled.into_response();
    }

    let expired = || {
        (
            StatusCode::GONE,
            Json(json!({ "status": "expired" })),
        )
            .into_response()
    };

    let rec = match state.user_store.get_warrant_request(&req.code) {
        Ok(Some(rec)) => rec,
        // Unknown == expired == already delivered: indistinguishable.
        Ok(None) => return expired(),
        Err(e) => return e.into_response(),
    };

    if rec.is_expired() {
        let _ = state.user_store.delete_warrant_request(&req.code);
        return expired();
    }

    // Rate limit per code.
    match state.user_store.touch_warrant_poll(&req.code) {
        Ok(Some(prev)) if Utc::now() - prev < Duration::seconds(POLL_INTERVAL_SECONDS) => {
            return BrokerError::PollTooFast.into_response();
        }
        Err(e) => return e.into_response(),
        _ => {}
    }

    match rec.status {
        WarrantRequestStatus::Pending => {
            Json(json!({ "status": "pending" })).into_response()
        }
        WarrantRequestStatus::Approved => {
            let warrants = rec.warrants.clone().unwrap_or_default();
            let _ = state.user_store.delete_warrant_request(&req.code);
            // `warrant` (singular) kept for single-grant compat.
            let single = (warrants.len() == 1).then(|| warrants[0].clone());
            Json(json!({ "status": "approved", "warrants": warrants, "warrant": single }))
                .into_response()
        }
        WarrantRequestStatus::Denied => {
            let _ = state.user_store.delete_warrant_request(&req.code);
            Json(json!({ "status": "denied" })).into_response()
        }
    }
}

// ===========================================================================
// Browser-facing: the consent page's API (session + CSRF)
// ===========================================================================

#[derive(Serialize)]
pub struct PendingRequestInfo {
    pub code: String,
    pub delegator_email: String,
    pub agent_email: String,
    pub label: String,
    /// Requested grants — one per audience, each with its scopes
    pub grants: Vec<WarrantGrantItem>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct ListRequestsResponse {
    pub success: bool,
    pub requests: Vec<PendingRequestInfo>,
}

/// GET /wsapi/warrant_requests — the signed-in user's open consent requests
pub async fn list_requests<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Result<Json<ListRequestsResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    if !state.agent_provisioning_enabled {
        return Err(BrokerError::AgentProvisioningDisabled);
    }
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    let requests = state
        .user_store
        .list_pending_warrant_requests(session.user_id)?
        .into_iter()
        .map(|r| PendingRequestInfo {
            code: r.code,
            delegator_email: r.delegator_email,
            agent_email: r.agent_email,
            label: r.label,
            grants: r.grants,
            created_at: r.created_at,
            expires_at: r.expires_at,
        })
        .collect();
    Ok(Json(ListRequestsResponse { success: true, requests }))
}

#[derive(Deserialize)]
pub struct RespondBody {
    pub csrf: String,
    pub code: String,
    pub approve: bool,
    /// The warrant JWSs the consent page signed client-side, one per grant
    /// in the request's grant order (approve only)
    pub warrants: Option<Vec<String>>,
}

#[derive(Serialize)]
pub struct RespondResponse {
    pub success: bool,
}

/// POST /wsapi/warrant_respond — resolve a pending request. On approve, the
/// page has already signed the warrant with the identity key held in this
/// origin; the broker validates it against the pending request (right agent,
/// right audience, right delegator — no swapped-in grants) and stores it for
/// the single pickup.
pub async fn respond<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<RespondBody>,
) -> Result<Json<RespondResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    if !state.agent_provisioning_enabled {
        return Err(BrokerError::AgentProvisioningDisabled);
    }
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    if session.csrf_token != req.csrf {
        return Err(BrokerError::InvalidCsrf);
    }

    let rec = state
        .user_store
        .get_warrant_request(&req.code)?
        .ok_or(BrokerError::WarrantRequestNotFound)?;
    if rec.user_id != session.user_id {
        return Err(BrokerError::WarrantRequestNotFound);
    }

    if !req.approve {
        state
            .user_store
            .respond_warrant_request(session.user_id, &req.code, None)?;
        return Ok(Json(RespondResponse { success: true }));
    }

    // All-or-nothing: exactly one signed warrant per requested grant, in
    // grant order, each validated against its grant — no swapped-in grants.
    let warrant_jwss = req.warrants.as_deref().ok_or_else(|| {
        BrokerError::ValidationError("approve requires the signed warrants".into())
    })?;
    if warrant_jwss.len() != rec.grants.len() {
        return Err(BrokerError::ValidationError(format!(
            "expected {} warrants (one per grant), got {}",
            rec.grants.len(),
            warrant_jwss.len()
        )));
    }
    let mut records = Vec::with_capacity(warrant_jwss.len());
    for (jws, grant) in warrant_jwss.iter().zip(&rec.grants) {
        let warrant = Warrant::parse(jws)
            .map_err(|e| BrokerError::ValidationError(format!("bad warrant: {e}")))?;
        if warrant.audience() != grant.audience {
            return Err(BrokerError::ValidationError(
                "warrant audience does not match its grant".into(),
            ));
        }
        if warrant.agent() != rec.agent_email {
            return Err(BrokerError::ValidationError(
                "warrant agent does not match the request".into(),
            ));
        }
        if !warrant.delegator().eq_ignore_ascii_case(&rec.delegator_email) {
            return Err(BrokerError::ValidationError(
                "warrant delegator does not match the request".into(),
            ));
        }
        records.push(warrant_to_record(session.user_id, &warrant, jws));
    }

    state
        .user_store
        .respond_warrant_request(session.user_id, &req.code, Some(warrant_jwss))?;
    // Registry (jipx): the delegator's own reviewable record of each grant.
    for record in records {
        state.user_store.upsert_warrant(record)?;
    }
    tracing::info!(delegator = %rec.delegator_email, grants = rec.grants.len(),
        "warrant consent approved");
    Ok(Json(RespondResponse { success: true }))
}

// ===========================================================================
// Warrant registry (jipx): the delegator's own record of issued warrants
// ===========================================================================

fn warrant_to_record(
    user_id: crate::store::UserId,
    warrant: &Warrant,
    jws: &str,
) -> WarrantRecord {
    let claims = warrant.claims();
    let ts = |secs: i64| DateTime::from_timestamp(secs, 0).unwrap_or_else(Utc::now);
    WarrantRecord {
        id: 0, // assigned by the store
        user_id,
        delegator_email: warrant.delegator().to_string(),
        agent_email: warrant.agent().to_string(),
        audience: warrant.audience().to_string(),
        scopes: claims.scopes.clone().unwrap_or_default(),
        warrant: jws.to_string(),
        signed_at: ts(claims.iat),
        expires_at: ts(claims.exp),
    }
}

#[derive(Serialize)]
pub struct WarrantInfo {
    pub id: u64,
    pub delegator_email: String,
    pub agent_email: String,
    pub audience: String,
    pub scopes: Vec<String>,
    /// The signed JWS — the delegator's own copy (paste into an agent)
    pub warrant: String,
    pub signed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct ListWarrantsResponse {
    pub success: bool,
    pub warrants: Vec<WarrantInfo>,
}

/// GET /wsapi/warrants — the signed-in user's registered warrants
pub async fn list_warrants<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Result<Json<ListWarrantsResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    if !state.agent_provisioning_enabled {
        return Err(BrokerError::AgentProvisioningDisabled);
    }
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    let warrants = state
        .user_store
        .list_warrants(session.user_id)?
        .into_iter()
        .map(|r| WarrantInfo {
            id: r.id,
            delegator_email: r.delegator_email,
            agent_email: r.agent_email,
            audience: r.audience,
            scopes: r.scopes,
            warrant: r.warrant,
            signed_at: r.signed_at,
            expires_at: r.expires_at,
        })
        .collect();
    Ok(Json(ListWarrantsResponse { success: true, warrants }))
}

#[derive(Deserialize)]
pub struct RegisterWarrantBody {
    pub csrf: String,
    /// A warrant JWS signed client-side (manual card / reissue)
    pub warrant: String,
}

/// POST /wsapi/register_warrant — record a warrant signed outside the
/// consent flow (manual signing, reissue). The delegator must be a verified
/// email on this account; the JWS itself is the user-signed authorization.
pub async fn register_warrant<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<RegisterWarrantBody>,
) -> Result<Json<RespondResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    if !state.agent_provisioning_enabled {
        return Err(BrokerError::AgentProvisioningDisabled);
    }
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    if session.csrf_token != req.csrf {
        return Err(BrokerError::InvalidCsrf);
    }
    let warrant = Warrant::parse(&req.warrant)
        .map_err(|e| BrokerError::ValidationError(format!("bad warrant: {e}")))?;
    let owns = state
        .user_store
        .list_emails(session.user_id)?
        .iter()
        .any(|e| e.email.eq_ignore_ascii_case(warrant.delegator()) && e.verified);
    if !owns {
        return Err(BrokerError::ValidationError(
            "the warrant's delegator is not a verified email on this account".into(),
        ));
    }
    state
        .user_store
        .upsert_warrant(warrant_to_record(session.user_id, &warrant, &req.warrant))?;
    Ok(Json(RespondResponse { success: true }))
}

#[derive(Deserialize)]
pub struct ForgetWarrantBody {
    pub csrf: String,
    pub id: u64,
}

/// POST /wsapi/forget_warrant — drop a registry row. The signed warrant the
/// agent holds stays valid until it expires; per-warrant revocation arrives
/// with certificate status lists (egr7).
pub async fn forget_warrant<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<ForgetWarrantBody>,
) -> Result<Json<RespondResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    if !state.agent_provisioning_enabled {
        return Err(BrokerError::AgentProvisioningDisabled);
    }
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    if session.csrf_token != req.csrf {
        return Err(BrokerError::InvalidCsrf);
    }
    state.user_store.delete_warrant(session.user_id, req.id)?;
    Ok(Json(RespondResponse { success: true }))
}
