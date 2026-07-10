//! Warrant consent flow (agent spec §6, v0.4).
//!
//! Warrants are requested, not configured: an agent that hits an RP's
//! `WWW-Authenticate` challenge raises a **consent request** here (its
//! registrar), the delegator approves on the consent page — which signs the
//! warrant client-side with the identity key held in this origin — and the
//! agent polls the result (RFC 8628 shape).
//!
//! Privacy (§6.4): the audience and scopes live only in the pending request;
//! the row is deleted on delivery (or denial), so the broker retains no
//! record of where warrants apply.

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
use crate::store::{SessionStore, UserStore, WarrantRequestRecord, WarrantRequestStatus};

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
    let audience = claims.warrant_aud.as_deref().ok_or_else(|| {
        BrokerError::InvalidProvisioningRequest("warrant request requires warrant-aud".into())
    })?;
    if audience.is_empty() || audience.contains('*') || audience.len() > 512 {
        return Err(BrokerError::InvalidProvisioningRequest(
            "warrant-aud must be one exact origin".into(),
        ));
    }
    let scopes = claims.warrant_scopes.clone().unwrap_or_default();
    if scopes.len() > 32 || scopes.iter().any(|s| s.len() > 64) {
        return Err(BrokerError::InvalidProvisioningRequest(
            "too many / too long scopes".into(),
        ));
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
        audience: audience.to_string(),
        scopes,
        status: WarrantRequestStatus::Pending,
        warrant: None,
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
            let warrant = rec.warrant.clone().unwrap_or_default();
            let _ = state.user_store.delete_warrant_request(&req.code);
            Json(json!({ "status": "approved", "warrant": warrant })).into_response()
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
    pub audience: String,
    pub scopes: Vec<String>,
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
            audience: r.audience,
            scopes: r.scopes,
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
    /// The warrant JWS the consent page signed client-side (approve only)
    pub warrant: Option<String>,
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

    let warrant_jws = req.warrant.as_deref().ok_or_else(|| {
        BrokerError::ValidationError("approve requires the signed warrant".into())
    })?;
    let warrant = Warrant::parse(warrant_jws)
        .map_err(|e| BrokerError::ValidationError(format!("bad warrant: {e}")))?;
    if warrant.audience() != rec.audience {
        return Err(BrokerError::ValidationError(
            "warrant audience does not match the request".into(),
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

    state
        .user_store
        .respond_warrant_request(session.user_id, &req.code, Some(warrant_jws))?;
    tracing::info!(delegator = %rec.delegator_email, "warrant consent approved");
    Ok(Json(RespondResponse { success: true }))
}
