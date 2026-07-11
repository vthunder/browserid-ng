//! Warrant consent flow (agent spec §6, v0.4) + warrant registry (jipx) +
//! signed revocation status list (core §6.4). Unbundled from the broker per
//! 1pnf — this is the registrar's consent surface API.
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
use browserid_core::{StatusList, StatusListToken, Warrant};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_cookies::Cookies;

use crate::error::RegistrarError;
use crate::host::require_csrf;
use crate::models::{WarrantGrantItem, WarrantRecord, WarrantRequestRecord, WarrantRequestStatus};
use crate::registry::{require_enabled, require_session};
use crate::RegistrarState;

/// Pending consent requests expire unapproved after this long
const REQUEST_VALIDITY_SECONDS: i64 = 900;
/// Minimum seconds between polls of one code
const POLL_INTERVAL_SECONDS: i64 = 5;

/// The registrar's published status list URI (core §6.4)
pub fn status_list_uri(domain: &str) -> String {
    format!("{}/.well-known/browserid-status", public_origin(domain))
}

/// The composite status subject for one warrant grant. A grant's identity
/// is (audience, scopes) — two warrants may share an audience and differ
/// only in scopes (e85i) — so the subject carries the scope fingerprint.
pub fn warrant_status_subject(user_id: u64, agent: &str, aud: &str, scopes: &[String]) -> String {
    format!("{}|{}|{}|{}", user_id, agent, aud, scope_fingerprint(scopes))
}

/// Order-insensitive fingerprint of an opaque scope list (e85i). The
/// registrar never interprets scopes — it hashes them for keying: grant
/// identity, registry upserts, status subjects. Empty scopes hash too, so
/// "no scopes" is one stable identity.
pub fn scope_fingerprint(scopes: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut sorted: Vec<&str> = scopes.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let mut h = Sha256::new();
    for s in &sorted {
        h.update(s.as_bytes());
        h.update([0]);
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&h.finalize()[..16])
}

pub fn public_origin(domain: &str) -> String {
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
pub async fn request(
    State(state): State<Arc<RegistrarState>>,
    Json(req): Json<WarrantRequestBody>,
) -> Result<Json<WarrantRequestResponse>, RegistrarError> {
    require_enabled(&state)?;
    // Opportunistic sweep so expired rows don't accumulate.
    let _ = state.store.cleanup_expired_warrant_requests();

    let bundle = browserid_core::RequestBundle::parse(&req.request_bundle)
        .map_err(|e| RegistrarError::InvalidProvisioningRequest(e.to_string()))?;

    // Registry gate (same as endorse): registered + unrevoked, request signed
    // by P_priv and fresh.
    let p_pub = bundle.provisioning_cert().public_key().to_base64();
    let rec = state
        .store
        .get_provisioning_cert_by_pub(&p_pub)?
        .ok_or(RegistrarError::ProvisioningCertNotFound)?;
    if !rec.is_active() {
        return Err(RegistrarError::PolicyRefused(
            "provisioning certificate revoked".into(),
        ));
    }
    let request = bundle.request();
    request
        .verify(bundle.provisioning_cert().public_key())
        .map_err(|e| {
            RegistrarError::InvalidProvisioningRequest(format!("bad request signature: {e}"))
        })?;
    if request.is_expired() {
        return Err(RegistrarError::InvalidProvisioningRequest(
            "request expired".into(),
        ));
    }
    let claims = request.claims();
    if claims.action != Action::Warrant {
        return Err(RegistrarError::InvalidProvisioningRequest(
            "request action must be 'warrant'".into(),
        ));
    }
    if claims.domain != state.domain {
        return Err(RegistrarError::InvalidProvisioningRequest(
            "request domain does not target this registrar".into(),
        ));
    }
    let name = claims.name.as_deref().ok_or_else(|| {
        RegistrarError::InvalidProvisioningRequest("warrant request requires a name".into())
    })?;
    if !bundle.provisioning_cert().constraint().authorizes(name) {
        return Err(RegistrarError::PolicyRefused(format!(
            "'{name}' is not authorized by this key's constraint"
        )));
    }
    let grants = claims.warrant_grants.clone().unwrap_or_default();
    if grants.is_empty() || grants.len() > browserid_core::MAX_WARRANT_GRANTS {
        return Err(RegistrarError::InvalidProvisioningRequest(format!(
            "warrant request must carry 1..={} grants",
            browserid_core::MAX_WARRANT_GRANTS
        )));
    }
    let mut seen: Vec<(String, String)> = Vec::new();
    for g in &grants {
        // No wildcards, and no whitespace/control characters: the audience
        // is rendered verbatim on the consent page, where padding or
        // invisible characters could disguise what is being approved.
        if g.aud.is_empty()
            || g.aud.contains('*')
            || g.aud.len() > 512
            || g.aud.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(RegistrarError::InvalidProvisioningRequest(
                "each grant audience must be one exact identifier".into(),
            ));
        }
        let scopes = g.scopes.as_deref().unwrap_or_default();
        if scopes.len() > 32 || scopes.iter().any(|s| s.len() > 64) {
            return Err(RegistrarError::InvalidProvisioningRequest(
                "too many / too long scopes".into(),
            ));
        }
        // A grant's identity is (audience, scopes) — same audience with
        // different scopes is a legitimate pair of grants (e85i); an exact
        // duplicate is a malformed batch.
        let key = (g.aud.clone(), scope_fingerprint(scopes));
        if seen.contains(&key) {
            return Err(RegistrarError::InvalidProvisioningRequest(
                "duplicate grants (same audience and scopes)".into(),
            ));
        }
        seen.push(key);
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
        .ok_or_else(|| RegistrarError::Internal("registered bundle has no parseable U_cert".into()))?;
    let agent_email = format!("{name}@{idp_domain}");

    let code = new_code();
    let now = Utc::now();
    // One stable status index per grant (egr7): the consent page embeds it,
    // so each single warrant is revocable on its own.
    let mut grant_items = Vec::with_capacity(grants.len());
    for g in grants {
        let idx = state.store.get_or_allocate_status(
            "warrant",
            &warrant_status_subject(
                rec.user_id,
                &agent_email,
                &g.aud,
                g.scopes.as_deref().unwrap_or_default(),
            ),
        )?;
        grant_items.push(WarrantGrantItem {
            audience: g.aud,
            scopes: g.scopes.unwrap_or_default(),
            status_idx: Some(idx),
        });
    }
    state.store.create_warrant_request(WarrantRequestRecord {
        code: code.clone(),
        user_id: rec.user_id,
        delegator_email: rec.delegator_email.clone(),
        agent_email,
        label: rec.label.clone(),
        grants: grant_items,
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
pub async fn poll(
    State(state): State<Arc<RegistrarState>>,
    Json(req): Json<PollBody>,
) -> Response {
    if let Err(e) = require_enabled(&state) {
        return e.into_response();
    }

    let expired = || {
        (
            StatusCode::GONE,
            Json(json!({ "status": "expired" })),
        )
            .into_response()
    };

    let rec = match state.store.get_warrant_request(&req.code) {
        Ok(Some(rec)) => rec,
        // Unknown == expired == already delivered: indistinguishable.
        Ok(None) => return expired(),
        Err(e) => return e.into_response(),
    };

    if rec.is_expired() {
        let _ = state.store.delete_warrant_request(&req.code);
        return expired();
    }

    // Rate limit per code.
    match state.store.touch_warrant_poll(&req.code) {
        Ok(Some(prev)) if Utc::now() - prev < Duration::seconds(POLL_INTERVAL_SECONDS) => {
            return RegistrarError::PollTooFast.into_response();
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
            let _ = state.store.delete_warrant_request(&req.code);
            // `warrant` (singular) kept for single-grant compat.
            let single = (warrants.len() == 1).then(|| warrants[0].clone());
            Json(json!({ "status": "approved", "warrants": warrants, "warrant": single }))
                .into_response()
        }
        WarrantRequestStatus::Denied => {
            let _ = state.store.delete_warrant_request(&req.code);
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
    /// The registrar's status list URI — pages embed it (with each grant's
    /// `status_idx`) into the warrants they sign
    pub status_uri: String,
    pub requests: Vec<PendingRequestInfo>,
}

/// GET /wsapi/warrant_requests — the signed-in user's open consent requests
pub async fn list_requests(
    State(state): State<Arc<RegistrarState>>,
    cookies: Cookies,
) -> Result<Json<ListRequestsResponse>, RegistrarError> {
    require_enabled(&state)?;
    let user = require_session(&state, &cookies)?;
    let requests = state
        .store
        .list_pending_warrant_requests(user.user_id)?
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
    Ok(Json(ListRequestsResponse {
        success: true,
        status_uri: status_list_uri(&state.domain),
        requests,
    }))
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
/// origin; the registrar validates it against the pending request (right
/// agent, right audience, right delegator — no swapped-in grants) and stores
/// it for the single pickup.
pub async fn respond(
    State(state): State<Arc<RegistrarState>>,
    cookies: Cookies,
    Json(req): Json<RespondBody>,
) -> Result<Json<RespondResponse>, RegistrarError> {
    require_enabled(&state)?;
    let user = require_session(&state, &cookies)?;
    require_csrf(&user, &req.csrf)?;

    let rec = state
        .store
        .get_warrant_request(&req.code)?
        .ok_or(RegistrarError::WarrantRequestNotFound)?;
    if rec.user_id != user.user_id {
        return Err(RegistrarError::WarrantRequestNotFound);
    }

    if !req.approve {
        state
            .store
            .respond_warrant_request(user.user_id, &req.code, None)?;
        return Ok(Json(RespondResponse { success: true }));
    }

    // All-or-nothing: exactly one signed warrant per requested grant, in
    // grant order, each validated against its grant — no swapped-in grants.
    let warrant_jwss = req.warrants.as_deref().ok_or_else(|| {
        RegistrarError::ValidationError("approve requires the signed warrants".into())
    })?;
    if warrant_jwss.len() != rec.grants.len() {
        return Err(RegistrarError::ValidationError(format!(
            "expected {} warrants (one per grant), got {}",
            rec.grants.len(),
            warrant_jwss.len()
        )));
    }
    let mut records = Vec::with_capacity(warrant_jwss.len());
    for (jws, grant) in warrant_jwss.iter().zip(&rec.grants) {
        let warrant = Warrant::parse(jws)
            .map_err(|e| RegistrarError::ValidationError(format!("bad warrant: {e}")))?;
        if warrant.audience() != grant.audience {
            return Err(RegistrarError::ValidationError(
                "warrant audience does not match its grant".into(),
            ));
        }
        if warrant.agent() != rec.agent_email {
            return Err(RegistrarError::ValidationError(
                "warrant agent does not match the request".into(),
            ));
        }
        if !warrant.delegator().eq_ignore_ascii_case(&rec.delegator_email) {
            return Err(RegistrarError::ValidationError(
                "warrant delegator does not match the request".into(),
            ));
        }
        records.push(warrant_to_record(user.user_id, &warrant, jws));
    }

    state
        .store
        .respond_warrant_request(user.user_id, &req.code, Some(warrant_jwss))?;
    // Registry (jipx): the delegator's own reviewable record of each grant.
    for record in records {
        state.store.upsert_warrant(record)?;
    }
    tracing::info!(delegator = %rec.delegator_email, grants = rec.grants.len(),
        "warrant consent approved");
    Ok(Json(RespondResponse { success: true }))
}

// ===========================================================================
// Warrant registry (jipx): the delegator's own record of issued warrants
// ===========================================================================

fn warrant_to_record(user_id: u64, warrant: &Warrant, jws: &str) -> WarrantRecord {
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
        status_idx: warrant.status().map(|s| s.idx),
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
    /// Present iff the warrant carries a status claim (revocable per-grant)
    pub status_idx: Option<u64>,
    /// Whether this warrant's status bit is set (revoked, egr7)
    pub revoked: bool,
    pub signed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct ListWarrantsResponse {
    pub success: bool,
    pub warrants: Vec<WarrantInfo>,
}

/// GET /wsapi/warrants — the signed-in user's registered warrants
pub async fn list_warrants(
    State(state): State<Arc<RegistrarState>>,
    cookies: Cookies,
) -> Result<Json<ListWarrantsResponse>, RegistrarError> {
    require_enabled(&state)?;
    let user = require_session(&state, &cookies)?;
    let warrants = state
        .store
        .list_warrants(user.user_id)?
        .into_iter()
        .map(|r| {
            let revoked = r
                .status_idx
                .map(|i| state.store.is_status_revoked_idx(i).unwrap_or(false))
                .unwrap_or(false);
            WarrantInfo {
                id: r.id,
                delegator_email: r.delegator_email,
                agent_email: r.agent_email,
                audience: r.audience,
                scopes: r.scopes,
                warrant: r.warrant,
                status_idx: r.status_idx,
                revoked,
                signed_at: r.signed_at,
                expires_at: r.expires_at,
            }
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
pub async fn register_warrant(
    State(state): State<Arc<RegistrarState>>,
    cookies: Cookies,
    Json(req): Json<RegisterWarrantBody>,
) -> Result<Json<RespondResponse>, RegistrarError> {
    require_enabled(&state)?;
    let user = require_session(&state, &cookies)?;
    require_csrf(&user, &req.csrf)?;
    let warrant = Warrant::parse(&req.warrant)
        .map_err(|e| RegistrarError::ValidationError(format!("bad warrant: {e}")))?;
    if !state
        .host
        .owns_verified_email(user.user_id, warrant.delegator())?
    {
        return Err(RegistrarError::ValidationError(
            "the warrant's delegator is not a verified email on this account".into(),
        ));
    }
    state
        .store
        .upsert_warrant(warrant_to_record(user.user_id, &warrant, &req.warrant))?;
    Ok(Json(RespondResponse { success: true }))
}

#[derive(Deserialize)]
pub struct ForgetWarrantBody {
    pub csrf: String,
    pub id: u64,
}

/// POST /wsapi/forget_warrant — drop a registry row. The signed warrant the
/// agent holds stays valid until it expires; per-warrant revocation is
/// `revoke_warrant` (status bit).
pub async fn forget_warrant(
    State(state): State<Arc<RegistrarState>>,
    cookies: Cookies,
    Json(req): Json<ForgetWarrantBody>,
) -> Result<Json<RespondResponse>, RegistrarError> {
    require_enabled(&state)?;
    let user = require_session(&state, &cookies)?;
    require_csrf(&user, &req.csrf)?;
    state.store.delete_warrant(user.user_id, req.id)?;
    Ok(Json(RespondResponse { success: true }))
}

#[derive(Deserialize)]
pub struct AllocateStatusBody {
    pub csrf: String,
    pub agent_email: String,
    pub audience: String,
    /// The grant's scopes — part of its identity (e85i)
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Serialize)]
pub struct AllocateStatusResponse {
    pub success: bool,
    pub uri: String,
    pub idx: u64,
}

/// POST /wsapi/allocate_warrant_status — the manual-signing/reissue surfaces
/// fetch (or re-fetch — stable per grant) the status index to embed before
/// signing.
pub async fn allocate_warrant_status(
    State(state): State<Arc<RegistrarState>>,
    cookies: Cookies,
    Json(req): Json<AllocateStatusBody>,
) -> Result<Json<AllocateStatusResponse>, RegistrarError> {
    require_enabled(&state)?;
    let user = require_session(&state, &cookies)?;
    require_csrf(&user, &req.csrf)?;
    if req.audience.is_empty()
        || req.audience.contains('*')
        || req.audience.len() > 512
        || req.audience.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(RegistrarError::ValidationError("bad audience".into()));
    }
    let idx = state.store.get_or_allocate_status(
        "warrant",
        &warrant_status_subject(user.user_id, &req.agent_email, &req.audience, &req.scopes),
    )?;
    Ok(Json(AllocateStatusResponse {
        success: true,
        uri: status_list_uri(&state.domain),
        idx,
    }))
}

#[derive(Deserialize)]
pub struct RevokeWarrantBody {
    pub csrf: String,
    pub id: u64,
}

/// POST /wsapi/revoke_warrant — set the grant's status bit: the warrant (and
/// any reissue sharing its index) dies at status-checking verifiers within
/// one cache window, leaving the agent's other grants intact. The registry
/// row is kept (marked by its bit) so the account view still shows it.
pub async fn revoke_warrant(
    State(state): State<Arc<RegistrarState>>,
    cookies: Cookies,
    Json(req): Json<RevokeWarrantBody>,
) -> Result<Json<RespondResponse>, RegistrarError> {
    require_enabled(&state)?;
    let user = require_session(&state, &cookies)?;
    require_csrf(&user, &req.csrf)?;
    let record = state
        .store
        .list_warrants(user.user_id)?
        .into_iter()
        .find(|r| r.id == req.id)
        .ok_or(RegistrarError::WarrantRequestNotFound)?;
    let idx = record.status_idx.ok_or_else(|| {
        RegistrarError::ValidationError(
            "this warrant predates status lists — reissue it (which replaces it) or revoke the agent key".into(),
        )
    })?;
    state.store.set_status_revoked_idx(idx)?;
    tracing::info!(delegator = %record.delegator_email, audience = %record.audience,
        "warrant revoked (status bit set)");
    Ok(Json(RespondResponse { success: true }))
}

/// GET /.well-known/browserid-status — the registrar's signed status list
/// (core §6.4). Rebuilt per request: the bitmap is tiny and Ed25519 signing
/// is cheap; `iat` is always fresh and consumers cache per `ttl`.
pub async fn status_list(
    State(state): State<Arc<RegistrarState>>,
) -> Result<String, RegistrarError> {
    let (revoked, max) = state.store.revoked_status_indices()?;
    let list = StatusList::from_revoked(revoked, max);
    let token = StatusListToken::create(
        &state.domain,
        &status_list_uri(&state.domain),
        &list,
        &state.keypair,
    )
    .map_err(|e| RegistrarError::Internal(format!("status list sign: {e}")))?;
    Ok(token.encoded().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_fingerprint_is_order_insensitive_and_distinct() {
        let a = scope_fingerprint(&["post".into(), "read".into()]);
        let b = scope_fingerprint(&["read".into(), "post".into()]);
        assert_eq!(a, b, "scope order must not matter");
        assert_ne!(a, scope_fingerprint(&["read".into()]));
        assert_ne!(scope_fingerprint(&[]), scope_fingerprint(&["read".into()]));
        // Concatenation must not collide with a differently-split list.
        assert_ne!(
            scope_fingerprint(&["ab".into(), "c".into()]),
            scope_fingerprint(&["a".into(), "bc".into()])
        );
    }

    #[test]
    fn status_subject_carries_the_grant_identity() {
        let base = warrant_status_subject(7, "a@x", "https://rp", &[]);
        let scoped = warrant_status_subject(7, "a@x", "https://rp", &["post".into()]);
        assert_ne!(base, scoped, "same audience, different scopes = different grant");
    }
}
