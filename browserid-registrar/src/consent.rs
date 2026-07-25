//! Warrant consent flow (device-cert model) + warrant registry (jipx) +
//! signed revocation status list (core §6.4). Unbundled from the broker per
//! 1pnf — this is the registrar's consent surface API.
//!
//! Warrants are requested, not configured: an agent that hits an RP's
//! `WWW-Authenticate` challenge raises a **consent request** here
//! (`POST /warrant/request`, authenticated by its IdP-signed agent device
//! cert), the delegator approves on the consent page — which signs each
//! warrant client-side with the **config (authorization) device cert** held
//! in this origin's keystore — and the agent polls the result
//! (`POST /warrant/poll`, RFC 8628 shape), receiving `warrant~config_cert`
//! pairs it presents inside the 4-object access presentation.
//!
//! The pending request (the poll code) is single-delivery and deleted on
//! handover; the issued warrants are retained in the per-delegator warrant
//! registry (§6.4 as revised by jipx) — the delegator's own reviewable
//! record, and the substrate for per-warrant revocation (egr7).

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use base64::Engine;
use browserid_core::device::{DeviceCert, Purpose, Warrant};
use browserid_core::{StatusList, StatusListToken};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::error::RegistrarError;
use crate::host::require_csrf;
use crate::models::{WarrantGrantItem, WarrantRecord, WarrantRequestRecord, WarrantRequestStatus};
use crate::registry::{require_enabled, require_session};
use crate::RegistrarState;

/// How long a pending consent request lives before it expires.
const REQUEST_TTL_MINUTES: i64 = 15;
/// Minimum seconds between polls on one code.
const POLL_INTERVAL_SECONDS: i64 = 5;

/// The delegator (account identity) behind an agent identity: the local part
/// with any `+tag` sub-address stripped. `danmills+claude@sandmill.org` →
/// `danmills@sandmill.org`; a bare identity maps to itself.
pub fn delegator_of(identity: &str) -> String {
    match identity.split_once('@') {
        Some((local, domain)) => {
            let base = local.split('+').next().unwrap_or(local);
            format!("{base}@{domain}")
        }
        None => identity.to_string(),
    }
}

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
/// Mint an opaque holder id under a namespace prefix: `<prefix>.<10 rand>`.
/// Mirrors the broker's `crypto::assign_holder_id` (kept here so the registrar
/// doesn't depend on the broker crate). The requester never chooses the prefix.
pub fn assign_holder_id(prefix: &str) -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    let suffix: String = (0..10)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect();
    format!("{prefix}.{suffix}")
}

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

// ===========================================================================
// Browser-facing: the consent page's API (session + CSRF)
// ===========================================================================

#[derive(Serialize)]
pub struct PendingRequestInfo {
    pub code: String,
    pub delegator_email: String,
    pub agent_email: String,
    /// The agent's opaque holder id — the consent page defaults the signed
    /// warrant's matcher to this (`<id>` isolation) or its `<ns>.*` prefix.
    pub holder: String,
    pub label: String,
    /// Requested grants — one per audience, each with its scopes
    pub grants: Vec<WarrantGrantItem>,
    /// External request (§6.6) — raised by a foreign-IdP service, not one
    /// of the account's own agents; the page words the ask accordingly
    pub external: bool,
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

#[derive(Deserialize)]
pub struct ListRequestsQuery {
    /// Deep-linked code from `/consent/<code>` — the only way an external
    /// request is ever surfaced (redirect-tied, §6.6)
    pub code: Option<String>,
}

/// GET /wsapi/warrant_requests — the signed-in user's open consent requests.
///
/// Own-agent requests are always listed (the page shows the user's whole
/// pending queue, as it always has). External requests are redirect-tied:
/// reachable only through the `/consent/<code>` link the requesting service
/// sent the user to, so one is surfaced only when its `code` is passed —
/// an unsolicited external request is never browsable and just expires.
pub async fn list_requests(
    State(state): State<Arc<RegistrarState>>,
    cookies: Cookies,
    axum::extract::Query(query): axum::extract::Query<ListRequestsQuery>,
) -> Result<Json<ListRequestsResponse>, RegistrarError> {
    require_enabled(&state)?;
    let user = require_session(&state, &cookies)?;
    let requests = state
        .store
        .list_pending_warrant_requests(user.user_id)?
        .into_iter()
        .filter(|r| !r.external || query.code.as_deref() == Some(r.code.as_str()))
        .map(|r| PendingRequestInfo {
            code: r.code,
            delegator_email: r.delegator_email,
            agent_email: r.agent_email,
            holder: r.holder,
            label: r.label,
            grants: r.grants,
            external: r.external,
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
    /// The warrant JWSs the consent page signed client-side with the config
    /// key, one per grant in the request's grant order (approve only)
    pub warrants: Option<Vec<String>>,
    /// The config (authorization) device cert whose key signed the warrants
    /// (approve only) — stored + delivered with them; the agent presents it
    /// as the 4th object of the access presentation
    pub config_cert: Option<String>,
    /// The warrant GRANTOR the page signed with — who the actions are
    /// attributed to. Absent = the agent itself (grantor == grantee, the
    /// original shape). A named grantor must be an identity this account
    /// owns: the consent page uses it to keep an on-behalf agent on-behalf
    /// (grantor = the human) instead of silently collapsing both roles.
    pub grantor: Option<String>,
}

#[derive(Serialize)]
pub struct RespondResponse {
    pub success: bool,
}

/// POST /wsapi/warrant_respond — resolve a pending request. On approve, the
/// page has already signed each warrant with the config (authorization)
/// device key held in this origin's keystore; the registrar validates them
/// against the pending request (right agent identity, right audience, signed
/// by the presented config cert — no swapped-in grants) and stores
/// `warrant~config_cert` pairs for the single pickup.
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
    let config_jws = req.config_cert.as_deref().ok_or_else(|| {
        RegistrarError::ValidationError("approve requires the signing config cert".into())
    })?;
    // The grantee (actor) is always the requesting agent. The grantor
    // (attributed identity) defaults to the agent too — the original as-you
    // shape — but the page may name one of the account's own identities so a
    // later grant matches how the agent was authorized (on-behalf, bean 8v6c).
    let grantor = match req.grantor.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => rec.agent_email.clone(),
        Some(g) => {
            let g = g.to_lowercase();
            if g != rec.agent_email
                && !state.host.owns_verified_email(user.user_id, &delegator_of(&g))?
            {
                return Err(RegistrarError::ValidationError(
                    "the warrant grantor must be the agent or an identity on this account".into(),
                ));
            }
            g
        }
    };
    let warrants = validate_grant_warrants(
        warrant_jwss, config_jws, &grantor, &rec.agent_email, &rec.holder, &rec.grants,
    )?;
    let records: Vec<WarrantRecord> = warrants
        .iter()
        .zip(warrant_jwss)
        .map(|(warrant, jws)| {
            warrant_to_record(user.user_id, &rec.delegator_email, warrant, jws, config_jws)
        })
        .collect();

    // Single-delivery payload: each entry is `warrant~config_cert`, the exact
    // tail the agent splices into its access presentations.
    let delivery: Vec<String> = warrant_jwss
        .iter()
        .map(|w| format!("{w}~{config_jws}"))
        .collect();
    state
        .store
        .respond_warrant_request(user.user_id, &req.code, Some(&delivery))?;
    // Registry (jipx): the delegator's own reviewable record of each grant.
    for record in records {
        state.store.upsert_warrant(record)?;
    }
    tracing::info!(delegator = %rec.delegator_email, grants = rec.grants.len(),
        "warrant consent approved");
    Ok(Json(RespondResponse { success: true }))
}

/// Validate a consent approval's client-signed warrants against the requested
/// grants — shared by the warrant consent flow (`respond`) and the merged
/// agent-provisioning approval (`agent_provision::complete`). All-or-nothing,
/// grant order: the config cert must be a live authorization cert covering the
/// agent identity and must have signed each warrant; each warrant must match
/// its grant's audience and name the agent identity.
///
/// (holder-authorization model) The old "warrant subject must be 'agent'" gate
/// is gone — the user/agent axis was a self-asserted hint. The warrant is bound
/// to the agent by its `identifier` and by its holder matcher: a bare `*` is
/// rejected (over-broad, fungible across all the user's holders) and the
/// matcher must actually cover the agent's holder (`<id>` isolation, or its
/// `<ns>.*` prefix) — defense-in-depth against a malformed or over-broad
/// consent. Returns the parsed warrants in grant order.
pub(crate) fn validate_grant_warrants(
    warrant_jwss: &[String],
    config_jws: &str,
    grantor: &str,
    grantee: &str,
    agent_holder: &str,
    grants: &[WarrantGrantItem],
) -> Result<Vec<Warrant>, RegistrarError> {
    if warrant_jwss.len() != grants.len() {
        return Err(RegistrarError::ValidationError(format!(
            "expected {} warrants (one per grant), got {}",
            grants.len(),
            warrant_jwss.len()
        )));
    }
    let config_cert = DeviceCert::parse(config_jws)
        .map_err(|e| RegistrarError::ValidationError(format!("bad config cert: {e}")))?;
    if config_cert.purpose() != Purpose::Authorization {
        return Err(RegistrarError::ValidationError(
            "signing cert is not an authorization (config) cert".into(),
        ));
    }
    if config_cert.is_expired() {
        return Err(RegistrarError::ValidationError("config cert expired".into()));
    }
    // The config cert must be authoritative for the GRANTOR (the attributed
    // identity that authorizes the grant) — NOT the grantee, which may be a
    // distinct/foreign service in a delegated grant.
    if !config_cert.authorizes_identity(grantor) {
        return Err(RegistrarError::ValidationError(
            "config cert does not authorize the warrant grantor".into(),
        ));
    }
    let agent_holder = browserid_core::device::Holder::new(agent_holder.to_string())
        .map_err(|e| RegistrarError::ValidationError(format!("bad agent holder: {e}")))?;
    let mut warrants = Vec::with_capacity(warrant_jwss.len());
    for (jws, grant) in warrant_jwss.iter().zip(grants) {
        let warrant = Warrant::parse(jws)
            .map_err(|e| RegistrarError::ValidationError(format!("bad warrant: {e}")))?;
        warrant
            .verify(config_cert.public_key())
            .map_err(|_| RegistrarError::ValidationError(
                "warrant is not signed by the presented config cert".into(),
            ))?;
        let claims = warrant.claims();
        if claims.audience != grant.audience {
            return Err(RegistrarError::ValidationError(
                "warrant audience does not match its grant".into(),
            ));
        }
        if claims.grantor != grantor {
            return Err(RegistrarError::ValidationError(
                "warrant grantor does not match the approving identity".into(),
            ));
        }
        if claims.grantee != grantee {
            return Err(RegistrarError::ValidationError(
                "warrant grantee does not match the requested actor".into(),
            ));
        }
        if claims.holder.as_str() == "*" {
            return Err(RegistrarError::ValidationError(
                "over-broad holder matcher (bare `*`) not allowed".into(),
            ));
        }
        if !claims.holder.matches(&agent_holder) {
            return Err(RegistrarError::ValidationError(
                "warrant holder matcher does not cover the agent's holder".into(),
            ));
        }
        warrants.push(warrant);
    }
    Ok(warrants)
}

/// Shape check on one requested grant (audience + opaque scopes) — shared by
/// `warrant_request` and `agent_provision::request`.
pub(crate) fn validate_grant_shape(audience: &str, scopes: &[String]) -> Result<(), RegistrarError> {
    if audience.is_empty()
        || audience.contains('*')
        || audience.len() > 512
        || audience.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(RegistrarError::ValidationError("bad audience".into()));
    }
    if scopes.len() > 32 || scopes.iter().any(|s| s.len() > 128) {
        return Err(RegistrarError::ValidationError("bad scopes".into()));
    }
    Ok(())
}

// ===========================================================================
// Warrant registry (jipx): the delegator's own record of issued warrants
// ===========================================================================

pub(crate) fn warrant_to_record(
    user_id: u64,
    delegator_email: &str,
    warrant: &Warrant,
    jws: &str,
    config_cert: &str,
) -> WarrantRecord {
    let claims = warrant.claims();
    let ts = |secs: i64| DateTime::from_timestamp(secs, 0).unwrap_or_else(Utc::now);
    WarrantRecord {
        id: 0, // assigned by the store
        user_id,
        delegator_email: delegator_email.to_string(),
        agent_email: claims.grantee.clone(),
        audience: claims.audience.clone(),
        scopes: claims.scopes.clone(),
        warrant: jws.to_string(),
        status_idx: claims.status.as_ref().map(|s| s.idx),
        holder: Some(claims.holder.as_str().to_string()),
        config_cert: Some(config_cert.to_string()),
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
    /// The warrant's holder matcher (`*` / `<ns>.*` / `<id>`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    /// The config cert that signed this warrant (4th object of a presentation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_cert: Option<String>,
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
                holder: r.holder,
                config_cert: r.config_cert,
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
    /// A warrant JWS signed client-side (manual card / reissue / login sync)
    pub warrant: String,
    /// The config (authorization) device cert whose key signed it
    pub config_cert: String,
}

/// POST /wsapi/register_warrant — record a warrant signed outside the
/// consent flow (manual signing, reissue, or the login dialog syncing a
/// warrant for device-agnostic reuse). The warrant's delegator — its
/// identifier with any `+tag` stripped — must be a verified email on this
/// account, and the warrant must verify against the presented config cert.
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
    let config_cert = DeviceCert::parse(&req.config_cert)
        .map_err(|e| RegistrarError::ValidationError(format!("bad config cert: {e}")))?;
    if config_cert.purpose() != Purpose::Authorization {
        return Err(RegistrarError::ValidationError(
            "signing cert is not an authorization (config) cert".into(),
        ));
    }
    warrant
        .verify(config_cert.public_key())
        .map_err(|_| RegistrarError::ValidationError(
            "warrant is not signed by the presented config cert".into(),
        ))?;
    let grantor = &warrant.claims().grantor;
    if !config_cert.authorizes_identity(grantor) {
        return Err(RegistrarError::ValidationError(
            "config cert does not authorize the warrant's grantor".into(),
        ));
    }
    let delegator = delegator_of(grantor);
    if !state.host.owns_verified_email(user.user_id, &delegator)? {
        return Err(RegistrarError::ValidationError(
            "the warrant's delegator is not a verified email on this account".into(),
        ));
    }
    state.store.upsert_warrant(warrant_to_record(
        user.user_id,
        &delegator,
        &warrant,
        &req.warrant,
        &req.config_cert,
    ))?;
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

// ===========================================================================
// Agent-facing: raise + poll a consent request (device-cert model)
// ===========================================================================

fn new_poll_code() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Deserialize)]
pub struct WarrantRequestGrant {
    pub audience: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Deserialize)]
pub struct WarrantRequestBody {
    /// The agent's IdP-signed AUTHENTICATION device cert (subject `agent`) —
    /// the credential that raises the request
    pub device_cert: String,
    /// Which agent identity (∈ the cert's identities) the warrants are for
    pub identity: String,
    /// The grants being asked for — one warrant per audience
    pub grants: Vec<WarrantRequestGrant>,
    /// Display label shown on the consent page
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Serialize)]
pub struct WarrantRequestResponse {
    pub success: bool,
    /// The poll credential (single delivery)
    pub code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

fn bad(msg: impl Into<String>) -> RegistrarError {
    RegistrarError::ValidationError(msg.into())
}

/// POST /warrant/request — an agent raises a consent request, authenticated
/// by its IdP-signed agent device cert. The delegator is derived from the
/// agent identity (`+tag` stripped) and must be a verified email on a local
/// account; the request then appears on that account's consent page.
pub async fn warrant_request(
    State(state): State<Arc<RegistrarState>>,
    Json(req): Json<WarrantRequestBody>,
) -> Result<Json<WarrantRequestResponse>, RegistrarError> {
    require_enabled(&state)?;

    let device_cert = DeviceCert::parse(&req.device_cert)
        .map_err(|e| bad(format!("bad device cert: {e}")))?;
    // Must be OUR issuance: this registrar is the agent's IdP.
    device_cert
        .verify(&state.keypair.public_key())
        .map_err(|_| bad("device cert not issued by this registrar's IdP"))?;
    if device_cert.iss() != state.domain {
        return Err(bad("device cert not issued by this registrar's IdP"));
    }
    if device_cert.is_expired() {
        return Err(bad("device cert expired"));
    }
    if device_cert.purpose() != Purpose::Authentication {
        return Err(bad("device cert must be an authentication cert"));
    }
    // (holder-authorization model) The old "device cert subject must be 'agent'"
    // gate is removed — the user/agent axis is gone; the device cert's holder
    // (opaque) now identifies which of the user's things is acting.
    let identity = req.identity.trim().to_lowercase();
    if !device_cert.authorizes_identity(&identity) {
        return Err(bad("device cert does not authorize this identity"));
    }
    // Revoked agents can't raise requests (their status bit is flipped).
    if let Some(status) = &device_cert.claims().status {
        if status.uri == status_list_uri(&state.domain)
            && state.store.is_status_revoked_idx(status.idx)?
        {
            return Err(bad("device cert revoked"));
        }
    }
    if req.grants.is_empty() || req.grants.len() > 10 {
        return Err(bad("between 1 and 10 grants per request"));
    }
    for g in &req.grants {
        validate_grant_shape(&g.audience, &g.scopes)?;
    }

    // Route to the delegator's account: the identity with `+tag` stripped
    // must be a verified email on a local account. (Bare agent names on a
    // primary domain need a reverse name-registry lookup — not wired yet.)
    let delegator = delegator_of(&identity);
    let user_id = state
        .host
        .user_for_verified_email(&delegator)?
        .ok_or_else(|| bad("no local account for this identity's delegator"))?;

    // One warrant per grant; each gets its stable status index up front so
    // the consent page embeds it in what it signs.
    let grants: Vec<WarrantGrantItem> = req
        .grants
        .iter()
        .map(|g| {
            let idx = state.store.get_or_allocate_status(
                "warrant",
                &warrant_status_subject(user_id, &identity, &g.audience, &g.scopes),
            )?;
            Ok(WarrantGrantItem {
                audience: g.audience.clone(),
                scopes: g.scopes.clone(),
                status_idx: Some(idx),
            })
        })
        .collect::<Result<_, RegistrarError>>()?;

    let code = new_poll_code();
    let now = Utc::now();
    state.store.create_warrant_request(WarrantRequestRecord {
        code: code.clone(),
        user_id,
        delegator_email: delegator.clone(),
        agent_email: identity.clone(),
        holder: device_cert.holder().as_str().to_string(),
        label: req.label.unwrap_or_else(|| identity.clone()),
        grants,
        status: WarrantRequestStatus::Pending,
        warrants: None,
        external: false,
        created_at: now,
        expires_at: now + Duration::minutes(REQUEST_TTL_MINUTES),
        last_polled_at: None,
    })?;
    state.store.cleanup_expired_warrant_requests().ok();

    let origin = public_origin(&state.domain);
    tracing::info!(agent = %identity, delegator = %delegator, "warrant request raised");
    Ok(Json(WarrantRequestResponse {
        success: true,
        code: code.clone(),
        verification_uri: format!("{origin}/consent"),
        verification_uri_complete: format!("{origin}/consent/{code}"),
        expires_in: REQUEST_TTL_MINUTES * 60,
        interval: POLL_INTERVAL_SECONDS,
    }))
}

#[derive(Deserialize)]
pub struct WarrantPollBody {
    pub code: String,
}

#[derive(Serialize)]
pub struct WarrantPollGrant {
    pub audience: String,
    /// `warrant~config_cert` — splice `~{this}` after your access cert +
    /// assertion to form the 4-object presentation
    pub warrant: String,
}

#[derive(Serialize)]
pub struct WarrantPollResponse {
    pub success: bool,
    /// "pending" | "approved" | "denied"
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grants: Option<Vec<WarrantPollGrant>>,
}

/// POST /warrant/poll — RFC-8628-shaped poll on a consent request. Single
/// delivery: an approved request is deleted on pickup.
pub async fn warrant_poll(
    State(state): State<Arc<RegistrarState>>,
    Json(req): Json<WarrantPollBody>,
) -> Result<Json<WarrantPollResponse>, RegistrarError> {
    require_enabled(&state)?;
    let rec = state
        .store
        .get_warrant_request(&req.code)?
        .ok_or(RegistrarError::WarrantRequestNotFound)?;
    if rec.is_expired() {
        state.store.delete_warrant_request(&req.code).ok();
        return Err(RegistrarError::WarrantRequestNotFound);
    }
    match rec.status {
        WarrantRequestStatus::Pending => {
            // Slow-down: enforce the advertised interval while still pending.
            // A resolved request delivers immediately regardless.
            if let Some(last) = state.store.touch_warrant_poll(&req.code)? {
                if Utc::now() - last < Duration::seconds(POLL_INTERVAL_SECONDS) {
                    return Err(bad("slow_down: poll at most every 5 seconds"));
                }
            }
            Ok(Json(WarrantPollResponse {
                success: true,
                status: "pending".into(),
                grants: None,
            }))
        }
        WarrantRequestStatus::Denied => {
            state.store.delete_warrant_request(&req.code).ok();
            Ok(Json(WarrantPollResponse {
                success: true,
                status: "denied".into(),
                grants: None,
            }))
        }
        WarrantRequestStatus::Approved => {
            let warrants = rec.warrants.clone().unwrap_or_default();
            let grants = rec
                .grants
                .iter()
                .zip(warrants)
                .map(|(g, w)| WarrantPollGrant {
                    audience: g.audience.clone(),
                    warrant: w,
                })
                .collect();
            // Single delivery.
            state.store.delete_warrant_request(&req.code)?;
            Ok(Json(WarrantPollResponse {
                success: true,
                status: "approved".into(),
                grants: Some(grants),
            }))
        }
    }
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

    /// The optional grantor on a consent response (bean k0s9): absent keeps
    /// the original grantor == grantee shape; a named grantor is gated on
    /// account ownership of its delegator. Pin the decision table here — the
    /// respond() handler applies it against the store.
    #[test]
    fn respond_grantor_defaults_and_ownership_gate() {
        let agent = "danmills+bsky@sandmill.org";
        // The expression under test, as it appears in respond(): which
        // identity must pass the owns_verified_email gate for a given input.
        let gate_for = |requested: Option<&str>| -> Option<String> {
            match requested.map(str::trim).filter(|s| !s.is_empty()) {
                None => None, // default: the agent itself, no ownership gate
                Some(g) => {
                    let g = g.to_lowercase();
                    if g == agent { None } else { Some(delegator_of(&g)) }
                }
            }
        };
        // Absent / empty / whitespace → today's shape, nothing to check.
        assert_eq!(gate_for(None), None);
        assert_eq!(gate_for(Some("")), None);
        assert_eq!(gate_for(Some("  ")), None);
        // Naming the agent itself is the same as the default.
        assert_eq!(gate_for(Some("danmills+bsky@sandmill.org")), None);
        // An on-behalf grantor is gated on owning it.
        assert_eq!(gate_for(Some("danmills@sandmill.org")), Some("danmills@sandmill.org".into()));
        // A +tag grantor is gated on owning its base identity.
        assert_eq!(gate_for(Some("danmills+other@sandmill.org")), Some("danmills@sandmill.org".into()));
    }
}
