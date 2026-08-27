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
use crate::models::{
    RecordRequestMeta, RequestKind, WarrantGrantItem, WarrantRecord, WarrantRequestRecord,
    WarrantRequestStatus,
};
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
    match browserid_core::identity::email_parts(identity) {
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
    /// The request's GRANTOR pin, normalized (t1jp): `*` = the approver
    /// chooses (dropdown: the agent itself, or any identity they own); a
    /// concrete email = pinned — the page renders it as text and the only
    /// choice is approve/deny. `self` arrives already normalized to the
    /// agent's own email.
    pub grantor: String,
    /// The agent's own account of why it wants this (eywc) — quoted on the
    /// card under an "unverified" marking, never trusted. `None` renders as
    /// "it didn't say what it intends to do with this".
    pub message: Option<String>,
    /// The USER-CHOSEN name for this agent (Flow I step 2) — the trustworthy
    /// "who" the permission card opens with. `None` for agents named before
    /// display names existed (the page falls back to the holder label / email).
    pub display_name: Option<String>,
    /// When this account first authorized the agent ("created April 12").
    pub agent_created_at: Option<DateTime<Utc>>,
    /// Whether this account has met the agent at all. `false` renders the
    /// deny-only card (P4): no consent is offered to a stranger.
    pub known: bool,
    /// Requested grants — one per audience, each with its scopes
    pub grants: Vec<WarrantGrantItem>,
    /// External request (§6.6) — raised by a foreign-IdP service, not one
    /// of the account's own agents; the page words the ask accordingly
    pub external: bool,
    /// "agent" | "connection" | "authoring" — the consent card variant.
    pub kind: String,
    /// Connection requests: the client descriptor. `client_name` is the
    /// site's own report — the page MUST mark it unverified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// Connection requests: the broker-minted `binding.id` the signed record
    /// must carry (§6.6 invariant 5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<String>,
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
    let mut requests: Vec<PendingRequestInfo> = state
        .store
        .list_pending_warrant_requests(user.user_id)?
        .into_iter()
        .filter(|r| !r.external || query.code.as_deref() == Some(r.code.as_str()))
        .map(|r| pending_info(&state, user.user_id, r))
        .collect();
    // Record requests (§7.5) are unclaimed at creation (user_id 0) so they
    // never appear in an inbox listing — they are surfaced only through
    // their deep-linked consent_uri, after the audience proof verifies, and
    // are claimed for the viewing account (status indexes allocated) so the
    // page can embed the refs in the records it signs.
    if let Some(code) = query.code.as_deref() {
        if !requests.iter().any(|r| r.code == code) {
            if let Some(rec) = state.store.get_warrant_request(code)? {
                if rec.kind != RequestKind::Agent
                    && rec.status == WarrantRequestStatus::Pending
                    && !rec.is_expired()
                {
                    if let Some(rec) = surface_record_request(&state, user.user_id, rec).await? {
                        requests.push(pending_info(&state, user.user_id, rec));
                    }
                }
            }
        }
    }
    Ok(Json(ListRequestsResponse {
        success: true,
        status_uri: status_list_uri(&state.domain),
        requests,
    }))
}

pub(crate) fn pending_info(
    state: &RegistrarState,
    user_id: u64,
    r: WarrantRequestRecord,
) -> PendingRequestInfo {
    // The trustworthy "who" (eywc) — agent flow only: the user-chosen name and
    // first-authorized date from the host's registry, or nothing, which the
    // page renders as the deny-only unknown-agent card (P4). Record requests
    // have no requesting agent; their gate is the audience proof, so the card
    // is always offered ("known").
    let met = if r.kind == RequestKind::Agent {
        state.host.known_agent(user_id, &r.agent_email).unwrap_or(None)
    } else {
        None
    };
    let meta = r.meta.as_ref();
    PendingRequestInfo {
        code: r.code,
        delegator_email: r.delegator_email,
        agent_email: r.agent_email,
        holder: r.holder,
        label: r.label,
        grantor: r.grantor,
        message: r.message,
        display_name: met.as_ref().and_then(|k| k.display_name.clone()),
        agent_created_at: met.as_ref().and_then(|k| k.created_at),
        known: r.kind != RequestKind::Agent || met.is_some(),
        grants: r.grants,
        external: r.external,
        kind: r.kind.as_str().to_string(),
        client_host: meta.and_then(|m| m.client_host.clone()),
        client_name: meta.and_then(|m| m.client_name.clone()),
        binding_id: meta.and_then(|m| m.binding_id.clone()),
        created_at: r.created_at,
        expires_at: r.expires_at,
    }
}

/// Gate + claim a record request for the viewing account (§7.5): verify the
/// audience proof (fetch the published nonce, byte-compare after stripping
/// trailing ASCII whitespace — fail-closed, the card never renders without
/// it), then bind the row to this account and allocate each grant's status
/// index so the page can embed the refs in the records it signs.
async fn surface_record_request(
    state: &RegistrarState,
    user_id: u64,
    mut rec: WarrantRequestRecord,
) -> Result<Option<WarrantRequestRecord>, RegistrarError> {
    let Some(mut meta) = rec.meta.clone() else { return Ok(None) };
    if !meta.proof_ok {
        let Some(fetcher) = state.proof_fetcher.as_ref() else { return Ok(None) };
        let origin = audience_origin(&rec.grants[0].audience)?;
        let body = fetcher.fetch_proof(&origin, &rec.code).await?;
        if body.trim_end_matches(|c: char| c.is_ascii_whitespace()) != meta.challenge {
            return Err(vfail("audience_unproven", "audience proof mismatch"));
        }
        meta.proof_ok = true;
        rec.meta = Some(meta.clone());
    }
    let needs_claim =
        rec.user_id != user_id || rec.grants.iter().any(|g| g.status_idx.is_none());
    if needs_claim {
        rec.user_id = user_id;
        let grants = std::mem::take(&mut rec.grants);
        rec.grants = grants
            .into_iter()
            .map(|mut g| {
                let subject = match rec.kind {
                    // Per-connection revocation axis: stable per binding.id.
                    RequestKind::Connection => format!(
                        "cn|{}|{}",
                        user_id,
                        meta.binding_id.as_deref().unwrap_or_default()
                    ),
                    // Policy rows: stable per (grantee, audience, scopes).
                    _ => warrant_status_subject(
                        user_id,
                        g.grantee.as_deref().unwrap_or_default(),
                        &g.audience,
                        &g.scopes,
                    ),
                };
                g.status_idx = Some(state.store.get_or_allocate_status("warrant", &subject)?);
                Ok(g)
            })
            .collect::<Result<_, RegistrarError>>()?;
        state.store.update_warrant_request(&rec)?;
    }
    Ok(Some(rec))
}

/// Claim a pending record request for `user_id` — the token lane's
/// `POST /api/v1/requests/claim` (registry-api-v1 §5.1): the legacy GET's
/// hidden side effect, made explicit. Verifies the audience proof
/// (fail-closed; a fresh fetch when not yet proven) and binds the row,
/// allocating each grant's status index. Idempotent for the same account; a
/// request claimed by another account — or an agent-kind code, which is
/// never claimable — is `WarrantRequestNotFound` (no existence leaks).
pub(crate) async fn claim_core(
    state: &Arc<RegistrarState>,
    user_id: u64,
    code: &str,
) -> Result<WarrantRequestRecord, RegistrarError> {
    let rec = state
        .store
        .get_warrant_request(code)?
        .ok_or(RegistrarError::WarrantRequestNotFound)?;
    if rec.kind == RequestKind::Agent
        || rec.status != WarrantRequestStatus::Pending
        || rec.is_expired()
        || (rec.user_id != 0 && rec.user_id != user_id)
    {
        return Err(RegistrarError::WarrantRequestNotFound);
    }
    surface_record_request(state, user_id, rec)
        .await?
        .ok_or_else(|| vfail("audience_unproven", "the audience proof could not be verified"))
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
    /// The request's origin-validated `return_url`, echoed so the consent
    /// page can send the browser back to the requesting service after a
    /// successful approval (the OAuth authorization-code lane). Validated
    /// at request time — never a caller-supplied redirect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_url: Option<String>,
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
    let core = RespondCore {
        code: req.code,
        approve: req.approve,
        warrants: req.warrants,
        config_cert: req.config_cert,
        grantor: req.grantor,
    };
    // Echoed on a denial too: the page offers a manual "return to the app"
    // link so the requesting service can pick up the denial (it never
    // auto-navigates on deny).
    let return_url = respond_core(&state, user.user_id, &core)?;
    Ok(Json(RespondResponse { success: true, return_url }))
}

/// The lane-independent fields of a consent response (the cookie body minus
/// `csrf`; exactly the registry-api-v1 §5.1 respond shape).
pub(crate) struct RespondCore {
    pub code: String,
    pub approve: bool,
    pub warrants: Option<Vec<String>>,
    pub config_cert: Option<String>,
    pub grantor: Option<String>,
}

/// Resolve a pending consent request for `user_id` — the shared core behind
/// the cookie lane (`/wsapi/warrant_respond`) and the token lane
/// (`POST /api/v1/requests/respond`), so the two validation bars can never
/// drift. Returns the request's origin-validated `return_url`.
pub(crate) fn respond_core(
    state: &Arc<RegistrarState>,
    user_id: u64,
    req: &RespondCore,
) -> Result<Option<String>, RegistrarError> {
    let rec = state
        .store
        .get_warrant_request(&req.code)?
        .ok_or(RegistrarError::WarrantRequestNotFound)?;
    if rec.user_id != user_id {
        return Err(RegistrarError::WarrantRequestNotFound);
    }

    // Record requests (§7.5) resolve through their own approval path: the
    // approver signed v2 admission records (a connection self-grant, or
    // policy rows), not agent presentation warrants.
    if rec.kind != RequestKind::Agent {
        return respond_record(state, user_id, req, rec);
    }

    if !req.approve {
        state.store.respond_warrant_request(user_id, &req.code, None)?;
        return Ok(rec.return_url);
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
    // shape — but the approver may name one of the account's own identities so
    // a later grant matches how the agent was authorized (on-behalf, bean 8v6c).
    let grantor = match req.grantor.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => rec.agent_email.clone(),
        Some(g) => {
            let g = g.to_lowercase();
            if g != rec.agent_email
                && !state.host.owns_verified_email(user_id, &delegator_of(&g))?
            {
                return Err(vfail(
                    "grantor_not_owned",
                    "the warrant grantor must be the agent or an identity on this account",
                ));
            }
            g
        }
    };
    // Honor the request's grantor pin (t1jp): a pinned request is
    // approve/deny only — the approver must not substitute a different grantor.
    if rec.grantor != "*" && grantor != rec.grantor {
        return Err(vfail(
            "grantor_pinned_mismatch",
            format!("this request pins the grantor to '{}'", rec.grantor),
        ));
    }
    let warrants = validate_grant_warrants(
        warrant_jwss,
        config_jws,
        &grantor,
        &rec.agent_email,
        &rec.holder,
        &rec.grants,
        &status_list_uri(&state.domain),
    )?;
    // Re-authorization (status bleed, 2026-07-27): the warrant status index is
    // stable per (user, agent, audience, scopes), so a revoked grant — or a
    // forgotten holder's grants — leaves its bit SET. A fresh approval of the
    // same subject must reactivate it, or the newly issued warrant is born
    // revoked. (The provisioning flow has done this since 8v6c; the consent
    // flow never did.)
    for g in &rec.grants {
        if let Some(idx) = g.status_idx {
            let _ = state.store.set_status_active_idx(idx);
        }
    }
    let records: Vec<WarrantRecord> = warrants
        .iter()
        .zip(warrant_jwss)
        .map(|(warrant, jws)| {
            warrant_to_record(user_id, &rec.delegator_email, warrant, jws, config_jws)
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
        .respond_warrant_request(user_id, &req.code, Some(&delivery))?;
    // Registry (jipx): the delegator's own reviewable record of each grant.
    for record in records {
        state.store.upsert_warrant(record)?;
    }
    tracing::info!(delegator = %rec.delegator_email, grants = rec.grants.len(),
        "warrant consent approved");
    Ok(rec.return_url)
}

/// Resolve a record request (§7.5): the connection variant's single
/// self-grant record, or the authoring ceremony's per-grantee policy rows.
/// The approver (the signed-in account) is the GRANTOR of every record; the
/// page signed each with the config (authorization) key in this origin's
/// keystore, and validation pins every claim to the pending request — the
/// broker-minted binding.id, the client descriptor, audiences, scopes, and
/// the allocated status refs. All-or-nothing, grant order.
fn respond_record(
    state: &Arc<RegistrarState>,
    user_id: u64,
    req: &RespondCore,
    rec: WarrantRequestRecord,
) -> Result<Option<String>, RegistrarError> {
    let meta = rec.meta.clone().unwrap_or_default();

    if !req.approve {
        state.store.respond_warrant_request(user_id, &req.code, None)?;
        return Ok(rec.return_url);
    }
    if !meta.proof_ok {
        return Err(vfail("audience_unproven", "audience proof not verified"));
    }
    let warrant_jwss = req.warrants.as_deref().ok_or_else(|| {
        RegistrarError::ValidationError("approve requires the signed records".into())
    })?;
    let config_jws = req.config_cert.as_deref().ok_or_else(|| {
        RegistrarError::ValidationError("approve requires the signing config cert".into())
    })?;
    // The grantor is the approver — a verified identity on this account.
    let grantor = req
        .grantor
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad("approve requires the signing identity (grantor)"))?
        .to_lowercase();
    if !state.host.owns_verified_email(user_id, &delegator_of(&grantor))? {
        return Err(vfail("grantor_not_owned", "the grantor must be an identity on this account"));
    }
    // Identity-first pin (§7.5 rule shared with the JIT flow): a pinned
    // request is approve/deny only — never a different identity.
    if rec.grantor != "*" && grantor != rec.grantor {
        return Err(vfail(
            "grantor_pinned_mismatch",
            format!("this request pins the identity to '{}'", rec.grantor),
        ));
    }

    let config_cert = DeviceCert::parse(config_jws)
        .map_err(|e| vfail("config_cert_invalid", format!("bad config cert: {e}")))?;
    if config_cert.purpose() != Purpose::Authorization {
        return Err(vfail("config_cert_wrong_purpose", "config cert is not an authorization cert"));
    }
    if config_cert.is_expired() {
        return Err(vfail("config_cert_expired", "config cert expired"));
    }
    if !config_cert.authorizes_identity(&grantor) {
        return Err(vfail("grantor_not_authorized", "config cert does not authorize the grantor"));
    }
    if warrant_jwss.len() != rec.grants.len() {
        return Err(vfail(
            "warrant_count_mismatch",
            format!(
                "expected {} records (one per grant), got {}",
                rec.grants.len(),
                warrant_jwss.len()
            ),
        ));
    }

    let status_uri = status_list_uri(&state.domain);
    let mut warrants = Vec::with_capacity(warrant_jwss.len());
    for (jws, grant) in warrant_jwss.iter().zip(&rec.grants) {
        let warrant = Warrant::parse(jws)
            .map_err(|e| vfail("warrant_invalid", format!("bad record: {e}")))?;
        warrant
            .verify(config_cert.public_key())
            .map_err(|_| vfail("warrant_invalid", "record is not signed by the presented config cert"))?;
        let claims = warrant.claims();
        if claims.typ != browserid_core::device::TYP_WARRANT_V2 {
            return Err(vfail("warrant_invalid", "admission records must be browserid-warrant-v2"));
        }
        if claims.grantor != grantor {
            return Err(vfail("grantor_mismatch", "record grantor does not match the approving identity"));
        }
        if claims.audience != grant.audience {
            return Err(vfail("audience_mismatch", "record audience does not match its grant"));
        }
        let mut want = grant.scopes.clone();
        let mut got = claims.scope_strings();
        want.sort_unstable();
        got.sort_unstable();
        if want != got {
            return Err(vfail("scope_mismatch", "record scopes do not match the requested grant"));
        }
        // The revocation ref must be EXACTLY the allocated one (same rule as
        // the agent flow): a record carrying someone else's index would arm
        // our revoke lever at a grant the signer doesn't own.
        let idx = grant.status_idx.ok_or_else(|| bad("grant has no allocated status index"))?;
        match &claims.status {
            Some(st) if st.uri == status_uri && st.idx == idx => {}
            Some(_) => return Err(vfail("status_ref_mismatch", "record status ref does not match the allocated one")),
            None => return Err(vfail("status_ref_missing", "record is missing its allocated status ref")),
        }
        let bset = claims.binding_set();
        match (rec.kind, bset.entries()) {
            (
                RequestKind::Connection,
                [browserid_core::device::Binding::Connection { protocol: _, id, client_host, client_name }],
            ) => {
                // Warrant::parse already enforced the self-grant rule and an
                // implemented protocol; pin the descriptor to the request.
                if Some(id.as_str()) != meta.binding_id.as_deref() {
                    return Err(vfail("binding_mismatch", "record binding.id does not match this request"));
                }
                if Some(client_host.as_str()) != meta.client_host.as_deref() {
                    return Err(vfail("binding_mismatch", "record client_host does not match this request"));
                }
                if *client_name != meta.client_name.clone().unwrap_or_default() {
                    return Err(vfail("binding_mismatch", "record client_name does not match this request"));
                }
            }
            (RequestKind::Authoring, [browserid_core::device::Binding::Holder { .. }]) => {
                let want = grant.grantee.as_deref().unwrap_or_default();
                if claims.grantee != want {
                    return Err(vfail("grantee_mismatch", "record grantee does not match its grant row"));
                }
            }
            _ => return Err(vfail("binding_mismatch", "record binding kind does not match this request")),
        }
        warrants.push(warrant);
    }

    // Re-activate each allocated bit (same status-bleed rule as the agent
    // flow): a fresh approval of a previously revoked subject must not be
    // born revoked.
    for g in &rec.grants {
        if let Some(idx) = g.status_idx {
            let _ = state.store.set_status_active_idx(idx);
        }
    }
    let delegator = delegator_of(&grantor);
    let records: Vec<WarrantRecord> = warrants
        .iter()
        .zip(warrant_jwss)
        .map(|(warrant, jws)| warrant_to_record(user_id, &delegator, warrant, jws, config_jws))
        .collect();
    let delivery: Vec<String> =
        warrant_jwss.iter().map(|w| format!("{w}~{config_jws}")).collect();
    state.store.respond_warrant_request(user_id, &req.code, Some(&delivery))?;
    for record in records {
        state.store.upsert_warrant(record)?;
    }
    tracing::info!(kind = %rec.kind.as_str(), grants = rec.grants.len(),
        "record request approved");
    Ok(rec.return_url)
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
    status_uri: &str,
) -> Result<Vec<Warrant>, RegistrarError> {
    if warrant_jwss.len() != grants.len() {
        return Err(vfail(
            "warrant_count_mismatch",
            format!(
                "expected {} warrants (one per grant), got {}",
                grants.len(),
                warrant_jwss.len()
            ),
        ));
    }
    let config_cert = DeviceCert::parse(config_jws)
        .map_err(|e| vfail("config_cert_invalid", format!("bad config cert: {e}")))?;
    if config_cert.purpose() != Purpose::Authorization {
        return Err(vfail(
            "config_cert_wrong_purpose",
            "signing cert is not an authorization (config) cert",
        ));
    }
    if config_cert.is_expired() {
        return Err(vfail("config_cert_expired", "config cert expired"));
    }
    // The config cert must be authoritative for the GRANTOR (the attributed
    // identity that authorizes the grant) — NOT the grantee, which may be a
    // distinct/foreign service in a delegated grant.
    if !config_cert.authorizes_identity(grantor) {
        return Err(vfail(
            "grantor_not_authorized",
            "config cert does not authorize the warrant grantor",
        ));
    }
    let agent_holder = browserid_core::device::Holder::new(agent_holder.to_string())
        .map_err(|e| RegistrarError::ValidationError(format!("bad agent holder: {e}")))?;
    let mut warrants = Vec::with_capacity(warrant_jwss.len());
    for (jws, grant) in warrant_jwss.iter().zip(grants) {
        let warrant = Warrant::parse(jws)
            .map_err(|e| vfail("warrant_invalid", format!("bad warrant: {e}")))?;
        warrant
            .verify(config_cert.public_key())
            .map_err(|_| vfail(
                "warrant_invalid",
                "warrant is not signed by the presented config cert",
            ))?;
        let claims = warrant.claims();
        if claims.audience != grant.audience {
            return Err(vfail("audience_mismatch", "warrant audience does not match its grant"));
        }
        if claims.grantor != grantor {
            return Err(vfail(
                "grantor_mismatch",
                "warrant grantor does not match the approving identity",
            ));
        }
        if claims.grantee != grantee {
            return Err(vfail(
                "grantee_mismatch",
                "warrant grantee does not match the requested actor",
            ));
        }
        // This flow signs PRESENTATION grants for an agent, so the record must
        // be holder-bound (a connection-bound record is admission-only and is
        // minted by the broker's own consent surface, never supplied here).
        let Some(matcher) = claims.holder_matcher() else {
            return Err(vfail("not_holder_bound", "warrant is not holder-bound"));
        };
        if matcher.as_str() == "*" {
            return Err(vfail(
                "wildcard_holder",
                "over-broad holder matcher (bare `*`) not allowed",
            ));
        }
        if !matcher.matches(&agent_holder) {
            return Err(vfail(
                "holder_mismatch",
                "warrant holder matcher does not cover the agent's holder",
            ));
        }
        // The revocation ref must be EXACTLY the one allocated for this grant
        // (our list, this grant's index). A warrant carrying someone else's
        // index would otherwise arm our revoke lever — and any verifier — at
        // a grant the signer doesn't own.
        if let Some(idx) = grant.status_idx {
            match &claims.status {
                Some(st) if st.uri == status_uri && st.idx == idx => {}
                Some(_) => {
                    return Err(vfail(
                        "status_ref_mismatch",
                        "warrant status ref does not match the allocated one",
                    ))
                }
                None => {
                    return Err(vfail(
                        "status_ref_missing",
                        "warrant is missing its allocated status ref",
                    ))
                }
            }
        }
        warrants.push(warrant);
    }
    Ok(warrants)
}

/// The origin of an http(s) URL as `(scheme, host, effective_port)` — a
/// deliberately strict hand parser (no `url` crate in this workspace).
/// Refuses userinfo (`user@host` spoofing), backslashes, whitespace/control
/// characters, and anything that isn't plain `http`/`https`. Host is
/// lowercased; the port defaults per scheme so `https://a` == `https://a:443`.
fn url_origin(u: &str) -> Option<(&'static str, String, u16)> {
    if u.len() > 2048 || u.chars().any(|c| c.is_whitespace() || c.is_control()) || u.contains('\\') {
        return None;
    }
    let (scheme, rest, default_port) = if let Some(r) = u.strip_prefix("https://") {
        ("https", r, 443)
    } else if let Some(r) = u.strip_prefix("http://") {
        ("http", r, 80)
    } else {
        return None;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()?),
        None => (authority, default_port),
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme, host.to_ascii_lowercase(), port))
}

/// Open-redirect guard for the consent flow's `return_url`: the URL must be
/// plain http(s) — https except for localhost dev — and its origin must
/// provably belong to the REQUESTER: either its host equals the requesting
/// agent identity's domain, or its full origin equals the origin of one of
/// the requested grant audiences (the gateway's `resource`, which is also
/// what the warrant binds to). Anything else is refused up front, so the
/// consent page only ever redirects back to the service that raised the
/// request.
pub(crate) fn validate_return_url(
    return_url: &str,
    identity: &str,
    audiences: &[&str],
) -> Result<(), RegistrarError> {
    let (scheme, host, port) = url_origin(return_url)
        .ok_or_else(|| bad("return_url must be a plain http(s) URL"))?;
    if scheme == "http" && !(host == "localhost" || host.starts_with("127.")) {
        return Err(bad("return_url must be https (http is allowed only for localhost)"));
    }
    let identity_domain = identity.rsplit('@').next().unwrap_or_default().to_ascii_lowercase();
    if !identity_domain.is_empty() && host == identity_domain {
        return Ok(());
    }
    if audiences
        .iter()
        .filter_map(|a| url_origin(a))
        .any(|origin| origin == (scheme, host.clone(), port))
    {
        return Ok(());
    }
    Err(bad(
        "return_url origin does not belong to the requesting service \
         (it must match the requester's identity domain or a requested audience)",
    ))
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
        scopes: claims.scope_strings(),
        warrant: jws.to_string(),
        status_idx: claims.status.as_ref().map(|s| s.idx),
        holder: claims.holder_matcher().map(|m| m.as_str().to_string()),
        config_cert: Some(config_cert.to_string()),
        binding_id: match claims.binding_set().connection() {
            Some(browserid_core::device::Binding::Connection { id, .. }) => Some(id.clone()),
            _ => None,
        },
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
    /// Connection records (spec §5): the binding.id + client descriptor, so
    /// the account page renders these as host↔service connections.
    /// `client_name` is the site's own report — rendered marked unverified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// Signing grants (spec §5): the requester entry's origin, so the account
    /// page renders these as site↔audience signing rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester_origin: Option<String>,
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
    let warrants = list_warrants_core(&state, user.user_id)?;
    Ok(Json(ListWarrantsResponse { success: true, warrants }))
}

/// The account's registered warrants as `WarrantInfo` rows — shared by both
/// lanes (`revoked` computed live from each status bit).
pub(crate) fn list_warrants_core(
    state: &Arc<RegistrarState>,
    user_id: u64,
) -> Result<Vec<WarrantInfo>, RegistrarError> {
    let warrants = state
        .store
        .list_warrants(user_id)?
        .into_iter()
        .map(|r| {
            let revoked = r
                .status_idx
                .map(|i| state.store.is_status_revoked_idx(i).unwrap_or(false))
                .unwrap_or(false);
            let bset = Warrant::parse(&r.warrant).ok().map(|w| w.claims().binding_set());
            let (client_host, client_name) = match bset.as_ref().and_then(|b| b.connection()) {
                Some(browserid_core::device::Binding::Connection {
                    client_host, client_name, ..
                }) => (Some(client_host.clone()), Some(client_name.clone())),
                _ => (None, None),
            };
            let requester_origin = bset
                .as_ref()
                .and_then(|b| b.requester_origin())
                .map(str::to_string);
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
                binding_id: r.binding_id,
                client_host,
                client_name,
                requester_origin,
                signed_at: r.signed_at,
                expires_at: r.expires_at,
            }
        })
        .collect();
    Ok(warrants)
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
    register_warrant_core(&state, user.user_id, &req.warrant, &req.config_cert)?;
    Ok(Json(RespondResponse { success: true, return_url: None }))
}

/// Record an externally-minted warrant — the shared core behind the cookie
/// lane and `POST /api/v1/warrants/register` (registry-api-v1 §5.2).
pub(crate) fn register_warrant_core(
    state: &Arc<RegistrarState>,
    user_id: u64,
    warrant_jws: &str,
    config_jws: &str,
) -> Result<(), RegistrarError> {
    let warrant = Warrant::parse(warrant_jws)
        .map_err(|e| vfail("warrant_invalid", format!("bad warrant: {e}")))?;
    let config_cert = DeviceCert::parse(config_jws)
        .map_err(|e| vfail("config_cert_invalid", format!("bad config cert: {e}")))?;
    if config_cert.purpose() != Purpose::Authorization {
        return Err(vfail(
            "config_cert_wrong_purpose",
            "signing cert is not an authorization (config) cert",
        ));
    }
    warrant
        .verify(config_cert.public_key())
        .map_err(|_| vfail(
            "warrant_invalid",
            "warrant is not signed by the presented config cert",
        ))?;
    let grantor = &warrant.claims().grantor;
    if !config_cert.authorizes_identity(grantor) {
        return Err(vfail(
            "grantor_not_authorized",
            "config cert does not authorize the warrant's grantor",
        ));
    }
    let delegator = delegator_of(grantor);
    if !state.host.owns_verified_email(user_id, &delegator)? {
        return Err(vfail(
            "grantor_not_owned",
            "the warrant's delegator is not a verified email on this account",
        ));
    }
    let mut record = warrant_to_record(
        user_id,
        &delegator,
        &warrant,
        warrant_jws,
        config_jws,
    );
    // Trust the embedded status ref for OUR revoke lever only when it is
    // provably this grant's own index: our list URI, and the index the
    // subject registry allocates for exactly (user, grantee, audience,
    // scopes). Anything else is recorded without an index — the row stays
    // reviewable/forgettable, but our revoke button can't be pointed at a
    // grant the registrant doesn't own. A verified ref is also reactivated,
    // same as a consent-flow reissue.
    let claims = warrant.claims();
    match &claims.status {
        Some(st) if st.uri == status_list_uri(&state.domain) => {
            let own_idx = state.store.get_or_allocate_status(
                "warrant",
                &warrant_status_subject(
                    user_id,
                    &claims.grantee,
                    &claims.audience,
                    &claims.scope_strings(),
                ),
            )?;
            if st.idx == own_idx {
                let _ = state.store.set_status_active_idx(own_idx);
            } else {
                tracing::warn!(claimed = st.idx, allocated = own_idx,
                    "register_warrant: status ref is not this grant's own index — recording without one");
                record.status_idx = None;
            }
        }
        Some(_) => {
            // A foreign list: verifiers may honor it, but it is not ours to
            // flip — never wire it to this account's revoke lever.
            record.status_idx = None;
        }
        None => {}
    }
    state.store.upsert_warrant(record)?;
    Ok(())
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
    Ok(Json(RespondResponse { success: true, return_url: None }))
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
    let (uri, idx) =
        allocate_status_core(&state, user.user_id, &req.agent_email, &req.audience, &req.scopes)?;
    Ok(Json(AllocateStatusResponse { success: true, uri, idx }))
}

/// Allocate (idempotently) the stable status ref for a grant — shared by
/// both lanes (registry-api-v1 §5.2 `warrants/allocate_status`). Stable per
/// `(account, agent_email, audience, scope set)`.
pub(crate) fn allocate_status_core(
    state: &Arc<RegistrarState>,
    user_id: u64,
    agent_email: &str,
    audience: &str,
    scopes: &[String],
) -> Result<(String, u64), RegistrarError> {
    if audience.is_empty()
        || audience.contains('*')
        || audience.len() > 512
        || audience.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(RegistrarError::ValidationError("bad audience".into()));
    }
    let idx = state.store.get_or_allocate_status(
        "warrant",
        &warrant_status_subject(user_id, agent_email, audience, scopes),
    )?;
    Ok((status_list_uri(&state.domain), idx))
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
    revoke_warrant_core(&state, user.user_id, req.id)?;
    Ok(Json(RespondResponse { success: true, return_url: None }))
}

/// Flip a registered warrant's status bit — shared by both lanes. A warrant
/// without a status ref cannot be revoked: `409` / `no_status_ref`
/// (registry-api-v1 §5.2) — the remedy is reissuing with an allocated ref.
pub(crate) fn revoke_warrant_core(
    state: &Arc<RegistrarState>,
    user_id: u64,
    warrant_id: u64,
) -> Result<(), RegistrarError> {
    let record = state
        .store
        .list_warrants(user_id)?
        .into_iter()
        .find(|r| r.id == warrant_id)
        .ok_or(RegistrarError::WarrantRequestNotFound)?;
    let idx = record.status_idx.ok_or_else(|| RegistrarError::Conflict {
        reason: "no_status_ref",
        message: "this warrant predates status lists — reissue it (which replaces it) or revoke the agent key".into(),
    })?;
    state.store.set_status_revoked_idx(idx)?;
    tracing::info!(delegator = %record.delegator_email, audience = %record.audience,
        "warrant revoked (status bit set)");
    Ok(())
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
    /// GRANTOR pin (t1jp): who the warrants attribute to. Absent (or `*`) —
    /// the approver chooses (the consent page's dropdown: the agent itself,
    /// or any identity they own). `self` — pinned to the agent itself
    /// (grantor == grantee; normalized to the agent identity, which exists
    /// here). A concrete email — pinned to that identity; refused up front
    /// when it isn't on the delegator's account.
    #[serde(default)]
    pub grantor: Option<String>,
    /// The agent's own account of why it wants this (eywc) — displayed
    /// quoted and marked unverified. Optional but encouraged.
    #[serde(default)]
    pub message: Option<String>,
    /// Where the consent page should send the browser after the request is
    /// resolved (the OAuth authorization-code lane's bounce back to the
    /// requesting service). ORIGIN-VALIDATED here, up front: the URL's origin
    /// must belong to the requester — its identity's domain, or the origin of
    /// one of the requested grant audiences — or the whole request is
    /// refused. The consent page never sees an unvalidated redirect.
    #[serde(default)]
    pub return_url: Option<String>,
}

/// Normalize a warrant request's grantor pin against the (already known)
/// agent identity: absent/empty/`*` → `*` (approver's choice); `self` → the
/// agent identity itself; anything else → a lowercased concrete email pin.
fn norm_warrant_grantor_pin(raw: Option<&str>, agent_identity: &str) -> String {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None | Some("*") => "*".to_string(),
        Some(s) if s.eq_ignore_ascii_case("self") => agent_identity.to_lowercase(),
        Some(s) => s.to_lowercase(),
    }
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

/// A consent-validation failure with its registry-api-v1 §7.1 machine
/// reason. The cookie lane renders it exactly like [`bad`]; the token lane
/// maps it to `422 invalid_warrant` + the reason.
fn vfail(reason: &'static str, msg: impl Into<String>) -> RegistrarError {
    RegistrarError::WarrantValidation { reason, message: msg.into() }
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
    // Our own issuance verifies against our key. A PRIMARY IdP's issuance is
    // accepted too — verified against the issuer's published key, and only
    // when that issuer is the agent identity's own domain (the same rule the
    // provisioning approval applies to primary-signed certs). Without this,
    // every primary-rooted user's agent was locked out of the consent flow
    // ("device cert not issued by this registrar's IdP" — bit Dan live on
    // the guestbook demo, 2026-07-25).
    if device_cert.iss() == state.domain {
        device_cert
            .verify(&state.keypair.public_key())
            .map_err(|_| bad("device cert not signed by this registrar's IdP"))?;
    } else {
        let agent_domain = browserid_core::identity::email_domain(req.identity.trim())
            .unwrap_or_default()
            .to_lowercase();
        if device_cert.iss() != agent_domain {
            return Err(bad("device cert issuer is not the identity's own domain"));
        }
        let resolver = state.issuer_resolver.as_ref().ok_or_else(|| {
            bad("primary-issued device certs are not accepted here (no issuer discovery)")
        })?;
        let idp_key = resolver.resolve_issuer_key(device_cert.iss()).await?;
        device_cert
            .verify(&idp_key)
            .map_err(|_| bad("device cert is not signed by its domain's IdP"))?;
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
    let message = req
        .message
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if message.as_deref().is_some_and(|m| m.len() > 500) {
        return Err(bad("message too long (500 chars max)"));
    }
    // Origin-validate the optional return_url NOW (open-redirect guard):
    // a request carrying a foreign return_url is refused outright.
    let return_url = req
        .return_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if let Some(u) = return_url.as_deref() {
        let audiences: Vec<&str> = req.grants.iter().map(|g| g.audience.as_str()).collect();
        validate_return_url(u, &identity, &audiences)?;
    }

    // Route to the delegator's account: the identity with `+tag` stripped
    // must be a verified email on a local account. (Bare agent names on a
    // primary domain need a reverse name-registry lookup — not wired yet.)
    let delegator = delegator_of(&identity);
    let user_id = state
        .host
        .user_for_verified_email(&delegator)?
        .ok_or_else(|| bad("no local account for this identity's delegator"))?;

    // Grantor pin (t1jp): fail early when the pinned identity can never be
    // satisfied by the routed account — the requester learns now, not as an
    // expiry fifteen minutes later.
    let grantor = norm_warrant_grantor_pin(req.grantor.as_deref(), &identity);
    if grantor != "*"
        && grantor != identity
        && !state.host.owns_verified_email(user_id, &delegator_of(&grantor))?
    {
        return Err(bad(format!(
            "unsatisfiable grantor pin: '{grantor}' is not an identity on the delegator's account"
        )));
    }

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
                grantee: None,
            })
        })
        .collect::<Result<_, RegistrarError>>()?;

    let code = new_poll_code();
    let now = Utc::now();
    state.store.create_warrant_request(WarrantRequestRecord {
        code: code.clone(),
        kind: RequestKind::Agent,
        meta: None,
        user_id,
        delegator_email: delegator.clone(),
        agent_email: identity.clone(),
        holder: device_cert.holder().as_str().to_string(),
        label: req.label.unwrap_or_else(|| identity.clone()),
        grantor,
        message,
        grants,
        status: WarrantRequestStatus::Pending,
        warrants: None,
        external: false,
        return_url,
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

// ===========================================================================
// Admission-record flows (spec §7.5): connection grant requests (audience-
// initiated) + the grant-authoring ceremony (grantor-initiated). Both are
// raised by the RESOURCE — anonymous, no device key — and authenticated by
// proof of audience control: a challenge nonce the resource publishes at
// `/.well-known/browserid-audience-proof/<request_id>`, fetched fail-closed
// before the consent page renders. Approval signs v2 records client-side
// (connection: a self-grant with the broker-minted binding.id; authoring:
// per-grantee policy records) and the resource polls the same RFC-8628
// machinery for the `warrant~config_cert` pairs it will hold (§6.4).
// ===========================================================================

/// Per-origin sliding-window limiter for record requests (§7.5 SHOULD:
/// rate-limit connection requests per audience origin).
#[derive(Default)]
pub struct RecordRequestLimiter {
    inner: std::sync::Mutex<std::collections::HashMap<String, Vec<DateTime<Utc>>>>,
}

impl RecordRequestLimiter {
    const WINDOW_MINUTES: i64 = 10;
    const MAX_PER_WINDOW: usize = 10;

    /// Record an attempt for `origin`; `false` = over the limit, refuse.
    pub fn allow(&self, origin: &str) -> bool {
        let now = Utc::now();
        let cutoff = now - Duration::minutes(Self::WINDOW_MINUTES);
        let mut map = self.inner.lock().unwrap();
        map.retain(|_, v| {
            v.retain(|t| *t > cutoff);
            !v.is_empty()
        });
        let v = map.entry(origin.to_string()).or_default();
        if v.len() >= Self::MAX_PER_WINDOW {
            return false;
        }
        v.push(now);
        true
    }
}

#[derive(Deserialize)]
pub struct RecordClientInfo {
    /// The enforceable client datum: the registered redirect-URI host.
    pub client_host: String,
    /// Display-only, marked unverified everywhere it appears.
    #[serde(default)]
    pub client_name: Option<String>,
}

#[derive(Deserialize)]
pub struct AuthoringGrantItem {
    /// Exact email, or an admission grantee matcher (`*` / `*@<domain>`).
    pub grantee: String,
    pub audience: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Deserialize)]
pub struct RecordRequestBody {
    /// "connection" | "authoring"
    pub r#type: String,
    // --- connection ---
    pub audience: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub client: Option<RecordClientInfo>,
    /// Connection only, OPTIONAL: pin the identity the record must be
    /// signed by/for (the resource authenticated the connecting user first —
    /// the identity-first flow). Pinned cards render the identity fixed
    /// (approve/deny only, no selector), mirroring the JIT flow's grantor
    /// pin: a pin is never silently substituted.
    pub grantor: Option<String>,
    pub message: Option<String>,
    /// Where the consent page sends the browser after approval (the OAuth
    /// authorize hop back to the resource). Origin-validated against the
    /// audience origin.
    pub return_url: Option<String>,
    // --- authoring ---
    pub grants: Option<Vec<AuthoringGrantItem>>,
}

#[derive(Serialize)]
pub struct RecordRequestResponse {
    pub success: bool,
    /// The poll credential AND the audience-proof path component.
    pub request_id: String,
    /// The nonce to publish at
    /// `/.well-known/browserid-audience-proof/<request_id>`.
    pub challenge: String,
    /// The page the connecting user (or the grantor) must visit.
    pub consent_uri: String,
    pub expires_in: i64,
    pub interval: i64,
}

/// POST /warrant/record-request — a resource raises a connection grant
/// request or a grant-authoring ceremony (spec §7.5). No caller
/// authentication: the request is authenticated by audience control (the
/// proof fetch, at consent render), and the stakes of a forged request are
/// bounded — an attacker-raised record is redeemable only by the genuine
/// audience inside its own custody dance.
pub async fn record_request(
    State(state): State<Arc<RegistrarState>>,
    Json(req): Json<RecordRequestBody>,
) -> Result<Json<RecordRequestResponse>, RegistrarError> {
    require_enabled(&state)?;
    if state.proof_fetcher.is_none() {
        return Err(bad("record requests are not supported here"));
    }

    let (kind, grants, meta, return_url, grantor_pin) = match req.r#type.as_str() {
        "connection" => {
            let audience = req
                .audience
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| bad("connection request requires an audience"))?;
            validate_grant_shape(audience, &req.scopes)?;
            // The proof is origin-scoped (§7.5): the audience must be a plain
            // http(s) URL whose origin we can fetch from.
            audience_origin(audience)?;
            let client = req
                .client
                .as_ref()
                .ok_or_else(|| bad("connection request requires client { client_host }"))?;
            let client_host = client.client_host.trim().to_ascii_lowercase();
            if client_host.is_empty()
                || client_host.len() > 253
                || client_host.contains(['/', ':', '@', '*'])
                || client_host.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(bad("bad client_host"));
            }
            let client_name = client
                .client_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.chars().take(100).collect::<String>());
            // Optional identity pin (identity-first flow): must be an exact
            // email — a pin is an identity, never a matcher.
            let pin = req
                .grantor
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_lowercase);
            if let Some(g) = pin.as_deref() {
                if !g.contains('@') || g.starts_with("*") || g.len() > 254 {
                    return Err(bad("bad grantor pin (must be an exact email)"));
                }
            }
            let grants = vec![WarrantGrantItem {
                audience: audience.to_string(),
                scopes: req.scopes.clone(),
                status_idx: None, // allocated when the approver claims the row
                grantee: None,
            }];
            let meta = RecordRequestMeta {
                challenge: new_poll_code(),
                proof_ok: false,
                client_host: Some(client_host),
                client_name,
                binding_id: Some(format!(
                    "cn_{}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(rand::random::<[u8; 16]>())
                )),
            };
            // Origin-validate the optional return_url against the audience
            // origin (there is no requester identity domain here).
            let return_url = req
                .return_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            if let Some(u) = return_url.as_deref() {
                validate_return_url(u, "", &[audience])?;
            }
            (RequestKind::Connection, grants, meta, return_url, pin)
        }
        "authoring" => {
            let items = req
                .grants
                .as_deref()
                .filter(|g| !g.is_empty())
                .ok_or_else(|| bad("authoring request requires grants"))?;
            if items.len() > 32 {
                return Err(bad("at most 32 grants per authoring request"));
            }
            // All audiences share one origin (the proof is origin-scoped) and
            // (grantee, audience) pairs are unique.
            let first_origin = audience_origin(&items[0].audience)?;
            let mut seen = std::collections::HashSet::new();
            for g in items {
                validate_grant_shape(&g.audience, &g.scopes)?;
                if audience_origin(&g.audience)? != first_origin {
                    return Err(bad("all grant audiences must share one origin"));
                }
                let grantee = g.grantee.trim();
                if !(grantee == "*"
                    || grantee.strip_prefix("*@").is_some_and(|d| !d.is_empty())
                    || grantee.contains('@'))
                    || grantee.len() > 254
                {
                    return Err(bad(format!("bad grantee '{grantee}'")));
                }
                if !seen.insert((grantee.to_string(), g.audience.clone())) {
                    return Err(bad("duplicate (grantee, audience) pair"));
                }
            }
            let grants = items
                .iter()
                .map(|g| WarrantGrantItem {
                    audience: g.audience.clone(),
                    scopes: g.scopes.clone(),
                    status_idx: None,
                    grantee: Some(g.grantee.trim().to_string()),
                })
                .collect();
            let pin = req
                .grantor
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_lowercase);
            if let Some(g) = pin.as_deref() {
                if !g.contains('@') || g.starts_with('*') || g.len() > 254 {
                    return Err(bad("bad grantor pin (must be an exact email)"));
                }
            }
            let meta = RecordRequestMeta { challenge: new_poll_code(), ..Default::default() };
            let audiences: Vec<&str> = items.iter().map(|g| g.audience.as_str()).collect();
            let return_url = req
                .return_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            if let Some(u) = return_url.as_deref() {
                validate_return_url(u, "", &audiences)?;
            }
            (RequestKind::Authoring, grants, meta, return_url, pin)
        }
        other => return Err(bad(format!("unknown request type '{other}'"))),
    };

    let message = req
        .message
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if message.as_deref().is_some_and(|m| m.len() > 500) {
        return Err(bad("message too long (500 chars max)"));
    }

    // Per-origin rate limit (§7.5 SHOULD).
    let origin = audience_origin(&grants[0].audience)?;
    if !state.record_request_limiter.allow(&origin) {
        return Err(RegistrarError::PollTooFast);
    }

    let request_id = new_poll_code();
    let now = Utc::now();
    state.store.create_warrant_request(WarrantRequestRecord {
        code: request_id.clone(),
        kind,
        meta: Some(meta.clone()),
        // Unclaimed: the approving account binds at consent render (the row
        // is deep-linked via consent_uri, never listed in anyone's inbox).
        user_id: 0,
        delegator_email: String::new(),
        agent_email: String::new(),
        holder: String::new(),
        label: meta.client_name.clone().unwrap_or_else(|| origin.clone()),
        grantor: grantor_pin.unwrap_or_else(|| "*".to_string()),
        message,
        grants,
        status: WarrantRequestStatus::Pending,
        warrants: None,
        external: true,
        return_url,
        created_at: now,
        expires_at: now + Duration::minutes(REQUEST_TTL_MINUTES),
        last_polled_at: None,
    })?;
    state.store.cleanup_expired_warrant_requests().ok();

    let origin = public_origin(&state.domain);
    tracing::info!(kind = %kind.as_str(), "record request raised");
    Ok(Json(RecordRequestResponse {
        success: true,
        request_id: request_id.clone(),
        challenge: meta.challenge,
        consent_uri: format!("{origin}/consent/{request_id}"),
        expires_in: REQUEST_TTL_MINUTES * 60,
        interval: POLL_INTERVAL_SECONDS,
    }))
}

/// The origin of an audience URL — the scope at which the audience proof is
/// published and WebPKI names the audience (§7.5). Path audiences prove at
/// origin scope.
fn audience_origin(audience: &str) -> Result<String, RegistrarError> {
    let (scheme, host, port) = url_origin(audience)
        .ok_or_else(|| bad("audience must be a plain http(s) URL"))?;
    if scheme == "http" && !(host == "localhost" || host.starts_with("127.")) {
        return Err(bad("audience must be https (http is allowed only for localhost)"));
    }
    Ok(if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    })
}

#[derive(Deserialize)]
pub struct WarrantPollBody {
    /// The JIT flow's `code`; record flows poll with `request_id` (§7.5) —
    /// same credential, either name.
    #[serde(alias = "request_id")]
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
    /// Machine reason accompanying a denial (eywc), e.g. `unknown_agent` —
    /// this account has never met the requesting agent, so no consent was
    /// offered; run the identity flow (agent provisioning) first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
                reason: None,
            }))
        }
        WarrantRequestStatus::Denied => {
            state.store.delete_warrant_request(&req.code).ok();
            // Tell an unknown agent WHY (eywc): its request rendered the
            // deny-only card because this account has never met it — the fix
            // is to run the identity flow first, not to ask again. (Agent
            // flow only: record requests have no requesting agent.)
            let reason = match rec.kind {
                RequestKind::Agent => match state.host.known_agent(rec.user_id, &rec.agent_email) {
                    Ok(None) => Some(
                        "unknown_agent: this account has not met this agent; \
                         request an identity (agent provisioning) first"
                            .to_string(),
                    ),
                    _ => None,
                },
                _ => None,
            };
            Ok(Json(WarrantPollResponse {
                success: true,
                status: "denied".into(),
                grants: None,
                reason,
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
                reason: None,
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

    /// The consent flow's return_url open-redirect guard: only an origin the
    /// requester provably is — its identity's domain or a requested grant
    /// audience's origin — is ever handed back to the browser.
    #[test]
    fn return_url_origin_validation() {
        let ok = |url: &str, identity: &str, auds: &[&str]| {
            validate_return_url(url, identity, auds).is_ok()
        };
        // Matches a requested audience's origin (the gateway's resource).
        assert!(ok("https://mcp.example.com/authorize/return?st=x",
            "gate@browserid.me", &["https://mcp.example.com"]));
        // Port + scheme are part of the origin.
        assert!(ok("http://localhost:8787/authorize/return",
            "gate@browserid.me", &["http://localhost:8787"]));
        assert!(!ok("http://localhost:9999/authorize/return",
            "gate@browserid.me", &["http://localhost:8787"]));
        assert!(!ok("http://mcp.example.com/return", // http != https origin
            "gate@browserid.me", &["https://mcp.example.com"]));
        // Matches the requesting identity's domain (§6.6 foreign service).
        assert!(ok("https://svc.example/done", "bot@svc.example", &["https://other.example"]));
        // A foreign origin is refused.
        assert!(!ok("https://evil.example/phish",
            "gate@browserid.me", &["https://mcp.example.com"]));
        // Sub- and superstring hosts of an audience don't pass.
        assert!(!ok("https://mcp.example.com.evil.example/x",
            "gate@browserid.me", &["https://mcp.example.com"]));
        assert!(!ok("https://evil.example/https://mcp.example.com",
            "gate@browserid.me", &["https://mcp.example.com"]));
        // Userinfo spoofing is refused outright.
        assert!(!ok("https://mcp.example.com@evil.example/x",
            "gate@browserid.me", &["https://mcp.example.com"]));
        // Plain-http return to a non-localhost host is refused even when the
        // audience itself is plain http.
        assert!(!ok("http://mcp.example.com/x",
            "gate@browserid.me", &["http://mcp.example.com"]));
        // Non-http(s) schemes and garbage are refused.
        assert!(!ok("javascript:alert(1)", "gate@browserid.me", &["https://mcp.example.com"]));
        assert!(!ok("ftp://mcp.example.com/x", "gate@browserid.me", &["https://mcp.example.com"]));
        assert!(!ok("https://", "gate@browserid.me", &["https://mcp.example.com"]));
        // A non-URL audience contributes nothing (but the identity rule may
        // still match).
        assert!(!ok("https://mcp.example.com/x", "gate@browserid.me", &["sbo+raw://x:y:1/"]));
        assert!(ok("https://browserid.me/x", "gate@browserid.me", &["sbo+raw://x:y:1/"]));
        // Host comparison is case-insensitive.
        assert!(ok("https://MCP.Example.Com/return",
            "gate@browserid.me", &["https://mcp.example.com"]));
    }

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

    /// The grantor pin on a warrant REQUEST (t1jp): `*`/absent leaves the
    /// choice to the approver (the page's dropdown); `self` pins the agent
    /// itself — normalized to the agent identity, which exists on this
    /// surface; anything else is a concrete pinned email.
    #[test]
    fn warrant_request_grantor_pin_normalizes() {
        let agent = "danmills+bsky@sandmill.org";
        assert_eq!(norm_warrant_grantor_pin(None, agent), "*");
        assert_eq!(norm_warrant_grantor_pin(Some(""), agent), "*");
        assert_eq!(norm_warrant_grantor_pin(Some("  "), agent), "*");
        assert_eq!(norm_warrant_grantor_pin(Some("*"), agent), "*");
        assert_eq!(norm_warrant_grantor_pin(Some("self"), agent), agent);
        assert_eq!(norm_warrant_grantor_pin(Some("SELF"), agent), agent);
        assert_eq!(
            norm_warrant_grantor_pin(Some("DanMills@Sandmill.org"), agent),
            "danmills@sandmill.org"
        );
        // An agent pinning its own email is the same as pinning `self`.
        assert_eq!(norm_warrant_grantor_pin(Some(agent), agent), agent);
    }

    /// A pinned request is approve/deny only: the approved grantor must equal
    /// the pin verbatim; `*` accepts whatever the (already ownership-gated)
    /// page chose. Mirrors the check in respond().
    #[test]
    fn respond_honors_the_grantor_pin() {
        let pinned_ok = |pin: &str, approved: &str| pin == "*" || approved == pin;
        assert!(pinned_ok("*", "danmills@sandmill.org"));
        assert!(pinned_ok("*", "danmills+bsky@sandmill.org"));
        assert!(pinned_ok("danmills@sandmill.org", "danmills@sandmill.org"));
        assert!(!pinned_ok("danmills@sandmill.org", "danmills+bsky@sandmill.org"));
        // A self pin (normalized to the agent) refuses an on-behalf approval.
        assert!(!pinned_ok("danmills+bsky@sandmill.org", "danmills@sandmill.org"));
    }
}
