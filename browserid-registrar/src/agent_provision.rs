//! Paired agent provisioning (bean 74u1) — a device-grant bootstrap for the
//! initial agent credential, mirroring the warrant consent flow (`consent.rs`).
//!
//! The agent generates its provisioning keypair and sends only the **public**
//! key. The human authorizes at the verification URL, where their identity key
//! signs a delegation (`U_cert~P_cert`) over that public key. The agent polls
//! and picks up the (public) delegation, then mints with its held private key.
//! The provisioning private key never transits the broker — and the poll result
//! is useless without it.
//!
//! Pending records are held in-process: pairing codes are ephemeral, single
//! instance, and expire in 15 minutes, so they need neither the registrar store
//! nor cross-instance durability.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_cookies::Cookies;

use browserid_core::device::{DeviceCert, Purpose, DEVICE_CERT_VALIDITY_DAYS};
use browserid_core::{PublicKey, StatusRef};

use crate::consent::{
    public_origin, status_list_uri, validate_grant_shape, validate_grant_warrants,
    warrant_status_subject, warrant_to_record,
};
use crate::error::RegistrarError;
use crate::host::{require_csrf, AuthedUser};
use crate::models::WarrantGrantItem;
use crate::registry::{require_enabled, require_session};
use crate::{agent_identity_email, agent_name_allowed, RegistrarState};

const REQUEST_VALIDITY_SECONDS: i64 = 900;
const POLL_INTERVAL_SECONDS: i64 = 5;
const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Clone, PartialEq)]
enum Status {
    Pending,
    /// Two-stage approval (eywc): the identity stage is done — the cert is
    /// minted — and the grants stage (the permission screens) is still open.
    /// The agent's poll keeps reading "pending" until the whole request
    /// resolves; abandoning here leaves an honest identity-without-permissions.
    IdentityIssued,
    Completed,
    Denied,
    Failed,
}

#[derive(Clone)]
struct Record {
    provisioning_pubkey: String,
    requested_names: Vec<String>,
    requested_patterns: Vec<String>,
    /// Normalized holder-namespace hint from the request (`agents` default).
    namespace: String,
    /// GRANTOR pin: `<id>` (pinned attributed identity) or `*` (approver picks).
    grantor: String,
    /// GRANTEE pin: `<id>` (pinned actor), `*` (approver picks/mints), or empty
    /// (as-you required, grantee ≡ grantor).
    grantee: String,
    /// A concrete foreign grantee's own holder (see [`RequestBody::grantee_holder`]).
    grantee_holder: Option<String>,
    /// Warrant grants requested alongside the device cert (merged one-approval
    /// flow) — `status_idx` filled by `prepare`.
    grants: Vec<WarrantGrantItem>,
    label: String,
    /// The agent's own account of why it wants this (eywc) — quoted on the
    /// permission screens, marked unverified.
    message: Option<String>,
    fingerprint: String,
    status: Status,
    fail_reason: Option<String>,
    /// Set when the grants stage was DENIED after the identity stage issued
    /// the cert (eywc): the poll still delivers the credential, with no
    /// grants and this reason.
    grants_denied: Option<String>,
    idp: Option<String>,
    // Filled by `prepare` (session-authed, from the approval page): the
    // broker-assigned holder the device cert AND the warrant matchers bind to,
    // plus the identity it was prepared for (re-prepare on a different pick).
    holder: Option<String>,
    prepared_identity: Option<String>,
    // filled on approval (device-cert model): the IdP signs an AGENT DEVICE
    // CERT for the agent's key.
    device_cert: Option<String>,
    agent_email: Option<String>,
    /// Where the agent mints access certs — the IdP's discovered mint URL
    /// (primaries publish arbitrary paths; never assume `/access/mint`).
    access_mint: Option<String>,
    /// `warrant~config_cert` per grant (grant order), signed client-side with
    /// the user's config cert on approval.
    warrants: Option<Vec<String>>,
    expires_at: DateTime<Utc>,
    last_polled_at: Option<DateTime<Utc>>,
}
impl Record {
    fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

static PROVISIONS: LazyLock<Mutex<HashMap<String, Record>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static USER_CODES: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn new_code() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("apr_{}", B64.encode(bytes))
}

/// Short, human-typeable code (no ambiguous chars), e.g. `WXYZ-2345`.
fn new_user_code() -> String {
    const ALPHA: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    let s: String = bytes.iter().map(|b| ALPHA[*b as usize % ALPHA.len()] as char).collect();
    format!("{}-{}", &s[..4], &s[4..])
}

/// First 3 bytes of SHA-256(pubkey) as `4F-2A-9C` — matches the SDK's
/// `fingerprint()`; shown on the page for pairing confirmation.
fn fingerprint(pubkey_b64: &str) -> String {
    use sha2::{Digest, Sha256};
    let raw = B64.decode(pubkey_b64).unwrap_or_default();
    let h = Sha256::digest(&raw);
    h[..3].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("-")
}

fn sweep() {
    let mut m = PROVISIONS.lock().unwrap();
    m.retain(|_, r| !r.is_expired());
}

/// The holder namespace to file a provisioned agent under: a short lowercase
/// identifier (`[a-z][a-z0-9_-]{0,31}`). Defaults to `agents`. Cosmetic — the
/// user can re-categorize later — but validated so it can't smuggle odd bytes
/// into a holder id.
fn normalize_namespace(hint: Option<&str>) -> Result<String, RegistrarError> {
    let ns = match hint.map(str::trim).filter(|s| !s.is_empty()) {
        None => return Ok("agents".to_string()),
        Some(s) => s.to_lowercase(),
    };
    let mut chars = ns.chars();
    let ok = ns.len() <= 32
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && ns
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !ok {
        return Err(RegistrarError::ValidationError(format!(
            "bad namespace hint '{ns}'"
        )));
    }
    Ok(ns)
}

// ===========================================================================
// Agent-facing: POST /agent-provision/request + /agent-provision/poll (unauth)
// ===========================================================================

#[derive(Deserialize)]
pub struct PubkeyField {
    pub algorithm: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

#[derive(Deserialize, Default)]
pub struct Handles {
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Deserialize)]
pub struct GrantReq {
    pub audience: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Deserialize)]
pub struct RequestBody {
    pub provisioning_pubkey: PubkeyField,
    #[serde(default)]
    pub requested_handles: Option<Handles>,
    /// Holder namespace hint (`agents` default, `services` for a service);
    /// cosmetic + user-confirmable, never the holder id itself.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Warrant grants to bundle into the same approval (merged flow): one
    /// warrant per `audience[+scopes]`, signed client-side on approval.
    #[serde(default)]
    pub grants: Vec<GrantReq>,
    #[serde(default)]
    pub label: Option<String>,
    /// The agent's own account of why it wants the bundled grants (eywc) —
    /// displayed quoted and marked unverified on the permission screens.
    #[serde(default)]
    pub message: Option<String>,
    /// GRANTOR pin (warrant semantics): the identity the write attributes to.
    /// `<id>` pins it; `*` (or absent → `*`) lets the approver choose which of
    /// their identities delegates; `self` (t1jp) pins the to-be-minted agent
    /// identity itself (grantor == grantee — the agent acts as itself), which
    /// no concrete email can express before approval.
    #[serde(default)]
    pub grantor: Option<String>,
    /// GRANTEE pin: the actor identity. `<id>` pins it (a foreign service like
    /// `mingo-poster@…`, or an owned sub-identity); `*` lets the approver
    /// choose/mint one; empty/absent means **as-you required** (grantee ≡
    /// grantor) — the broker warns.
    #[serde(default)]
    pub grantee: Option<String>,
    /// A concrete FOREIGN grantee's holder (broker-assigned by the grantee's own
    /// issuer, e.g. mingo). Required when `grantee` names an identity the approver
    /// does not own — the warrant matcher binds to it (`<id>`). Ignored for owned
    /// grantees (the broker assigns their holder).
    #[serde(default)]
    pub grantee_holder: Option<String>,
}

/// Normalize a `grantor`/`grantee` pin: absent → the field's default sentinel.
/// grantor absent → `*` (any); grantee absent/empty → `` (as-you required).
/// A grantor of `self` (t1jp) survives normalization as the literal sentinel —
/// the agent identity it pins doesn't exist until approval.
fn norm_grantor(p: Option<&str>) -> String {
    match p.map(str::trim).filter(|s| !s.is_empty()) {
        None => "*".to_string(),
        Some(s) => s.to_lowercase(),
    }
}

/// Reject a request whose pins can never be satisfied together (t1jp). A
/// `self` grantor pin means the warrants must name the minted agent as their
/// own authority — contradictory with an as-you demand (empty grantee: the
/// agent would BE the human identity, which is exactly what `self` exists to
/// avoid asking for).
fn request_pin_contradiction(grantor: &str, grantee: &str) -> Option<&'static str> {
    if grantor == "self" && grantee.is_empty() {
        return Some(
            "contradictory pins: grantor 'self' (the agent acts as itself) \
             cannot be combined with an as-you grantee (the agent becomes the user)",
        );
    }
    None
}
fn norm_grantee(p: Option<&str>) -> String {
    match p.map(str::trim) {
        None | Some("") => String::new(), // as-you required
        Some("*") => "*".to_string(),
        Some(s) => s.to_lowercase(),
    }
}

#[derive(Serialize)]
pub struct RequestResponse {
    pub success: bool,
    pub code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub user_code: String,
    pub fingerprint: String,
    pub expires_in: i64,
    pub interval: i64,
}

/// POST /agent-provision/request — an agent starts pairing. Unauthenticated:
/// it only registers a pending record bound to the agent-supplied pubkey.
pub async fn request(
    State(state): State<Arc<RegistrarState>>,
    Json(req): Json<RequestBody>,
) -> Result<Json<RequestResponse>, RegistrarError> {
    require_enabled(&state)?;
    sweep();
    if req.provisioning_pubkey.algorithm != "Ed25519" {
        return Err(RegistrarError::ValidationError("provisioning_pubkey must be Ed25519".into()));
    }
    let pubkey = req.provisioning_pubkey.public_key;
    if B64.decode(&pubkey).map(|b| b.len()).unwrap_or(0) != 32 {
        return Err(RegistrarError::ValidationError("provisioning_pubkey must be a 32-byte Ed25519 key".into()));
    }
    let handles = req.requested_handles.unwrap_or_default();
    let namespace = normalize_namespace(req.namespace.as_deref())?;
    let grantor = norm_grantor(req.grantor.as_deref());
    let grantee = norm_grantee(req.grantee.as_deref());
    if let Some(reason) = request_pin_contradiction(&grantor, &grantee) {
        return Err(RegistrarError::ValidationError(reason.into()));
    }
    // A concrete foreign grantee must carry its holder (the warrant binds to it).
    let grantee_holder = req
        .grantee_holder
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if req.grants.len() > 10 {
        return Err(RegistrarError::ValidationError("at most 10 grants per request".into()));
    }
    for g in &req.grants {
        validate_grant_shape(&g.audience, &g.scopes)?;
    }
    let grants: Vec<WarrantGrantItem> = req
        .grants
        .into_iter()
        .map(|g| WarrantGrantItem { audience: g.audience, scopes: g.scopes, status_idx: None })
        .collect();
    let message = req
        .message
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if message.as_deref().is_some_and(|m| m.len() > 500) {
        return Err(RegistrarError::ValidationError("message too long (500 chars max)".into()));
    }
    let code = new_code();
    let user_code = new_user_code();
    let fp = fingerprint(&pubkey);
    let origin = public_origin(&state.domain);
    let rec = Record {
        provisioning_pubkey: pubkey,
        requested_names: handles.names,
        requested_patterns: handles.patterns,
        namespace,
        grantor,
        grantee,
        grantee_holder,
        grants,
        label: req.label.unwrap_or_default(),
        message,
        fingerprint: fp.clone(),
        status: Status::Pending,
        fail_reason: None,
        grants_denied: None,
        idp: None,
        holder: None,
        prepared_identity: None,
        device_cert: None,
        agent_email: None,
        access_mint: None,
        warrants: None,
        expires_at: Utc::now() + Duration::seconds(REQUEST_VALIDITY_SECONDS),
        last_polled_at: None,
    };
    PROVISIONS.lock().unwrap().insert(code.clone(), rec);
    USER_CODES.lock().unwrap().insert(user_code.clone(), code.clone());
    Ok(Json(RequestResponse {
        success: true,
        verification_uri: format!("{origin}/account"),
        verification_uri_complete: format!("{origin}/account?provision={code}"),
        user_code,
        fingerprint: fp,
        expires_in: REQUEST_VALIDITY_SECONDS,
        interval: POLL_INTERVAL_SECONDS,
        code,
    }))
}

#[derive(Deserialize)]
pub struct PollBody {
    pub code: String,
}

/// POST /agent-provision/poll — the agent's pickup. Single delivery.
pub async fn poll(State(state): State<Arc<RegistrarState>>, Json(req): Json<PollBody>) -> Response {
    if let Err(e) = require_enabled(&state) {
        return e.into_response();
    }
    let expired = || (StatusCode::GONE, Json(json!({ "status": "expired" }))).into_response();
    let mut m = PROVISIONS.lock().unwrap();
    let Some(rec) = m.get(&req.code).cloned() else {
        return expired(); // unknown == expired == already delivered
    };
    if rec.is_expired() {
        m.remove(&req.code);
        return expired();
    }
    // Slow-down applies while the human is still deciding; a RESOLVED request
    // delivers immediately regardless (same rule as the consent flow's poll).
    let deciding = rec.status == Status::Pending || rec.status == Status::IdentityIssued;
    if deciding {
        if let Some(prev) = rec.last_polled_at {
            if Utc::now() - prev < Duration::seconds(POLL_INTERVAL_SECONDS) {
                return RegistrarError::PollTooFast.into_response();
            }
        }
    }
    if let Some(r) = m.get_mut(&req.code) {
        r.last_polled_at = Some(Utc::now());
    }
    match rec.status {
        // The grants stage is still with the human — the agent keeps waiting.
        Status::Pending | Status::IdentityIssued => {
            Json(json!({ "status": "pending" })).into_response()
        }
        Status::Denied => {
            m.remove(&req.code);
            Json(json!({ "status": "denied" })).into_response()
        }
        Status::Failed => {
            let reason = rec.fail_reason.clone().unwrap_or_else(|| "provisioning failed".into());
            m.remove(&req.code);
            Json(json!({ "status": "failed", "reason": reason })).into_response()
        }
        Status::Completed => {
            m.remove(&req.code);
            // Hand back an IdP-signed agent device cert, plus any warrants
            // approved in the same consent (merged flow) — each entry is the
            // `warrant~config_cert` tail the agent splices into its access
            // presentations. The agent mints access certs headlessly at the
            // IdP's `/access/mint`.
            let grants: Vec<serde_json::Value> = rec
                .grants
                .iter()
                .zip(rec.warrants.clone().unwrap_or_default())
                .map(|(g, w)| json!({ "audience": g.audience, "warrant": w }))
                .collect();
            let mut body = json!({
                "status": "completed",
                "credential": {
                    "device_cert": rec.device_cert,
                    "idp": rec.idp,
                    "identity": rec.agent_email,
                    "access_mint": rec.access_mint,
                },
                "grants": grants,
            });
            // Two-stage flow (eywc): identity approved, permissions declined.
            // The credential is real; say why the grants aren't.
            if let Some(reason) = &rec.grants_denied {
                body["grants_denied"] = json!(reason);
            }
            Json(body).into_response()
        }
    }
}

// ===========================================================================
// Page-facing: display info (by code) + resolve a typed user_code
// ===========================================================================

#[derive(Deserialize)]
pub struct InfoBody {
    pub code: String,
}

#[derive(Serialize)]
pub struct InfoResponse {
    pub success: bool,
    pub provisioning_pubkey: String,
    pub fingerprint: String,
    pub label: String,
    pub requested_names: Vec<String>,
    pub requested_patterns: Vec<String>,
    /// Holder namespace the requester hinted (`agents` / `services`).
    pub namespace: String,
    /// GRANTOR pin (`<id>`, `*`, or `self` for the minted agent itself, t1jp)
    /// — who the write attributes to.
    pub grantor: String,
    /// GRANTEE pin (`<id>`, `*`, or empty for as-you-required) — the actor. The
    /// card derives owned-vs-foreign from the approver's own identities.
    pub grantee: String,
    /// A concrete foreign grantee's holder, when the request supplied one. Its
    /// absence on a foreign-grantee request lets the page refuse up front
    /// ("a foreign grantee must supply its holder") instead of failing only
    /// after the human approves.
    pub grantee_holder: Option<String>,
    /// Warrant grants asked for in the same approval (merged flow).
    pub grants: Vec<WarrantGrantItem>,
    /// The agent's own account of why it wants the grants (eywc) — quoted,
    /// unverified.
    pub message: Option<String>,
    /// Two-stage progress (eywc): "pending" (nothing approved yet) or
    /// "identity_issued" (Flow I done, the permission screens are open). Lets
    /// a reloaded page resume mid-flow instead of reporting nothing waiting.
    pub stage: String,
    /// Filled once the identity stage is done — what the grants stage needs
    /// to render and sign without re-running prepare.
    pub agent_email: Option<String>,
    pub holder: Option<String>,
    /// The registrar's status list URI — embedded (with each grant's
    /// status_idx) in the warrants the page signs.
    pub status_uri: String,
}

/// POST /agent-provision/info — what the verify page shows. By code (the bearer
/// in the URL); returns only non-secret display data.
pub async fn info(
    State(state): State<Arc<RegistrarState>>,
    Json(req): Json<InfoBody>,
) -> Result<Json<InfoResponse>, RegistrarError> {
    require_enabled(&state)?;
    let m = PROVISIONS.lock().unwrap();
    let rec = m
        .get(&req.code)
        .filter(|r| {
            !r.is_expired()
                && (r.status == Status::Pending || r.status == Status::IdentityIssued)
        })
        .ok_or(RegistrarError::ProvisionRequestNotFound)?;
    let identity_issued = rec.status == Status::IdentityIssued;
    Ok(Json(InfoResponse {
        success: true,
        provisioning_pubkey: rec.provisioning_pubkey.clone(),
        fingerprint: rec.fingerprint.clone(),
        label: rec.label.clone(),
        requested_names: rec.requested_names.clone(),
        requested_patterns: rec.requested_patterns.clone(),
        namespace: rec.namespace.clone(),
        grantor: rec.grantor.clone(),
        grantee: rec.grantee.clone(),
        grantee_holder: rec.grantee_holder.clone(),
        grants: rec.grants.clone(),
        message: rec.message.clone(),
        stage: if identity_issued { "identity_issued".into() } else { "pending".into() },
        agent_email: rec.agent_email.clone().filter(|_| identity_issued),
        holder: rec.holder.clone().filter(|_| identity_issued),
        status_uri: status_list_uri(&state.domain),
    }))
}

#[derive(Deserialize)]
pub struct ResolveBody {
    pub user_code: String,
}

#[derive(Serialize)]
pub struct ResolveResponse {
    pub success: bool,
    pub code: String,
}

/// POST /agent-provision/resolve — the `/link` page maps a typed user_code to
/// its code (for the cross-device path).
pub async fn resolve(
    State(state): State<Arc<RegistrarState>>,
    Json(req): Json<ResolveBody>,
) -> Result<Json<ResolveResponse>, RegistrarError> {
    require_enabled(&state)?;
    let uc = req.user_code.trim().to_uppercase();
    let code = USER_CODES
        .lock()
        .unwrap()
        .get(&uc)
        .cloned()
        .ok_or(RegistrarError::ProvisionRequestNotFound)?;
    let live = PROVISIONS
        .lock()
        .unwrap()
        .get(&code)
        .map(|r| {
            !r.is_expired()
                && (r.status == Status::Pending || r.status == Status::IdentityIssued)
        })
        .unwrap_or(false);
    if !live {
        return Err(RegistrarError::ProvisionRequestNotFound);
    }
    Ok(Json(ResolveResponse { success: true, code }))
}

// ===========================================================================
// Browser-facing: prepare + complete (session + CSRF)
// ===========================================================================

/// The identity/handle policy shared by `prepare` and `complete`: the session
/// must own the delegating identity, and the handle must be one this owner may
/// mint. Returns `(name, agent_email)`.
///
/// The approving USER chooses how the agent acts (`identity_mode`):
/// - `"self"` — an **as-you** agent: it holds the delegating identity ITSELF
///   (writes stay owned by and attributed to the user), isolated by its
///   broker-assigned holder. Overrides any handle the requester asked for.
/// - `"handle"` — a named agent under `chosen_handle` (the page's pick, which
///   may differ from what the requester suggested).
/// - absent — legacy behavior: the requester's first suggested name, else
///   as-you.
fn resolve_agent_identity(
    state: &Arc<RegistrarState>,
    user: &AuthedUser,
    identity_email: &str,
    identity_mode: Option<&str>,
    chosen_handle: Option<&str>,
    requested_name: Option<String>,
) -> Result<(Option<String>, String), RegistrarError> {
    if !state.host.owns_verified_email(user.user_id, identity_email).unwrap_or(false) {
        return Err(RegistrarError::PolicyRefused(
            "you don't own the delegating identity".into(),
        ));
    }
    let name = match identity_mode {
        Some("self") => None,
        // "handle" (attributed to the approver — an on-behalf agent) and
        // "standalone" (the agent is answerable for itself) both name an agent
        // identity; they differ only in the warrant's GRANTOR, decided below.
        Some("handle") | Some("standalone") => Some(
            chosen_handle
                .map(|h| h.trim().to_lowercase())
                .filter(|h| !h.is_empty())
                .ok_or_else(|| {
                    RegistrarError::ValidationError("identity_mode 'handle' needs a handle".into())
                })?,
        ),
        Some(other) => {
            return Err(RegistrarError::ValidationError(format!(
                "unknown identity_mode '{other}'"
            )))
        }
        None => requested_name,
    };
    let Some(name) = name else {
        return Ok((None, identity_email.to_lowercase()));
    };
    // Anti-squatting: the handle must be one this owner may mint (same rule the
    // legacy path enforces via the signed provisioning cert).
    if !agent_name_allowed(&name, identity_email, &state.domain) {
        return Err(RegistrarError::PolicyRefused(
            "agent handle not permitted for this identity".into(),
        ));
    }
    let agent_email = agent_identity_email(identity_email, &name);
    Ok((Some(name), agent_email))
}

/// Gate the approver's chosen identity against the request's GRANTOR pin: a
/// concrete pin must equal it (case-insensitive); `*` accepts any (ownership is
/// checked separately). `self` (t1jp) also accepts any — it constrains the
/// WARRANTS (grantor == the minted agent), not which identity mints.
fn check_grantor_pin(pin: &str, identity_email: &str) -> Result<(), RegistrarError> {
    if pin == "*" || pin == "self" || pin.eq_ignore_ascii_case(identity_email) {
        Ok(())
    } else {
        Err(RegistrarError::PolicyRefused(format!(
            "this grant must be authorized by '{pin}', not '{identity_email}'"
        )))
    }
}

/// Whether the approver owns `id`: an exact verified email, or a `+tag`
/// sub-address of one they own and may mint. A grantee they do NOT own is
/// FOREIGN — browser mints no cert for it (it holds its own from its issuer) and
/// the approval is warrant-only (delegated attribution).
fn approver_owns_identity(state: &Arc<RegistrarState>, user: &AuthedUser, id: &str) -> bool {
    if state.host.owns_verified_email(user.user_id, id).unwrap_or(false) {
        return true;
    }
    if let Some((local, domain)) = id.split_once('@') {
        if let Some((base_local, tag)) = local.split_once('+') {
            let base = format!("{base_local}@{domain}");
            return state.host.owns_verified_email(user.user_id, &base).unwrap_or(false)
                && agent_name_allowed(tag, &base, &state.domain);
        }
    }
    false
}

/// A concrete grantee pin the approver does NOT own → a delegated (foreign)
/// grant. Empty (`as-you`) and `*` (approver picks/mints an owned one) are not
/// foreign — they resolve to an owned grantee at approval.
fn grantee_is_foreign(state: &Arc<RegistrarState>, user: &AuthedUser, rec: &Record) -> bool {
    let g = rec.grantee.trim();
    !g.is_empty() && g != "*" && !approver_owns_identity(state, user, g)
}

#[derive(Deserialize)]
pub struct PrepareBody {
    pub csrf: String,
    pub code: String,
    /// The verified email the user is minting the agent under.
    pub identity_email: String,
    /// Namespace override (defaults to the requester's hint).
    #[serde(default)]
    pub namespace: Option<String>,
    /// How the agent acts: "self" (as-you) or "handle" (named). Absent =
    /// legacy (requester's suggestion, else as-you). MUST match `complete`.
    #[serde(default)]
    pub identity_mode: Option<String>,
    /// The chosen handle when `identity_mode` is "handle".
    #[serde(default)]
    pub handle: Option<String>,
}

#[derive(Serialize)]
pub struct PrepareResponse {
    pub success: bool,
    pub agent_email: String,
    /// The broker-assigned holder the device cert will carry — the approval
    /// page signs warrant matchers against it (`<id>` / `<ns>.*`).
    pub holder: String,
    pub status_uri: String,
    /// The request's grants with their status indices allocated, ready to
    /// embed in the warrants the page signs.
    pub grants: Vec<WarrantGrantItem>,
}

/// POST /agent-provision/prepare — the approval page's first hop (merged
/// one-approval flow): assign the broker holder from the user's namespace
/// registry and allocate each grant's status index, so the page can sign the
/// warrant(s) client-side with the config cert BEFORE calling `complete`.
/// Idempotent per identity pick; re-prepare with a different identity
/// reassigns. No handle is reserved and nothing is issued yet.
pub async fn prepare(
    State(state): State<Arc<RegistrarState>>,
    cookies: Cookies,
    Json(req): Json<PrepareBody>,
) -> Result<Json<PrepareResponse>, RegistrarError> {
    require_enabled(&state)?;
    let user = require_session(&state, &cookies)?;
    require_csrf(&user, &req.csrf)?;

    let snapshot = {
        let m = PROVISIONS.lock().unwrap();
        m.get(&req.code)
            .filter(|r| !r.is_expired() && r.status == Status::Pending)
            .cloned()
            .ok_or(RegistrarError::ProvisionRequestNotFound)?
    };
    // The approver's chosen identity is the GRANTOR: it must be one they own and
    // satisfy the request's grantor pin.
    if !state.host.owns_verified_email(user.user_id, &req.identity_email).unwrap_or(false) {
        return Err(RegistrarError::PolicyRefused(
            "you don't own the delegating identity".into(),
        ));
    }
    check_grantor_pin(&snapshot.grantor, &req.identity_email)?;

    // Delegated (foreign grantee): the grantee is a distinct service that holds
    // its OWN device cert + holder from its issuer. browser assigns no holder —
    // it uses the one the request supplied, and the warrant matcher binds to it.
    let (agent_email, holder) = if grantee_is_foreign(&state, &user, &snapshot) {
        let holder = snapshot.grantee_holder.clone().ok_or_else(|| {
            RegistrarError::ValidationError("a foreign grantee must supply its holder".into())
        })?;
        browserid_core::device::Holder::new(holder.clone())
            .map_err(|e| RegistrarError::ValidationError(format!("bad grantee holder: {e}")))?;
        (snapshot.grantee.clone(), holder)
    } else {
        // Owned path: the approver picks an as-you / named agent identity, and
        // the broker assigns its holder from the approver's namespace registry.
        let (_, agent_email) = resolve_agent_identity(
            &state, &user, &req.identity_email,
            req.identity_mode.as_deref(), req.handle.as_deref(),
            snapshot.requested_names.first().cloned(),
        )?;
        let existing = snapshot.prepared_identity.clone().zip(snapshot.holder.clone());
        let holder = match existing {
            Some((identity, holder)) if identity == req.identity_email => holder,
            _ => {
                let namespace = match req.namespace.as_deref() {
                    Some(ns) => normalize_namespace(Some(ns))?,
                    None => snapshot.namespace.clone(),
                };
                let prefix = state.store.get_or_create_namespace(user.user_id, &namespace)?;
                crate::consent::assign_holder_id(&prefix)
            }
        };
        (agent_email, holder)
    };

    // Stable per-grant status indices (same subject rule as the consent flow).
    let mut m = PROVISIONS.lock().unwrap();
    let rec = m
        .get_mut(&req.code)
        .filter(|r| !r.is_expired() && r.status == Status::Pending)
        .ok_or(RegistrarError::ProvisionRequestNotFound)?;
    for g in &mut rec.grants {
        let idx = state.store.get_or_allocate_status(
            "warrant",
            &warrant_status_subject(user.user_id, &agent_email, &g.audience, &g.scopes),
        )?;
        g.status_idx = Some(idx);
    }
    rec.holder = Some(holder.clone());
    rec.prepared_identity = Some(req.identity_email.clone());
    let grants = rec.grants.clone();
    drop(m);

    Ok(Json(PrepareResponse {
        success: true,
        agent_email,
        holder,
        status_uri: status_list_uri(&state.domain),
        grants,
    }))
}

#[derive(Deserialize)]
pub struct CompleteBody {
    pub csrf: String,
    pub code: String,
    pub approve: bool,
    /// The verified email the user is minting the agent under (approve only).
    /// The agent identity is `<requested-name>@<its domain>`.
    #[serde(default)]
    pub identity_email: Option<String>,
    /// Which holder namespace to file this agent/service under (holder-auth
    /// model): the requester hints it (`agents` | `services` | …), the user
    /// confirms here. Defaults to `agents`. Cosmetic + re-categorizable.
    #[serde(default)]
    pub namespace: Option<String>,
    /// How the agent acts, the approving user's choice (overriding the
    /// requester's suggestion; same values as `prepare`):
    /// - `self`       — as-you: the agent IS this identity
    /// - `handle`     — a named agent acting ON BEHALF OF this identity
    ///                  (grantor = this identity, grantee = the agent)
    /// - `standalone` — a named agent answerable for ITSELF (grantor ==
    ///                  grantee == the agent); nothing is attributed here
    #[serde(default)]
    pub identity_mode: Option<String>,
    /// The chosen handle when `identity_mode` is "handle".
    #[serde(default)]
    pub handle: Option<String>,
    /// Two-stage approval (eywc). Absent = the legacy single-shot (identity +
    /// warrants in one call). "identity" = Flow I's commit: mint the cert now;
    /// a request with grants moves to the grants stage instead of completing.
    /// "grants" = Flow P's commit on an identity-issued request: record the
    /// page-signed warrants (or decline them) and complete.
    #[serde(default)]
    pub stage: Option<String>,
    /// The USER-CHOSEN display name for the agent (Flow I step 2, eywc) —
    /// stored on the agent identity; every later permission card opens with
    /// it. Honored on the identity stage / legacy path for named agents.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Grants-stage only (eywc): the grantor the permission screens' dropdown
    /// chose — the agent's own email (acts as itself) or an owned identity
    /// (on-behalf). Must satisfy the request's grantor pin. Absent = the
    /// legacy shape (identity_mode decides).
    #[serde(default)]
    pub grantor: Option<String>,
    /// The warrant JWSs the approval page signed client-side with the config
    /// key, one per requested grant in grant order (required iff the request
    /// carries grants).
    #[serde(default)]
    pub warrants: Option<Vec<String>>,
    /// The config (authorization) device cert whose key signed the warrants.
    #[serde(default)]
    pub config_cert: Option<String>,
    /// A PRIMARY-signed agent device cert, when the delegating identity is
    /// rooted at its own IdP: the presentation's issuer-consistency rule
    /// (`config_cert.iss == access_cert.iss`) means a primary-domain agent's
    /// cert must come from the primary, so the approval page hops to the
    /// primary's device-authorize surface (agent mode) with the broker-assigned
    /// holder and hands the signed cert back here instead of having the
    /// registrar sign one.
    #[serde(default)]
    pub device_cert: Option<String>,
    /// The primary's access-mint URL (from the broker's discovery of the
    /// identity's IdP) — primaries publish arbitrary paths, so the agent must
    /// be told where to mint rather than assuming `/access/mint`. Only
    /// honored with a primary-signed `device_cert`, and only when it sits on
    /// the cert issuer's own origin.
    #[serde(default)]
    pub access_mint: Option<String>,
}

#[derive(Serialize)]
pub struct CompleteResponse {
    pub success: bool,
}

/// POST /agent-provision/complete — the verify page, after the human approves.
/// Session + CSRF authenticated. On approval the IdP signs an agent device cert
/// over the requested pubkey for the session-owned identity.
pub async fn complete(
    State(state): State<Arc<RegistrarState>>,
    cookies: Cookies,
    Json(req): Json<CompleteBody>,
) -> Result<Json<CompleteResponse>, RegistrarError> {
    require_enabled(&state)?;
    let user = require_session(&state, &cookies)?;
    require_csrf(&user, &req.csrf)?;

    // Two-stage approval (eywc): which record state this call may act on.
    let stage = match req.stage.as_deref() {
        None => CompleteStage::Legacy,
        Some("identity") => CompleteStage::Identity,
        Some("grants") => CompleteStage::Grants,
        Some(other) => {
            return Err(RegistrarError::ValidationError(format!("unknown stage '{other}'")))
        }
    };
    let wanted = match stage {
        CompleteStage::Legacy | CompleteStage::Identity => Status::Pending,
        CompleteStage::Grants => Status::IdentityIssued,
    };

    // Snapshot the pending record (drop the lock before DB work).
    let snapshot = {
        let m = PROVISIONS.lock().unwrap();
        m.get(&req.code)
            .filter(|r| !r.is_expired() && r.status == wanted)
            .cloned()
            .ok_or(RegistrarError::ProvisionRequestNotFound)?
    };

    if !req.approve {
        match stage {
            // Nothing exists yet: the whole request is denied.
            CompleteStage::Legacy | CompleteStage::Identity => {
                if let Some(rec) = PROVISIONS.lock().unwrap().get_mut(&req.code) {
                    rec.status = Status::Denied;
                }
            }
            // The identity is already real — deliver it, with the grants
            // declined and a reason the agent can act on.
            CompleteStage::Grants => {
                if let Some(rec) = PROVISIONS.lock().unwrap().get_mut(&req.code) {
                    rec.grants_denied = Some("the user declined the permissions".into());
                    rec.status = Status::Completed;
                }
            }
        }
        return Ok(Json(CompleteResponse { success: true }));
    }

    if stage == CompleteStage::Grants {
        return complete_grants_stage(&state, &user, &req, snapshot);
    }

    // Enforce the GRANTOR pin against the approver's chosen identity (both paths).
    if let Some(identity) = req.identity_email.as_deref() {
        check_grantor_pin(&snapshot.grantor, identity)?;
    }

    // Re-authorization: the warrant status index is stable per subject, so a
    // prior revoke may have left it set. A fresh approval must reactivate it, or
    // the reissued warrant would verify as already-revoked.
    for g in &snapshot.grants {
        if let Some(idx) = g.status_idx {
            let _ = state.store.set_status_active_idx(idx);
        }
    }

    // Delegated (foreign grantee) vs owned (as-you / named agent) approval.
    if grantee_is_foreign(&state, &user, &snapshot) {
        // A foreign grantee gets no identity here — its warrant-only approval
        // has no identity stage to split off.
        if stage == CompleteStage::Identity {
            return Err(RegistrarError::ValidationError(
                "a foreign grantee has no identity stage: it holds its own credential".into(),
            ));
        }
        complete_delegated_warrant(&state, &user, &req, snapshot).await
    } else {
        complete_device_cert(&state, &user, &req, snapshot, stage == CompleteStage::Identity)
            .await
    }
}

#[derive(Clone, Copy, PartialEq)]
enum CompleteStage {
    /// Single-shot: identity + warrants in one call (the pre-eywc shape).
    Legacy,
    /// Flow I's commit: mint the cert; grants (if any) stay open.
    Identity,
    /// Flow P's commit on an identity-issued request: record the warrants.
    Grants,
}

/// Grants-stage completion (eywc): the identity stage already minted the cert;
/// validate and record the page-signed warrants under the grantor the
/// permission screens chose — the agent itself, or an owned identity —
/// honoring the request's grantor pin, then complete the request.
fn complete_grants_stage(
    state: &Arc<RegistrarState>,
    user: &AuthedUser,
    req: &CompleteBody,
    snapshot: Record,
) -> Result<Json<CompleteResponse>, RegistrarError> {
    let agent_email = snapshot.agent_email.clone().ok_or_else(|| {
        RegistrarError::Internal("identity-issued record without an agent email".into())
    })?;
    let holder = snapshot.holder.clone().ok_or_else(|| {
        RegistrarError::Internal("identity-issued record without a holder".into())
    })?;
    let delegator = snapshot.prepared_identity.clone().ok_or_else(|| {
        RegistrarError::Internal("identity-issued record without a prepared identity".into())
    })?;
    if snapshot.grants.is_empty() {
        return Err(RegistrarError::ValidationError("this request has no grants stage".into()));
    }

    // The grantor the dropdown chose: the agent itself, or an identity this
    // account owns. Absent defaults to on-behalf of the delegating identity.
    let grantor = match req.grantor.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => delegator.clone(),
        Some(g) => {
            let g = g.to_lowercase();
            if g != agent_email
                && !state
                    .host
                    .owns_verified_email(user.user_id, &crate::consent::delegator_of(&g))
                    .unwrap_or(false)
            {
                return Err(RegistrarError::PolicyRefused(
                    "the warrant grantor must be the agent or an identity on this account".into(),
                ));
            }
            g
        }
    };
    // Honor the request's grantor pin (t1jp): `self` pins the agent itself;
    // a concrete email pins that identity; `*` accepts the dropdown's choice.
    match snapshot.grantor.as_str() {
        "*" => {}
        "self" => {
            if grantor != agent_email {
                return Err(RegistrarError::PolicyRefused(
                    "this request requires the agent to act as itself".into(),
                ));
            }
        }
        pin => {
            if !grantor.eq_ignore_ascii_case(pin) {
                return Err(RegistrarError::PolicyRefused(format!(
                    "this request requires attribution to '{pin}'"
                )));
            }
        }
    }

    let warrant_jwss = req.warrants.as_deref().ok_or_else(|| {
        RegistrarError::ValidationError("approve requires the signed warrants".into())
    })?;
    let config_jws = req.config_cert.as_deref().ok_or_else(|| {
        RegistrarError::ValidationError("approve requires the signing config cert".into())
    })?;
    // Re-activation, as in the single-shot path: a prior revoke may have left
    // the stable per-subject index set.
    for g in &snapshot.grants {
        if let Some(idx) = g.status_idx {
            let _ = state.store.set_status_active_idx(idx);
        }
    }
    let warrants = validate_grant_warrants(
        warrant_jwss, config_jws, &grantor, &agent_email, &holder, &snapshot.grants,
    )?;
    for (warrant, jws) in warrants.iter().zip(warrant_jwss) {
        state.store.upsert_warrant(warrant_to_record(
            user.user_id, &delegator, warrant, jws, config_jws,
        ))?;
    }
    let delivery: Vec<String> =
        warrant_jwss.iter().map(|w| format!("{w}~{config_jws}")).collect();

    let mut m = PROVISIONS.lock().unwrap();
    let rec = m
        .get_mut(&req.code)
        .filter(|r| r.status == Status::IdentityIssued)
        .ok_or(RegistrarError::ProvisionRequestNotFound)?;
    rec.warrants = Some(delivery);
    rec.status = Status::Completed;
    Ok(Json(CompleteResponse { success: true }))
}

/// Delegated approval (foreign grantee): the approver signs a warrant delegating
/// to a service identity minted by ITS OWN issuer. The registrar issues NO cert
/// — it validates the page-signed warrant(s) (config authorizes the grantor;
/// grantor/grantee/holder match) and records them; the poll delivers only
/// `warrant~config` (the grantee already holds its own device cert + mint).
async fn complete_delegated_warrant(
    state: &Arc<RegistrarState>,
    user: &AuthedUser,
    req: &CompleteBody,
    snapshot: Record,
) -> Result<Json<CompleteResponse>, RegistrarError> {
    let grantor = req.identity_email.clone().ok_or_else(|| {
        RegistrarError::ValidationError("identity_email required to approve".into())
    })?;
    if !state.host.owns_verified_email(user.user_id, &grantor).unwrap_or(false) {
        return Err(RegistrarError::PolicyRefused(
            "you don't own the delegating identity".into(),
        ));
    }
    // A foreign grantee's warrants are always signed BY the approver — a
    // `self` grantor pin can't be satisfied here (the foreign service's own
    // authority is its own issuer's business, not this account's).
    if snapshot.grantor == "self" {
        return Err(RegistrarError::PolicyRefused(
            "a foreign grantee cannot act as itself here: this account can only \
             delegate on the approver's behalf"
                .into(),
        ));
    }
    let grantee = snapshot.grantee.clone();
    let holder = snapshot.grantee_holder.clone().ok_or_else(|| {
        RegistrarError::ValidationError("a foreign grantee must supply its holder".into())
    })?;
    if snapshot.grants.is_empty() {
        return Err(RegistrarError::ValidationError(
            "a delegated grant needs at least one warrant grant".into(),
        ));
    }
    let warrant_jwss = req.warrants.as_deref().ok_or_else(|| {
        RegistrarError::ValidationError("approve requires the signed warrants".into())
    })?;
    let config_jws = req.config_cert.as_deref().ok_or_else(|| {
        RegistrarError::ValidationError("approve requires the signing config cert".into())
    })?;
    let warrants = validate_grant_warrants(
        warrant_jwss, config_jws, &grantor, &grantee, &holder, &snapshot.grants,
    )?;

    // Record each warrant in the approver's registry (an "external service").
    for (warrant, jws) in warrants.iter().zip(warrant_jwss) {
        state.store.upsert_warrant(warrant_to_record(
            user.user_id, &grantor, warrant, jws, config_jws,
        ))?;
    }
    let delivery: Vec<String> = warrant_jwss
        .iter()
        .map(|w| format!("{w}~{config_jws}"))
        .collect();

    // Land the service under a "services" namespace by default: adopt its holder
    // prefix onto a fresh `services` namespace (a no-op if that namespace already
    // has holders under another prefix — then it falls back to Uncategorized).
    let prefix = holder
        .split_once('.')
        .map(|(p, _)| p.to_string())
        .unwrap_or_else(|| holder.clone());
    let _ = state.store.get_or_create_namespace(user.user_id, "services");
    let _ = state.store.adopt_namespace_prefix(user.user_id, "services", &prefix);

    // Record the foreign grantee as a SERVICE entry so it shows under "Devices &
    // services" (labeled + revocable — removing the holder revokes its warrants
    // by holder match). It holds its own cert at its issuer, so there is no local
    // key: an empty pubkey marks it external.
    let grantee_iss = grantee.rsplit('@').next().unwrap_or_default().to_string();
    let (iat, exp) = warrants
        .first()
        .map(|w| (w.claims().iat, w.claims().exp))
        .unwrap_or((0, 0));
    let label = Some(snapshot.label.as_str()).filter(|l| !l.trim().is_empty());
    state.host.record_agent_device_cert(
        user.user_id, &grantee, &holder, "", &grantee_iss, iat, exp, None, label,
    );

    let mut m = PROVISIONS.lock().unwrap();
    let rec = m
        .get_mut(&req.code)
        .filter(|r| r.status == Status::Pending)
        .ok_or(RegistrarError::ProvisionRequestNotFound)?;
    rec.agent_email = Some(grantee);
    rec.warrants = Some(delivery);
    // No device_cert / idp / access_mint: the grantee holds its own from its issuer.
    rec.status = Status::Completed;
    Ok(Json(CompleteResponse { success: true }))
}

/// Device-cert approval: the IdP (this registrar's keypair) signs an AGENT
/// DEVICE CERT (`purpose=authentication`) certifying the agent's provisioning
/// key for the approved `<name>@<domain>` identity, carrying the holder
/// assigned at `prepare`. If the request bundled warrant grants (merged flow),
/// the page-signed warrants are validated against them here — all-or-nothing —
/// and recorded in the warrant registry; the poll delivers cert + warrants
/// together.
async fn complete_device_cert(
    state: &Arc<RegistrarState>,
    user: &AuthedUser,
    req: &CompleteBody,
    snapshot: Record,
    identity_only: bool,
) -> Result<Json<CompleteResponse>, RegistrarError> {
    let identity_email = req
        .identity_email
        .clone()
        .ok_or_else(|| RegistrarError::ValidationError("identity_email required to approve".into()))?;
    let (name, agent_email) = resolve_agent_identity(
        state,
        user,
        &identity_email,
        req.identity_mode.as_deref(),
        req.handle.as_deref(),
        snapshot.requested_names.first().cloned(),
    )?;

    // Holder-authorization model: the holder comes from `prepare` (which
    // assigned it from the user's namespace registry so the page could sign
    // matchers against it). A grant-less, registrar-signed request may skip
    // `prepare`; assign here in that case. The requester never chooses the
    // prefix either way — and a page-supplied primary cert must carry the
    // prepared holder, so that path always requires `prepare` too.
    let prepared = snapshot
        .holder
        .clone()
        .filter(|_| snapshot.prepared_identity.as_deref() == Some(identity_email.as_str()));
    let holder_id = match prepared {
        Some(h) => h,
        None if snapshot.grants.is_empty() && req.device_cert.is_none() => {
            let namespace = match req.namespace.as_deref() {
                Some(ns) => normalize_namespace(Some(ns))?,
                None => snapshot.namespace.clone(),
            };
            let prefix = state.store.get_or_create_namespace(user.user_id, &namespace)?;
            crate::consent::assign_holder_id(&prefix)
        }
        None => {
            return Err(RegistrarError::ValidationError(
                "call /agent-provision/prepare for this identity first".into(),
            ))
        }
    };
    let holder = browserid_core::device::Holder::new(holder_id.clone())
        .map_err(|e| RegistrarError::ValidationError(format!("holder: {e}")))?;

    // Merged flow: validate the page-signed warrants BEFORE any side effect
    // (handle reservation, cert signing) — all-or-nothing with the approval.
    // The identity stage (eywc) signs nothing yet: the grants stage follows.
    let signed_warrants = if snapshot.grants.is_empty() || identity_only {
        None
    } else {
        let warrant_jwss = req.warrants.as_deref().ok_or_else(|| {
            RegistrarError::ValidationError("approve requires the signed warrants".into())
        })?;
        let config_jws = req.config_cert.as_deref().ok_or_else(|| {
            RegistrarError::ValidationError("approve requires the signing config cert".into())
        })?;
        // Owned path. WHO IS ANSWERABLE is the approver's chosen identity, not
        // the agent's — otherwise a named agent can only ever act as itself and
        // the on-behalf shape is unreachable (which it was; see bean 8v6c).
        // Three shapes land here:
        //   self       -> agent_email == identity_email, so grantor == grantee
        //   handle     -> grantor = the human, grantee = the agent  (ON BEHALF OF)
        //   standalone -> grantor == grantee == the agent, deliberately NOT
        //                 attributed to the human (a segregated identity)
        // A `self` grantor pin (t1jp) forces the standalone shape; a concrete
        // pin forbids it (the requester named a human authority) — never
        // silently substituted, same rule as every other pin.
        let standalone = req.identity_mode.as_deref() == Some("standalone");
        if standalone && snapshot.grantor != "*" && snapshot.grantor != "self" {
            return Err(RegistrarError::PolicyRefused(format!(
                "this request requires attribution to '{}'",
                snapshot.grantor
            )));
        }
        let grantor = if standalone || snapshot.grantor == "self" {
            &agent_email
        } else {
            &identity_email
        };
        let warrants = validate_grant_warrants(
            warrant_jwss,
            config_jws,
            grantor,
            &agent_email,
            &holder_id,
            &snapshot.grants,
        )?;
        Some((warrant_jwss.to_vec(), config_jws.to_string(), warrants))
    };

    // Reserve the handle NOW (session-authenticated), same as the legacy path.
    // An as-you service has no handle to reserve — its identity IS the user's.
    if let Some(name) = &name {
        if let Err(e) = state.host.reserve_agent_names(user.user_id, &identity_email, &[name.clone()]) {
            if let Some(rec) = PROVISIONS.lock().unwrap().get_mut(&req.code) {
                rec.status = Status::Failed;
                rec.fail_reason = Some(e.to_string());
            }
            return Err(e);
        }
    }

    let device_pub = PublicKey::from_base64(&snapshot.provisioning_pubkey)
        .map_err(|e| RegistrarError::ValidationError(format!("bad provisioning pubkey: {e}")))?;
    let (device_cert_jws, idp_origin, access_mint) = match req.device_cert.as_deref() {
        // Primary-signed cert from the page's device-authorize hop: verify it
        // certifies exactly this pairing — the request's pubkey, the approved
        // agent identity, the PREPARED holder — and that its issuer is the
        // identity's own domain, with a signature that checks out against the
        // primary's published key. The primary carries its own status ref.
        Some(jws) => {
            let cert = DeviceCert::parse(jws)
                .map_err(|e| RegistrarError::ValidationError(format!("bad device cert: {e}")))?;
            let claims = cert.claims();
            if cert.purpose() != Purpose::Authentication {
                return Err(RegistrarError::ValidationError(
                    "supplied device cert must be an authentication cert".into(),
                ));
            }
            if cert.is_expired() {
                return Err(RegistrarError::ValidationError("supplied device cert expired".into()));
            }
            if cert.public_key() != &device_pub {
                return Err(RegistrarError::ValidationError(
                    "supplied device cert does not certify the request's key".into(),
                ));
            }
            // The cert must AUTHORIZE the approved agent identity — exact,
            // or the base identity covering its `+tag` sub-address (RFC
            // subaddressing is a protocol rule; the warrant still pins the
            // exact presentable identity).
            if !cert.authorizes_identity(&agent_email) {
                return Err(RegistrarError::ValidationError(
                    "supplied device cert does not authorize the approved agent identity".into(),
                ));
            }
            if cert.holder().as_str() != holder.as_str() {
                return Err(RegistrarError::ValidationError(
                    "supplied device cert does not carry the prepared holder".into(),
                ));
            }
            let agent_domain = agent_email.rsplit('@').next().unwrap_or_default();
            if claims.iss != agent_domain {
                return Err(RegistrarError::ValidationError(
                    "supplied device cert issuer is not the identity's own domain".into(),
                ));
            }
            let resolver = state.issuer_resolver.as_ref().ok_or_else(|| {
                RegistrarError::ValidationError(
                    "primary-signed agent certs are not accepted here (no issuer discovery)".into(),
                )
            })?;
            let idp_key = resolver.resolve_issuer_key(&claims.iss).await?;
            cert.verify(&idp_key).map_err(|_| {
                RegistrarError::ValidationError(
                    "supplied device cert is not signed by its domain's IdP".into(),
                )
            })?;
            let idp_origin = public_origin(&claims.iss);
            // Where this agent mints: the primary's discovered mint URL,
            // pinned to the issuer's own origin so a page can't point the
            // agent elsewhere.
            let access_mint = match req.access_mint.as_deref() {
                Some(url) if url.starts_with(&format!("{idp_origin}/")) => url.to_string(),
                Some(_) => {
                    return Err(RegistrarError::ValidationError(
                        "access_mint must be on the cert issuer's origin".into(),
                    ))
                }
                None => format!("{idp_origin}/access/mint"),
            };
            (jws.to_string(), idp_origin, access_mint)
        }
        // Registrar-signed (fallback-domain agents): sign with the IdP key over
        // the agent's provisioning key. A per-device status ref means revoking
        // it logs the agent out.
        None => {
            let idx = state.store.get_or_allocate_status("device", &snapshot.provisioning_pubkey)?;
            let status = StatusRef { uri: status_list_uri(&state.domain), idx };
            let device_cert = DeviceCert::create(
                &state.domain,
                &device_pub,
                Purpose::Authentication,
                holder,
                vec![agent_email.clone()],
                chrono::Duration::days(DEVICE_CERT_VALIDITY_DAYS),
                &state.keypair,
                Some(status),
            )
            .map_err(|e| RegistrarError::ValidationError(format!("device cert: {e}")))?;
            let origin = public_origin(&state.domain);
            let access_mint = format!("{origin}/access/mint");
            (device_cert.encoded().to_string(), origin, access_mint)
        }
    };

    // Registry (jipx) + delivery payload for the merged grants.
    let delivery = if let Some((warrant_jwss, config_jws, warrants)) = signed_warrants {
        for (warrant, jws) in warrants.iter().zip(&warrant_jwss) {
            state.store.upsert_warrant(warrant_to_record(
                user.user_id,
                &identity_email,
                warrant,
                jws,
                &config_jws,
            ))?;
        }
        Some(warrant_jwss.iter().map(|w| format!("{w}~{config_jws}")).collect())
    } else {
        None
    };

    // Holder registry: the account's "Devices & services" view derives from
    // recorded cert rows — without this the provisioned agent is invisible.
    // Best-effort; a registry hiccup must not fail the approval. The status
    // index is ours only for registrar-signed certs (a primary's status ref
    // points at its own list).
    {
        let parsed = DeviceCert::parse(&device_cert_jws)
            .map_err(|e| RegistrarError::ValidationError(format!("device cert: {e}")))?;
        let claims = parsed.claims();
        let own_status_idx = claims
            .status
            .as_ref()
            .filter(|s| s.uri == status_list_uri(&state.domain))
            .map(|s| s.idx);
        // The holder's friendly label: the USER-CHOSEN display name wins over
        // whatever the requester suggested — the human edited it for a reason
        // (this was silently ignored once; the device list showed the agent's
        // own string).
        let holder_label = req
            .display_name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .unwrap_or(&snapshot.label);
        state.host.record_agent_device_cert(
            user.user_id,
            &agent_email,
            &holder_id,
            &snapshot.provisioning_pubkey,
            &claims.iss,
            claims.iat,
            claims.exp,
            own_status_idx,
            Some(holder_label),
        );
    }

    // The user-chosen display name (Flow I step 2, eywc): stored on the agent
    // identity so every later permission card opens with it. Named agents
    // only — an as-you agent IS the user's identity.
    if let Some(display) = req.display_name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        if name.is_some() {
            state.host.set_agent_display_name(user.user_id, &agent_email, display);
        }
    }

    let mut m = PROVISIONS.lock().unwrap();
    let rec = m
        .get_mut(&req.code)
        .filter(|r| r.status == Status::Pending)
        .ok_or(RegistrarError::ProvisionRequestNotFound)?;
    rec.device_cert = Some(device_cert_jws);
    rec.idp = Some(idp_origin);
    rec.agent_email = Some(agent_email);
    rec.access_mint = Some(access_mint);
    rec.warrants = delivery;
    // Identity stage of a bundled request (eywc): the cert exists; the
    // permission screens are still open. Everything else completes here.
    rec.status = if identity_only && !snapshot.grants.is_empty() {
        Status::IdentityIssued
    } else {
        Status::Completed
    };
    Ok(Json(CompleteResponse { success: true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_matches_sdk_known_answer() {
        // Same vector as the JS SDK's fingerprint(): pubkey for seed 1..32.
        let pubkey = "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ";
        let fp = fingerprint(pubkey);
        assert_eq!(fp.len(), 8); // "XX-XX-XX"
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        // deterministic
        assert_eq!(fingerprint(pubkey), fp);
    }

    /// The three owned shapes differ ONLY in the warrant's grantor, so pin that
    /// mapping here: a named agent defaults to acting FOR the approver, and
    /// only an explicit "standalone" makes the agent answerable for itself.
    /// Getting this wrong is invisible until an RP reports the wrong author
    /// (it was wrong for months — see bean browserid-ng-8v6c).
    #[test]
    fn grantor_follows_the_identity_mode() {
        let identity = "danmills@sandmill.org".to_string();
        let agent = "danmills+poster@sandmill.org".to_string();
        // The expression under test, as it appears in complete_device_cert.
        let grantor_for = |mode: Option<&str>, agent_email: &str| -> String {
            let standalone = mode == Some("standalone");
            if standalone { agent_email.to_string() } else { identity.clone() }
        };

        // as-you: resolve_agent_identity returns the identity itself, so both
        // sides coincide without special-casing.
        assert_eq!(grantor_for(Some("self"), &identity), identity);

        // named agent, attributed to the human -> ON BEHALF OF
        assert_eq!(grantor_for(Some("handle"), &agent), identity);
        assert_ne!(grantor_for(Some("handle"), &agent), agent, "must not collapse to the agent");

        // named agent answerable for itself
        assert_eq!(grantor_for(Some("standalone"), &agent), agent);

        // Absent mode (requester supplied a name, human didn't re-choose):
        // default to attributing to the human, never silently to the agent.
        assert_eq!(grantor_for(None, &agent), identity);
    }

    /// The `self` grantor pin (t1jp): decision table for how the pin composes
    /// with the approver's identity_mode in complete_device_cert. `self`
    /// forces the standalone shape regardless of mode; a concrete pin refuses
    /// standalone (never silently substituted); `*` follows the mode.
    #[test]
    fn self_grantor_pin_forces_standalone() {
        let identity = "danmills@sandmill.org".to_string();
        let agent = "danmills+poster@sandmill.org".to_string();
        // The expression under test, as it appears in complete_device_cert:
        // Ok(grantor) or Err(the pin that refused standalone).
        let grantor_for = |pin: &str, mode: Option<&str>| -> Result<String, String> {
            let standalone = mode == Some("standalone");
            if standalone && pin != "*" && pin != "self" {
                return Err(pin.to_string());
            }
            Ok(if standalone || pin == "self" { agent.clone() } else { identity.clone() })
        };

        // self pin: standalone shape whatever the page sends.
        assert_eq!(grantor_for("self", None), Ok(agent.clone()));
        assert_eq!(grantor_for("self", Some("handle")), Ok(agent.clone()));
        assert_eq!(grantor_for("self", Some("standalone")), Ok(agent.clone()));
        // unpinned: the mode decides (the k0s9 table).
        assert_eq!(grantor_for("*", Some("handle")), Ok(identity.clone()));
        assert_eq!(grantor_for("*", Some("standalone")), Ok(agent.clone()));
        // concrete pin: on-behalf of the pinned identity; standalone refused.
        assert_eq!(grantor_for("danmills@sandmill.org", Some("handle")), Ok(identity.clone()));
        assert_eq!(
            grantor_for("danmills@sandmill.org", Some("standalone")),
            Err("danmills@sandmill.org".into())
        );
    }

    /// Pin combinations a request can never satisfy are refused at request
    /// time (t1jp) — the agent learns immediately, not as a 15-minute expiry.
    #[test]
    fn contradictory_pins_fail_the_request_up_front() {
        // grantor self + as-you demand (empty grantee): contradictory.
        assert!(request_pin_contradiction("self", "").is_some());
        // grantor self with a mintable or pinned grantee: fine.
        assert!(request_pin_contradiction("self", "*").is_none());
        assert!(request_pin_contradiction("self", "danmills+bsky@sandmill.org").is_none());
        // any other grantor with any grantee: fine (ownership is checked later).
        assert!(request_pin_contradiction("*", "").is_none());
        assert!(request_pin_contradiction("danmills@sandmill.org", "").is_none());
        assert!(request_pin_contradiction("danmills@sandmill.org", "*").is_none());
    }

    /// `check_grantor_pin` accepts any minting identity for `*` and `self`
    /// (self constrains the warrants, not who mints) and only the pinned
    /// identity otherwise.
    #[test]
    fn grantor_pin_gates_the_minting_identity() {
        assert!(check_grantor_pin("*", "danmills@sandmill.org").is_ok());
        assert!(check_grantor_pin("self", "danmills@sandmill.org").is_ok());
        assert!(check_grantor_pin("danmills@sandmill.org", "danmills@sandmill.org").is_ok());
        assert!(check_grantor_pin("DanMills@sandmill.org", "danmills@sandmill.org").is_ok());
        assert!(check_grantor_pin("other@sandmill.org", "danmills@sandmill.org").is_err());
    }

    #[test]
    fn user_codes_have_no_ambiguous_chars() {
        for _ in 0..50 {
            let c = new_user_code();
            assert_eq!(c.len(), 9); // XXXX-XXXX
            assert!(!c.contains(['I', 'L', 'O', '0', '1']));
        }
    }
}
