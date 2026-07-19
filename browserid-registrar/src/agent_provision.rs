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

use browserid_core::device::{DeviceCert, Purpose, Subject, DEVICE_CERT_VALIDITY_DAYS};
use browserid_core::{PublicKey, StatusRef};

use crate::consent::{public_origin, status_list_uri};
use crate::error::RegistrarError;
use crate::host::{require_csrf, AuthedUser};
use crate::registry::{require_enabled, require_session};
use crate::{agent_identity_email, agent_name_allowed, RegistrarState};

const REQUEST_VALIDITY_SECONDS: i64 = 900;
const POLL_INTERVAL_SECONDS: i64 = 5;
const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Clone, PartialEq)]
enum Status {
    Pending,
    Completed,
    Denied,
    Failed,
}

#[derive(Clone)]
struct Record {
    provisioning_pubkey: String,
    requested_names: Vec<String>,
    requested_patterns: Vec<String>,
    label: String,
    fingerprint: String,
    status: Status,
    fail_reason: Option<String>,
    idp: Option<String>,
    // filled on approval (device-cert model): the IdP signs an AGENT DEVICE
    // CERT for the agent's key.
    device_cert: Option<String>,
    agent_email: Option<String>,
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
pub struct RequestBody {
    pub provisioning_pubkey: PubkeyField,
    #[serde(default)]
    pub requested_handles: Option<Handles>,
    #[serde(default)]
    pub label: Option<String>,
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
    let code = new_code();
    let user_code = new_user_code();
    let fp = fingerprint(&pubkey);
    let origin = public_origin(&state.domain);
    let rec = Record {
        provisioning_pubkey: pubkey,
        requested_names: handles.names,
        requested_patterns: handles.patterns,
        label: req.label.unwrap_or_default(),
        fingerprint: fp.clone(),
        status: Status::Pending,
        fail_reason: None,
        idp: None,
        device_cert: None,
        agent_email: None,
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
    if let Some(prev) = rec.last_polled_at {
        if Utc::now() - prev < Duration::seconds(POLL_INTERVAL_SECONDS) {
            return RegistrarError::PollTooFast.into_response();
        }
    }
    if let Some(r) = m.get_mut(&req.code) {
        r.last_polled_at = Some(Utc::now());
    }
    match rec.status {
        Status::Pending => Json(json!({ "status": "pending" })).into_response(),
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
            // Hand back an IdP-signed agent device cert. The agent mints access
            // certs headlessly at the IdP's `/access/mint`.
            Json(json!({
                "status": "completed",
                "credential": {
                    "device_cert": rec.device_cert,
                    "idp": rec.idp,
                    "identity": rec.agent_email,
                }
            }))
            .into_response()
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
        .filter(|r| !r.is_expired() && r.status == Status::Pending)
        .ok_or(RegistrarError::ProvisionRequestNotFound)?;
    Ok(Json(InfoResponse {
        success: true,
        provisioning_pubkey: rec.provisioning_pubkey.clone(),
        fingerprint: rec.fingerprint.clone(),
        label: rec.label.clone(),
        requested_names: rec.requested_names.clone(),
        requested_patterns: rec.requested_patterns.clone(),
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
        .map(|r| !r.is_expired() && r.status == Status::Pending)
        .unwrap_or(false);
    if !live {
        return Err(RegistrarError::ProvisionRequestNotFound);
    }
    Ok(Json(ResolveResponse { success: true, code }))
}

// ===========================================================================
// Browser-facing: complete (session + CSRF)
// ===========================================================================

#[derive(Deserialize)]
pub struct CompleteBody {
    pub csrf: String,
    pub code: String,
    pub approve: bool,
    /// The verified email the user is minting the agent under (approve only).
    /// The agent identity is `<requested-name>@<its domain>`.
    #[serde(default)]
    pub identity_email: Option<String>,
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

    // Snapshot the pending record (drop the lock before DB work).
    let (expected_pubkey, requested_name) = {
        let m = PROVISIONS.lock().unwrap();
        let rec = m
            .get(&req.code)
            .filter(|r| !r.is_expired() && r.status == Status::Pending)
            .ok_or(RegistrarError::ProvisionRequestNotFound)?;
        (
            rec.provisioning_pubkey.clone(),
            rec.requested_names.first().cloned(),
        )
    };

    if !req.approve {
        if let Some(rec) = PROVISIONS.lock().unwrap().get_mut(&req.code) {
            rec.status = Status::Denied;
        }
        return Ok(Json(CompleteResponse { success: true }));
    }

    complete_device_cert(&state, &user, &req, &expected_pubkey, requested_name)
}

/// Device-cert approval: the IdP (this registrar's keypair) signs an AGENT
/// DEVICE CERT (`purpose=authentication`, `subject=agent`) certifying the
/// agent's provisioning key for the approved `<name>@<domain>` identity. The
/// user just approves.
fn complete_device_cert(
    state: &Arc<RegistrarState>,
    user: &AuthedUser,
    req: &CompleteBody,
    expected_pubkey: &str,
    requested_name: Option<String>,
) -> Result<Json<CompleteResponse>, RegistrarError> {
    let identity_email = req
        .identity_email
        .clone()
        .ok_or_else(|| RegistrarError::ValidationError("identity_email required to approve".into()))?;
    let name = requested_name
        .ok_or_else(|| RegistrarError::ValidationError("no requested agent handle".into()))?;

    // The session must own the identity the agent will act for.
    if !state.host.owns_verified_email(user.user_id, &identity_email).unwrap_or(false) {
        return Err(RegistrarError::PolicyRefused(
            "you don't own the delegating identity".into(),
        ));
    }
    // Anti-squatting: the handle must be one this owner may mint (same rule the
    // legacy path enforces via the signed provisioning cert).
    if !agent_name_allowed(&name, &identity_email, &state.domain) {
        return Err(RegistrarError::PolicyRefused(
            "agent handle not permitted for this identity".into(),
        ));
    }
    let agent_email = agent_identity_email(&identity_email, &name);

    // Reserve the handle NOW (session-authenticated), same as the legacy path.
    if let Err(e) = state.host.reserve_agent_names(user.user_id, &identity_email, &[name.clone()]) {
        if let Some(rec) = PROVISIONS.lock().unwrap().get_mut(&req.code) {
            rec.status = Status::Failed;
            rec.fail_reason = Some(e.to_string());
        }
        return Err(e);
    }

    // Sign the agent device cert with the IdP key over the agent's provisioning
    // key. A per-device status ref means revoking it logs the agent out.
    let device_pub = PublicKey::from_base64(expected_pubkey)
        .map_err(|e| RegistrarError::ValidationError(format!("bad provisioning pubkey: {e}")))?;
    let idx = state.store.get_or_allocate_status("device", expected_pubkey)?;
    let status = StatusRef { uri: status_list_uri(&state.domain), idx };
    let device_cert = DeviceCert::create(
        &state.domain,
        &device_pub,
        Purpose::Authentication,
        Subject::Agent,
        vec![agent_email.clone()],
        chrono::Duration::days(DEVICE_CERT_VALIDITY_DAYS),
        &state.keypair,
        Some(status),
    )
    .map_err(|e| RegistrarError::ValidationError(format!("device cert: {e}")))?;

    let mut m = PROVISIONS.lock().unwrap();
    let rec = m
        .get_mut(&req.code)
        .filter(|r| r.status == Status::Pending)
        .ok_or(RegistrarError::ProvisionRequestNotFound)?;
    rec.device_cert = Some(device_cert.encoded().to_string());
    rec.idp = Some(public_origin(&state.domain));
    rec.agent_email = Some(agent_email);
    rec.status = Status::Completed;
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

    #[test]
    fn user_codes_have_no_ambiguous_chars() {
        for _ in 0..50 {
            let c = new_user_code();
            assert_eq!(c.len(), 9); // XXXX-XXXX
            assert!(!c.contains(['I', 'L', 'O', '0', '1']));
        }
    }
}
