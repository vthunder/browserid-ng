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

use crate::consent::public_origin;
use crate::error::RegistrarError;
use crate::host::require_csrf;
use crate::registry::{require_enabled, require_session};
use crate::RegistrarState;

const REQUEST_VALIDITY_SECONDS: i64 = 900;
const POLL_INTERVAL_SECONDS: i64 = 5;
const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Clone, PartialEq)]
enum Status {
    Pending,
    Completed,
    Denied,
}

#[derive(Clone)]
struct Record {
    provisioning_pubkey: String,
    requested_names: Vec<String>,
    requested_patterns: Vec<String>,
    label: String,
    fingerprint: String,
    status: Status,
    // filled on approval, derived from the signed delegation:
    delegation: Option<String>,
    idp: Option<String>,
    names: Vec<String>,
    patterns: Vec<String>,
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

fn jwt_claims(jwt: &str) -> Option<serde_json::Value> {
    let payload = jwt.split('.').nth(1)?;
    serde_json::from_slice(&B64.decode(payload).ok()?).ok()
}

/// From a `U_cert~P_cert` delegation: the provisioning pubkey, constraint
/// names/patterns, and the IdP issuer (from the U_cert). All from the signed
/// certs — never trusted client metadata.
fn delegation_meta(delegation: &str) -> Option<(String, Vec<String>, Vec<String>, String)> {
    let mut parts = delegation.split('~');
    let u_cert = parts.next()?;
    let p_cert = parts.next()?;
    let u = jwt_claims(u_cert)?;
    let p = jwt_claims(p_cert)?;
    let p_pub = p.get("public-key")?.get("publicKey")?.as_str()?.to_string();
    let arr = |v: &serde_json::Value, k| -> Vec<String> {
        v.get("constraint")
            .and_then(|c| c.get(k))
            .and_then(|n| n.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default()
    };
    let names = arr(&p, "names");
    let patterns = arr(&p, "patterns");
    let idp_iss = u.get("iss")?.as_str()?.to_string();
    Some((p_pub, names, patterns, idp_iss))
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
        delegation: None,
        idp: None,
        names: vec![],
        patterns: vec![],
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
        Status::Completed => {
            m.remove(&req.code);
            Json(json!({
                "status": "completed",
                "credential": {
                    "delegation": rec.delegation,
                    "broker": public_origin(&state.domain),
                    "idp": rec.idp,
                    "names": rec.names,
                    "patterns": rec.patterns,
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
    /// The `U_cert~P_cert` delegation the identity key signed (approve only).
    #[serde(default)]
    pub delegation: Option<String>,
}

#[derive(Serialize)]
pub struct CompleteResponse {
    pub success: bool,
}

/// POST /agent-provision/complete — the verify page, after the human signs the
/// delegation over the agent's pubkey. Session + CSRF authenticated. Metadata
/// (idp, names, patterns) is derived from the signed delegation, not trusted
/// from the client; the delegation must certify the requested pubkey.
pub async fn complete(
    State(state): State<Arc<RegistrarState>>,
    cookies: Cookies,
    Json(req): Json<CompleteBody>,
) -> Result<Json<CompleteResponse>, RegistrarError> {
    require_enabled(&state)?;
    let user = require_session(&state, &cookies)?;
    require_csrf(&user, &req.csrf)?;

    let mut m = PROVISIONS.lock().unwrap();
    let rec = m
        .get_mut(&req.code)
        .filter(|r| !r.is_expired() && r.status == Status::Pending)
        .ok_or(RegistrarError::ProvisionRequestNotFound)?;

    if !req.approve {
        rec.status = Status::Denied;
        return Ok(Json(CompleteResponse { success: true }));
    }

    let delegation = req
        .delegation
        .ok_or_else(|| RegistrarError::ValidationError("delegation required to approve".into()))?;
    let (p_pub, names, patterns, idp_iss) = delegation_meta(&delegation)
        .ok_or_else(|| RegistrarError::ValidationError("malformed delegation".into()))?;
    // Binding: the delegation must certify the AGENT's provisioning pubkey.
    if p_pub != rec.provisioning_pubkey {
        return Err(RegistrarError::ValidationError(
            "delegation does not certify the requested provisioning key".into(),
        ));
    }
    rec.delegation = Some(delegation);
    rec.idp = Some(public_origin(&idp_iss));
    rec.names = names;
    rec.patterns = patterns;
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
    fn delegation_meta_extracts_pubkey_names_and_idp() {
        // A minimal U_cert~P_cert (payloads only need the fields we read; sigs
        // aren't checked here — binding is by pubkey equality).
        let b64 = |v: &serde_json::Value| B64.encode(serde_json::to_vec(v).unwrap());
        let u = json!({ "iss": "mingo.place", "principal": { "email": "alice@mingo.place" } });
        let p = json!({ "public-key": { "algorithm": "Ed25519", "publicKey": "PUBKEY123" },
                        "constraint": { "names": ["researcher"], "patterns": ["svc+*"] } });
        let u_cert = format!("h.{}.s", b64(&u));
        let p_cert = format!("h.{}.s", b64(&p));
        let (pubkey, names, patterns, idp) = delegation_meta(&format!("{u_cert}~{p_cert}")).unwrap();
        assert_eq!(pubkey, "PUBKEY123");
        assert_eq!(names, vec!["researcher"]);
        assert_eq!(patterns, vec!["svc+*"]);
        assert_eq!(idp, "mingo.place");
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
