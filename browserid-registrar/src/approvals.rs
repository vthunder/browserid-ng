//! Approve a new device from one already enrolled (registry-api-v1
//! §5.2.8, bean puo8). The login page opens an approval for the account
//! and shows its code; a device signed in to the account types that code
//! back, which proves the person at the enrolled device can see the new
//! one's screen; the page's poll then receives a one-time login token and
//! the new device enrols its key as `approval` (§4.2).
//!
//! Enumeration-safe: opening an approval for an unknown account answers a
//! code like any other, which nothing will ever approve. Polls by the
//! approval's id, a secret handle only the opener holds.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::Json;
use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::api::{ApiError, ApiUser};
use crate::models::ApprovalRecord;
use crate::policy::{self, Facts};
use crate::RegistrarState;

/// An approval waits this long for the enrolled device.
pub const APPROVAL_SECONDS: i64 = 300;
/// Open approvals an account can have at once (a flood cap).
const MAX_PENDING: usize = 5;
/// Code alphabet: no 0/O/1/I ambiguity, since a human reads it across.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

fn new_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let pick = |rng: &mut rand::rngs::ThreadRng| CODE_ALPHABET[rng.gen_range(0..CODE_ALPHABET.len())] as char;
    let a: String = (0..3).map(|_| pick(&mut rng)).collect();
    let b: String = (0..3).map(|_| pick(&mut rng)).collect();
    format!("{a}-{b}")
}

/// Codes compare after normalisation: case, and the dash, are the human's.
fn normalize_code(c: &str) -> String {
    c.trim().to_ascii_uppercase().chars().filter(|ch| ch.is_ascii_alphanumeric()).collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenRequest {
    account: String,
    #[serde(default)]
    label: Option<String>,
}

/// `POST /api/v1/approvals` — the login page opens one for `account`.
pub async fn open(
    State(state): State<Arc<RegistrarState>>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req: OpenRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let now = Utc::now();
    let expires_at = now + Duration::seconds(APPROVAL_SECONDS);
    let id = crate::api::new_token();
    let code = new_code();
    let label = match req.label.as_deref().map(str::trim).filter(|l| !l.is_empty()) {
        Some(l) => crate::holders::validate_label(l).ok(),
        None => headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .and_then(crate::holders::ua_label),
    };
    let user_id = state
        .host
        .account_for_public_id(req.account.trim())
        .map_err(|e| ApiError::Internal(format!("account lookup: {e}")))?;
    if let Some(uid) = user_id {
        let pending = state
            .store
            .list_pending_approvals(uid)
            .map_err(|e| ApiError::Internal(format!("approvals: {e}")))?;
        if pending.len() >= MAX_PENDING {
            // Same shape as any other refusal the page could see.
            return Err(ApiError::Forbidden { reason: "login_rejected", description: "too many open approvals".into() });
        }
        state
            .store
            .create_approval(ApprovalRecord {
                id: id.clone(),
                user_id: uid,
                code: code.clone(),
                label,
                created_at: now,
                expires_at,
                approved_by: None,
                denied: false,
                token: None,
            })
            .map_err(|e| ApiError::Internal(format!("approvals: {e}")))?;
        tracing::info!("approval: opened");
    }
    Ok(Json(serde_json::json!({ "id": id, "code": code, "expires_at": expires_at.to_rfc3339() })))
}

/// `GET /api/v1/approvals/:id` — the page's poll: `pending`, `approved`
/// (with the one-time `login` token, handed out once), `denied`, or
/// `expired`. Unknown ids read as pending until the client's own expiry.
pub async fn poll(
    State(state): State<Arc<RegistrarState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Some(rec) = state.store.get_approval(&id).map_err(|e| ApiError::Internal(format!("approvals: {e}")))? else {
        return Ok(Json(serde_json::json!({ "status": "pending" })));
    };
    if rec.denied {
        return Ok(Json(serde_json::json!({ "status": "denied" })));
    }
    if rec.expires_at < Utc::now() {
        return Ok(Json(serde_json::json!({ "status": "expired" })));
    }
    if rec.approved_by.is_some() {
        let token = state
            .store
            .take_approval_token(&id)
            .map_err(|e| ApiError::Internal(format!("approvals: {e}")))?;
        return Ok(Json(match token {
            Some(t) => serde_json::json!({ "status": "approved", "login": t }),
            // Already collected: a second poll sees the outcome, never the token.
            None => serde_json::json!({ "status": "approved" }),
        }));
    }
    Ok(Json(serde_json::json!({ "status": "pending" })))
}

/// `GET /api/v1/approvals` — the account's open approvals, for the devices
/// that may answer them. The code is not listed: the person types it from
/// the new device's screen.
pub async fn list(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let items: Vec<serde_json::Value> = state
        .store
        .list_pending_approvals(user.user_id)
        .map_err(|e| ApiError::Internal(format!("approvals: {e}")))?
        .into_iter()
        .map(|a| serde_json::json!({
            "id": a.id, "label": a.label,
            "created_at": a.created_at.to_rfc3339(), "expires_at": a.expires_at.to_rfc3339(),
        }))
        .collect();
    Ok(Json(serde_json::json!({ "approvals": items })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveRequest {
    id: String,
    code: String,
}

fn refused(reason: &'static str, d: &str) -> ApiError {
    ApiError::Forbidden { reason, description: d.into() }
}

/// `POST /api/v1/approvals/approve { id, code }` — under a session. The
/// approving key must be live on the account and, when it was itself
/// enrolled by approval, must have proven an identity since (the floor
/// that keeps approvals from chaining away from real credentials); the
/// account's policy must allow approval; the code must match.
pub async fn approve(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req: ApproveRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let rec = state
        .store
        .get_approval(&req.id)
        .map_err(|e| ApiError::Internal(format!("approvals: {e}")))?
        .filter(|a| a.user_id == user.user_id && a.approved_by.is_none() && !a.denied && a.expires_at > Utc::now())
        .ok_or(ApiError::NotFound)?;

    // The approver's own key and its standing.
    let keys = state
        .store
        .list_login_certs(user.user_id)
        .map_err(|e| ApiError::Internal(format!("login keys: {e}")))?;
    let me = keys.iter().find(|k| k.id == user.login_key_id).ok_or(ApiError::NotFound)?;
    if me.enrolled_by == policy::ENROLLED_BY_APPROVAL {
        let proven = state
            .store
            .list_device_certs(user.user_id)
            .map_err(|e| ApiError::Internal(format!("certs: {e}")))?
            .into_iter()
            .any(|c| c.login_key_id == Some(me.id) && c.is_active());
        if !proven {
            return Err(refused("approver_unproven", "a device let in by approval must prove an identity before it can approve others"));
        }
    }

    // The account's policy must take approval at all.
    let p = crate::account::account_policy(&state, user.user_id)?;
    let identities = state
        .host
        .roster(user.user_id)
        .map_err(|e| ApiError::Internal(format!("roster: {e}")))?
        .iter()
        .filter(|(_, s)| *s == "active")
        .count() as u32;
    if !p.enrol().met(&Facts { approval: true, identities, ..Default::default() }) {
        return Err(refused("approval_disabled", "this account's policy does not let a device in by approval"));
    }

    if normalize_code(&req.code) != normalize_code(&rec.code) {
        return Err(refused("code_mismatch", "that is not the code the new device shows"));
    }

    let token = state
        .store
        .create_login_token(user.user_id, policy::ENROLLED_BY_APPROVAL, Some(&me.kid))
        .map_err(|e| ApiError::Internal(format!("login token: {e}")))?;
    state
        .store
        .resolve_approval(&rec.id, Some(me.id), Some(&token))
        .map_err(|e| ApiError::Internal(format!("approvals: {e}")))?;
    tracing::info!(approver = %me.kid, "approval: approved");
    Ok(Json(serde_json::json!({ "approved": true })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DenyRequest {
    id: String,
}

/// `POST /api/v1/approvals/deny { id }` — under a session.
pub async fn deny(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req: DenyRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let rec = state
        .store
        .get_approval(&req.id)
        .map_err(|e| ApiError::Internal(format!("approvals: {e}")))?
        .filter(|a| a.user_id == user.user_id && a.approved_by.is_none() && !a.denied)
        .ok_or(ApiError::NotFound)?;
    state
        .store
        .resolve_approval(&rec.id, None, None)
        .map_err(|e| ApiError::Internal(format!("approvals: {e}")))?;
    tracing::info!("approval: denied");
    Ok(Json(serde_json::json!({ "denied": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_readable_and_compare_loosely() {
        let c = new_code();
        assert_eq!(c.len(), 7);
        assert!(!c.contains('0') && !c.contains('O') && !c.contains('1') && !c.contains('I'));
        assert_eq!(normalize_code(" abc-234 "), normalize_code("ABC234"));
        assert_ne!(normalize_code("ABC-234"), normalize_code("ABC-235"));
    }
}
