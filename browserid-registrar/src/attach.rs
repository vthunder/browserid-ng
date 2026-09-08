//! Account membership over the API (registry-api-v1 §5.2; bean 0c49
//! steps 4+5): `attach` records certs for one identity on an account and
//! is the only way an account is created; `detach` and `delete` make
//! identities leave (§4.1 rule 3). The guard (§4.2) is a token the
//! host's guard page mints; the registry only checks and spends it.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use crate::api::{ApiError, ApiUser};
use crate::models::{DeviceCertRecord, GuardTokenRecord, SessionRecord};
use crate::session::{
    b64url_sha256, header_proof, kid_of, replay_check, resolve_members, session_body, BodyHash,
    Proof, SESSION_TTL_SECONDS,
};
use crate::RegistrarState;

/// A cert moving an identity must have been issued within this window.
const FRESHNESS_SECONDS: i64 = 300;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertProof {
    cert: String,
    proof: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachRequest {
    identity: String,
    certs: Vec<CertProof>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    guard: Option<String>,
    #[serde(default)]
    confirm_takeover: bool,
}

fn invalid_cert(reason: &'static str, d: impl Into<String>) -> ApiError {
    ApiError::InvalidCert { reason, description: d.into() }
}

/// One carried cert after the validity bar.
struct Carried {
    kid: String,
    pubkey: String,
    purpose: String,
    holder: String,
    iss: String,
    iat: i64,
    exp: i64,
    identities: Vec<String>,
    status_uri: Option<String>,
    status_idx: Option<u64>,
}

fn guard_required(state: &RegistrarState) -> ApiError {
    let kinds = match &state.guard_page_url {
        Some(url) => vec![serde_json::json!({ "kind": "page", "url": url })],
        None => vec![],
    };
    ApiError::GuardRequired { kinds }
}

/// The session behind an optional `Authorization: Bearer`, with its live
/// members. `None` when the header is absent.
async fn optional_session(
    state: &RegistrarState,
    headers: &axum::http::HeaderMap,
) -> Result<Option<(u64, Vec<u64>)>, ApiError> {
    let Some(auth) = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let Some((scheme, token)) = auth.split_once(' ') else {
        return Err(ApiError::InvalidSession("malformed Authorization header".into()));
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(ApiError::InvalidSession("attach takes a Bearer session".into()));
    }
    let rec = state
        .store
        .get_session(&b64url_sha256(token.trim().as_bytes()))
        .map_err(|e| ApiError::Internal(format!("session lookup: {e}")))?
        .ok_or_else(|| ApiError::InvalidSession("unknown session".into()))?;
    if rec.is_expired() {
        return Err(ApiError::InvalidSession("session expired".into()));
    }
    let members = resolve_members(state, rec.user_id, &rec.member_cert_ids).await?;
    if members.is_empty() {
        return Err(ApiError::InvalidSession("no member of this session is still valid".into()));
    }
    Ok(Some((rec.user_id, members.iter().map(|m| m.cert.id).collect())))
}

/// A guard token the call carries, checked against the certs and identity
/// it was minted for (§4.2). Not yet spent.
fn check_guard(
    state: &RegistrarState,
    token: &str,
    identity: &str,
    kids: &[String],
) -> Result<GuardTokenRecord, ApiError> {
    let rejected = |d: &str| ApiError::Forbidden { reason: "guard_rejected", description: d.into() };
    let rec = state
        .store
        .get_guard_token(&b64url_sha256(token.as_bytes()))
        .map_err(|e| ApiError::Internal(format!("guard lookup: {e}")))?
        .ok_or_else(|| rejected("unknown or spent guard token"))?;
    if rec.expires_at <= Utc::now() {
        return Err(rejected("guard token expired"));
    }
    if !rec.identity.eq_ignore_ascii_case(identity) {
        return Err(rejected("guard token was minted for another identity"));
    }
    let mut want = kids.to_vec();
    want.sort();
    if rec.kids != want {
        return Err(rejected("guard token was minted for other certs"));
    }
    Ok(rec)
}

/// `POST /api/v1/account/attach` (§5.2.1).
pub async fn attach(
    State(state): State<Arc<RegistrarState>>,
    headers: axum::http::HeaderMap,
    axum::Extension(BodyHash(bh)): axum::Extension<BodyHash>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.enabled {
        return Err(ApiError::NotFound);
    }
    let path = "/api/v1/account/attach";
    let hp = header_proof(&headers)?;
    let req: AttachRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let identity = req.identity.trim().to_lowercase();
    if identity.is_empty() || !identity.contains('@') {
        return Err(ApiError::InvalidRequest("identity must be an email address".into()));
    }
    if req.certs.is_empty() || req.certs.len() > 2 {
        return Err(ApiError::InvalidRequest("certs must carry 1–2 entries".into()));
    }
    let verifier = state.presentation_verifier.as_ref().ok_or_else(|| {
        ApiError::Internal("device-cert verification is not configured on this host".into())
    })?;

    // Every cert: the validity bar, the holder rule, the retired-key rule,
    // and its possession proof (same jti, no bh).
    let mut carried: Vec<Carried> = Vec::new();
    for (i, cp) in req.certs.iter().enumerate() {
        let which = format!("certs[{i}]");
        let parsed = browserid_core::device::DeviceCert::parse(&cp.cert)
            .map_err(|e| invalid_cert("cert_malformed", format!("{which}: {e}")))?;
        let claims = parsed.claims();
        // A bare `*` glob is refused; the `local+*@domain` sub-address form
        // (core §4.6) is part of an ordinary identity's cert.
        if claims.identities.iter().any(|x| x.trim() == "*") {
            return Err(invalid_cert("glob_identity", format!("{which}: glob identities are refused")));
        }
        if !claims.identities.iter().any(|x| x.eq_ignore_ascii_case(&identity)) {
            return Err(invalid_cert("identity_not_named", format!("{which} does not name '{identity}'")));
        }
        let purpose = match claims.purpose {
            browserid_core::device::Purpose::Authentication => "authentication",
            browserid_core::device::Purpose::Authorization => "authorization",
        };
        let v = verifier
            .verify_device_cert(&cp.cert, purpose)
            .await
            .map_err(|r| r.into_api_error(&which))?;
        if let Some(existing) = state
            .store
            .get_device_cert_by_pubkey(&v.pubkey)
            .map_err(|e| ApiError::Internal(format!("cert lookup: {e}")))?
        {
            if !existing.is_active() {
                return Err(invalid_cert("cert_revoked", format!("{which}: this key was retired here")));
            }
        }
        let kid = kid_of(&v.pubkey).ok_or_else(|| invalid_cert("cert_malformed", format!("{which}: bad key")))?;
        let p = Proof::parse(&cp.proof)?;
        if p.jti != hp.jti {
            return Err(ApiError::InvalidProof("proofs in one request must share a jti".into()));
        }
        if p.kid != kid {
            return Err(ApiError::InvalidProof(format!("{which}: possession proof kid does not match the cert")));
        }
        p.verify(&v.pubkey)?;
        p.check_claims(&state, "POST", path, None)?;
        carried.push(Carried {
            kid,
            pubkey: v.pubkey,
            purpose: v.purpose,
            holder: v.holder,
            iss: v.iss,
            iat: v.iat,
            exp: v.exp,
            identities: v.identities,
            status_uri: v.status_uri,
            status_idx: v.status_idx,
        });
    }
    if carried.len() == 2 {
        if carried[0].holder != carried[1].holder {
            return Err(invalid_cert("holder_mismatch", "the two certs carry different holders"));
        }
        if carried[0].purpose == carried[1].purpose {
            return Err(ApiError::InvalidRequest("certs must be one auth cert and/or one config cert".into()));
        }
    }
    // The header proof: signed by one of the carried keys.
    let signer = carried
        .iter()
        .find(|c| c.kid == hp.kid)
        .ok_or_else(|| ApiError::InvalidProof("the Proof key is not one of the carried certs".into()))?;
    hp.verify(&signer.pubkey)?;
    hp.check_claims(&state, "POST", path, Some(&bh))?;
    replay_check(&state, &hp.kid, &hp.jti)?;

    let session = optional_session(&state, &headers).await?;
    let kids: Vec<String> = carried.iter().map(|c| c.kid.clone()).collect();
    let guard = match req.guard.as_deref() {
        Some(t) => Some(check_guard(&state, t, &identity, &kids)?),
        None => None,
    };
    let has_config = carried.iter().any(|c| c.purpose == "authorization");
    let now = Utc::now().timestamp();
    let fresh = carried.iter().all(|c| (now - c.iat).abs() <= FRESHNESS_SECONDS);
    let iss = carried[0].iss.clone();
    let require_config = || -> Result<(), ApiError> {
        if has_config { Ok(()) } else { Err(invalid_cert("config_required", "this case needs a config cert")) }
    };
    let require_fresh = || -> Result<(), ApiError> {
        if fresh { Ok(()) } else { Err(invalid_cert("cert_not_fresh", format!("a cert moving an identity must be issued within {FRESHNESS_SECONDS} s"))) }
    };
    let host = |e: crate::error::RegistrarError| ApiError::Internal(format!("membership: {e}"));
    let holder = state.host.identity_holder(&identity).map_err(host)?;

    // The case (§5.2.1). The membership move itself runs AFTER the certs
    // are recorded on the destination account, so an issuer that also runs
    // this registry revokes the old account's remaining certs for the
    // identity (hg2j) without touching the ones just carried in. `guard`
    // is spent only once the case succeeds.
    enum Pending {
        Transfer(u64, &'static str),
        Add,
        Restore,
    }
    let mut pending: Option<Pending> = None;
    let user_id: u64 = match req.account.as_deref() {
        None => match holder {
            None => {
                require_config()?;
                state.host.create_account_with_identity(&identity, &iss).map_err(host)?
            }
            Some(a) if guard.as_ref().map(|g| g.user_id) == Some(a) => a,
            Some(a) if req.confirm_takeover => {
                require_config()?;
                require_fresh()?;
                // Takeover: the identity leaves `a` into a new account around
                // the fresh certs. The new account is created empty and the
                // identity moves in (a hold on the way out, §4.1 rule 3).
                let fresh_account = state.host.create_empty_account().map_err(host)?;
                pending = Some(Pending::Transfer(a, "taken_over"));
                fresh_account
            }
            Some(_) => return Err(guard_required(&state)),
        },
        Some(pid) => {
            let Some(acct) = state.host.account_for_public_id(pid).map_err(host)? else {
                return Err(guard_required(&state));
            };
            let authorized = session.as_ref().map(|s| s.0) == Some(acct)
                || guard.as_ref().map(|g| g.user_id) == Some(acct);
            if !authorized {
                return Err(guard_required(&state));
            }
            if holder == Some(acct) {
                acct
            } else if state.host.identity_suspended_on(acct, &identity).map_err(host)? {
                require_fresh()?;
                pending = Some(match holder {
                    Some(elsewhere) => Pending::Transfer(elsewhere, "transferred"),
                    None => Pending::Restore,
                });
                acct
            } else if holder.is_none() {
                require_config()?;
                require_fresh()?;
                pending = Some(Pending::Add);
                acct
            } else {
                require_config()?;
                if !req.confirm_takeover {
                    return Err(guard_required(&state));
                }
                require_fresh()?;
                pending = Some(Pending::Transfer(holder.unwrap(), "transferred"));
                acct
            }
        }
    };
    if let Some(g) = &guard {
        state.store.delete_guard_token(&g.token_hash).ok();
    }

    // Record the certs: a holder mid-move must not resurrect its old row;
    // an orphan browser holder is healed as the cookie lane does.
    let holder_id = carried[0].holder.clone();
    if state
        .store
        .resolve_holder_move(user_id, &holder_id)
        .map_err(|e| ApiError::Internal(format!("holder-move lookup: {e}")))?
        .is_some()
    {
        return Err(ApiError::Conflict {
            reason: "holder_moved",
            description: "this holder was moved; re-issue under the new holder".into(),
        });
    }
    let mut move_target = None;
    if let Some((prefix, _)) = holder_id.split_once('.') {
        match state.store.adopt_namespace_prefix(user_id, "browsers", prefix) {
            Ok(true) => {}
            Ok(false) => {
                move_target = crate::holders::register_orphan_browser_move(&*state.store, user_id, &holder_id);
            }
            Err(e) => tracing::warn!("browsers prefix adoption failed: {e}"),
        }
    }
    let mut recorded_ids = Vec::new();
    for c in &carried {
        // Recorded for `identity` and for the cert's other identities that
        // are already active on this account.
        let mut recorded_for = vec![identity.clone()];
        for other in &c.identities {
            if other.eq_ignore_ascii_case(&identity) || other.contains('*') {
                continue;
            }
            if state.host.identity_holder(other).map_err(host)? == Some(user_id) {
                recorded_for.push(other.to_lowercase());
            }
        }
        let id = state
            .store
            .insert_device_cert(DeviceCertRecord {
                id: 0,
                user_id,
                identities: recorded_for,
                purpose: c.purpose.clone(),
                holder: c.holder.clone(),
                pubkey: c.pubkey.clone(),
                iss: c.iss.clone(),
                issued_at: DateTime::from_timestamp(c.iat, 0).unwrap_or_else(Utc::now),
                expires_at: DateTime::from_timestamp(c.exp, 0).unwrap_or_else(Utc::now),
                revoked_at: None,
                status_uri: c.status_uri.clone(),
                status_idx: c.status_idx,
            })
            .map_err(|e| ApiError::Internal(format!("device cert store: {e}")))?;
        recorded_ids.push(id);
    }
    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok());
    crate::holders::maybe_label_holder_from_ua(&*state.store, user_id, &holder_id, ua);
    if let Some(target) = &move_target {
        crate::holders::maybe_label_holder_from_ua(&*state.store, user_id, target, ua);
    }
    crate::holders::finish_holder_move(&*state.store, user_id, &holder_id);

    // Now the identity moves (§4.1 rule 3 on the way out of an account).
    match pending {
        Some(Pending::Transfer(from, reason)) => {
            state.host.transfer_identity(from, user_id, &identity, reason).map_err(host)?
        }
        Some(Pending::Add) => state.host.add_identity(user_id, &identity, &iss).map_err(host)?,
        Some(Pending::Restore) => state.host.restore_identity(user_id, &identity, &iss).map_err(host)?,
        None => {}
    }

    // The session: the call's certs, plus the caller's members under an
    // existing session on this account.
    let mut members = recorded_ids.clone();
    if let Some((s_user, s_members)) = &session {
        if *s_user == user_id {
            for m in s_members {
                if !members.contains(m) {
                    members.push(*m);
                }
            }
        }
    }
    let now = Utc::now();
    let expires_at = now + Duration::seconds(SESSION_TTL_SECONDS);
    let token = crate::api::new_token();
    state
        .store
        .create_session(SessionRecord {
            token_hash: b64url_sha256(token.as_bytes()),
            user_id,
            member_cert_ids: members.clone(),
            created_at: now,
            expires_at,
        })
        .map_err(|e| ApiError::Internal(format!("session store: {e}")))?;
    tracing::info!(%identity, holder = %holder_id, "attach: recorded {} cert(s)", recorded_ids.len());
    Ok(Json(session_body(&state, user_id, &token, expires_at, &members).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetachRequest {
    identity: String,
    #[serde(default)]
    guard: Option<String>,
}

/// `POST /api/v1/account/detach` (§5.2.2).
pub async fn detach(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    user.require_config()?;
    let req: DetachRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let identity = req.identity.trim().to_lowercase();
    let _ = req.guard; // a registry MAY require its guard here; this one does not
    let holder = state
        .host
        .identity_holder(&identity)
        .map_err(|e| ApiError::Internal(format!("membership: {e}")))?;
    if holder != Some(user.user_id) {
        return Err(ApiError::NotFound);
    }
    let active = state
        .host
        .roster(user.user_id)
        .map_err(|e| ApiError::Internal(format!("roster: {e}")))?
        .iter()
        .filter(|(_, s)| *s == "active")
        .count();
    if active <= 1 {
        return Err(ApiError::Conflict {
            reason: "last_identity",
            description: "the last identity cannot be detached; use delete".into(),
        });
    }
    state
        .host
        .detach_identity(user.user_id, &identity)
        .map_err(|e| ApiError::Internal(format!("membership: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteRequest {
    #[serde(default)]
    guard: Option<String>,
}

/// `POST /api/v1/account/delete` (§5.2.3).
pub async fn delete(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    user.require_config()?;
    let req: DeleteRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let _ = req.guard;
    state
        .host
        .delete_account(user.user_id)
        .map_err(|e| ApiError::Internal(format!("membership: {e}")))?;
    if let Some(h) = user.session_token_hash.as_deref() {
        state.store.delete_session(h).ok();
    }
    Ok(StatusCode::NO_CONTENT)
}
