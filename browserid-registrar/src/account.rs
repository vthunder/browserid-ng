//! Accounts, login, login certs, and membership over the API
//! (registry-api-v1 §4.2, §5.2): `accounts` creates an account around an
//! identity, `accounts/lookup` finds one, `login` opens a session by a
//! method the registry offers, `login-keys` are the registry's own signed
//! credentials for headless logins, and `attach` / `detach` / `delete`
//! are writes under a session.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use crate::api::{ApiError, ApiUser};
use crate::consent::status_list_uri;
use crate::models::{DeviceCertRecord, LoginCertRecord};
use crate::session::{b64url_sha256, header_proof, kid_of, replay_check, BodyHash, Proof};
use crate::RegistrarState;

/// A cert creating an account or moving an identity must be this fresh.
const FRESHNESS_SECONDS: i64 = 300;
/// Login cert lifetime: registry policy, RECOMMENDED 90 days.
const LOGIN_CERT_DAYS: i64 = 90;
pub const LOGIN_CERT_TYP: &str = "browserid-login-cert-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertProof {
    cert: String,
    proof: String,
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

/// The shared bar for carried certs (§5.2.1, §5.2.4): parse, identity
/// naming, no bare glob, the host's verification, the retired-key rule,
/// the possession proof (same jti, no bh); then the holder rule.
async fn carried_certs(
    state: &RegistrarState,
    hp: &Proof,
    path: &str,
    identity: &str,
    certs: &[CertProof],
) -> Result<Vec<Carried>, ApiError> {
    if certs.is_empty() || certs.len() > 2 {
        return Err(ApiError::InvalidRequest("certs must carry 1–2 entries".into()));
    }
    let verifier = state.presentation_verifier.as_ref().ok_or_else(|| {
        ApiError::Internal("device-cert verification is not configured on this host".into())
    })?;
    let mut out: Vec<Carried> = Vec::new();
    for (i, cp) in certs.iter().enumerate() {
        let which = format!("certs[{i}]");
        let parsed = browserid_core::device::DeviceCert::parse(&cp.cert)
            .map_err(|e| invalid_cert("cert_malformed", format!("{which}: {e}")))?;
        let claims = parsed.claims();
        if claims.identities.iter().any(|x| x.trim() == "*") {
            return Err(invalid_cert("glob_identity", format!("{which}: glob identities are refused")));
        }
        if !claims.identities.iter().any(|x| x.eq_ignore_ascii_case(identity)) {
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
        p.check_claims(state, "POST", path, None)?;
        out.push(Carried {
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
    if out.len() == 2 {
        if out[0].holder != out[1].holder {
            return Err(invalid_cert("holder_mismatch", "the two certs carry different holders"));
        }
        if out[0].purpose == out[1].purpose {
            return Err(ApiError::InvalidRequest("certs must be one auth cert and/or one config cert".into()));
        }
    }
    Ok(out)
}

fn fresh(carried: &[Carried]) -> bool {
    let now = Utc::now().timestamp();
    carried.iter().all(|c| (now - c.iat).abs() <= FRESHNESS_SECONDS)
}

fn host_err(e: crate::error::RegistrarError) -> ApiError {
    ApiError::Internal(format!("membership: {e}"))
}

/// Record carried certs on `user_id` with the holder healing the cookie
/// lane does; returns the recorded row ids.
async fn record(
    state: &RegistrarState,
    headers: &axum::http::HeaderMap,
    user_id: u64,
    identity: &str,
    carried: &[Carried],
) -> Result<Vec<u64>, ApiError> {
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
    let mut ids = Vec::new();
    for c in carried {
        let mut recorded_for = vec![identity.to_string()];
        for other in &c.identities {
            if other.eq_ignore_ascii_case(identity) || other.contains('*') {
                continue;
            }
            if state.host.identity_holder(other).map_err(host_err)? == Some(user_id) {
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
        ids.push(id);
    }
    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok());
    crate::holders::maybe_label_holder_from_ua(&*state.store, user_id, &holder_id, ua);
    if let Some(target) = &move_target {
        crate::holders::maybe_label_holder_from_ua(&*state.store, user_id, target, ua);
    }
    crate::holders::finish_holder_move(&*state.store, user_id, &holder_id);
    Ok(ids)
}

// ---------------------------------------------------------------------------
// §5.2.1 accounts, accounts/lookup
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountsRequest {
    identity: String,
    certs: Vec<CertProof>,
    #[serde(default)]
    confirm_takeover: bool,
}

fn identity_arg(raw: &str) -> Result<String, ApiError> {
    let identity = raw.trim().to_lowercase();
    if identity.is_empty() || !identity.contains('@') {
        return Err(ApiError::InvalidRequest("identity must be an email address".into()));
    }
    Ok(identity)
}

/// Header proof by one of the carried certs, its claims, and replay.
fn header_by_carried(state: &RegistrarState, hp: &Proof, carried: &[Carried], path: &str, bh: &str) -> Result<(), ApiError> {
    let signer = carried
        .iter()
        .find(|c| c.kid == hp.kid)
        .ok_or_else(|| ApiError::InvalidProof("the Proof key is not one of the carried certs".into()))?;
    hp.verify(&signer.pubkey)?;
    hp.check_claims(state, "POST", path, Some(bh))?;
    replay_check(state, &hp.kid, &hp.jti)
}

/// `POST /api/v1/accounts` (§5.2.1).
pub async fn create(
    State(state): State<Arc<RegistrarState>>,
    headers: axum::http::HeaderMap,
    axum::Extension(BodyHash(bh)): axum::Extension<BodyHash>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.enabled {
        return Err(ApiError::NotFound);
    }
    let path = "/api/v1/accounts";
    let hp = header_proof(&headers)?;
    let req: AccountsRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let identity = identity_arg(&req.identity)?;
    let carried = carried_certs(&state, &hp, path, &identity, &req.certs).await?;
    header_by_carried(&state, &hp, &carried, path, &bh)?;
    if !carried.iter().any(|c| c.purpose == "authorization") {
        return Err(invalid_cert("config_required", "creating an account needs a config cert"));
    }
    if !fresh(&carried) {
        return Err(invalid_cert("cert_not_fresh", format!("certs creating an account must be issued within {FRESHNESS_SECONDS} s")));
    }
    let holder = state.host.identity_holder(&identity).map_err(host_err)?;
    let iss = carried[0].iss.clone();
    let user_id = match holder {
        None => state.host.create_account_with_identity(&identity, &iss).map_err(host_err)?,
        Some(_) if !req.confirm_takeover => {
            return Err(ApiError::Conflict {
                reason: "identity_held",
                description: "another account holds this identity; set confirm_takeover to take it".into(),
            })
        }
        Some(a) => {
            // Takeover: the certs are recorded on the new account FIRST, so an
            // issuer that also runs this registry revokes only the old
            // account's remaining certs for the identity (hg2j).
            let fresh_account = state.host.create_empty_account().map_err(host_err)?;
            let ids = record(&state, &headers, fresh_account, &identity, &carried).await?;
            state.host.transfer_identity(a, fresh_account, &identity, "taken_over").map_err(host_err)?;
            tracing::info!(%identity, "accounts: takeover into a new account");
            return Ok(Json(crate::session::open(&state, fresh_account, ids, None).await?));
        }
    };
    let ids = record(&state, &headers, user_id, &identity, &carried).await?;
    tracing::info!(%identity, "accounts: created");
    Ok(Json(crate::session::open(&state, user_id, ids, None).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LookupRequest {
    identity: String,
    certs: Vec<CertProof>,
}

/// `POST /api/v1/accounts/lookup` (§5.2.1).
pub async fn lookup(
    State(state): State<Arc<RegistrarState>>,
    headers: axum::http::HeaderMap,
    axum::Extension(BodyHash(bh)): axum::Extension<BodyHash>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.enabled {
        return Err(ApiError::NotFound);
    }
    let path = "/api/v1/accounts/lookup";
    let hp = header_proof(&headers)?;
    let req: LookupRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let identity = identity_arg(&req.identity)?;
    let carried = carried_certs(&state, &hp, path, &identity, &req.certs).await?;
    header_by_carried(&state, &hp, &carried, path, &bh)?;
    let Some(user_id) = state.host.identity_holder(&identity).map_err(host_err)? else {
        return Err(ApiError::NotFound);
    };
    let account = state.host.account_public_id(user_id).map_err(host_err)?;
    Ok(Json(serde_json::json!({ "account": account })))
}

// ---------------------------------------------------------------------------
// §4.2 login
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    account: String,
    method: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    proof: Option<String>,
}

fn rejected(d: &str) -> ApiError {
    ApiError::Forbidden { reason: "login_rejected", description: d.into() }
}

/// `POST /api/v1/login` (§4.2). Every failure is one reason.
pub async fn login(
    State(state): State<Arc<RegistrarState>>,
    headers: axum::http::HeaderMap,
    axum::Extension(BodyHash(bh)): axum::Extension<BodyHash>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.enabled {
        return Err(ApiError::NotFound);
    }
    let path = "/api/v1/login";
    let req: LoginRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let account = state
        .host
        .account_for_public_id(&req.account)
        .map_err(|e| ApiError::Internal(format!("account lookup: {e}")))?;
    match req.method.as_str() {
        "login_page" => {
            let Some(token) = req.token.filter(|t| !t.is_empty()) else {
                let Some(url) = state.login_page_url.clone() else {
                    return Err(rejected("this registry offers no login page"));
                };
                return Err(ApiError::LoginRequired { url });
            };
            let spent = state
                .store
                .take_login_token(&b64url_sha256(token.as_bytes()))
                .map_err(|e| ApiError::Internal(format!("login token: {e}")))?;
            match (spent, account) {
                (Some(uid), Some(acct)) if uid == acct => {
                    Ok(Json(crate::session::open(&state, acct, Vec::new(), None).await?))
                }
                _ => Err(rejected("login refused")),
            }
        }
        "stored_key" => {
            // The header proof (bh) and the possession proof are both by the
            // login key; `proof` names it by kid.
            let hp = header_proof(&headers)?;
            let Some(raw) = req.proof.as_deref() else {
                return Err(ApiError::InvalidRequest("proof is required for stored_key".into()));
            };
            let pp = Proof::parse(raw)?;
            let Some(acct) = account else { return Err(rejected("login refused")) };
            let rec = state
                .store
                .get_login_cert_by_kid(&pp.kid)
                .map_err(|e| ApiError::Internal(format!("login cert: {e}")))?
                .filter(|c| c.user_id == acct && c.is_live())
                .filter(|c| !c.status_idx.map_or(false, |i| state.store.is_status_revoked_idx(i).unwrap_or(true)))
                .ok_or_else(|| rejected("login refused"))?;
            if hp.kid != rec.kid || pp.jti != hp.jti {
                return Err(rejected("login refused"));
            }
            hp.verify(&rec.pubkey).map_err(|_| rejected("login refused"))?;
            hp.check_claims(&state, "POST", path, Some(&bh))?;
            pp.verify(&rec.pubkey).map_err(|_| rejected("login refused"))?;
            pp.check_claims(&state, "POST", path, None)?;
            replay_check(&state, &hp.kid, &hp.jti)?;
            Ok(Json(crate::session::open(&state, acct, Vec::new(), Some(rec.id)).await?))
        }
        other => Err(ApiError::InvalidRequest(format!("unknown login method '{other}'"))),
    }
}

// ---------------------------------------------------------------------------
// §5.2.3 login-keys
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginKeyRequest {
    pubkey: String,
    #[serde(default)]
    label: Option<String>,
}

/// `POST /api/v1/login-keys`: sign the wallet's login key into a login cert.
pub async fn create_login_key(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req: LoginKeyRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let key = browserid_core::PublicKey::from_base64(&req.pubkey)
        .map_err(|e| ApiError::InvalidRequest(format!("bad pubkey: {e}")))?;
    let kid = key.kid();
    let label = match req.label.as_deref().map(str::trim).filter(|l| !l.is_empty()) {
        Some(l) => Some(crate::holders::validate_label(l).map_err(|e| ApiError::InvalidRequest(e.to_string()))?),
        None => None,
    };
    if let Some(existing) = state
        .store
        .get_login_cert_by_kid(&kid)
        .map_err(|e| ApiError::Internal(format!("login cert: {e}")))?
    {
        if existing.user_id != user.user_id {
            return Err(ApiError::InvalidRequest("this key is already a login key elsewhere".into()));
        }
    }
    let account = state
        .host
        .account_public_id(user.user_id)
        .map_err(|e| ApiError::Internal(format!("account id: {e}")))?;
    let idx = state
        .store
        .get_or_allocate_status("login", &kid)
        .map_err(|e| ApiError::Internal(format!("status: {e}")))?;
    let now = Utc::now();
    let exp = now + Duration::days(LOGIN_CERT_DAYS);
    let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"EdDSA","typ":"{LOGIN_CERT_TYP}","kid":"{kid}"}}"#));
    let claims = serde_json::json!({
        "typ": LOGIN_CERT_TYP,
        "iss": state.domain,
        "sub": account,
        "kid": kid,
        "public-key": req.pubkey,
        "iat": now.timestamp(),
        "exp": exp.timestamp(),
        "status": { "uri": status_list_uri(&state.domain), "idx": idx },
    });
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let message = format!("{header}.{payload}");
    let sig = URL_SAFE_NO_PAD.encode(state.keypair.sign(message.as_bytes()));
    let cert = format!("{message}.{sig}");
    let id = state
        .store
        .insert_login_cert(LoginCertRecord {
            id: 0,
            user_id: user.user_id,
            kid: kid.clone(),
            pubkey: req.pubkey,
            label,
            cert: cert.clone(),
            issued_at: now,
            expires_at: exp,
            revoked_at: None,
            status_idx: Some(idx),
        })
        .map_err(|e| ApiError::Internal(format!("login cert store: {e}")))?;
    // A replaced (re-issued) key is live again.
    state.store.set_status_active_idx(idx).ok();
    Ok(Json(serde_json::json!({ "id": id, "kid": kid, "cert": cert, "expires_at": exp.to_rfc3339() })))
}

/// `GET /api/v1/login-keys`.
pub async fn list_login_keys(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let certs = state
        .store
        .list_login_certs(user.user_id)
        .map_err(|e| ApiError::Internal(format!("login certs: {e}")))?;
    let items: Vec<serde_json::Value> = certs
        .into_iter()
        .map(|c| serde_json::json!({
            "id": c.id, "kid": c.kid, "label": c.label,
            "issued_at": c.issued_at.to_rfc3339(), "expires_at": c.expires_at.to_rfc3339(),
            "revoked": c.revoked_at.is_some() || c.status_idx.map_or(false, |i| state.store.is_status_revoked_idx(i).unwrap_or(false)),
        }))
        .collect();
    Ok(Json(serde_json::json!({ "login_keys": items })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginKeyRevokeRequest {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    kid: Option<String>,
}

/// `POST /api/v1/login-keys/revoke`: own key under any session, else config.
pub async fn revoke_login_key(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let req: LoginKeyRevokeRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let certs = state
        .store
        .list_login_certs(user.user_id)
        .map_err(|e| ApiError::Internal(format!("login certs: {e}")))?;
    let rec = match (req.id, req.kid) {
        (Some(id), None) => certs.into_iter().find(|c| c.id == id),
        (None, Some(kid)) => certs.into_iter().find(|c| c.kid == kid),
        _ => return Err(ApiError::InvalidRequest("exactly one of id or kid".into())),
    }
    .ok_or(ApiError::NotFound)?;
    if user.login_key_id != Some(rec.id) {
        user.require_config()?;
    }
    state.store.revoke_login_cert(user.user_id, rec.id).map_err(|e| ApiError::Internal(format!("login cert: {e}")))?;
    if let Some(idx) = rec.status_idx {
        state.store.set_status_revoked_idx(idx).ok();
    }
    state.store.end_sessions_solely_on_login_key(user.user_id, rec.id).ok();
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// §5.2.4–§5.2.6 attach, detach, delete
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachRequest {
    identity: String,
    certs: Vec<CertProof>,
    #[serde(default)]
    confirm_takeover: bool,
}

/// `POST /api/v1/account/attach` (§5.2.4): a write under a session. The
/// header proof is by a session member, or by one of the carried certs —
/// a page login's session has no member until this call gives it one.
pub async fn attach(
    State(state): State<Arc<RegistrarState>>,
    headers: axum::http::HeaderMap,
    axum::Extension(BodyHash(bh)): axum::Extension<BodyHash>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let path = "/api/v1/account/attach";
    let (session, members) = crate::session::bearer_session(&state, &headers).await?;
    let hp = header_proof(&headers)?;
    let req: AttachRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let identity = identity_arg(&req.identity)?;
    let carried = carried_certs(&state, &hp, path, &identity, &req.certs).await?;
    let signer_key = members
        .iter()
        .find(|m| m.kid() == hp.kid)
        .map(|m| m.pubkey().to_string())
        .or_else(|| carried.iter().find(|c| c.kid == hp.kid).map(|c| c.pubkey.clone()))
        .ok_or_else(|| ApiError::InvalidProof("the Proof key is neither a member nor a carried cert".into()))?;
    hp.verify(&signer_key)?;
    hp.check_claims(&state, "POST", path, Some(&bh))?;
    replay_check(&state, &hp.kid, &hp.jti)?;
    let member_cert_ids: Vec<u64> = members.iter().filter_map(|m| match m {
        crate::session::Member::Cert { cert, .. } => Some(cert.id),
        _ => None,
    }).collect();
    let has_config = carried.iter().any(|c| c.purpose == "authorization");
    let iss = carried[0].iss.clone();
    let acct = session.user_id;
    let holder = state.host.identity_holder(&identity).map_err(host_err)?;
    let require_config = || -> Result<(), ApiError> {
        if has_config { Ok(()) } else { Err(invalid_cert("config_required", "this case needs a config cert")) }
    };
    let require_fresh = || -> Result<(), ApiError> {
        if fresh(&carried) { Ok(()) } else { Err(invalid_cert("cert_not_fresh", format!("a cert moving an identity must be issued within {FRESHNESS_SECONDS} s"))) }
    };
    enum Pending {
        Transfer(u64),
        Add,
        Restore,
    }
    let pending = if holder == Some(acct) {
        None
    } else if state.host.identity_suspended_on(acct, &identity).map_err(host_err)? {
        require_fresh()?;
        Some(match holder {
            Some(elsewhere) => Pending::Transfer(elsewhere),
            None => Pending::Restore,
        })
    } else if holder.is_none() {
        require_config()?;
        require_fresh()?;
        Some(Pending::Add)
    } else {
        require_config()?;
        if !req.confirm_takeover {
            return Err(ApiError::Conflict {
                reason: "identity_held",
                description: "another account holds this identity; set confirm_takeover to transfer it".into(),
            });
        }
        require_fresh()?;
        Some(Pending::Transfer(holder.unwrap()))
    };
    let ids = record(&state, &headers, acct, &identity, &carried).await?;
    match pending {
        Some(Pending::Transfer(from)) => state.host.transfer_identity(from, acct, &identity, "transferred").map_err(host_err)?,
        Some(Pending::Add) => state.host.add_identity(acct, &identity, &iss).map_err(host_err)?,
        Some(Pending::Restore) => state.host.restore_identity(acct, &identity, &iss).map_err(host_err)?,
        None => {}
    }
    // The fresh session: the call's certs plus the caller's members.
    let mut union = ids.clone();
    for m in &member_cert_ids {
        if !union.contains(m) {
            union.push(*m);
        }
    }
    tracing::info!(%identity, "attach: recorded {} cert(s)", ids.len());
    Ok(Json(crate::session::open(&state, acct, union, session.login_key_id).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetachRequest {
    identity: String,
}

/// `POST /api/v1/account/detach` (§5.2.5).
pub async fn detach(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    user.require_config()?;
    let req: DetachRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let identity = req.identity.trim().to_lowercase();
    if state.host.identity_holder(&identity).map_err(host_err)? != Some(user.user_id) {
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
    state.host.detach_identity(user.user_id, &identity).map_err(host_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/account/delete` (§5.2.6).
pub async fn delete(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    user.require_config()?;
    let _: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    state.host.delete_account(user.user_id).map_err(host_err)?;
    if let Some(h) = user.session_token_hash.as_deref() {
        state.store.delete_session(h).ok();
    }
    Ok(StatusCode::NO_CONTENT)
}

