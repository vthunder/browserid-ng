//! Accounts, login, login keys, and membership over the API
//! (registry-api-v1 §4.2, §5.2): `accounts` creates an account around an
//! identity, `accounts/lookup` finds one, `login` opens a session bound to
//! the device's login key (enrolled right there), `login-keys` lists and
//! revokes those keys, and `attach` / `detach` / `delete` are writes under
//! a session.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use crate::api::{ApiError, ApiUser};
use crate::models::{DeviceCertRecord, LoginCertRecord};
use crate::session::{b64url_sha256, header_proof, kid_of, replay_check, BodyHash, Proof};
use crate::RegistrarState;

/// A cert creating an account or moving an identity must be this fresh.
const FRESHNESS_SECONDS: i64 = 300;
/// Login key lifetime from its last login through the page: registry
/// policy, RECOMMENDED 90 days.
const LOGIN_KEY_DAYS: i64 = 90;

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

/// Record carried certs on `user_id`; returns the recorded row ids. A
/// first device's self-assigned holder prefix becomes the account's
/// `browsers` namespace while that is still unused; otherwise the holder
/// keeps its own prefix and lists outside the namespaces (§5.6).
async fn record(
    state: &RegistrarState,
    headers: &axum::http::HeaderMap,
    user_id: u64,
    identity: &str,
    carried: &[Carried],
    login_key_id: u64,
) -> Result<Vec<u64>, ApiError> {
    let holder_id = carried[0].holder.clone();
    if let Some((prefix, _)) = holder_id.split_once('.') {
        if let Err(e) = state.store.adopt_namespace_prefix(user_id, "browsers", prefix) {
            tracing::warn!("browsers prefix adoption failed: {e}");
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
                login_key_id: Some(login_key_id),
            })
            .map_err(|e| ApiError::Internal(format!("device cert store: {e}")))?;
        ids.push(id);
    }
    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok());
    crate::holders::maybe_label_holder_from_ua(&*state.store, user_id, &holder_id, ua);
    Ok(ids)
}

// ---------------------------------------------------------------------------
// Login keys (§4.2): the argument `accounts` and `login_page` carry, its
// possession proof, and enrolment.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginKeyArg {
    pubkey: String,
    #[serde(default)]
    label: Option<String>,
    proof: String,
}

/// The login key a session-opening call brings, after its possession proof
/// (same jti as the header proof, no bh) and the header proof by it.
struct BroughtKey {
    pubkey: String,
    kid: String,
    label: Option<String>,
}

/// `label` is the wallet's, else one derived from the User-Agent ("Chrome
/// on macOS"), so a device the wallet did not name still reads as itself.
fn brought_key(
    state: &RegistrarState,
    headers: &axum::http::HeaderMap,
    hp: &Proof,
    path: &str,
    bh: &str,
    arg: &LoginKeyArg,
) -> Result<BroughtKey, ApiError> {
    let key = browserid_core::PublicKey::from_base64(&arg.pubkey)
        .map_err(|e| ApiError::InvalidRequest(format!("login_key: bad pubkey: {e}")))?;
    let kid = key.kid();
    let pp = Proof::parse(&arg.proof)?;
    if pp.jti != hp.jti {
        return Err(ApiError::InvalidProof("proofs in one request must share a jti".into()));
    }
    if pp.kid != kid {
        return Err(ApiError::InvalidProof("login_key: possession proof kid does not match the key".into()));
    }
    pp.verify(&arg.pubkey)?;
    pp.check_claims(state, "POST", path, None)?;
    if hp.kid != kid {
        return Err(ApiError::InvalidProof("the Proof header must be signed by the login key".into()));
    }
    hp.verify(&arg.pubkey)?;
    hp.check_claims(state, "POST", path, Some(bh))?;
    replay_check(state, &kid, &hp.jti)?;
    let label = match arg.label.as_deref().map(str::trim).filter(|l| !l.is_empty()) {
        Some(l) => Some(crate::holders::validate_label(l).map_err(|e| ApiError::InvalidRequest(e.to_string()))?),
        None => headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .and_then(crate::holders::ua_label),
    };
    Ok(BroughtKey { pubkey: arg.pubkey.clone(), kid, label })
}

/// Enrol (or re-enrol) a login key on `user_id` after a passed login: a
/// fresh expiry, revocation cleared, label and holder kept unless given.
fn enroll(
    state: &RegistrarState,
    user_id: u64,
    key: &BroughtKey,
    holder: Option<&str>,
) -> Result<LoginCertRecord, ApiError> {
    let existing = state
        .store
        .get_login_cert_by_kid(&key.kid)
        .map_err(|e| ApiError::Internal(format!("login key: {e}")))?;
    if let Some(e) = &existing {
        if e.user_id != user_id {
            return Err(ApiError::InvalidRequest("this key is a login key on another account".into()));
        }
    }
    let now = Utc::now();
    let rec = LoginCertRecord {
        id: 0,
        user_id,
        kid: key.kid.clone(),
        pubkey: key.pubkey.clone(),
        label: key.label.clone().or_else(|| existing.as_ref().and_then(|e| e.label.clone())),
        holder: holder.map(str::to_string).or_else(|| existing.as_ref().and_then(|e| e.holder.clone())),
        cert: String::new(),
        issued_at: now,
        expires_at: now + Duration::days(LOGIN_KEY_DAYS),
        revoked_at: None,
        status_idx: None,
    };
    let id = state
        .store
        .insert_login_cert(rec.clone())
        .map_err(|e| ApiError::Internal(format!("login key store: {e}")))?;
    Ok(LoginCertRecord { id, ..rec })
}

// ---------------------------------------------------------------------------
// §5.2.1 accounts, accounts/lookup
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountsRequest {
    identity: String,
    certs: Vec<CertProof>,
    login_key: LoginKeyArg,
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
    let path = "/api/v1/accounts";
    let hp = header_proof(&headers)?;
    let req: AccountsRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let identity = identity_arg(&req.identity)?;
    let carried = carried_certs(&state, &hp, path, &identity, &req.certs).await?;
    let key = brought_key(&state, &headers, &hp, path, &bh, &req.login_key)?;
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
            let k = enroll(&state, fresh_account, &key, Some(&carried[0].holder))?;
            record(&state, &headers, fresh_account, &identity, &carried, k.id).await?;
            state.host.transfer_identity(a, fresh_account, &identity, "taken_over").map_err(host_err)?;
            tracing::info!(%identity, "accounts: takeover into a new account");
            return Ok(Json(crate::session::open(&state, fresh_account, &k).await?));
        }
    };
    let k = enroll(&state, user_id, &key, Some(&carried[0].holder))?;
    record(&state, &headers, user_id, &identity, &carried, k.id).await?;
    tracing::info!(%identity, "accounts: created");
    Ok(Json(crate::session::open(&state, user_id, &k).await?))
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
    login_key: Option<LoginKeyArg>,
    #[serde(default)]
    proof: Option<String>,
}

fn rejected(d: &str) -> ApiError {
    ApiError::Forbidden { reason: "login_rejected", description: d.into() }
}

/// `403 login_required` with the page, or `login_rejected` when this
/// registry runs no page.
fn login_required(state: &RegistrarState) -> ApiError {
    match state.login_page_url.clone() {
        Some(url) => ApiError::LoginRequired { url },
        None => rejected("this registry offers no login page"),
    }
}

/// `POST /api/v1/login` (§4.2): `login_page` enrols the key the call
/// brings; `stored_key` proves one already enrolled. Anything the registry
/// will not open headlessly is `login_required`; a bad token is
/// `login_rejected`.
pub async fn login(
    State(state): State<Arc<RegistrarState>>,
    headers: axum::http::HeaderMap,
    axum::Extension(BodyHash(bh)): axum::Extension<BodyHash>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
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
                return Err(login_required(&state));
            };
            let Some(arg) = req.login_key.as_ref() else {
                return Err(ApiError::InvalidRequest("login_key is required with a token".into()));
            };
            let hp = header_proof(&headers)?;
            let key = brought_key(&state, &headers, &hp, path, &bh, arg)?;
            let spent = state
                .store
                .take_login_token(&b64url_sha256(token.as_bytes()))
                .map_err(|e| ApiError::Internal(format!("login token: {e}")))?;
            match (spent, account) {
                (Some(uid), Some(acct)) if uid == acct => {
                    let k = enroll(&state, acct, &key, None)?;
                    Ok(Json(crate::session::open(&state, acct, &k).await?))
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
            let Some(acct) = account else { return Err(login_required(&state)) };
            let rec = state
                .store
                .get_login_cert_by_kid(&pp.kid)
                .map_err(|e| ApiError::Internal(format!("login key: {e}")))?
                .filter(|c| c.user_id == acct && c.is_live())
                .ok_or_else(|| login_required(&state))?;
            if hp.kid != rec.kid || pp.jti != hp.jti {
                return Err(ApiError::InvalidProof("the Proof header and proof must be by the same login key".into()));
            }
            hp.verify(&rec.pubkey)?;
            hp.check_claims(&state, "POST", path, Some(&bh))?;
            pp.verify(&rec.pubkey)?;
            pp.check_claims(&state, "POST", path, None)?;
            replay_check(&state, &hp.kid, &hp.jti)?;
            Ok(Json(crate::session::open(&state, acct, &rec).await?))
        }
        other => Err(ApiError::InvalidRequest(format!("unknown login method '{other}'"))),
    }
}

// ---------------------------------------------------------------------------
// §5.2.3 login-keys
// ---------------------------------------------------------------------------

/// `GET /api/v1/login-keys`.
pub async fn list_login_keys(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let keys = state
        .store
        .list_login_certs(user.user_id)
        .map_err(|e| ApiError::Internal(format!("login keys: {e}")))?;
    let items: Vec<serde_json::Value> = keys
        .into_iter()
        .map(|k| serde_json::json!({
            "id": k.id, "kid": k.kid, "label": k.label, "holder": k.holder,
            "enrolled_at": k.issued_at.to_rfc3339(), "expires_at": k.expires_at.to_rfc3339(),
            "revoked": k.revoked_at.is_some(),
            "current": k.id == user.login_key_id,
        }))
        .collect();
    Ok(Json(serde_json::json!({ "login_keys": items })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginKeyRenameRequest {
    id: u64,
    label: String,
}

/// `POST /api/v1/login-keys/rename` (§5.2.3).
pub async fn rename_login_key(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let req: LoginKeyRenameRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let label = crate::holders::validate_label(req.label.trim()).map_err(|e| ApiError::InvalidRequest(e.to_string()))?;
    let ok = state
        .store
        .set_login_cert_label(user.user_id, req.id, &label)
        .map_err(|e| ApiError::Internal(format!("login key: {e}")))?;
    if !ok {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginKeyRevokeRequest {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    kid: Option<String>,
}

/// `POST /api/v1/login-keys/revoke`: logs the device out — the key revoked
/// and its sessions ended (this one included, when it is the key named),
/// and the certs recorded with its holder retired, so it can neither manage
/// the account nor sign in anywhere with them.
pub async fn revoke_login_key(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req: LoginKeyRevokeRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let keys = state
        .store
        .list_login_certs(user.user_id)
        .map_err(|e| ApiError::Internal(format!("login keys: {e}")))?;
    let rec = match (req.id, req.kid) {
        (Some(id), None) => keys.into_iter().find(|c| c.id == id),
        (None, Some(kid)) => keys.into_iter().find(|c| c.kid == kid),
        _ => return Err(ApiError::InvalidRequest("exactly one of id or kid".into())),
    }
    .ok_or(ApiError::NotFound)?;
    state.store.revoke_login_cert(user.user_id, rec.id).map_err(|e| ApiError::Internal(format!("login key: {e}")))?;
    state.store.end_sessions_on_login_key(user.user_id, rec.id).ok();
    let unrevocable = crate::holders::log_out_key_core(&*state.store, &*state.host, &state.domain, user.user_id, &rec)
        .map_err(|e| ApiError::Internal(format!("device logout: {e}")))?;
    Ok(Json(serde_json::json!({ "unrevocable": unrevocable })))
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

/// `POST /api/v1/account/attach` (§5.2.4): records certs under a session.
/// The session is unchanged; the device's holder lands on the session's
/// login key when it has none yet.
pub async fn attach(
    State(state): State<Arc<RegistrarState>>,
    headers: axum::http::HeaderMap,
    axum::Extension(BodyHash(bh)): axum::Extension<BodyHash>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let path = "/api/v1/account/attach";
    let (session, key, hp) = crate::session::verify_session_call(&state, &headers, "POST", path, Some(&bh)).await?;
    let req: AttachRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let identity = identity_arg(&req.identity)?;
    let carried = carried_certs(&state, &hp, path, &identity, &req.certs).await?;
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
    let ids = record(&state, &headers, acct, &identity, &carried, key.id).await?;
    match pending {
        Some(Pending::Transfer(from)) => state.host.transfer_identity(from, acct, &identity, "transferred").map_err(host_err)?,
        Some(Pending::Add) => state.host.add_identity(acct, &identity, &iss).map_err(host_err)?,
        Some(Pending::Restore) => state.host.restore_identity(acct, &identity, &iss).map_err(host_err)?,
        None => {}
    }
    if key.holder.is_none() {
        state.store.set_login_cert_holder(acct, key.id, &carried[0].holder).ok();
    }
    tracing::info!(%identity, "attach: recorded {} cert(s)", ids.len());
    Ok(Json(serde_json::json!({ "recorded": ids })))
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
    let _: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    state.host.delete_account(user.user_id).map_err(host_err)?;
    state.store.delete_session(&user.session_token_hash).ok();
    Ok(StatusCode::NO_CONTENT)
}

