//! Registry API v1 (docs/specs/registry-api-v1.md): the token-authenticated
//! wire surface that makes a native wallet a first-class registry client.
//!
//! Authentication is a two-step (§3): `POST /api/v1/token` exchanges a
//! presentation bundle addressed to the registry's own origin for a
//! short-lived, sender-constrained access token; every subsequent call
//! carries the token plus a DPoP-style proof signed with the same config-cert
//! key the presentation proved. There are no refresh tokens — re-exchanging a
//! fresh presentation IS the refresh — and revocation rides the bound config
//! cert's status bit, re-checked fail-closed on every call.
//!
//! Errors are OAuth-shaped (§7): `{ "error": ..., "error_description": ...,
//! "reason"?: ... }` — a deliberate departure from the legacy
//! `{"success": false}` envelope, which does not exist on this surface.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::extract::{FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::consent::status_list_uri;
use crate::RegistrarState;

/// Token lifetime ceiling (§3.1): `expires_in` SHOULD be at most 3600s, and
/// the token MUST NOT outlive the config cert it is bound to.
/// Proof `iat` acceptance window (§3.2, RECOMMENDED ±300s).
pub(crate) const PROOF_IAT_WINDOW_SECONDS: i64 = 300;
/// Request body cap, API-wide (§3.1, RECOMMENDED 64 KiB).
pub(crate) const API_BODY_LIMIT: usize = 64 * 1024;
/// The proof's domain-separating JWS `typ` (§3.2).
pub(crate) const PROOF_TYP: &str = "browserid-registry-proof-v1";

// ===========================================================================
// Host-provided verification
// ===========================================================================

/// The host's core §6 verification stack, seen through the registry API's
/// eyes. The registrar deliberately does not verify presentations itself —
/// DNSSEC-rooted discovery, conformance rules, and fail-closed status
/// fetching live with the host (the broker's `verify_access_with_dns`), and
/// the exchange MUST NOT be weaker in any respect than the cookie sibling.
pub trait PresentationVerifier: Send + Sync {
    /// Fail-closed revocation check of one status ref (core §6.3): own-list
    /// refs answered authoritatively, foreign refs by authenticated fetch.
    /// `Ok(true)` = revoked; `Err` = uncheckable, which callers MUST treat as
    /// revoked.
    fn check_status_ref<'a>(
        &'a self,
        uri: &'a str,
        idx: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>>;

    /// Verify ONE device cert for §5.3 `devices/register`: parse, purpose,
    /// expiry, issuer acceptance (the identity domain's DNSSEC key, or a
    /// fallback issuer in the operator's accepted set), signature, and a
    /// fail-closed status check. Refusals are distinguishable so the
    /// endpoint can surface §7.1's `invalid_cert` reasons — unlike the
    /// anonymous exchange, this endpoint is authenticated, so it is not a
    /// verification oracle.
    fn verify_device_cert<'a>(
        &'a self,
        cert: &'a str,
        expected_purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<VerifiedDeviceCert, DeviceCertRefusal>> + Send + 'a>>;
}

/// What §5.3 registration learns from one fully verified device cert.
#[derive(Debug, Clone)]
pub struct VerifiedDeviceCert {
    /// Emails (or single-`*` globs) the cert authorizes.
    pub identities: Vec<String>,
    /// "authentication" | "authorization".
    pub purpose: String,
    /// The opaque holder id the cert acts as.
    pub holder: String,
    /// The cert's public key, base64.
    pub pubkey: String,
    /// Issuing IdP domain.
    pub iss: String,
    /// Issued-at / expiry, epoch seconds.
    pub iat: i64,
    pub exp: i64,
    /// The cert's own status ref, when it carries one.
    pub status_uri: Option<String>,
    pub status_idx: Option<u64>,
}

/// Why [`PresentationVerifier::verify_device_cert`] refused — one variant per
/// §7.1 `invalid_cert` reason the host can decide.
#[derive(Debug)]
pub enum DeviceCertRefusal {
    /// Does not parse as a device cert (or carries no concrete identity).
    Malformed(String),
    /// `purpose` differs from the expected one.
    WrongPurpose(String),
    /// Past `exp`.
    Expired,
    /// Issuer is neither the identity domain's DNSSEC IdP nor in the
    /// operator's accepted-fallback set.
    IssuerNotAccepted(String),
    /// Signature does not verify under the resolved issuer key.
    SignatureInvalid,
    /// A status ref checks revoked, or is uncheckable (fail-closed).
    Revoked(String),
    /// A deployment fault, never a caller error.
    Internal(String),
}

impl DeviceCertRefusal {
    /// Map onto the §7.1 `invalid_cert` reason vocabulary; `which` names the
    /// offending request field in the human diagnostic.
    pub(crate) fn into_api_error(self, which: &str) -> ApiError {
        let (reason, description) = match self {
            DeviceCertRefusal::Malformed(d) => ("cert_malformed", format!("{which}: {d}")),
            DeviceCertRefusal::WrongPurpose(d) => ("wrong_purpose", format!("{which}: {d}")),
            DeviceCertRefusal::Expired => ("cert_expired", format!("{which} is expired")),
            DeviceCertRefusal::IssuerNotAccepted(d) => {
                ("issuer_not_accepted", format!("{which}: {d}"))
            }
            DeviceCertRefusal::SignatureInvalid => (
                "signature_invalid",
                format!("{which}: signature does not verify under the issuer's key"),
            ),
            DeviceCertRefusal::Revoked(d) => ("cert_revoked", format!("{which}: {d}")),
            DeviceCertRefusal::Internal(d) => return ApiError::Internal(d),
        };
        ApiError::InvalidCert { reason, description }
    }
}

// ===========================================================================
// Errors (§7)
// ===========================================================================

#[derive(Debug)]
pub enum ApiError {
    /// 400 — malformed JSON, missing/unknown fields, grammar violations.
    InvalidRequest(String),
    /// 401 — the proof failed one of the §4.4 checks.
    InvalidProof(String),
    /// 401 — session token missing, unknown, expired or ended; no member
    /// left; the Proof key is not a member (§4.5). `WWW-Authenticate: Bearer`.
    InvalidSession(String),
    /// 401 — `invalid_cert` on `session` (§7): a proof's key is not a
    /// recorded, unretired cert of the named account, or fails the bar.
    InvalidCertUnauthorized { reason: &'static str, description: String },
    /// 403 — `forbidden`: a login is needed or rejected (§7.1).
    Forbidden { reason: &'static str, description: String },
    /// 403 — `forbidden/login_required`, carrying the login page (§4.2).
    LoginRequired { url: String },
    /// 409 — a state refusal (e.g. revoking a refless warrant).
    Conflict { reason: &'static str, description: String },
    /// 422 — a client-signed warrant / admission record (or the claim
    /// precondition) failed the §5.1/§5.2 validation bar.
    InvalidWarrant { reason: &'static str, description: String },
    /// 422 — the `devices/register` cert pair failed the §5.3 bar.
    InvalidCert { reason: &'static str, description: String },
    /// 404 — owner-scoped miss, or the API is not served here.
    NotFound,
    /// 500 — a deployment fault, never a caller error.
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::LoginRequired { url } = self {
            let body = serde_json::json!({
                "error": "forbidden", "reason": "login_required",
                "error_description": "open the login page and retry with its token",
                "url": url,
            });
            return (StatusCode::FORBIDDEN, Json(body)).into_response();
        }
        let (status, error, description, reason) = match self {
            ApiError::InvalidRequest(d) => (StatusCode::BAD_REQUEST, "invalid_request", d, None),
            ApiError::InvalidProof(d) => (StatusCode::UNAUTHORIZED, "invalid_proof", d, None),
            ApiError::InvalidSession(d) => (StatusCode::UNAUTHORIZED, "invalid_session", d, None),
            ApiError::InvalidCertUnauthorized { reason, description } => {
                (StatusCode::UNAUTHORIZED, "invalid_cert", description, Some(reason))
            }
            ApiError::Forbidden { reason, description } => {
                (StatusCode::FORBIDDEN, "forbidden", description, Some(reason))
            }
            // Handled above with its structured body.
            ApiError::LoginRequired { .. } => unreachable!("login_required is answered above"),
            ApiError::Conflict { reason, description } => {
                (StatusCode::CONFLICT, "conflict", description, Some(reason))
            }
            ApiError::InvalidWarrant { reason, description } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_warrant",
                description,
                Some(reason),
            ),
            ApiError::InvalidCert { reason, description } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_cert",
                description,
                Some(reason),
            ),
            ApiError::NotFound => {
                (StatusCode::NOT_FOUND, "not_found", "not found".to_string(), None)
            }
            ApiError::Internal(d) => {
                tracing::error!("registry API internal error: {d}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "internal error".to_string(),
                    None,
                )
            }
        };
        let mut body = serde_json::json!({ "error": error, "error_description": description });
        if let Some(r) = reason {
            body["reason"] = serde_json::Value::String(r.to_string());
        }
        let mut resp = (status, Json(body)).into_response();
        if status == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer"),
            );
        }
        resp
    }
}

// ===========================================================================
// Replay cache (proof `jti`s + exchange assertions)
// ===========================================================================

/// In-memory single-use tracking (§3.1/§3.2): proof `jti`s keyed by proof
/// key, and exchange assertions keyed by their hash. Entries retain at least
/// as long as the acceptance window. Single-process by design (the handoff's
/// frontloaded decision) — a multi-node registry needs a shared cache, which
/// the spec leaves to the implementation.
///
/// Growth is bounded by construction: entries are inserted only after a
/// signature verified (proofs) or a full core §6 verification passed
/// (assertions), and every insert prunes expired rows first.
#[derive(Default)]
pub struct ReplayCache {
    inner: std::sync::Mutex<std::collections::HashMap<String, i64>>,
}

impl ReplayCache {
    /// Record `key` unless a live entry exists. `true` = fresh (recorded),
    /// `false` = replayed.
    pub fn insert_once(&self, key: &str, retain_until: i64) -> bool {
        let now = Utc::now().timestamp();
        let mut map = self.inner.lock().unwrap();
        map.retain(|_, exp| *exp > now);
        if map.contains_key(key) {
            return false;
        }
        map.insert(key.to_string(), retain_until);
        true
    }
}

// ===========================================================================
// POST /api/v1/token — the presentation → token exchange (§3.1)
// ===========================================================================

/// A fresh opaque token: 32 random bytes, base64url (≥128-bit entropy, §3.1).
pub(crate) fn new_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

// ===========================================================================
// The request-proof extractor (§3.2)
// ===========================================================================

/// The authenticated caller of a session-authed endpoint: token + the
/// `Proof` header by the session's login key, verified to the §4.4 bar.
pub struct ApiUser {
    pub user_id: u64,
    /// The session's token hash, so `session/end` and `delete` can end it.
    pub session_token_hash: String,
    /// The login key the session is bound to.
    pub login_key_id: u64,
}

#[axum::async_trait]
impl FromRequestParts<Arc<RegistrarState>> for ApiUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<RegistrarState>,
    ) -> Result<Self, ApiError> {
        if !state.enabled {
            return Err(ApiError::NotFound);
        }
        let expect_bh = if parts.method == axum::http::Method::GET {
            None
        } else {
            Some(
                parts
                    .extensions
                    .get::<crate::session::BodyHash>()
                    .map(|b| b.0.clone())
                    .ok_or_else(|| ApiError::Internal("body hash middleware missing".into()))?,
            )
        };
        let (rec, key, _) = crate::session::verify_session_call(
            state,
            &parts.headers,
            parts.method.as_str(),
            parts.uri.path(),
            expect_bh.as_deref(),
        )
        .await?;
        Ok(ApiUser { user_id: rec.user_id, session_token_hash: rec.token_hash, login_key_id: key.id })
    }
}

// ===========================================================================
// GET /api/v1/requests — the consent inbox (§5.1)
// ===========================================================================

#[derive(Deserialize)]
pub struct ApiRequestsQuery {
    /// External requests are surfaced only through their code (§5.1).
    pub code: Option<String>,
    /// Long-poll hint — currently ignored, which §5.1 makes conformant.
    #[allow(dead_code)]
    pub wait: Option<u64>,
}

#[derive(Serialize)]
pub struct ApiRequestsResponse {
    pub status_uri: String,
    pub requests: Vec<crate::consent::PendingRequestInfo>,
}

/// A pure GET (§4): no claim side effect — claiming a record request is the
/// separate `POST /api/v1/requests/claim`. Unclaimed record requests are
/// therefore not listed here until claimed.
pub async fn list_requests(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    Query(query): Query<ApiRequestsQuery>,
) -> Result<Json<ApiRequestsResponse>, ApiError> {
    // Expired holds are dropped opportunistically (registry-api-v1 §4.1).
    if let Err(e) = state.host.sweep_holds() {
        tracing::warn!(error = %e, "hold sweep failed");
    }
    let requests = state
        .store
        .list_pending_warrant_requests(user.user_id)
        .map_err(|e| ApiError::Internal(format!("inbox: {e}")))?
        .into_iter()
        .filter(|r| !r.external || query.code.as_deref() == Some(r.code.as_str()))
        .map(|r| crate::consent::pending_info(&state, user.user_id, r))
        .collect();
    Ok(Json(ApiRequestsResponse {
        status_uri: status_list_uri(&state.domain),
        requests,
    }))
}

// ===========================================================================
// POST /api/v1/requests/claim + /respond (§5.1)
// ===========================================================================

/// Map a shared-core consent error onto the API taxonomy (§7): reasoned
/// validation failures → 422 invalid_warrant; owner-scoped misses → 404;
/// missing/malformed inputs → 400 invalid_request.
fn consent_err(e: crate::error::RegistrarError) -> ApiError {
    use crate::error::RegistrarError as E;
    match e {
        E::WarrantValidation { reason, message } => {
            ApiError::InvalidWarrant { reason, description: message }
        }
        E::Conflict { reason, message } => ApiError::Conflict { reason, description: message },
        E::WarrantRequestNotFound => ApiError::NotFound,
        // Owner-scoped misses are indistinguishable from absence (§7).
        E::DeviceCertNotFound | E::HolderNotFound | E::NamespaceNotFound => ApiError::NotFound,
        E::ValidationError(m) => ApiError::InvalidRequest(m),
        E::PolicyRefused(m) => ApiError::InvalidRequest(m),
        E::AgentProvisioningDisabled => ApiError::NotFound,
        other => ApiError::Internal(other.to_string()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiClaimRequest {
    code: String,
}

/// `POST /api/v1/requests/claim` — the legacy GET's hidden side effect made
/// explicit: verify the audience proof (fail-closed) and bind the record
/// request to this account, allocating grant status indexes. Returns the
/// claimed request in the §5.1 item shape.
pub async fn claim_request(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: axum::body::Bytes,
) -> Result<Json<crate::consent::PendingRequestInfo>, ApiError> {
    let req: ApiClaimRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let rec = crate::consent::claim_core(&state, user.user_id, &req.code)
        .await
        .map_err(consent_err)?;
    Ok(Json(crate::consent::pending_info(&state, user.user_id, rec)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiRespondRequest {
    code: String,
    approve: bool,
    #[serde(default)]
    warrants: Option<Vec<String>>,
    #[serde(default)]
    config_cert: Option<String>,
    #[serde(default)]
    grantor: Option<String>,
}

/// `POST /api/v1/requests/respond` — approve or deny a pending request.
/// Identical semantics to `/wsapi/warrant_respond` minus `csrf`: the SAME
/// shared core validates the client-signed warrants, so the two lanes'
/// bars cannot drift. Always `200` with a JSON body — `{return_url}` on an
/// approve whose request carried one, `{}` otherwise (including every deny).
pub async fn respond(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req: ApiRespondRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let approve = req.approve;
    let core = crate::consent::RespondCore {
        code: req.code,
        approve,
        warrants: req.warrants,
        config_cert: req.config_cert,
        grantor: req.grantor,
    };
    let return_url =
        crate::consent::respond_core(&state, user.user_id, &core).map_err(consent_err)?;
    let mut resp = serde_json::Map::new();
    if approve {
        if let Some(url) = return_url {
            resp.insert("return_url".into(), serde_json::Value::String(url));
        }
    }
    Ok(Json(serde_json::Value::Object(resp)))
}

// ===========================================================================
// Warrant registry over the token lane (§5.2)
// ===========================================================================

#[derive(Serialize)]
pub struct ApiWarrantsResponse {
    pub warrants: Vec<crate::consent::WarrantInfo>,
}

/// `GET /api/v1/warrants` — the account's registered warrants.
pub async fn list_warrants(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
) -> Result<Json<ApiWarrantsResponse>, ApiError> {
    let warrants = crate::consent::list_warrants_core(&state, user.user_id).map_err(consent_err)?;
    Ok(Json(ApiWarrantsResponse { warrants }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiRegisterWarrantRequest {
    warrant: String,
    config_cert: String,
}

/// `POST /api/v1/warrants/register` — record a warrant the wallet signed
/// outside the inbox flow (§5.4). Beyond the shared core's bar: the config
/// cert must be an unretired cert of the account, the grantor an active
/// identity, and the warrant's status ref exactly the one this registry
/// holds for the record key.
pub async fn register_warrant(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req: ApiRegisterWarrantRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let warrant = browserid_core::device::Warrant::parse(&req.warrant).map_err(|e| ApiError::InvalidWarrant {
        reason: "warrant_invalid",
        description: format!("bad warrant: {e}"),
    })?;
    let cc = browserid_core::device::DeviceCert::parse(&req.config_cert).map_err(|e| ApiError::InvalidWarrant {
        reason: "config_cert_invalid",
        description: format!("bad config cert: {e}"),
    })?;
    let recorded = state
        .store
        .get_device_cert_by_pubkey(&cc.claims().public_key.to_base64())
        .map_err(|e| ApiError::Internal(format!("cert lookup: {e}")))?;
    if !recorded.map_or(false, |r| r.user_id == user.user_id && r.is_active()) {
        return Err(ApiError::InvalidWarrant {
            reason: "config_cert_not_recorded",
            description: "the config cert is not an unretired cert of this account".into(),
        });
    }
    let claims = warrant.claims();
    let grantor = crate::consent::delegator_of(&claims.grantor);
    if state
        .host
        .identity_holder(&grantor)
        .map_err(|e| ApiError::Internal(format!("membership: {e}")))?
        != Some(user.user_id)
    {
        return Err(ApiError::InvalidWarrant {
            reason: "grantor_not_owned",
            description: "the grantor is not an active identity on this account".into(),
        });
    }
    let live = crate::consent::live_status_index(
        &*state.store,
        user.user_id,
        &claims.grantee,
        &claims.audience,
        &claims.scope_strings(),
    )
    .map_err(consent_err)?;
    match &claims.status {
        None => {
            return Err(ApiError::InvalidWarrant {
                reason: "status_ref_missing",
                description: "the warrant carries no status ref; allocate one first".into(),
            })
        }
        Some(st) if st.uri != status_list_uri(&state.domain) || st.idx != live => {
            return Err(ApiError::InvalidWarrant {
                reason: "status_ref_mismatch",
                description: "the warrant's status ref is not the one allocated for this record".into(),
            })
        }
        Some(_) => {}
    }
    crate::consent::register_warrant_core(&state, user.user_id, &req.warrant, &req.config_cert)
        .map_err(consent_err)?;
    let id = state
        .store
        .list_warrants(user.user_id)
        .map_err(consent_err)?
        .into_iter()
        .find(|r| r.status_idx == Some(live) && r.audience == claims.audience && r.agent_email == claims.grantee)
        .map(|r| r.id)
        .ok_or_else(|| ApiError::Internal("registered warrant not found".into()))?;
    Ok(Json(serde_json::json!({ "id": id })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiWarrantIdRequest {
    id: u64,
}

/// `POST /api/v1/warrants/revoke` — flip the warrant's status bit (sticky).
pub async fn revoke_warrant(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: axum::body::Bytes,
) -> Result<StatusCode, ApiError> {
    let req: ApiWarrantIdRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    crate::consent::revoke_warrant_core(&state, user.user_id, req.id).map_err(consent_err)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiAllocateStatusRequest {
    /// The identity that will present the warrant (§5.4).
    grantee: String,
    audience: String,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Serialize)]
pub struct ApiAllocateStatusResponse {
    pub uri: String,
    pub idx: u64,
}

/// `POST /api/v1/warrants/allocate_status` — the stable status ref for a
/// grant, fetched before signing. What lets a wallet mint login warrants
/// WITH per-site revocation bits (closing the prototype gap).
pub async fn allocate_status(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: axum::body::Bytes,
) -> Result<Json<ApiAllocateStatusResponse>, ApiError> {
    let req: ApiAllocateStatusRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    if req.grantee.trim().is_empty() {
        return Err(ApiError::InvalidRequest("grantee is required".into()));
    }
    let (uri, idx) = crate::consent::allocate_status_core(
        &state,
        user.user_id,
        &req.grantee,
        &req.audience,
        &req.scopes,
    )
    .map_err(consent_err)?;
    Ok(Json(ApiAllocateStatusResponse { uri, idx }))
}

// ===========================================================================
// Devices over the token lane (§5.3)
// ===========================================================================

/// `GET /api/v1/certs` — the account's recorded certs (§5.5), retired ones
/// included, each with its `kid`.
pub async fn list_certs(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let certs = state
        .store
        .list_device_certs(user.user_id)
        .map_err(|e| ApiError::Internal(format!("certs: {e}")))?;
    let items: Vec<serde_json::Value> = certs
        .into_iter()
        .map(|c| {
            let mut v = serde_json::json!({
                "id": c.id,
                "kid": crate::session::kid_of(&c.pubkey).unwrap_or_default(),
                "identities": c.identities,
                "purpose": c.purpose,
                "holder": c.holder,
                "login_key": c.login_key_id,
                "pubkey": c.pubkey,
                "iss": c.iss,
                "issued_at": c.issued_at.to_rfc3339(),
                "expires_at": c.expires_at.to_rfc3339(),
                "revoked": c.revoked_at.is_some()
                    || c.status_idx.map_or(false, |i| state.store.is_status_revoked_idx(i).unwrap_or(false)),
            });
            if let (Some(uri), Some(idx)) = (c.status_uri, c.status_idx) {
                v["status"] = serde_json::json!({ "uri": uri, "idx": idx });
            }
            v
        })
        .collect();
    Ok(Json(serde_json::json!({ "certs": items })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiCertRevokeRequest {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    kid: Option<String>,
}

/// `POST /api/v1/certs/revoke` — `{ id }` or `{ kid }` (§5.5). Any session
/// for a cert it itself holds; otherwise config. Retires the cert here and
/// sets the bit where this registry is the authority.
pub async fn revoke_cert(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: axum::body::Bytes,
) -> Result<Json<ApiRevokeDeviceResponse>, ApiError> {
    let req: ApiCertRevokeRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    let id = match (req.id, req.kid) {
        (Some(id), None) => id,
        (None, Some(kid)) => state
            .store
            .list_device_certs(user.user_id)
            .map_err(|e| ApiError::Internal(format!("certs: {e}")))?
            .into_iter()
            .find(|c| crate::session::kid_of(&c.pubkey).as_deref() == Some(kid.as_str()))
            .map(|c| c.id)
            .ok_or(ApiError::NotFound)?,
        _ => return Err(ApiError::InvalidRequest("exactly one of id or kid".into())),
    };
    let revoked = crate::holders::revoke_device_core(&*state.store, &*state.host, &state.domain, user.user_id, id)
        .map_err(consent_err)?;
    Ok(Json(ApiRevokeDeviceResponse { revoked }))
}

#[derive(Serialize)]
pub struct ApiRevokeDeviceResponse {
    /// Whether a status bit actually flipped here. `false` = the issuer is
    /// foreign: the row is hidden but the cert is NOT dead — route revocation
    /// to the issuing authority (§5.3).
    pub revoked: bool,
}

// ===========================================================================
// Holders + namespaces over the token lane (§5.4)
// ===========================================================================

/// `GET /api/v1/holders` — the grouped account view (namespaces → holders).
pub async fn list_holders(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
) -> Result<Json<crate::holders::HoldersView>, ApiError> {
    // The three namespaces core §4.5 defines always exist (§5.6).
    for ns in ["browsers", "agents", "services"] {
        state.store.get_or_create_namespace(user.user_id, ns).ok();
    }
    let view =
        crate::holders::holders_view_core(&*state.store, user.user_id).map_err(consent_err)?;
    Ok(Json(view))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiRenameHolderRequest {
    holder_id: String,
    label: String,
}

/// `POST /api/v1/holders/rename` — friendly label for one holder id.
pub async fn rename_holder(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: axum::body::Bytes,
) -> Result<StatusCode, ApiError> {
    let req: ApiRenameHolderRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    crate::holders::rename_holder_core(&*state.store, user.user_id, &req.holder_id, &req.label)
        .map_err(consent_err)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiForgetHolderRequest {
    holder_id: String,
}

#[derive(Serialize)]
pub struct ApiForgetHolderResponse {
    /// Issuers whose certs could NOT be revoked from here: the device can
    /// keep signing in with them until they expire — only that issuer can
    /// cut them off.
    pub unrevocable: Vec<String>,
}

/// `POST /api/v1/holders/forget` — revoke-then-delete a device/service.
pub async fn forget_holder(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: axum::body::Bytes,
) -> Result<Json<ApiForgetHolderResponse>, ApiError> {
    let req: ApiForgetHolderRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    // An external holder (another account's admitted agent) is refused (§5.6).
    let external = state
        .store
        .list_device_certs(user.user_id)
        .map_err(|e| ApiError::Internal(format!("certs: {e}")))?
        .iter()
        .any(|c| c.holder == req.holder_id && c.pubkey.is_empty());
    if external {
        return Err(ApiError::Conflict {
            reason: "external_holder",
            description: "an admitted external holder cannot be forgotten here".into(),
        });
    }
    let unrevocable = crate::holders::forget_holder_core(
        &*state.store,
        &*state.host,
        &state.domain,
        user.user_id,
        &req.holder_id,
    )
    .map_err(consent_err)?;
    Ok(Json(ApiForgetHolderResponse { unrevocable }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiRenameNamespaceRequest {
    name: String,
    label: String,
}

/// `POST /api/v1/namespaces/rename` — friendly label for a namespace.
pub async fn rename_namespace(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    body: axum::body::Bytes,
) -> Result<StatusCode, ApiError> {
    let req: ApiRenameNamespaceRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;
    crate::holders::rename_namespace_core(&*state.store, user.user_id, &req.name, &req.label)
        .map_err(consent_err)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_cache_is_single_use_until_expiry() {
        let cache = ReplayCache::default();
        let far = Utc::now().timestamp() + 600;
        assert!(cache.insert_once("a", far));
        assert!(!cache.insert_once("a", far));
        assert!(cache.insert_once("b", far));
    }

    #[test]
    fn tokens_are_high_entropy_and_hash_stable() {
        let t = new_token();
        assert!(t.len() >= 43, "{t}");
        assert_ne!(t, new_token());
        assert_eq!(crate::session::b64url_sha256(t.as_bytes()), crate::session::b64url_sha256(t.as_bytes()));
    }
}
