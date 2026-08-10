//! Device-cert model endpoints (DC Phases 2 + 6) — see
//! `docs/design/browserid-end-to-end-flow.md`.
//!
//! - `POST /device/issue`  (session) → a **user** device cert (authentication)
//!   + a **config** device cert (authorization), batch, both IdP-signed, each
//!   with a per-device status ref.
//! - `POST /access/mint`   (device-cert-authed) → a fresh-key **access cert**,
//!   rooted at the issuing device's status index.
//! - `POST /verify-access` → verify an `access_cert~assertion~warrant~config_cert`
//!   bundle with real primary/fallback conformance (convenience verifier).
//!
//! The warrant is signed CLIENT-side by the config cert; its registry/status
//! (revocation) lands with DC Phase 4.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use axum::extract::{Query, State};
use axum::Json;
use browserid_core::device::{AccessCert, AccessRequest, DeviceCert, Purpose};
use browserid_core::{PublicKey, StatusRef};

/// Seen access-request `jti`s → their `exp` (unix seconds). An access request is
/// single-use within its ~10-minute window; replaying it must not mint a second
/// access cert (audit L2). In-memory and single-instance, matching the app's
/// other anti-replay state; a restart only forgets already-expired-soon nonces.
static SEEN_JTIS: LazyLock<Mutex<HashMap<String, i64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Record `jti` as used until `exp`; returns `false` if it was already seen and
/// is still within its validity window (i.e. a replay). Prunes expired nonces.
pub(crate) fn claim_jti(jti: &str, exp: i64) -> bool {
    let now = chrono::Utc::now().timestamp();
    let mut seen = SEEN_JTIS.lock().unwrap();
    seen.retain(|_, &mut e| e > now);
    if seen.contains_key(jti) {
        return false;
    }
    seen.insert(jti.to_string(), exp);
    true
}
use chrono::Duration;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{DeviceCertRecord, SessionStore, UserStore};
use crate::verifier::{verify_access_with_dns, AccessVerificationResult};
use chrono::Utc;

fn ce(e: browserid_core::Error) -> BrokerError {
    BrokerError::InvalidProvisioningRequest(e.to_string())
}
fn parse_pub(s: &str) -> Result<PublicKey, BrokerError> {
    PublicKey::from_base64(s).map_err(|e| BrokerError::ValidationError(format!("bad pubkey: {e}")))
}

fn owned_verified_email<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    cookies: &Cookies,
    csrf: &str,
    email: &str,
) -> Result<String, BrokerError> {
    let session = super::session::get_session_from_cookies(cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, csrf)?;
    let normalized = email.to_lowercase();
    let emails = state.user_store.list_emails(session.user_id)?;
    let rec = emails
        .iter()
        .find(|e| e.email.to_lowercase() == normalized && e.verified)
        .ok_or(BrokerError::EmailNotFound)?;
    Ok(rec.email.clone())
}

fn device_status<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    device_pub: &PublicKey,
) -> Result<StatusRef, BrokerError> {
    let idx = state
        .user_store
        .get_or_allocate_status("device", &device_pub.to_base64())?;
    Ok(StatusRef {
        uri: browserid_registrar::consent::status_list_uri(&state.domain),
        idx,
    })
}

// ---------------------------------------------------------------------------
// POST /device/issue  (session) → user device cert + config cert (batch)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DeviceIssueRequest {
    pub csrf: String,
    pub email: String,
    pub device_pubkey: String,
    pub config_pubkey: String,
    /// The client broker's stable per-browser holder (reused across identities),
    /// which must sit in this account's `browsers` namespace. Optional for
    /// backward-compat: absent → the broker assigns a fresh one.
    #[serde(default)]
    pub holder: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceIssueResponse {
    pub success: bool,
    pub device_cert: String,
    pub config_cert: String,
}

#[derive(Serialize)]
pub struct BrowserHolderResponse {
    pub prefix: String,
}

/// GET /wsapi/browser_holder  (session) → the account's `browsers` namespace
/// prefix, so the client broker can form this browser's stable holder
/// `<prefix>.<rand>` once and reuse it across identities.
pub async fn browser_holder<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Result<Json<BrowserHolderResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    let prefix = state
        .user_store
        .get_or_create_namespace(session.user_id, "browsers")?;
    Ok(Json(BrowserHolderResponse { prefix }))
}

pub async fn device_issue<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    headers: axum::http::HeaderMap,
    Json(req): Json<DeviceIssueRequest>,
) -> Result<Json<DeviceIssueResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // owned_verified_email re-derives the session; grab it too so we can
    // persist the issued certs under this account (DC Phase 8 — listable +
    // revocable in the account UI).
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    let email = owned_verified_email(&state, &cookies, &req.csrf, &req.email)?;
    let device_pub = parse_pub(&req.device_pubkey)?;
    let config_pub = parse_pub(&req.config_pubkey)?;
    let device_ref = device_status(&state, &device_pub)?;
    let config_ref = device_status(&state, &config_pub)?;
    let ttl = Duration::days(90);
    // One device slot → one holder in the user's `browsers` namespace, carried by
    // BOTH the authentication (device) and authorization (config) cert. The client
    // broker supplies this browser's stable holder (reused across identities); it
    // must sit in this account's `browsers` namespace (the requester can name a
    // holder only *within* its own browsers namespace, never a service's). Absent
    // → the broker assigns a fresh one (older clients / first contact).
    let ns_prefix = state.user_store.get_or_create_namespace(session.user_id, "browsers")?;
    let holder = match req.holder.as_deref() {
        Some(h) if !h.is_empty() => {
            browserid_core::device::Holder::new(h.to_string()).map_err(ce)?;
            // Account-driven namespace move: a stale client supplying its old
            // holder is silently redirected to the broker-assigned target —
            // the device heals at its next issuance without knowing the move
            // happened (its old certs were revoked at move time).
            let resolved = state
                .user_store
                .resolve_holder_move(session.user_id, h)?;
            match resolved {
                Some(target) => target,
                None => {
                    // Well-formed holder, and in THIS account's browsers
                    // namespace — OR the exact target of a recorded move
                    // (which may sit in any of the user's namespaces; the id
                    // was broker-assigned at move time, never client-chosen).
                    let prefix = h.split_once('.').map(|(p, _)| p).unwrap_or("");
                    let is_move_target = state
                        .user_store
                        .list_holder_moves(session.user_id)?
                        .iter()
                        .any(|(_, new)| new == h);
                    if prefix != ns_prefix && !is_move_target {
                        return Err(BrokerError::PolicyRefused(
                            "supplied holder is not in this account's browsers namespace".into(),
                        ));
                    }
                    h.to_string()
                }
            }
        }
        _ => crate::crypto::assign_holder_id(&ns_prefix),
    };
    let holder_id = browserid_core::device::Holder::new(holder.clone()).map_err(ce)?;
    let device_cert = DeviceCert::create(
        &state.domain, &device_pub, Purpose::Authentication, holder_id.clone(),
        vec![email.clone()], ttl, &state.keypair, Some(device_ref.clone()),
    ).map_err(ce)?;
    // The config cert also covers `+tag` sub-addresses so it can sign
    // warrants for the user's plus-named agent identities (design doc §3).
    let config_identities = match email.split_once('@') {
        Some((local, domain)) => vec![email.clone(), format!("{local}+*@{domain}")],
        None => vec![email.clone()],
    };
    let config_cert = DeviceCert::create(
        &state.domain, &config_pub, Purpose::Authorization, holder_id.clone(),
        config_identities, ttl, &state.keypair, Some(config_ref.clone()),
    ).map_err(ce)?;

    // Durable registry rows (upsert on pubkey) so the certs are enumerable and
    // revocable per account.
    let now = Utc::now();
    let expires = now + ttl;
    for (pubkey, purpose, status_idx) in [
        (&req.device_pubkey, "authentication", device_ref.idx),
        (&req.config_pubkey, "authorization", config_ref.idx),
    ] {
        state.user_store.insert_device_cert(DeviceCertRecord {
            id: 0,
            user_id: session.user_id,
            identities: vec![email.clone()],
            purpose: purpose.to_string(),
            holder: holder.clone(),
            pubkey: pubkey.clone(),
            iss: state.domain.clone(),
            issued_at: now,
            expires_at: expires,
            revoked_at: None,
            status_idx: Some(status_idx),
        })?;
    }
    // First sight of this holder → a friendly UA-derived default label
    // ("Chrome on macOS"); never clobbers a user rename, never fails issuance.
    super::holders::maybe_label_holder_from_ua(
        state.user_store.as_ref(), session.user_id, &holder, &headers,
    );
    // If this issuance completed an account-driven namespace move, drop the
    // old holder's (already-revoked) rows so the device appears exactly once.
    super::holders::finish_holder_move(state.user_store.as_ref(), session.user_id, &holder);

    Ok(Json(DeviceIssueResponse {
        success: true,
        device_cert: device_cert.encoded().to_string(),
        config_cert: config_cert.encoded().to_string(),
    }))
}

// ---------------------------------------------------------------------------
// POST /access/mint  (the device cert is the credential — no session)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AccessMintRequest {
    pub device_cert: String,
    pub access_request: String,
}

#[derive(Serialize)]
pub struct AccessMintResponse {
    pub success: bool,
    pub access_cert: String,
    pub email: String,
}

pub async fn access_mint<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<AccessMintRequest>,
) -> Result<Json<AccessMintResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let device_cert = DeviceCert::parse(&req.device_cert).map_err(ce)?;
    device_cert.verify(&state.keypair.public_key()).map_err(ce)?;
    if device_cert.iss() != state.domain {
        return Err(BrokerError::InvalidProvisioningRequest("device cert not issued by this IdP".into()));
    }
    if device_cert.is_expired() {
        return Err(BrokerError::InvalidProvisioningRequest("device cert expired".into()));
    }
    if device_cert.purpose() != Purpose::Authentication {
        return Err(BrokerError::PolicyRefused("device cert cannot mint access certs (not authentication)".into()));
    }
    // Fail-closed revocation gate at the mint (audit M1 / bean mmnp): a revoked
    // device cert must mint nothing new. The spec's "instant revocation at the
    // mint" (§6.3) depends on this check — without it a revoked device keeps
    // minting fresh 24h access certs until its own cert expires. Only the
    // broker's OWN status list is authoritative here (the device cert is
    // broker-issued); its bit is checked directly.
    if let Some(status) = &device_cert.claims().status {
        if status.uri == browserid_registrar::consent::status_list_uri(&state.domain)
            && state.user_store.is_status_revoked_idx(status.idx)?
        {
            return Err(BrokerError::PolicyRefused("device cert revoked".into()));
        }
    }
    let areq = AccessRequest::parse(&req.access_request).map_err(ce)?;
    areq.verify(device_cert.public_key()).map_err(ce)?;
    if areq.is_expired() {
        return Err(BrokerError::InvalidProvisioningRequest("access request expired".into()));
    }
    // Single-use jti: reject a replayed access request within its validity
    // window (audit L2). Bounded in-memory set, pruned by expiry — consistent
    // with the app's other in-memory anti-replay/throttle state.
    let c = areq.claims();
    if !claim_jti(&c.jti, c.exp) {
        return Err(BrokerError::InvalidProvisioningRequest("access request replayed (jti seen)".into()));
    }
    if c.domain != state.domain {
        return Err(BrokerError::InvalidProvisioningRequest("wrong target domain".into()));
    }
    if !device_cert.authorizes_identity(&c.identity) {
        return Err(BrokerError::PolicyRefused("device cert not authorized for this identity".into()));
    }
    // The mint copies the DEVICE cert's holder verbatim into the access cert —
    // the requester cannot choose a different holder (isolation guarantee). The
    // access request's holder, if present, must equal the device's.
    if c.holder != *device_cert.holder() {
        return Err(BrokerError::PolicyRefused("holder mismatch".into()));
    }
    // Access cert inherits the DEVICE's status index (revoke a device → its
    // access certs die), per the B3 fix.
    let access_cert = AccessCert::create(
        &state.domain, &c.identity, device_cert.holder().clone(), &c.access_key,
        Duration::hours(24), &state.keypair, device_cert.claims().status.clone(),
    ).map_err(ce)?;
    Ok(Json(AccessMintResponse {
        success: true,
        access_cert: access_cert.encoded().to_string(),
        email: c.identity.clone(),
    }))
}

// ---------------------------------------------------------------------------
// POST /verify-access  (convenience verifier, real conformance)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct VerifyAccessRequest {
    pub presentation: String,
    pub audience: String,
    #[serde(default)]
    pub accepted_fallbacks: Option<Vec<String>>,
}

pub async fn verify_access<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<VerifyAccessRequest>,
) -> Json<AccessVerificationResult>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let fetcher = match state.fallback_fetcher().await {
        Ok(f) => f,
        Err(e) => return Json(AccessVerificationResult::fail(format!("fetcher: {e}"))),
    };
    let accepted = req.accepted_fallbacks.unwrap_or_else(|| vec![state.domain.clone()]);
    let is_own_revoked =
        |idx: u64| state.user_store.is_status_revoked_idx(idx).map_err(|e| e.to_string());
    let status = crate::verifier::StatusCtx {
        own_uri: browserid_registrar::consent::status_list_uri(&state.domain),
        is_own_revoked: &is_own_revoked,
        cache: &state.foreign_status_lists,
        // Enforce the SSRF guard in production; relax only on localhost dev.
        allow_private_hosts: !crate::routes::session::cookie_secure(&state.domain),
    };
    Json(
        verify_access_with_dns(&req.presentation, &req.audience, fetcher.as_ref(), &accepted, status)
            .await,
    )
}

// ---------------------------------------------------------------------------
// GET /wsapi/device_certs  (session) → this account's device + config certs
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct DeviceCertView {
    pub id: u64,
    pub identities: Vec<String>,
    /// "authentication" (device/agent login) | "authorization" (config, warrant signer)
    pub purpose: String,
    /// The opaque broker-assigned holder id (`<ns>.<id>`) this cert acts as.
    pub holder: String,
    pub pubkey: String,
    pub iss: String,
    pub issued_at: String,
    pub expires_at: String,
    pub revoked: bool,
}

#[derive(Serialize)]
pub struct DeviceCertsResponse {
    pub success: bool,
    pub certs: Vec<DeviceCertView>,
}

/// GET /wsapi/device_certs — list the session account's device certs
/// (authentication: user/agent) and config certs (authorization). Own-account
/// only, session-gated.
pub async fn device_certs<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Result<Json<DeviceCertsResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    let certs = state
        .user_store
        .list_device_certs(session.user_id)?
        .into_iter()
        .map(|r| DeviceCertView {
            id: r.id,
            identities: r.identities,
            purpose: r.purpose,
            holder: r.holder,
            pubkey: r.pubkey,
            iss: r.iss,
            issued_at: r.issued_at.to_rfc3339(),
            expires_at: r.expires_at.to_rfc3339(),
            revoked: r.revoked_at.is_some(),
        })
        .collect();
    Ok(Json(DeviceCertsResponse { success: true, certs }))
}

// ---------------------------------------------------------------------------
// POST /wsapi/revoke_device_cert  (session, CSRF) → log a device/agent out
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RevokeDeviceCertRequest {
    pub csrf: String,
    pub id: u64,
}

#[derive(Serialize)]
pub struct RevokeDeviceCertResponse {
    pub success: bool,
}

/// POST /wsapi/revoke_device_cert — owner-scoped soft-revoke. Also flips the
/// cert's status-list bit so any outstanding access certs rooted at this device
/// fail-closed at the RP verifier ("log this device/agent out"). Sticky: the
/// revoked_at / status bit are never un-set.
pub async fn revoke_device_cert<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<RevokeDeviceCertRequest>,
) -> Result<Json<RevokeDeviceCertResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;

    // Capture status index + issuer BEFORE revoking (owner-scoped lookup).
    let rec = state
        .user_store
        .list_device_certs(session.user_id)?
        .into_iter()
        .find(|r| r.id == req.id);
    let status_idx = rec.as_ref().and_then(|r| r.status_idx);
    let iss = rec.map(|r| r.iss).unwrap_or_default();

    // Owner-scoped: errors DeviceCertNotFound if it isn't this user's cert.
    state
        .user_store
        .revoke_device_cert(session.user_id, req.id)?;

    // Kill outstanding access certs rooted at this device (fail-closed
    // status) — but only OUR list's bits are ours to flip
    // (browserid-ng-ft55). A foreign-issued cert's idx numbers the
    // ISSUER's list: flipping the same index on our list would not revoke
    // it anywhere a verifier looks, and could collaterally revoke an
    // unrelated broker-issued cert. Foreign certs are revoked at the
    // issuer via its advertised device-revoke page; here the row is only
    // soft-hidden.
    if iss.is_empty() || iss.eq_ignore_ascii_case(&state.domain) {
        if let Some(idx) = status_idx {
            state.user_store.set_status_revoked_idx(idx)?;
        }
    }

    Ok(Json(RevokeDeviceCertResponse { success: true }))
}

#[derive(serde::Deserialize)]
pub struct CertRevocationStatusQuery {
    pub id: u64,
}

#[derive(serde::Serialize)]
pub struct CertRevocationStatusResponse {
    /// "revoked" | "active" | "unknown". `unknown` = the check could not be
    /// made (no status ref recorded, or the issuer's list is unreachable) —
    /// the caller must not claim success on it.
    pub state: &'static str,
}

/// GET /wsapi/cert_revocation_status?id= — did a revocation actually land
/// on the ISSUER's signed status list? The account page calls this after
/// the cross-issuer revoke hop (browserid-ng-ft55): the popup's word is
/// not proof — the user may have cancelled, or the issuer may be broken —
/// but the issuer's signed list is. Fresh-fetched (cache-busted) so a
/// just-flipped bit shows immediately.
pub async fn cert_revocation_status<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Query(query): Query<CertRevocationStatusQuery>,
) -> Result<Json<CertRevocationStatusResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    let rec = state
        .user_store
        .list_device_certs(session.user_id)?
        .into_iter()
        .find(|r| r.id == query.id)
        .ok_or(BrokerError::DeviceCertNotFound)?;

    let Some(idx) = rec.status_idx else {
        return Ok(Json(CertRevocationStatusResponse { state: "unknown" }));
    };
    // Own-issued: our store is the authority, no network.
    if rec.iss.is_empty() || rec.iss.eq_ignore_ascii_case(&state.domain) {
        let revoked = state.user_store.is_status_revoked_idx(idx)?;
        return Ok(Json(CertRevocationStatusResponse {
            state: if revoked { "revoked" } else { "active" },
        }));
    }

    // Foreign: consult the issuer's signed list. The join records only the
    // idx, so the uri is reconstructed from the conformant well-known path
    // every IdP here publishes under.
    let r = browserid_core::StatusRef {
        uri: format!("https://{}/.well-known/browserid-status", rec.iss),
        idx,
    };
    let fetcher = match state.fallback_fetcher().await {
        Ok(f) => f,
        Err(_) => return Ok(Json(CertRevocationStatusResponse { state: "unknown" })),
    };
    let allow_private =
        state.domain.starts_with("localhost") || state.domain.starts_with("127.");
    match crate::verifier::check_foreign_status_fresh(
        &r,
        fetcher.as_ref(),
        &state.foreign_status_lists,
        allow_private,
    )
    .await
    {
        Ok(true) => Ok(Json(CertRevocationStatusResponse { state: "revoked" })),
        Ok(false) => Ok(Json(CertRevocationStatusResponse { state: "active" })),
        Err(e) => {
            tracing::warn!(iss = %rec.iss, "post-revocation status check failed: {e}");
            Ok(Json(CertRevocationStatusResponse { state: "unknown" }))
        }
    }
}

#[derive(serde::Deserialize)]
pub struct IssuerRevokeUrlQuery {
    pub iss: String,
}

#[derive(serde::Serialize)]
pub struct IssuerRevokeUrlResponse {
    /// Absolute URL of the issuer's device-revoke page, or None when the
    /// issuer advertises none (its certs run to expiry).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_url: Option<String>,
}

/// GET /wsapi/issuer_revoke_url?iss=<domain> — where the USER can revoke
/// certs a foreign issuer signed (browserid-ng-ft55), discovered from the
/// issuer's support document (`device-revoke`). The account page opens the
/// answer with `#identity=…&return_origin=…`; the issuer re-authenticates
/// the user and flips its own status list — the broker never holds that
/// power. Cached per issuer for ten minutes.
pub async fn issuer_revoke_url<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Query(query): Query<IssuerRevokeUrlQuery>,
) -> Result<Json<IssuerRevokeUrlResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;

    let iss = query.iss.trim().to_ascii_lowercase();
    if iss.is_empty() || iss == state.domain.to_ascii_lowercase() {
        return Ok(Json(IssuerRevokeUrlResponse { revoke_url: None }));
    }

    use std::sync::{OnceLock, RwLock};
    use std::time::{Duration, Instant};
    static CACHE: OnceLock<RwLock<std::collections::HashMap<String, (Option<String>, Instant)>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some((url, at)) = cache.read().unwrap().get(&iss).cloned() {
        if at.elapsed() < Duration::from_secs(600) {
            return Ok(Json(IssuerRevokeUrlResponse { revoke_url: url }));
        }
    }

    let url = match state.fallback_fetcher().await {
        Ok(f) => match f.discover(&iss).await {
            Ok(r) if r.is_primary => {
                let base = r.serving_host.clone().unwrap_or_else(|| iss.clone());
                r.document
                    .device_revocation
                    .as_ref()
                    .map(|path| format!("https://{base}{path}"))
            }
            _ => None,
        },
        Err(_) => None,
    };
    cache
        .write()
        .unwrap()
        .insert(iss, (url.clone(), Instant::now()));
    Ok(Json(IssuerRevokeUrlResponse { revoke_url: url }))
}
