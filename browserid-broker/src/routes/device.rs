//! Device-cert model endpoints (DC Phases 2 + 6) — see
//! `docs/design/browserid-end-to-end-flow.md`.
//!
//! - `POST /device/issue`  (session) → a **user** device cert (authentication)
//!   + a **config** device cert (authorization), batch, both IdP-signed, each
//!   with a per-device status ref.
//! - `POST /access/mint`   (device-cert-authed) → a fresh-key **access cert**,
//!   rooted at the issuing device's status index.
//! - `POST /verify` → verify an `access_cert~assertion~warrant~config_cert`
//!   bundle with real primary/fallback conformance (convenience verifier).
//!
//! The warrant is signed CLIENT-side by the config cert; its registry/status
//! (revocation) lands with DC Phase 4.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use axum::extract::rejection::JsonRejection;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
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

/// Broker-signed cert TTL for broker-vouched (E3/agent) identities. E2 TTLs
/// are the BRIDGE's decision, threaded through the bridge grant (pr3a).
const BROKER_VOUCHED_CERT_TTL_DAYS: i64 = 90;

/// Ownership + provenance gate for broker mints: the account must own the
/// verified email, AND the chokepoint (browserid-ng-u4xz) must authorize a
/// mint for its provenance — `decide` is the caller's chokepoint (a cookie
/// session's level, or a registry login key's standing, bean 73ok).
/// Returns the email, the cert TTL — the VOUCHER's decision for delegated
/// (E2) provenance, redeemed from the live bridge grant (pr3a) — and the
/// proof class the cert is issued under (stamped into the cert so
/// /access/mint can refuse it after a later provenance upgrade, kts0). No
/// live grant, or a Primary (E1) identity → refusal; `NeedPassword` maps to
/// a 401 step-up.
fn mintable_email<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    user_id: crate::store::UserId,
    email: &str,
    decide: impl FnOnce(&crate::store::Email) -> Result<crate::mint::MintDecision, BrokerError>,
) -> Result<(String, Duration, &'static str), BrokerError> {
    let normalized = email.to_lowercase();
    let emails = state.user_store.list_emails(user_id)?;
    let rec = emails
        .iter()
        .find(|e| e.email.to_lowercase() == normalized && e.verified)
        .ok_or(BrokerError::EmailNotFound)?;
    // A derived agent whose parent identity has left the account is on hold
    // (registry-api-v1 §4.1 rule 3): its records are frozen and it must not
    // mint — the old account no longer controls the mailbox it derives from.
    if rec.is_suspended() {
        return Err(BrokerError::PolicyRefused(
            "this identity is suspended: its parent identity has left the account".into(),
        ));
    }
    let prov = rec.proof.as_str();
    match decide(rec)? {
        crate::mint::MintDecision::Allow => Ok((
            rec.email.clone(),
            Duration::days(BROKER_VOUCHED_CERT_TTL_DAYS),
            prov,
        )),
        crate::mint::MintDecision::NeedPassword => Err(BrokerError::PasswordRequired),
        crate::mint::MintDecision::Reverify => Err(BrokerError::EmailVerificationExpired),
        crate::mint::MintDecision::Delegate(crate::mint::Voucher::Primary) => {
            Err(BrokerError::PolicyRefused(
                "issuance for a primary identity is its own IdP's; the broker cannot sign it"
                    .into(),
            ))
        }
        crate::mint::MintDecision::Delegate(_) => {
            match state.take_bridge_grant(user_id, &rec.email) {
                Some(ttl) => Ok((rec.email.clone(), ttl, prov)),
                None => Err(BrokerError::PolicyRefused(
                    "a live bridge proof is required to mint this address".into(),
                )),
            }
        }
    }
}

/// The cookie-session form of [`mintable_email`]: the session's account,
/// CSRF-bound, judged by the session's level.
fn owned_mintable_email<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    cookies: &Cookies,
    csrf: &str,
    email: &str,
) -> Result<(String, Duration, &'static str), BrokerError> {
    let session = super::session::get_session_from_cookies(cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, csrf)?;
    let level = session.level;
    mintable_email(state, session.user_id, email, |rec| Ok(crate::mint::authorize_mint(rec, level)))
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
    /// The cookie session's CSRF token. Absent on the registry-session form
    /// (bean 73ok: `Authorization: Bearer` + `Proof` by the login key).
    #[serde(default)]
    pub csrf: Option<String>,
    pub email: String,
    pub device_pubkey: String,
    pub config_pubkey: String,
    /// The client broker's stable per-browser holder (reused across identities),
    /// which must sit in this account's `browsers` namespace. Optional for
    /// backward-compat: absent → the broker assigns a fresh one.
    #[serde(default)]
    pub holder: Option<String>,
    /// The wallet's `return_origin` when the caller is the ceremony page
    /// (fallback-idp-api-v1 §3.1). Absent = the issuer's own first-party
    /// dialog (a same-origin, CSRF-bound call). Enforced here, not only in
    /// the page: anything but loopback, a custom scheme, our own origin, or
    /// a configured trusted wallet is refused.
    #[serde(default)]
    pub return_origin: Option<String>,
    /// The ceremony page asks for a registry login token alongside the
    /// certs (fallback-idp-api-v1 §3.3): when what this session proved meets
    /// the account's add-a-device rule, the wallet enrols its login key
    /// with it and needs no second ceremony. Cookie form only.
    #[serde(default)]
    pub want_login: bool,
}

#[derive(Serialize)]
pub struct DeviceIssueResponse {
    pub success: bool,
    pub device_cert: String,
    pub config_cert: String,
    /// A one-time registry login token (§3.3), when asked for and earned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
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

/// Who is asking `/device/issue`: the issuer's own cookie session (the
/// dialog, the ceremony page), or a wallet on its registry login key
/// (co-located issuer + registry, bean 73ok).
enum IssueCaller {
    Cookie(crate::store::Session),
    Key { user_id: crate::store::UserId, key: browserid_registrar::models::LoginCertRecord },
}

pub async fn device_issue<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<DeviceIssueResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let req: DeviceIssueRequest = serde_json::from_slice(&body)
        .map_err(|e| BrokerError::ValidationError(format!("bad request body: {e}")))?;
    // The registry-session form: Bearer + Proof by an enrolled login key.
    // The registrar verifies the whole §4.4 path (token, live key, proof,
    // body hash, replay); the issuer then applies its own mint chokepoint.
    let caller = if headers.contains_key(axum::http::header::AUTHORIZATION) {
        let registrar = state
            .registrar
            .get()
            .ok_or_else(|| BrokerError::Internal("registrar not wired".into()))?;
        let bh = browserid_registrar::session::b64url_sha256_pub(&body);
        let (session, key, _proof) = browserid_registrar::session::verify_session_call(
            registrar, &headers, "POST", "/device/issue", Some(&bh),
        )
        .await
        .map_err(|e| BrokerError::PolicyRefused(format!("registry session: {e:?}")))?;
        IssueCaller::Key { user_id: crate::store::UserId(session.user_id), key }
    } else {
        let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
            .ok_or(BrokerError::NotAuthenticated)?;
        IssueCaller::Cookie(session)
    };
    let (user_id, email, ttl, prov, login_key_id): (crate::store::UserId, String, Duration, &'static str, Option<u64>) = match &caller {
        IssueCaller::Cookie(session) => {
            let csrf = req.csrf.as_deref().unwrap_or("");
            let (email, ttl, prov) = owned_mintable_email(&state, &cookies, csrf, &req.email)?;
            if let Some(ro) = req.return_origin.as_deref().filter(|s| !s.trim().is_empty()) {
                if !state.return_origin_accepted(ro, &state.domain) {
                    return Err(BrokerError::PolicyRefused(crate::return_origin::REFUSAL.into()));
                }
            }
            (session.user_id, email, ttl, prov, None)
        }
        IssueCaller::Key { user_id, key } => {
            let store = state.user_store.as_ref();
            let (email, ttl, prov) = mintable_email(&state, *user_id, &req.email, |rec| {
                let met = crate::account_auth::mint_rule_met(store, *user_id, key, &rec.email)?;
                Ok(crate::mint::authorize_mint_on_login_key(rec, met))
            })?;
            (*user_id, email, ttl, prov, Some(key.id))
        }
    };
    let device_pub = parse_pub(&req.device_pubkey)?;
    let config_pub = parse_pub(&req.config_pubkey)?;
    let device_ref = device_status(&state, &device_pub)?;
    let config_ref = device_status(&state, &config_pub)?;
    // One device slot → one holder in the user's `browsers` namespace, carried by
    // BOTH the authentication (device) and authorization (config) cert. The client
    // broker supplies this browser's stable holder (reused across identities); it
    // must sit in this account's `browsers` namespace (the requester can name a
    // holder only *within* its own browsers namespace, never a service's). Absent
    // → the broker assigns a fresh one (older clients / first contact).
    let ns_prefix = state.user_store.get_or_create_namespace(user_id, "browsers")?;
    let holder = match req.holder.as_deref() {
        Some(h) if !h.is_empty() => {
            browserid_core::device::Holder::new(h.to_string()).map_err(ce)?;
            // Well-formed, and in THIS account's browsers namespace.
            let prefix = h.split_once('.').map(|(p, _)| p).unwrap_or("");
            if prefix != ns_prefix {
                return Err(BrokerError::PolicyRefused(
                    "supplied holder is not in this account's browsers namespace".into(),
                ));
            }
            h.to_string()
        }
        _ => crate::crypto::assign_holder_id(&ns_prefix),
    };
    let holder_id = browserid_core::device::Holder::new(holder.clone()).map_err(ce)?;
    // Both certs carry the proof class they were issued under (kts0):
    // /access/mint refuses a cert whose class no longer matches the record,
    // so a later provenance upgrade swaps certs at their next use.
    let device_cert = DeviceCert::create_with_provenance(
        &state.domain, &device_pub, Purpose::Authentication, holder_id.clone(),
        vec![email.clone()], ttl, &state.keypair, Some(device_ref.clone()),
        Some(prov.to_string()),
    ).map_err(ce)?;
    // The config cert also covers `+tag` sub-addresses so it can sign
    // warrants for the user's plus-named agent identities (design doc §3).
    let config_identities = match browserid_core::identity::email_parts(&email) {
        Some((local, domain)) => vec![email.clone(), format!("{local}+*@{domain}")],
        None => vec![email.clone()],
    };
    let config_cert = DeviceCert::create_with_provenance(
        &state.domain, &config_pub, Purpose::Authorization, holder_id.clone(),
        config_identities, ttl, &state.keypair, Some(config_ref.clone()),
        Some(prov.to_string()),
    ).map_err(ce)?;

    // Durable registry rows (upsert on pubkey) so the certs are enumerable and
    // revocable per account. Issued on a login key, they are recorded under
    // it — the device's own certs, as an attach would record them.
    let now = Utc::now();
    let expires = now + ttl;
    for (pubkey, purpose, status_idx) in [
        (&req.device_pubkey, "authentication", device_ref.idx),
        (&req.config_pubkey, "authorization", config_ref.idx),
    ] {
        state.user_store.insert_device_cert(DeviceCertRecord {
            id: 0,
            user_id,
            identities: vec![email.clone()],
            purpose: purpose.to_string(),
            holder: holder.clone(),
            pubkey: pubkey.clone(),
            iss: state.domain.clone(),
            issued_at: now,
            expires_at: expires,
            revoked_at: None,
            status_uri: Some(browserid_registrar::consent::status_list_uri(&state.domain)),
            status_idx: Some(status_idx),
            prov: prov.to_string(),
            login_key_id,
        })?;
    }
    // First sight of this holder → a friendly UA-derived default label
    // ("Chrome on macOS"); never clobbers a user rename, never fails issuance.
    super::holders::maybe_label_holder_from_ua(
        state.user_store.as_ref(), user_id, &holder, &headers,
    );
    // The ceremony page's ask (§3.3): what this session proved — the
    // identity, and the password when the session is Full — against the
    // account's add-a-device rule; a token only when it is met.
    let login = match (&caller, req.want_login) {
        (IssueCaller::Cookie(session), true) => {
            let proofs = crate::account_auth::proofs_of_session(session.level, &email);
            match crate::account_auth::evaluate(state.user_store.as_ref(), user_id, &proofs) {
                Ok(o) if o.met => crate::account_auth::mint_login_token(state.user_store.as_ref(), user_id, &o).ok(),
                _ => None,
            }
        }
        _ => None,
    };
    if let IssueCaller::Key { key, .. } = &caller {
        tracing::info!(kid = %key.kid, %email, "device/issue: minted on a login key");
    }
    Ok(Json(DeviceIssueResponse {
        success: true,
        device_cert: device_cert.encoded().to_string(),
        config_cert: config_cert.encoded().to_string(),
        login,
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
    // Provenance-freshness gate (kts0): a device cert is only as good as the
    // verification class it was issued under. If the identity has since
    // upgraded to a bridge-vouched class (E2 — e.g. the broker gained OAuth
    // support for the domain and the record re-proved), a cert from the old
    // class is refused AND revoked here, at its next use — the dialog reacts
    // by re-issuing through the bridge ceremony, so E3-era certs are swapped
    // for E2 ones automatically. Certs without the marker predate it and read
    // as SMTP-issued. E3/agent records skip the check (their class hasn't
    // moved), as do identities the broker has no record for.
    if let Ok(Some(rec)) = state.user_store.get_email(&c.identity) {
        let is_e2 = rec.email_type == crate::store::EmailType::Secondary
            && matches!(
                rec.proof,
                crate::store::ProofMethod::Oidc | crate::store::ProofMethod::Atproto
            );
        let issued_under = device_cert.claims().prov.as_deref().unwrap_or("smtp");
        if is_e2 && issued_under != rec.proof.as_str() {
            // Precise class-wide revocation (x5c3): kill EVERY registry cert
            // for this (user, address) issued under a stale class — the
            // presented one, its config sibling, and other browsers' pairs —
            // with rows stamped so the account UI stays honest. Correctly-
            // classed certs are untouched.
            let _ = state
                .user_store
                .revoke_user_stale_class_certs(rec.user_id, &c.identity, rec.proof.as_str());
            // Belt-and-braces for certs with no registry row (pre-7ww7
            // cookie-only issuance): flip the presented cert's own bit too.
            if let Some(status) = &device_cert.claims().status {
                if status.uri == browserid_registrar::consent::status_list_uri(&state.domain) {
                    let _ = state.user_store.set_status_revoked_idx(status.idx);
                }
            }
            return Err(BrokerError::PolicyRefused(
                "device cert predates this address's current verification method and is now revoked — sign in again to reissue".into(),
            ));
        }
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
// POST /verify  (convenience verifier, real conformance)
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
    req: Result<Json<VerifyAccessRequest>, JsonRejection>,
) -> Response
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // A malformed body gets a structured JSON error, not axum's plain-text
    // rejection — this is the public API's front door.
    let Json(req) = match req {
        Ok(json) => json,
        Err(rej) => return crate::error::bad_request_json(rej.body_text()),
    };
    let fetcher = match state.fallback_fetcher().await {
        Ok(f) => f,
        Err(e) => {
            return Json(AccessVerificationResult::fail(format!("fetcher: {e}"))).into_response()
        }
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
    .into_response()
}

// ---------------------------------------------------------------------------
// POST /validate-record  (two-object record validation, operation A — §6.4)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ValidateRecordRequest {
    /// The held record: `warrant~config_cert`.
    pub record: String,
    /// The caller's own audience — validation checks `warrant.audience`
    /// against it exactly.
    pub audience: String,
    #[serde(default)]
    pub accepted_fallbacks: Option<Vec<String>>,
}

/// The record-validation call beside `/verify` (§6.4 steps 1b–1e). No
/// caller authentication: record validation authenticates no one, and a
/// record is attributed paper — readable, spendable nowhere — so serving the
/// check openly leaks nothing (§6.4).
pub async fn validate_record<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    req: Result<Json<ValidateRecordRequest>, JsonRejection>,
) -> Response
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    use crate::verifier::RecordValidationResult;
    // Same structured-JSON rejection contract as /verify.
    let Json(req) = match req {
        Ok(json) => json,
        Err(rej) => return crate::error::bad_request_json(rej.body_text()),
    };
    let fetcher = match state.fallback_fetcher().await {
        Ok(f) => f,
        Err(e) => {
            return Json(RecordValidationResult::fail(format!("fetcher: {e}"))).into_response()
        }
    };
    let accepted = req.accepted_fallbacks.unwrap_or_else(|| vec![state.domain.clone()]);
    let is_own_revoked =
        |idx: u64| state.user_store.is_status_revoked_idx(idx).map_err(|e| e.to_string());
    let status = crate::verifier::StatusCtx {
        own_uri: browserid_registrar::consent::status_list_uri(&state.domain),
        is_own_revoked: &is_own_revoked,
        cache: &state.foreign_status_lists,
        allow_private_hosts: !crate::routes::session::cookie_secure(&state.domain),
    };
    Json(
        crate::verifier::validate_record_with_dns(
            &req.record, &req.audience, fetcher.as_ref(), &accepted, status,
        )
        .await,
    )
    .into_response()
}

// ---------------------------------------------------------------------------



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
