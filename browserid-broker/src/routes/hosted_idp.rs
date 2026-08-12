//! Hosted-primary IdP surface (bean g5qt).
//!
//! browserid.me operates the full §7 primary contract for TENANT domains:
//! a customer domain publishes one DNSSEC `_browserid` record carrying a
//! custodial per-tenant public key plus `host=<idp host>`, and the pages and
//! APIs here — reached only via standard discovery, never by dialog
//! special-casing — issue certs with `iss = <tenant domain>` signed by the
//! tenant's own key. The existing dialog and fallback surfaces are untouched.
//!
//! Two route families live here:
//!
//! - `/idp/*` — the tenant-user §7 surface: `device-authorize` page glue
//!   (login/whoami/password), first-party device-cert issuance, the CORS
//!   headless mint, and per-tenant signed status lists at
//!   `/status/<tenant domain>`.
//! - `/wsapi/tenant/*` — onboarding + roster admin, broker-session + CSRF
//!   gated: create a tenant (generates the sealed keypair + the DNS record
//!   text; publishing that record IS the proof of domain control), poll the
//!   DNSSEC checker, manage the roster and admins.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_cookies::cookie::time::Duration as CookieDuration;
use tower_cookies::cookie::SameSite;
use tower_cookies::{Cookie, Cookies};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use browserid_core::device::{AccessCert, DeviceCert, Purpose};
use browserid_core::status::{StatusList, StatusListToken};
use browserid_core::{PublicKey, StatusRef};

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{RosterState, SessionStore, Tenant, TenantStatus, UserStore};

/// Device/config cert validity for tenant issuance — matches the fallback's.
const DEVICE_CERT_VALIDITY_DAYS: i64 = 90;
/// Tenant-user session cookie (scoped to /idp; signed, stateless).
const IDP_COOKIE: &str = "idp_session";
const IDP_SESSION_SECONDS: i64 = 2 * 60 * 60;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The tenant's status-list URI, served by this deployment on the idp host.
pub fn tenant_status_uri(idp_host: &str, tenant_domain: &str) -> String {
    format!(
        "{}/status/{}",
        browserid_registrar::consent::public_origin(idp_host),
        tenant_domain
    )
}

/// The TXT record a tenant publishes at `_browserid.<domain>`. Publishing
/// it is the onboarding challenge: the pubkey is generated per attempt, so
/// only the attempt's creator can be seated as first admin by it.
pub fn tenant_dns_record(public_key: &str, idp_host: &str) -> String {
    format!("v=browserid1; public-key-algorithm=Ed25519; public-key={public_key}; host={idp_host}")
}

fn split_email(email: &str) -> Option<(String, String)> {
    let (local, domain) = email.split_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    Some((local.to_lowercase(), domain.to_lowercase()))
}

/// The roster user a local part belongs to: the part before any `+tag`.
/// An agent identity is a subaddress of a roster user (`dan+poster` acts for
/// roster user `dan`), so roster/policy decisions about an agent are decided
/// on its base. RFC 5233 subaddressing; the same base-covers-`+tag` rule the
/// device cert and warrant already enforce.
fn base_local(local: &str) -> &str {
    local.split('+').next().unwrap_or(local)
}

/// Look up an ACTIVE tenant or refuse.
fn active_tenant<U: UserStore>(store: &U, domain: &str) -> Result<Tenant, BrokerError> {
    let tenant = store.get_tenant(domain)?.ok_or(BrokerError::TenantNotFound)?;
    if tenant.status != TenantStatus::Active {
        return Err(BrokerError::PolicyRefused("tenant is not active".into()));
    }
    Ok(tenant)
}

/// Unseal a tenant's signing keypair (refuses when the keystore is absent).
fn tenant_keypair<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    tenant: &Tenant,
) -> Result<browserid_core::KeyPair, BrokerError> {
    let keystore = state
        .tenant_keystore
        .as_ref()
        .ok_or_else(|| BrokerError::PolicyRefused("tenant keystore not configured".into()))?;
    keystore
        .unseal(&tenant.domain, &tenant.private_key_sealed)
        .map_err(|e| BrokerError::Internal(format!("tenant key unseal: {e}")))
}

// --- Tenant-user session cookie: stateless, signed by the broker key ------
// Value: b64url(json{email, exp, mc}) + "." + b64url(sig). `mc` =
// must-change-password: the session exists (so the page can drive the change
// form) but cert issuance is refused until the password is changed.

fn issue_idp_cookie<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    cookies: &Cookies,
    email: &str,
    must_change: bool,
) {
    let claims = json!({
        "email": email,
        "exp": (Utc::now() + Duration::seconds(IDP_SESSION_SECONDS)).timestamp(),
        "mc": must_change,
    })
    .to_string();
    let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(state.keypair.sign(payload.as_bytes()));
    let mut cookie = Cookie::new(IDP_COOKIE, format!("{payload}.{sig}"));
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/idp");
    cookie.set_max_age(CookieDuration::seconds(IDP_SESSION_SECONDS));
    cookie.set_secure(super::session::cookie_secure(&state.domain));
    cookies.add(cookie);
}

/// (email, must_change) from a valid, unexpired idp session cookie.
fn idp_session<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    cookies: &Cookies,
) -> Option<(String, bool)> {
    let raw = cookies.get(IDP_COOKIE)?.value().to_string();
    let (payload, sig) = raw.rsplit_once('.')?;
    let sig = URL_SAFE_NO_PAD.decode(sig).ok()?;
    state
        .keypair
        .public_key()
        .verify(payload.as_bytes(), &sig)
        .ok()?;
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    if claims.get("exp")?.as_i64()? < Utc::now().timestamp() {
        return None;
    }
    Some((
        claims.get("email")?.as_str()?.to_string(),
        claims.get("mc")?.as_bool().unwrap_or(false),
    ))
}

// ---------------------------------------------------------------------------
// Tenant support document — served for GET /.well-known/browserid when the
// request's Host is the idp host (wired in well_known.rs). Carries no key:
// the tenant's key lives only in its own DNSSEC record.
// ---------------------------------------------------------------------------

pub fn tenant_support_document() -> browserid_core::discovery::SupportDocument {
    let mut doc = browserid_core::discovery::SupportDocument::delegate("unused");
    doc.authority = None;
    doc.device_cert = Some("/idp/device_cert".into());
    doc.access_cert = Some("/idp/access_cert".into());
    doc.device_authorization = Some("/idp/device-authorize".into());
    doc
}

// ---------------------------------------------------------------------------
// POST /idp/login {email, password}
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct IdpLoginRequest {
    pub email: String,
    pub password: String,
}

pub async fn idp_login<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<IdpLoginRequest>,
) -> (StatusCode, Json<serde_json::Value>)
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let fail = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"success": false, "reason": "invalid email or password"})),
        )
    };
    let Some((local, domain)) = split_email(&req.email) else {
        return fail();
    };
    let Ok(tenant) = active_tenant(state.user_store.as_ref(), &domain) else {
        return fail();
    };
    let Ok(Some(entry)) = state.user_store.get_roster_entry(tenant.id, &local) else {
        return fail();
    };
    if entry.state != RosterState::Active {
        return fail();
    }
    if !crate::crypto::verify_password(&req.password, &entry.password_hash).unwrap_or(false) {
        return fail();
    }
    let email = format!("{local}@{domain}");
    issue_idp_cookie(state.as_ref(), &cookies, &email, entry.must_change_password);
    let _ = state.user_store.touch_roster_login(tenant.id, &local);
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "email": email,
            "must_change_password": entry.must_change_password,
        })),
    )
}

// ---------------------------------------------------------------------------
// GET /idp/whoami
// ---------------------------------------------------------------------------

pub async fn idp_whoami<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Json<serde_json::Value>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    match idp_session(state.as_ref(), &cookies) {
        Some((email, mc)) => Json(json!({"email": email, "must_change_password": mc})),
        None => Json(json!({"email": null})),
    }
}

// ---------------------------------------------------------------------------
// POST /idp/password {email, current_password, new_password}
// Credential-gated (no cookie required): the login page drives this for the
// forced first-login change. Success re-issues the session cookie with the
// must-change flag cleared.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct IdpPasswordRequest {
    pub email: String,
    pub current_password: String,
    pub new_password: String,
}

pub async fn idp_password<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<IdpPasswordRequest>,
) -> (StatusCode, Json<serde_json::Value>)
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let fail = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"success": false, "reason": "invalid email or password"})),
        )
    };
    if req.new_password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"success": false, "reason": "new password too short (minimum 8 characters)"})),
        );
    }
    if req.new_password.len() > 80 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"success": false, "reason": "new password too long (maximum 80 characters)"})),
        );
    }
    let Some((local, domain)) = split_email(&req.email) else {
        return fail();
    };
    let Ok(tenant) = active_tenant(state.user_store.as_ref(), &domain) else {
        return fail();
    };
    let Ok(Some(entry)) = state.user_store.get_roster_entry(tenant.id, &local) else {
        return fail();
    };
    if entry.state != RosterState::Active
        || !crate::crypto::verify_password(&req.current_password, &entry.password_hash)
            .unwrap_or(false)
    {
        return fail();
    }
    let Ok(hash) = crate::crypto::hash_password(&req.new_password) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"success": false, "reason": "hashing failed"})),
        );
    };
    if state
        .user_store
        .set_roster_password(tenant.id, &local, &hash, false)
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"success": false, "reason": "store failed"})),
        );
    }
    let email = format!("{local}@{domain}");
    issue_idp_cookie(state.as_ref(), &cookies, &email, false);
    (StatusCode::OK, Json(json!({"success": true, "email": email})))
}

// ---------------------------------------------------------------------------
// POST /idp/device_cert  (idp-session-gated, first-party)
// Mirrors the fallback's batch issuance, signed by the TENANT key.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct IdpDeviceCertRequest {
    pub email: String,
    pub device_pubkey: String,
    pub config_pubkey: String,
    /// Passthrough holder from the dialog; absent = cold login, self-assign.
    #[serde(default)]
    pub holder: Option<String>,
}

pub async fn idp_device_cert<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<IdpDeviceCertRequest>,
) -> (StatusCode, Json<serde_json::Value>)
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let err = |code: StatusCode, reason: String| (code, Json(json!({"success": false, "reason": reason})));

    let Some((session_email, must_change)) = idp_session(state.as_ref(), &cookies) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in".into());
    };
    if must_change {
        return err(StatusCode::FORBIDDEN, "password change required".into());
    }
    let Some((local, domain)) = split_email(&req.email) else {
        return err(StatusCode::BAD_REQUEST, "invalid email".into());
    };
    let email = format!("{local}@{domain}");
    if email != session_email {
        return err(StatusCode::FORBIDDEN, "signed-in identity does not match".into());
    }
    let tenant = match active_tenant(state.user_store.as_ref(), &domain) {
        Ok(t) => t,
        Err(e) => return err(StatusCode::FORBIDDEN, e.to_string()),
    };
    match state.user_store.get_roster_entry(tenant.id, &local) {
        Ok(Some(entry)) if entry.state == RosterState::Active => {}
        _ => return err(StatusCode::FORBIDDEN, "roster entry is not active".into()),
    }
    let keypair = match tenant_keypair(state.as_ref(), &tenant) {
        Ok(k) => k,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let (device_pub, config_pub) = match (
        PublicKey::from_base64(&req.device_pubkey),
        PublicKey::from_base64(&req.config_pubkey),
    ) {
        (Ok(d), Ok(c)) => (d, c),
        (Err(e), _) | (_, Err(e)) => return err(StatusCode::BAD_REQUEST, format!("bad pubkey: {e}")),
    };
    // Holder: verbatim passthrough (the dialog supplies the browser's stable
    // holder, and the reissue hop supplies a corrected one), else self-assign
    // a standalone `<prefix>.<rand>` exactly like a cold fallback login.
    let holder_str = req
        .holder
        .clone()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| {
            crate::crypto::assign_holder_id(&crate::crypto::generate_namespace_prefix())
        });
    let holder = match browserid_core::device::Holder::new(holder_str) {
        Ok(h) => h,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("holder: {e}")),
    };
    // Per-device status refs on the TENANT's list.
    let status_for = |pubkey: &PublicKey| -> Result<StatusRef, BrokerError> {
        let idx = state
            .user_store
            .tenant_status_allocate(tenant.id, &pubkey.to_base64())?;
        Ok(StatusRef {
            uri: tenant_status_uri(&state.idp_host, &tenant.domain),
            idx,
        })
    };
    let (device_ref, config_ref) = match (status_for(&device_pub), status_for(&config_pub)) {
        (Ok(d), Ok(c)) => (d, c),
        (Err(e), _) | (_, Err(e)) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("status: {e}")),
    };
    // Device-cert validity: a managed tenant's policy sets how long a
    // signed-in device stays signed in; otherwise the fallback's default.
    let ttl = tenant
        .management
        .as_ref()
        .filter(|m| m.enabled)
        .and_then(|m| m.device_cert_ttl)
        .map(Duration::seconds)
        .unwrap_or_else(|| Duration::days(DEVICE_CERT_VALIDITY_DAYS));
    let config_identities = vec![email.clone(), format!("{local}+*@{domain}")];
    // Managed marker (spec §4.7): stamped on EVERY device cert of a managed
    // identity, before the mint ever applies constraints — the durable,
    // issuance-time signal that drives UA disclosure.
    let managed = tenant
        .management
        .as_ref()
        .filter(|m| m.enabled)
        .map(|_| true);
    let issue = |pubkey: &PublicKey, purpose: Purpose, identities: Vec<String>, status: StatusRef| {
        let now = chrono::Utc::now();
        DeviceCert::from_claims(
            browserid_core::device::DeviceCertClaims {
                typ: browserid_core::device::TYP_DEVICE_CERT.to_string(),
                iss: tenant.domain.clone(),
                iat: now.timestamp(),
                exp: (now + ttl).timestamp(),
                purpose,
                holder: holder.clone(),
                identities,
                public_key: pubkey.clone(),
                status: Some(status),
                managed,
                constraints: None,
            },
            &keypair,
        )
    };
    let (device_cert, config_cert) = match (
        issue(&device_pub, Purpose::Authentication, vec![email.clone()], device_ref),
        issue(&config_pub, Purpose::Authorization, config_identities, config_ref),
    ) {
        (Ok(d), Ok(c)) => (d, c),
        (Err(e), _) | (_, Err(e)) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("cert: {e}")),
    };
    tracing::info!(email = %email, tenant = %tenant.domain, "hosted primary: issued device + config certs");
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "device_cert": device_cert.encoded(),
            "config_cert": config_cert.encoded(),
            "identity": email,
        })),
    )
}

// ---------------------------------------------------------------------------
// POST /idp/access_cert  (headless mint; CORS — the dialog calls it
// cross-origin with credentials omitted)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct IdpAccessCertRequest {
    pub device_cert: String,
    pub access_request: String,
}

pub async fn idp_access_cert<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<IdpAccessCertRequest>,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let ce = |e: browserid_core::Error| BrokerError::InvalidProvisioningRequest(e.to_string());
    let device_cert = DeviceCert::parse(&req.device_cert).map_err(ce)?;
    // Route by the cert's iss: it must name one of OUR active tenants, and
    // then the signature must verify under that tenant's key.
    let tenant = active_tenant(state.user_store.as_ref(), device_cert.iss())?;
    let keypair = tenant_keypair(state.as_ref(), &tenant)?;
    device_cert.verify(&keypair.public_key()).map_err(ce)?;
    if device_cert.is_expired() {
        return Err(BrokerError::InvalidProvisioningRequest("device cert expired".into()));
    }
    if device_cert.purpose() != Purpose::Authentication {
        return Err(BrokerError::PolicyRefused(
            "device cert cannot mint access certs (not authentication)".into(),
        ));
    }
    // Fail-closed revocation gate at the mint (closes the M1 gap for tenants):
    // the device's own status bit must be clear.
    if let Some(status) = &device_cert.claims().status {
        if state.user_store.tenant_status_is_revoked(tenant.id, status.idx)? {
            return Err(BrokerError::PolicyRefused("device cert revoked".into()));
        }
    }
    let areq = browserid_core::device::AccessRequest::parse(&req.access_request).map_err(ce)?;
    areq.verify(device_cert.public_key()).map_err(ce)?;
    if areq.is_expired() {
        return Err(BrokerError::InvalidProvisioningRequest("access request expired".into()));
    }
    let c = areq.claims();
    if !super::device::claim_jti(&c.jti, c.exp) {
        return Err(BrokerError::InvalidProvisioningRequest(
            "access request replayed (jti seen)".into(),
        ));
    }
    if c.domain != tenant.domain {
        return Err(BrokerError::InvalidProvisioningRequest("wrong target domain".into()));
    }
    if !device_cert.authorizes_identity(&c.identity) {
        return Err(BrokerError::PolicyRefused(
            "device cert not authorized for this identity".into(),
        ));
    }
    if c.holder != *device_cert.holder() {
        return Err(BrokerError::PolicyRefused("holder mismatch".into()));
    }
    // The roster stays authoritative at mint time: a disabled (or vanished)
    // user stops minting immediately, bounding a live session by the access
    // cert's 24h TTL even without touching the status list. An agent identity
    // (`dan+poster`) is checked against its base roster user (`dan`) — the
    // device cert already proved the base authorizes the subaddress.
    if let Some((local, _)) = split_email(&c.identity) {
        match state.user_store.get_roster_entry(tenant.id, base_local(&local))? {
            Some(entry) if entry.state == RosterState::Active => {}
            _ => return Err(BrokerError::PolicyRefused("roster entry is not active".into())),
        }
    }
    // Managed-identity policy (spec §4.7/§7.2): the mint is the per-~24 h
    // policy decision point. The `audience` request claim is honored ONLY for
    // a marked device cert (unmanaged mints stay RP-blind); constraints are
    // decided fresh from the tenant's current policy at every mint.
    let policy = tenant.management.as_ref().filter(|m| m.enabled);
    let mut constraints: Option<browserid_core::device::Constraints> = None;
    if let Some(p) = policy {
        let requested = c
            .audience
            .as_deref()
            .filter(|_| device_cert.claims().managed == Some(true));
        if let Some(aud) = requested {
            // Early, comprehensible policy failure at login time — not an
            // opaque verifier reject.
            if !p.audiences.is_empty() && !p.audiences.iter().any(|a| a == aud) {
                return Err(BrokerError::PolicyRefused(
                    "identity not permitted at this site (managed-identity policy)".into(),
                ));
            }
        }
        if p.per_audience && requested.is_none() {
            // Two ways to land here: a current credential that simply omitted
            // the audience, or a device cert issued BEFORE the domain turned
            // on managed identities (no `managed` marker, so the agent never
            // knows to mint per-audience). The stale-credential case is the
            // common one when a tenant enables management on an existing
            // roster, and it recovers only by re-provisioning — say so.
            if device_cert.claims().managed != Some(true) {
                return Err(BrokerError::PolicyRefused(format!(
                    "this credential predates managed-identity settings for {}; \
                     sign out and provision the identity again to continue",
                    tenant.domain
                )));
            }
            return Err(BrokerError::PolicyRefused(
                "audience required: this managed identity mints per-audience access certs".into(),
            ));
        }
        constraints = constraints_from_policy(p, if p.per_audience { requested } else { None })
            .map_err(|e| BrokerError::Internal(format!("constraints: {e}")))?;
    }
    // Access-cert validity: the policy's split knob wins; the legacy single
    // `max_ttl` bounds it for policies saved before the split; else 24h.
    let access_ttl = policy
        .and_then(|p| p.access_cert_ttl.or(p.max_ttl))
        .map(Duration::seconds)
        .unwrap_or_else(|| Duration::hours(24));
    let access_cert = {
        let now = chrono::Utc::now();
        AccessCert::from_claims(
            browserid_core::device::AccessCertClaims {
                typ: browserid_core::device::TYP_ACCESS_CERT.to_string(),
                iss: tenant.domain.clone(),
                iat: now.timestamp(),
                exp: (now + access_ttl).timestamp(),
                identity: c.identity.clone(),
                holder: device_cert.holder().clone(),
                access_key: c.access_key.clone(),
                status: device_cert.claims().status.clone(),
                constraints,
            },
            &keypair,
        )
        .map_err(ce)?
    };
    Ok(Json(json!({
        "success": true,
        "access_cert": access_cert.encoded(),
        "email": c.identity,
    })))
}

/// Build the wire `Constraints` from a tenant's policy. `single_audience`
/// (per-audience posture) scopes the cert to exactly that audience; otherwise
/// the full allowlist is hashed (broad posture — empty allowlist = no aud
/// constraint at all). Returns None when the policy restricts nothing.
fn constraints_from_policy(
    p: &crate::store::ManagementPolicy,
    single_audience: Option<&str>,
) -> Result<Option<browserid_core::device::Constraints>, browserid_core::Error> {
    use browserid_core::device::{AudConstraint, Constraints};
    let aud = match single_audience {
        Some(a) => Some(AudConstraint {
            salt: p.salt.clone(),
            hashes: vec![AudConstraint::hash_audience(&p.salt, a)?],
        }),
        None if !p.audiences.is_empty() => Some(AudConstraint {
            salt: p.salt.clone(),
            hashes: p
                .audiences
                .iter()
                .map(|a| AudConstraint::hash_audience(&p.salt, a))
                .collect::<Result<Vec<_>, _>>()?,
        }),
        None => None,
    };
    if aud.is_none() && p.scopes.is_none() && p.max_ttl.is_none() {
        return Ok(None);
    }
    Ok(Some(Constraints {
        aud,
        scopes: p.scopes.clone(),
        max_ttl: p.max_ttl,
        unknown: Default::default(),
    }))
}

// ---------------------------------------------------------------------------
// GET /status/:domain — the tenant's signed status list. Same wire format as
// every other list (`browserid-status-list-v1`), iss = the tenant domain,
// sub = this URI, signed by the tenant key. Verifiers accept the idp host as
// the serving host via the tenant's DNSSEC `host=` declaration.
// ---------------------------------------------------------------------------

pub async fn tenant_status_list<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Path(domain): Path<String>,
) -> Result<String, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let domain = domain.to_lowercase();
    let tenant = state
        .user_store
        .get_tenant(&domain)?
        .ok_or(BrokerError::TenantNotFound)?;
    // Suspended tenants keep serving their list (revocations must stay
    // visible); only pending ones (no possible certs) 404.
    if tenant.status == TenantStatus::PendingDns {
        return Err(BrokerError::TenantNotFound);
    }
    let keypair = tenant_keypair(state.as_ref(), &tenant)?;
    let (revoked, max) = state.user_store.tenant_status_snapshot(tenant.id)?;
    let list = StatusList::from_revoked(revoked, max);
    let token = StatusListToken::create(
        &tenant.domain,
        &tenant_status_uri(&state.idp_host, &tenant.domain),
        &list,
        &keypair,
    )
    .map_err(|e| BrokerError::Internal(format!("status list sign: {e}")))?;
    Ok(token.encoded().to_string())
}

// ===========================================================================
// Onboarding + roster admin (broker session + CSRF)
// ===========================================================================

/// Admin gate: the session's account either OWNS the tenant (onboarded it —
/// always retains access, even before any admin email is on the account) or
/// holds a verified identity that is a tenant admin. Returns an identity
/// string for audit (the matching admin email, else a verified account email,
/// else an owner marker).
fn session_admin_identity<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    cookies: &Cookies,
    csrf: &str,
    domain: &str,
) -> Result<String, BrokerError> {
    let session = super::session::get_session_from_cookies(cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    if session.csrf_token != csrf {
        return Err(BrokerError::InvalidCsrf);
    }
    let tenant = state.user_store.get_tenant(domain)?.ok_or(BrokerError::TenantNotFound)?;
    let emails = state.user_store.list_emails(session.user_id)?;
    // Admin-of-record match wins (better audit identity).
    for email in &emails {
        if email.verified && state.user_store.is_tenant_admin(domain, &email.email)? {
            return Ok(email.email.clone());
        }
    }
    // Owner of the tenant always retains access.
    if tenant.owner_user_id == Some(session.user_id) {
        let who = emails
            .iter()
            .find(|e| e.verified)
            .map(|e| e.email.clone())
            .unwrap_or_else(|| format!("owner:{}", session.user_id.0));
        return Ok(who);
    }
    Err(BrokerError::PolicyRefused("not a tenant admin".into()))
}

fn valid_tenant_domain(domain: &str) -> bool {
    let d = domain.trim();
    !d.is_empty()
        && d.len() <= 253
        && d.contains('.')
        && !d.starts_with('.')
        && !d.ends_with('.')
        && !d.contains("..")
        && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && d.split('.').last().is_some_and(|tld| tld.chars().all(|c| c.is_ascii_alphabetic()))
}

fn valid_local_part(local: &str) -> bool {
    !local.is_empty()
        && local.len() <= 64
        // `+` is reserved for subaddressing; `*` for globs.
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

#[derive(Deserialize)]
pub struct TenantCreateRequest {
    pub csrf: String,
    pub domain: String,
    /// Who administers the domain. Either an identity the account already
    /// holds (external — no password), or an email AT this domain (local —
    /// `password` required; it becomes the admin's login once verified).
    pub admin_email: String,
    /// Required iff `admin_email` is at `domain`; must be empty otherwise.
    #[serde(default)]
    pub password: Option<String>,
}

/// POST /wsapi/tenant/create — start an onboarding attempt: generate the
/// custodial keypair and return the record to publish. Records the admin of
/// record, ties the tenant to the onboarding account (owner), and — for a
/// domain-local admin — pre-creates that login (hashed now, usable only once
/// the tenant is active).
pub async fn tenant_create<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<TenantCreateRequest>,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    if session.csrf_token != req.csrf {
        return Err(BrokerError::InvalidCsrf);
    }
    let domain = req.domain.trim().to_lowercase();
    if !valid_tenant_domain(&domain) {
        return Err(BrokerError::ValidationError("invalid domain".into()));
    }
    if domain == state.domain.to_lowercase() || domain == state.idp_host.to_lowercase() {
        return Err(BrokerError::PolicyRefused("that domain is this service".into()));
    }
    let admin_email = req.admin_email.trim().to_lowercase();
    let (admin_local, admin_domain) =
        split_email(&admin_email).ok_or(BrokerError::InvalidEmail)?;
    let password = req.password.as_deref().unwrap_or("");
    let is_local_admin = admin_domain == domain;
    if is_local_admin {
        // Local admin: the domain will be authoritative for it, so it needs a
        // login password now. It need not (and usually will not) be on the
        // account yet — owner linkage keeps the operator's console access.
        if !valid_local_part(&admin_local) {
            return Err(BrokerError::ValidationError("invalid admin email local part".into()));
        }
        if password.len() < 8 {
            return Err(BrokerError::PasswordTooShort);
        }
        if password.len() > 80 {
            return Err(BrokerError::PasswordTooLong);
        }
    } else {
        // External admin: must be an identity the account already controls
        // (that is how we know they hold it), and no password applies.
        if !password.is_empty() {
            return Err(BrokerError::ValidationError(
                "a password only applies to an email at this domain".into(),
            ));
        }
        let owned = state
            .user_store
            .list_emails(session.user_id)?
            .into_iter()
            .any(|e| e.verified && e.email == admin_email);
        if !owned {
            return Err(BrokerError::PolicyRefused(
                "that identity is not verified on your account".into(),
            ));
        }
    }
    let keystore = state
        .tenant_keystore
        .as_ref()
        .ok_or_else(|| BrokerError::PolicyRefused("tenant onboarding is not enabled here".into()))?;
    let (public_key, sealed) = keystore
        .generate_sealed(&domain)
        .map_err(BrokerError::Internal)?;
    let tenant = state.user_store.create_tenant(
        &domain,
        &public_key,
        &sealed,
        Some(session.user_id),
        &admin_email,
    )?;
    // Pre-create the local admin's login (hashed now; gated by active_tenant
    // so unusable until the DNS record verifies). No forced change — the
    // admin chose this password.
    if is_local_admin {
        let hash = crate::crypto::hash_password(password)
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        state
            .user_store
            .create_roster_entry(tenant.id, &admin_local, &hash, false, &admin_email)?;
    }
    state.analytics.capture(
        "tenant_onboarding_started",
        crate::analytics::distinct_id_for_email(&admin_email),
        serde_json::json!({}),
    );
    Ok(Json(json!({
        "success": true,
        "domain": tenant.domain,
        "status": tenant.status,
        "record_name": format!("_browserid.{}", tenant.domain),
        "record": tenant_dns_record(&tenant.public_key, &state.idp_host),
    })))
}

/// GET /wsapi/tenant/list — tenants any of the account's verified identities
/// onboarded or administers.
pub async fn tenant_list<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session =
        super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
            .ok_or(BrokerError::NotAuthenticated)?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for email in state.user_store.list_emails(session.user_id)? {
        if !email.verified {
            continue;
        }
        for t in state.user_store.list_tenants_for(&email.email)? {
            if seen.insert(t.domain.clone()) {
                let users = state.user_store.list_roster(t.id)?.len();
                out.push(json!({
                    "domain": t.domain,
                    "status": t.status,
                    "created_by": t.created_by,
                    "record_name": format!("_browserid.{}", t.domain),
                    "record": tenant_dns_record(&t.public_key, &state.idp_host),
                    "activated_at": t.activated_at.map(|d| d.to_rfc3339()),
                    "users": users,
                }));
            }
        }
    }
    Ok(Json(json!({"success": true, "tenants": out})))
}

#[derive(Deserialize)]
pub struct TenantCheckRequest {
    pub csrf: String,
    pub domain: String,
}

#[derive(Serialize)]
pub struct TenantCheckResponse {
    pub success: bool,
    /// validated | no_record | insecure | bogus | wrong_key
    pub dns: String,
    pub status: TenantStatus,
    /// Whether the record's host= names this deployment (routing sanity).
    pub host_ok: Option<bool>,
}

/// POST /wsapi/tenant/check — run the DNSSEC checker once. When the
/// published, DNSSEC-validated record carries this attempt's key, the tenant
/// activates and the onboarder becomes first admin.
pub async fn tenant_check<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<TenantCheckRequest>,
) -> Result<Json<TenantCheckResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Gate: session + CSRF + (creator or admin). The check mutates nothing
    // unless the record validates, but it does trigger outbound DNS, so it
    // is not anonymous.
    let session =
        super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
            .ok_or(BrokerError::NotAuthenticated)?;
    if session.csrf_token != req.csrf {
        return Err(BrokerError::InvalidCsrf);
    }
    let domain = req.domain.trim().to_lowercase();
    let tenant = state
        .user_store
        .get_tenant(&domain)?
        .ok_or(BrokerError::TenantNotFound)?;
    let allowed = tenant.owner_user_id == Some(session.user_id) || {
        let mut ok = false;
        for email in state.user_store.list_emails(session.user_id)? {
            if email.verified
                && (email.email == tenant.created_by
                    || state.user_store.is_tenant_admin(&domain, &email.email)?)
            {
                ok = true;
                break;
            }
        }
        ok
    };
    if !allowed {
        return Err(BrokerError::PolicyRefused("not this tenant's onboarder or admin".into()));
    }

    let fetcher = crate::dns_fetcher::DnsFetcher::new()
        .map_err(|e| BrokerError::Internal(format!("dns fetcher: {e}")))?;
    let result = fetcher.lookup(&domain).await;
    use browserid_core::DnssecStatus;
    let (dns, host_ok) = match result.dnssec_status {
        DnssecStatus::Bogus => ("bogus".to_string(), None),
        DnssecStatus::Insecure => ("insecure".to_string(), None),
        DnssecStatus::Secure => match result.record {
            None => ("no_record".to_string(), None),
            Some(record) => {
                let host_ok = record
                    .host
                    .as_deref()
                    .map(|h| h.eq_ignore_ascii_case(&state.idp_host));
                if record.public_key.to_base64() == tenant.public_key {
                    ("validated".to_string(), host_ok)
                } else {
                    ("wrong_key".to_string(), host_ok)
                }
            }
        },
    };
    if dns == "validated" && tenant.status == TenantStatus::PendingDns {
        state.user_store.set_tenant_status(&domain, TenantStatus::Active)?;
        // A domain browserid already knew may have broker/fallback-issued
        // certs for identities there; the domain is now authoritative under
        // its own key, so retire those prior credentials (fail-closed). Certs
        // from the domain's previous external IdP aren't ours and die when its
        // DNS key changed to the tenant key.
        match state.user_store.revoke_domain_device_certs(&domain) {
            Ok(n) if n > 0 => {
                tracing::info!(domain = %domain, revoked = n, "hosted primary: revoked prior broker-issued certs on activation");
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(domain = %domain, "revoke prior certs failed: {e}"),
        }
        state.analytics.capture("tenant_activated", crate::analytics::distinct_id_for_email(&tenant.created_by), serde_json::json!({}));
        tracing::info!(domain = %domain, admin = %tenant.created_by, "hosted primary: tenant activated");
    }
    let tenant = state
        .user_store
        .get_tenant(&domain)?
        .ok_or(BrokerError::TenantNotFound)?;
    Ok(Json(TenantCheckResponse {
        success: true,
        dns,
        status: tenant.status,
        host_ok,
    }))
}

#[derive(Deserialize)]
pub struct RosterCreateRequest {
    pub csrf: String,
    pub domain: String,
    pub local_part: String,
    pub password: String,
    /// Force a password change on the user's first login. Defaults to `true`
    /// (an admin provisioning someone else with a temporary password); the
    /// onboarding wizard sends `false` when the admin sets up their own first
    /// account with a password they chose.
    #[serde(default)]
    pub require_password_change: Option<bool>,
}

/// POST /wsapi/tenant/roster — admin creates a user with a set password.
pub async fn roster_create<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<RosterCreateRequest>,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let domain = req.domain.trim().to_lowercase();
    let admin = session_admin_identity(state.as_ref(), &cookies, &req.csrf, &domain)?;
    let tenant = active_tenant(state.user_store.as_ref(), &domain)?;
    let local = req.local_part.trim().to_lowercase();
    if !valid_local_part(&local) {
        return Err(BrokerError::ValidationError(
            "invalid local part (letters, digits, . - _ only)".into(),
        ));
    }
    if req.password.len() < 8 {
        return Err(BrokerError::PasswordTooShort);
    }
    if req.password.len() > 80 {
        return Err(BrokerError::PasswordTooLong);
    }
    let hash = crate::crypto::hash_password(&req.password)
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
    let must_change = req.require_password_change.unwrap_or(true);
    state
        .user_store
        .create_roster_entry(tenant.id, &local, &hash, must_change, &admin)?;
    tracing::info!(tenant = %domain, local = %local, "hosted primary: roster user created");
    Ok(Json(json!({"success": true, "email": format!("{local}@{domain}")})))
}

#[derive(Deserialize)]
pub struct RosterListQuery {
    pub domain: String,
    pub csrf: String,
}

/// GET /wsapi/tenant/roster?domain=&csrf= — the roster, sans hashes.
pub async fn roster_list<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Query(q): Query<RosterListQuery>,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let domain = q.domain.trim().to_lowercase();
    session_admin_identity(state.as_ref(), &cookies, &q.csrf, &domain)?;
    let tenant = state
        .user_store
        .get_tenant(&domain)?
        .ok_or(BrokerError::TenantNotFound)?;
    let roster: Vec<_> = state
        .user_store
        .list_roster(tenant.id)?
        .into_iter()
        .map(|r| {
            json!({
                "local_part": r.local_part,
                "email": format!("{}@{}", r.local_part, domain),
                "state": r.state,
                "must_change_password": r.must_change_password,
                "created_by": r.created_by,
                "created_at": r.created_at.to_rfc3339(),
                "last_login_at": r.last_login_at.map(|d| d.to_rfc3339()),
            })
        })
        .collect();
    let admins = state.user_store.list_tenant_admins(&domain)?;
    Ok(Json(json!({"success": true, "roster": roster, "admins": admins})))
}

#[derive(Deserialize)]
pub struct RosterStateRequest {
    pub csrf: String,
    pub domain: String,
    pub local_part: String,
    /// "active" | "disabled"
    pub state: String,
}

/// POST /wsapi/tenant/roster/state — enable/disable a roster user.
pub async fn roster_state<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<RosterStateRequest>,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let domain = req.domain.trim().to_lowercase();
    session_admin_identity(state.as_ref(), &cookies, &req.csrf, &domain)?;
    let tenant = state
        .user_store
        .get_tenant(&domain)?
        .ok_or(BrokerError::TenantNotFound)?;
    let new_state = RosterState::parse(&req.state)
        .ok_or_else(|| BrokerError::ValidationError("state must be active or disabled".into()))?;
    let local = req.local_part.trim().to_lowercase();
    if !state.user_store.set_roster_state(tenant.id, &local, new_state)? {
        return Err(BrokerError::UserNotFound);
    }
    Ok(Json(json!({"success": true})))
}

#[derive(Deserialize)]
pub struct RosterPasswordRequest {
    pub csrf: String,
    pub domain: String,
    pub local_part: String,
    pub password: String,
}

/// POST /wsapi/tenant/roster/password — admin reset (must-change back on).
pub async fn roster_password<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<RosterPasswordRequest>,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let domain = req.domain.trim().to_lowercase();
    session_admin_identity(state.as_ref(), &cookies, &req.csrf, &domain)?;
    let tenant = state
        .user_store
        .get_tenant(&domain)?
        .ok_or(BrokerError::TenantNotFound)?;
    if req.password.len() < 8 {
        return Err(BrokerError::PasswordTooShort);
    }
    if req.password.len() > 80 {
        return Err(BrokerError::PasswordTooLong);
    }
    let hash = crate::crypto::hash_password(&req.password)
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
    let local = req.local_part.trim().to_lowercase();
    if !state
        .user_store
        .set_roster_password(tenant.id, &local, &hash, true)?
    {
        return Err(BrokerError::UserNotFound);
    }
    Ok(Json(json!({"success": true})))
}

#[derive(Deserialize)]
pub struct TenantAdminAddRequest {
    pub csrf: String,
    pub domain: String,
    pub identity: String,
}

/// POST /wsapi/tenant/admins — add an admin identity.
pub async fn tenant_admin_add<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<TenantAdminAddRequest>,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let domain = req.domain.trim().to_lowercase();
    let admin = session_admin_identity(state.as_ref(), &cookies, &req.csrf, &domain)?;
    let identity = req.identity.trim().to_lowercase();
    if split_email(&identity).is_none() {
        return Err(BrokerError::InvalidEmail);
    }
    state.user_store.add_tenant_admin(&domain, &identity, &admin)?;
    Ok(Json(json!({"success": true})))
}

#[derive(Deserialize)]
pub struct TenantAdminRemoveRequest {
    pub csrf: String,
    pub domain: String,
    pub identity: String,
}

/// POST /wsapi/tenant/admins/remove — remove an admin identity. Two floors:
/// you cannot remove yourself (any verified identity on your own account),
/// and a tenant can never drop below one admin.
pub async fn tenant_admin_remove<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<TenantAdminRemoveRequest>,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let domain = req.domain.trim().to_lowercase();
    let admin = session_admin_identity(state.as_ref(), &cookies, &req.csrf, &domain)?;
    let identity = req.identity.trim().to_lowercase();
    // "Yourself" = any verified identity on the session's account, not just
    // the one session_admin_identity happened to match.
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    let is_own = state
        .user_store
        .list_emails(session.user_id)?
        .iter()
        .any(|e| e.verified && e.email == identity);
    if is_own {
        return Err(BrokerError::PolicyRefused(
            "you cannot remove yourself as an administrator".into(),
        ));
    }
    let admins = state.user_store.list_tenant_admins(&domain)?;
    if !admins.iter().any(|a| a == &identity) {
        return Err(BrokerError::PolicyRefused("not an administrator of this domain".into()));
    }
    if admins.len() <= 1 {
        return Err(BrokerError::PolicyRefused(
            "a domain must keep at least one administrator".into(),
        ));
    }
    state.user_store.remove_tenant_admin(&domain, &identity)?;
    tracing::info!(tenant = %domain, removed = %identity, by = %admin, "hosted primary: admin removed");
    Ok(Json(json!({"success": true})))
}

#[derive(Deserialize)]
pub struct TenantRevokeAllRequest {
    pub csrf: String,
    pub domain: String,
}

/// POST /wsapi/tenant/revoke_all — the standalone "sign everyone out" lever:
/// revoke every outstanding credential for the domain right now (tenant-list
/// bits + broker-fallback certs), independent of the management policy — it
/// works whether or not managed identities are on. Admin-gated.
pub async fn tenant_revoke_all<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<TenantRevokeAllRequest>,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let domain = req.domain.trim().to_lowercase();
    let admin = session_admin_identity(state.as_ref(), &cookies, &req.csrf, &domain)?;
    let tenant = state
        .user_store
        .get_tenant(&domain)?
        .ok_or(BrokerError::TenantNotFound)?;
    let mut revoked = state.user_store.tenant_status_revoke_all(tenant.id)?;
    revoked += state.user_store.revoke_domain_device_certs(&domain)?;
    tracing::info!(tenant = %domain, by = %admin, revoked,
        "hosted primary: revoked all outstanding credentials");
    Ok(Json(json!({"success": true, "revoked": revoked})))
}

#[derive(Deserialize)]
pub struct TenantDeleteRequest {
    pub csrf: String,
    pub domain: String,
    /// Must equal `domain` — a typed confirmation so a delete can't be a
    /// fat-finger. The console asks the admin to type the domain to confirm.
    pub confirm: String,
}

/// POST /wsapi/tenant/delete — remove a tenant and all its broker-side rows
/// (admins, roster, status), so the domain can be onboarded from scratch. The
/// tenant's certs die once its DNS record is removed or re-onboarded (its key
/// no longer resolves). Admin-gated.
pub async fn tenant_delete<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<TenantDeleteRequest>,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let domain = req.domain.trim().to_lowercase();
    if req.confirm.trim().to_lowercase() != domain {
        return Err(BrokerError::ValidationError(
            "confirmation does not match the domain".into(),
        ));
    }
    let admin = session_admin_identity(state.as_ref(), &cookies, &req.csrf, &domain)?;
    state.user_store.delete_tenant(&domain)?;
    tracing::info!(tenant = %domain, by = %admin, "hosted primary: tenant deleted");
    Ok(Json(json!({"success": true})))
}

// ---------------------------------------------------------------------------
// Managed-identity policy admin (spec §4.7; bean 4vu7).
// GET  /wsapi/tenant/management?domain=&csrf=   → current policy
// POST /wsapi/tenant/management                 → save; enabling revokes the
//   tenant's outstanding certs (everyone re-logs in and comes back with
//   `managed: true` device certs — the marker MUST precede any stamping).
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ManagementQuery {
    pub csrf: String,
    pub domain: String,
}

pub async fn tenant_management_get<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Query(q): Query<ManagementQuery>,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let domain = q.domain.trim().to_lowercase();
    session_admin_identity(state.as_ref(), &cookies, &q.csrf, &domain)?;
    let tenant = state
        .user_store
        .get_tenant(&domain)?
        .ok_or(BrokerError::TenantNotFound)?;
    let m = tenant.management.unwrap_or_default();
    Ok(Json(json!({
        "success": true,
        "management": {
            "enabled": m.enabled,
            "per_audience": m.per_audience,
            "audiences": m.audiences,
            "scopes": m.scopes,
            "max_ttl": m.max_ttl,
            "device_cert_ttl": m.device_cert_ttl,
            "access_cert_ttl": m.access_cert_ttl,
        },
    })))
}

#[derive(Deserialize)]
pub struct ManagementSetRequest {
    pub csrf: String,
    pub domain: String,
    pub enabled: bool,
    /// Revoke every outstanding credential NOW, independent of the
    /// enable-transition (the explicit "sign everyone out" lever — saving an
    /// already-enabled policy deliberately does not re-revoke).
    #[serde(default)]
    pub revoke_now: bool,
    #[serde(default)]
    pub per_audience: bool,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub max_ttl: Option<i64>,
    /// Device-cert validity in seconds (None = default 90 days).
    #[serde(default)]
    pub device_cert_ttl: Option<i64>,
    /// Access-cert validity in seconds (None = `max_ttl`, else default 24h).
    #[serde(default)]
    pub access_cert_ttl: Option<i64>,
}

pub async fn tenant_management_set<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<ManagementSetRequest>,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let domain = req.domain.trim().to_lowercase();
    let admin = session_admin_identity(state.as_ref(), &cookies, &req.csrf, &domain)?;
    let tenant = state
        .user_store
        .get_tenant(&domain)?
        .ok_or(BrokerError::TenantNotFound)?;

    let was_enabled = tenant.management.as_ref().is_some_and(|m| m.enabled);
    // Keep the existing salt across saves (the hashes in outstanding certs
    // stay checkable); generate one the first time.
    let salt = tenant
        .management
        .as_ref()
        .map(|m| m.salt.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(crate::crypto::generate_salt_b64);

    let audiences: Vec<String> = req
        .audiences
        .into_iter()
        .map(|a| a.trim().trim_end_matches('/').to_string())
        .filter(|a| !a.is_empty())
        .collect();
    let policy = crate::store::ManagementPolicy {
        enabled: req.enabled,
        per_audience: req.per_audience,
        audiences,
        scopes: req.scopes.filter(|s| !s.is_empty()),
        max_ttl: req.max_ttl.filter(|t| *t > 0),
        device_cert_ttl: req.device_cert_ttl.filter(|t| *t > 0),
        access_cert_ttl: req.access_cert_ttl.filter(|t| *t > 0),
        salt,
    };
    state.user_store.set_tenant_management(&domain, &policy)?;

    // Enable transition: revoke every outstanding tenant credential so users
    // re-login and come back with MARKED device certs (spec §4.7: the marker
    // precedes any constraint stamping). Also sweep broker-fallback certs for
    // the domain, same as domain activation does.
    let mut revoked = 0;
    if req.revoke_now || (policy.enabled && !was_enabled) {
        revoked = state.user_store.tenant_status_revoke_all(tenant.id)?;
        revoked += state.user_store.revoke_domain_device_certs(&domain)?;
        tracing::info!(tenant = %domain, by = %admin, revoked,
            "management enabled: revoked outstanding certs for re-issue with managed marker");
    } else {
        tracing::info!(tenant = %domain, by = %admin, enabled = policy.enabled,
            "management policy updated");
    }
    Ok(Json(json!({"success": true, "revoked": revoked})))
}
