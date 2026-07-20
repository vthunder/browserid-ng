//! Fallback IdP surface (apgv, device-cert model): browserid.me vouches for
//! emails whose domain runs no primary IdP — gated by an SMTP challenge
//! instead of DNS authority.
//!
//! Flow (driven by the same-origin login dialog):
//! - `POST /auth/send {email}` emails a one-time code; `POST /auth/verify
//!   {email, code}` sets a **medium-lived email cookie** (30 days) proving
//!   control of `email`.
//! - `POST /auth/device_cert {email, device_pubkey, config_pubkey}` — gated on
//!   that cookie — batch-issues the two **device certs** for this browser:
//!   a **user** cert (`authentication`, mints access certs at `/access/mint`)
//!   and a **config** cert (`authorization`, signs warrants). iss = this
//!   broker's domain. Until the cookie expires the dialog can silently
//!   re-issue; then the SMTP dance runs again.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::Engine;
use browserid_core::device::{DeviceCert, Purpose, DEVICE_CERT_VALIDITY_DAYS};
use browserid_core::PublicKey;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tower_cookies::cookie::SameSite;
use tower_cookies::{Cookie, Cookies};

use crate::email::EmailSender;
use crate::state::AppState;
use crate::store::{DeviceCertRecord, SessionStore, UserStore};

/// Cookie proving this browser controls a verified email (SMTP-established).
const EMAIL_COOKIE: &str = "fb_email";
/// How long an SMTP-verified email cookie lasts (the re-verify cadence).
const EMAIL_COOKIE_DAYS: i64 = 30;
/// A one-time auth code is valid this long.
const CODE_TTL_MINUTES: i64 = 15;

/// email -> (code, expiry). In-memory: codes are short-lived and this is a
/// single-instance fallback; a restart just re-sends.
static AUTH_CODES: LazyLock<Mutex<HashMap<String, (String, DateTime<Utc>)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// --- rate limiting (o92d) --------------------------------------------------
// `/auth/send` is a public, directly-reachable endpoint, so cap it to prevent
// mailbombing a victim's inbox and burning the mail quota/reputation. The
// email template is fixed (no attacker content), so this is about *volume*.
/// Rolling window for both caps.
const RATE_WINDOW_MINUTES: i64 = 60;
/// Max codes to one recipient address per window.
const MAX_SENDS_PER_EMAIL: usize = 5;
/// Max codes across all recipients per window (protects mail quota/reputation).
const MAX_SENDS_GLOBAL: usize = 300;

/// Wrong-code attempts before a code is burned (anti brute-force on the
/// 6-digit code within its 15-min window).
const MAX_VERIFY_ATTEMPTS: u32 = 5;
/// email -> wrong-attempt count for the current code.
static VERIFY_ATTEMPTS: LazyLock<Mutex<HashMap<String, u32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// email -> send timestamps within the window.
static SEND_LOG: LazyLock<Mutex<HashMap<String, Vec<DateTime<Utc>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// All send timestamps within the window (global cap).
static SEND_LOG_GLOBAL: LazyLock<Mutex<Vec<DateTime<Utc>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// Returns Ok(()) if a send to `email` is within limits and records it, else
/// Err with a reason.
fn check_and_record_send(email: &str) -> Result<(), &'static str> {
    let now = Utc::now();
    let cutoff = now - Duration::minutes(RATE_WINDOW_MINUTES);

    {
        let mut global = SEND_LOG_GLOBAL.lock().unwrap();
        global.retain(|t| *t > cutoff);
        if global.len() >= MAX_SENDS_GLOBAL {
            return Err("service is busy, try again shortly");
        }
        // recorded below only if the per-email check also passes
    }
    {
        let mut per = SEND_LOG.lock().unwrap();
        let entry = per.entry(email.to_string()).or_default();
        entry.retain(|t| *t > cutoff);
        if entry.len() >= MAX_SENDS_PER_EMAIL {
            return Err("too many codes requested for this address; try again later");
        }
        entry.push(now);
    }
    SEND_LOG_GLOBAL.lock().unwrap().push(now);
    Ok(())
}

fn normalize_email(email: &str) -> Option<String> {
    let e = email.trim().to_lowercase();
    let mut parts = e.split('@');
    let (local, domain) = (parts.next()?, parts.next()?);
    if local.is_empty() || domain.is_empty() || parts.next().is_some() || e.contains(char::is_whitespace) {
        return None;
    }
    Some(e)
}

fn gen_code() -> String {
    use rand::Rng;
    format!("{:06}", rand::thread_rng().gen_range(0..1_000_000))
}

// --- signed email cookie (stateless; signed by the broker key) -------------

fn issue_email_token<U, S, E>(state: &AppState<U, S, E>, email: &str) -> String
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let exp = (Utc::now() + Duration::days(EMAIL_COOKIE_DAYS)).timestamp();
    let claims = json!({ "email": email, "exp": exp }).to_string();
    let sig = state.keypair.sign(claims.as_bytes());
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!("{}.{}", b64.encode(claims.as_bytes()), b64.encode(sig))
}

/// The verified email a valid, unexpired `fb_email` cookie authorizes.
fn email_from_cookie<U, S, E>(state: &AppState<U, S, E>, cookies: &Cookies) -> Option<String>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let token = cookies.get(EMAIL_COOKIE)?.value().to_string();
    let (claims_b64, sig_b64) = token.split_once('.')?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let claims = b64.decode(claims_b64).ok()?;
    let sig = b64.decode(sig_b64).ok()?;
    state.keypair.public_key().verify(&claims, &sig).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&claims).ok()?;
    let exp = v.get("exp")?.as_i64()?;
    if Utc::now().timestamp() >= exp {
        return None;
    }
    v.get("email")?.as_str().map(|s| s.to_string())
}

// --- POST /auth/send { email } ---------------------------------------------

#[derive(Deserialize)]
pub struct AuthSendRequest {
    pub email: String,
}

pub async fn auth_send<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<AuthSendRequest>,
) -> (StatusCode, Json<serde_json::Value>)
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let email = match normalize_email(&req.email) {
        Some(e) => e,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"success": false, "reason": "invalid email"}))),
    };
    // Rate limit (o92d): mailbomb / quota-burn protection on this public endpoint.
    if let Err(reason) = check_and_record_send(&email) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"success": false, "reason": reason})));
    }
    let code = gen_code();
    AUTH_CODES.lock().unwrap().insert(
        email.clone(),
        (code.clone(), Utc::now() + Duration::minutes(CODE_TTL_MINUTES)),
    );
    VERIFY_ATTEMPTS.lock().unwrap().remove(&email); // fresh code, fresh attempts
    if let Err(e) = state.email_sender.send_verification(&email, &code) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"success": false, "reason": e})));
    }
    tracing::info!(email = %email, "fallback IdP: sent SMTP auth code");
    (StatusCode::OK, Json(json!({"success": true})))
}

// --- POST /auth/verify { email, code } -> set email cookie -----------------

#[derive(Deserialize)]
pub struct AuthVerifyRequest {
    pub email: String,
    pub code: String,
}

pub async fn auth_verify<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<AuthVerifyRequest>,
) -> (StatusCode, Json<serde_json::Value>)
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let email = match normalize_email(&req.email) {
        Some(e) => e,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"success": false, "reason": "invalid email"}))),
    };
    let ok = {
        let mut codes = AUTH_CODES.lock().unwrap();
        match codes.get(&email) {
            Some((code, exp)) if code == req.code.trim() && Utc::now() < *exp => {
                codes.remove(&email);
                VERIFY_ATTEMPTS.lock().unwrap().remove(&email);
                true
            }
            _ => {
                // Wrong/expired: burn the code after too many tries so the
                // 6-digit space can't be walked within the 15-min window.
                let mut attempts = VERIFY_ATTEMPTS.lock().unwrap();
                let n = attempts.entry(email.clone()).or_insert(0);
                *n += 1;
                if *n >= MAX_VERIFY_ATTEMPTS {
                    codes.remove(&email);
                    attempts.remove(&email);
                }
                false
            }
        }
    };
    if !ok {
        return (StatusCode::UNAUTHORIZED, Json(json!({"success": false, "reason": "wrong or expired code"})));
    }

    // SameSite=Lax: the login dialog is SAME-ORIGIN with this fallback surface
    // (it drives /auth/send → /auth/verify → /auth/device_cert directly), so
    // the old cross-origin-iframe None is no longer needed — and None without
    // Secure is rejected outright by modern browsers on http dev hosts.
    let secure = crate::routes::session::cookie_secure(&state.domain);
    let cookie = Cookie::build((EMAIL_COOKIE, issue_email_token(state.as_ref(), &email)))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(tower_cookies::cookie::time::Duration::days(EMAIL_COOKIE_DAYS))
        .build();
    cookies.add(cookie);
    tracing::info!(email = %email, "fallback IdP: email verified, cookie set");
    (StatusCode::OK, Json(json!({"success": true})))
}

// --- GET /whoami -> which email this browser's cookie authorizes -----------

pub async fn whoami<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Json<serde_json::Value>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    match email_from_cookie(state.as_ref(), &cookies) {
        Some(email) => Json(json!({"authenticated": true, "email": email})),
        None => Json(json!({"authenticated": false})),
    }
}

// --- POST /auth/device_cert { email, device_pubkey, config_pubkey } ---------
// Cookie-gated batch issuance of the two device certs (device-cert model).

#[derive(Deserialize)]
pub struct FbDeviceCertRequest {
    pub email: String,
    /// base64url Ed25519 public key of the (non-extractable) device key.
    pub device_pubkey: String,
    /// base64url Ed25519 public key of the (non-extractable) config key.
    pub config_pubkey: String,
}

pub async fn device_cert<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<FbDeviceCertRequest>,
) -> (StatusCode, Json<serde_json::Value>)
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let email = match normalize_email(&req.email) {
        Some(e) => e,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"success": false, "reason": "invalid email"}))),
    };
    // Gate: the cookie must authorize exactly this email.
    match email_from_cookie(state.as_ref(), &cookies) {
        Some(cookie_email) if cookie_email == email => {}
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"success": false, "reason": "no verified session for this email"})),
            )
        }
    }
    let parse_pub = |s: &str| PublicKey::from_base64(s);
    let (device_pub, config_pub) = match (parse_pub(&req.device_pubkey), parse_pub(&req.config_pubkey)) {
        (Ok(d), Ok(c)) => (d, c),
        (Err(e), _) | (_, Err(e)) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"success": false, "reason": format!("bad pubkey: {e}")})))
        }
    };
    // Per-device status refs so each cert is individually revocable (revoking a
    // device kills the access certs minted from it — B3).
    let status_for = |pubkey: &PublicKey| -> Result<browserid_core::StatusRef, String> {
        let idx = state
            .user_store
            .get_or_allocate_status("device", &pubkey.to_base64())
            .map_err(|e| e.to_string())?;
        Ok(browserid_core::StatusRef {
            uri: browserid_registrar::consent::status_list_uri(&state.domain),
            idx,
        })
    };
    let (device_ref, config_ref) = match (status_for(&device_pub), status_for(&config_pub)) {
        (Ok(d), Ok(c)) => (d, c),
        (Err(e), _) | (_, Err(e)) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"success": false, "reason": format!("status: {e}")})))
        }
    };
    let ttl = Duration::days(DEVICE_CERT_VALIDITY_DAYS);
    // One broker-assigned holder in the user's `browsers` namespace, shared by
    // both certs (holder-authorization model). If a broker account owns this
    // email, the namespace prefix is the stored per-user one (so `<prefix>.*`
    // login warrants reuse across the user's browsers); a cookie-only fallback
    // identity with no account gets a fresh standalone prefix.
    let account = state.user_store.get_user_by_email(&email).ok().flatten();
    let ns_prefix = match &account {
        Some(user) => match state.user_store.get_or_create_namespace(user.id, "browsers") {
            Ok(p) => p,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"success": false, "reason": format!("namespace: {e}")}))),
        },
        None => crate::crypto::generate_namespace_prefix(),
    };
    let holder = match browserid_core::device::Holder::new(crate::crypto::assign_holder_id(&ns_prefix)) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"success": false, "reason": format!("holder: {e}")}))),
    };
    // The config (authorization) cert also covers the email's `+tag`
    // sub-addresses, so it can sign warrants for the user's plus-named agent
    // identities (design doc Stage 3 — e.g. `dan+claude@example.com`). The
    // authentication cert stays exact: only the user's own login.
    let config_identities = match email.split_once('@') {
        Some((local, domain)) => vec![email.clone(), format!("{local}+*@{domain}")],
        None => vec![email.clone()],
    };
    let issue = |pubkey: &PublicKey, purpose: Purpose, identities: Vec<String>, status: browserid_core::StatusRef| {
        DeviceCert::create(
            &state.domain, pubkey, purpose, holder.clone(),
            identities, ttl, &state.keypair, Some(status),
        )
    };
    let (device_cert, config_cert) = match (
        issue(&device_pub, Purpose::Authentication, vec![email.clone()], device_ref.clone()),
        issue(&config_pub, Purpose::Authorization, config_identities, config_ref.clone()),
    ) {
        (Ok(d), Ok(c)) => (d, c),
        (Err(e), _) | (_, Err(e)) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"success": false, "reason": format!("cert: {e}")})))
        }
    };

    // If a broker account owns this (verified) email, persist registry rows so
    // the certs are enumerable + revocable from the account UI. A cookie-only
    // fallback identity with no account still gets working certs (the status
    // refs above exist regardless); there is just no UI listing them yet.
    if let Ok(Some(user)) = state.user_store.get_user_by_email(&email) {
        let now = Utc::now();
        for (pubkey, purpose, status_idx) in [
            (&req.device_pubkey, "authentication", device_ref.idx),
            (&req.config_pubkey, "authorization", config_ref.idx),
        ] {
            let _ = state.user_store.insert_device_cert(DeviceCertRecord {
                id: 0,
                user_id: user.id,
                identities: vec![email.clone()],
                purpose: purpose.to_string(),
                holder: holder.as_str().to_string(),
                pubkey: pubkey.clone(),
                iss: state.domain.clone(),
                issued_at: now,
                expires_at: now + ttl,
                revoked_at: None,
                status_idx: Some(status_idx),
            });
        }
    }

    tracing::info!(email = %email, "fallback IdP: issued device + config certs");
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "device_cert": device_cert.encoded(),
            "config_cert": config_cert.encoded(),
        })),
    )
}
