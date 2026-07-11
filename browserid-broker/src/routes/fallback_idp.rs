//! Fallback IdP surface (apgv): the broker implements the **primary-IdP
//! interface** (a `.well-known` `authentication`/`provisioning` pair driven by
//! the dialog via `navigator.id.*`), with the only difference from a real
//! primary being that it vouches for emails whose domain it does **not** own —
//! gated by an SMTP challenge instead of DNS authority.
//!
//! Flow, mirroring a primary:
//! - `/provision` (page) runs in the dialog: `beginProvisioning` → `genKeyPair`
//!   (the dialog holds the private key) → `POST /cert_key {email, pubkey}` →
//!   `registerCertificate`. `/cert_key` is gated on a **medium-lived email
//!   cookie** proving control of `email`; absent it, it 401s and the dialog
//!   drops to interactive `/auth`.
//! - `/auth` (page) emails a one-time code; on `POST /auth/verify` we set the
//!   email cookie (reference: 30 days). Certs stay short (24h) and the dialog
//!   silently re-provisions against the cookie until it expires — then the
//!   SMTP dance runs again. No long-lived certs needed.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::Engine;
use browserid_core::{Certificate, PublicKey};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tower_cookies::cookie::SameSite;
use tower_cookies::{Cookie, Cookies};

use crate::email::EmailSender;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};

/// Cookie proving this browser controls a verified email (SMTP-established).
const EMAIL_COOKIE: &str = "fb_email";
/// How long an SMTP-verified email cookie lasts (the re-verify cadence).
const EMAIL_COOKIE_DAYS: i64 = 30;
/// A one-time auth code is valid this long.
const CODE_TTL_MINUTES: i64 = 15;
/// Issued fallback certs are short — the dialog silently refreshes them
/// against the cookie (matching a primary's 24h certs).
const CERT_HOURS: i64 = 24;

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

#[derive(Serialize)]
pub struct OkResponse {
    pub success: bool,
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

    // SameSite=None (+ Secure): the provision page fetches /cert_key from a
    // THIRD-PARTY iframe inside the mediator's dialog, so a Lax cookie would be
    // withheld. (Where the browser blocks third-party cookies entirely, silent
    // provisioning falls back to the top-level /auth flow.)
    let secure = crate::routes::session::cookie_secure(&state.domain);
    let cookie = Cookie::build((EMAIL_COOKIE, issue_email_token(state.as_ref(), &email)))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::None)
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

// --- POST /cert_key { email, pubkey } (primary-style, cookie-gated) ---------

#[derive(Deserialize)]
pub struct FbCertKeyRequest {
    pub email: String,
    pub pubkey: PubkeyJson,
}

#[derive(Deserialize)]
pub struct PubkeyJson {
    pub algorithm: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

pub async fn cert_key<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<FbCertKeyRequest>,
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
    if req.pubkey.algorithm != "Ed25519" {
        return (StatusCode::BAD_REQUEST, Json(json!({"success": false, "reason": "unsupported algorithm"})));
    }
    let pubkey = match PublicKey::from_base64(&req.pubkey.public_key) {
        Ok(k) => k,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"success": false, "reason": format!("bad pubkey: {e}")}))),
    };
    // Issue a short-lived cert with iss = this fallback's domain, principal =
    // the SMTP-verified email (a domain we don't own).
    let cert = match Certificate::create(
        &state.domain,
        &email,
        &pubkey,
        Duration::hours(CERT_HOURS),
        &state.keypair,
    ) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"success": false, "reason": format!("cert: {e}")}))),
    };
    tracing::info!(email = %email, "fallback IdP: issued cert");
    (StatusCode::OK, Json(json!({"success": true, "cert": cert.encoded()})))
}
