//! Per-IP rate limiting for the public verification API and the registry
//! API (`/api/v1`).
//!
//! Verification API: fixed 60-second window, 300 requests per client IP —
//! far above any legitimate RP's traffic, so in practice this bounds abuse
//! and gives agents something to self-throttle on: every response carries
//! the RateLimit headers (RateLimit-Limit / RateLimit-Remaining /
//! RateLimit-Reset, per the IETF httpapi ratelimit-headers draft), and an
//! over-limit call gets a structured JSON 429 with Retry-After.
//!
//! Registry API (registry-api-v1 §3, audit 2026-11 D8/W5-9): a blanket
//! per-source bucket on everything under `/api/v1`, a failures-only bucket
//! per source and per account on `login`, and a per-source cap on approval
//! opens — all answered `429 slow_down` + `Retry-After` BEFORE the handler
//! runs, so before any DNSSEC or status fetch. Generous defaults (Q5 (a)).
//!
//! The counters are in-memory and single-instance, matching the app's other
//! throttles (code_guard, login failures).

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Requests allowed per client IP per window. Documented in openapi.json and
/// llms.txt — keep the three in sync.
pub const LIMIT: u32 = 300;

/// Window length.
pub const WINDOW: Duration = Duration::from_secs(60);

struct Window {
    started: Instant,
    count: u32,
}

/// A fixed-window counter keyed by string (client IP, account id, …).
pub struct Limiter {
    windows: LazyLock<Mutex<HashMap<String, Window>>>,
    pub limit: u32,
    pub window: Duration,
}

impl Limiter {
    pub const fn new(limit: u32, window: Duration) -> Self {
        Self { windows: LazyLock::new(|| Mutex::new(HashMap::new())), limit, window }
    }

    /// Count a hit for `key`; returns (allowed, remaining, seconds-to-reset).
    pub fn take(&self, key: &str) -> (bool, u32, u64) {
        let mut map = self.windows.lock().unwrap();
        let now = Instant::now();
        // Opportunistic GC so key churn can't grow the map without bound.
        if map.len() > 10_000 {
            map.retain(|_, w| now.duration_since(w.started) < self.window);
        }
        let w = map.entry(key.to_string()).or_insert(Window { started: now, count: 0 });
        if now.duration_since(w.started) >= self.window {
            w.started = now;
            w.count = 0;
        }
        let reset = self.window.as_secs().saturating_sub(now.duration_since(w.started).as_secs()).max(1);
        if w.count >= self.limit {
            (false, 0, reset)
        } else {
            w.count += 1;
            (true, self.limit - w.count, reset)
        }
    }

    /// Is `key` at the cap? `Some(seconds-to-reset)` when it is. Counts nothing.
    pub fn over(&self, key: &str) -> Option<u64> {
        let map = self.windows.lock().unwrap();
        let w = map.get(key)?;
        let age = Instant::now().duration_since(w.started);
        if age < self.window && w.count >= self.limit {
            Some(self.window.as_secs().saturating_sub(age.as_secs()).max(1))
        } else {
            None
        }
    }

    /// Count one hit for `key` (a failure, say) without asking whether it
    /// is allowed.
    pub fn record(&self, key: &str) {
        let _ = self.take(key);
    }
}

/// The verification API's per-IP bucket.
static VERIFICATION: Limiter = Limiter::new(LIMIT, WINDOW);

fn take(ip: &str) -> (bool, u32, u64) {
    VERIFICATION.take(ip)
}

// ---------------------------------------------------------------------------
// Registry API (/api/v1) buckets
// ---------------------------------------------------------------------------

/// Blanket per-source cap on everything under `/api/v1`: 3000 a minute
/// (50 r/s) is far above any wallet, and bounds the ~20k r/s the audit measured.
pub static API_V1_PER_IP: Limiter = Limiter::new(3000, Duration::from_secs(60));
/// Failed `login` calls per source: a wallet never fails twenty times in
/// five minutes; a token guesser does.
pub static API_V1_LOGIN_FAILURES_PER_IP: Limiter = Limiter::new(20, Duration::from_secs(300));
/// Failed `login` calls per account id, across sources: a distributed
/// guess against one account.
pub static API_V1_LOGIN_FAILURES_PER_ACCOUNT: Limiter = Limiter::new(60, Duration::from_secs(300));
/// Approval opens (`POST /api/v1/approvals`) per source: anyone may open
/// one for any account (W5-9), so one source cannot flood queues.
pub static API_V1_APPROVAL_OPENS_PER_IP: Limiter = Limiter::new(30, Duration::from_secs(60));

/// The registry's `429 slow_down` (registry-api-v1 §3) with `Retry-After`.
fn slow_down(reset: u64) -> Response {
    let body = serde_json::json!({
        "error": "slow_down",
        "error_description": format!("Rate limit exceeded; retry after {reset}s."),
    });
    let mut r = (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
    r.headers_mut().insert("retry-after", HeaderValue::from(reset));
    r
}

/// Middleware for the registrar router: the `/api/v1` buckets above.
/// Other routes on that router pass through untouched. Runs outside the
/// registrar's own body buffering, so the login body is read here (within
/// the same 64 KiB cap) to key the per-account bucket.
pub async fn api_v1(req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if !path.starts_with("/api/v1/") {
        return next.run(req).await;
    }
    let ip = super::auth::client_ip(req.headers());
    let (allowed, _, reset) = API_V1_PER_IP.take(&ip);
    if !allowed {
        return slow_down(reset);
    }
    let is_post = req.method() == Method::POST;
    if is_post && path == "/api/v1/approvals" {
        let (allowed, _, reset) = API_V1_APPROVAL_OPENS_PER_IP.take(&ip);
        if !allowed {
            return slow_down(reset);
        }
    }
    if !(is_post && path == "/api/v1/login") {
        return next.run(req).await;
    }
    if let Some(reset) = API_V1_LOGIN_FAILURES_PER_IP.over(&ip) {
        return slow_down(reset);
    }
    // The account id, for the per-account bucket. Key = the id's hash, so
    // the map never holds account ids in the clear.
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            let body = serde_json::json!({"error": "invalid_request", "error_description": "request body too large"});
            return (StatusCode::BAD_REQUEST, axum::Json(body)).into_response();
        }
    };
    let account_key = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("account")?.as_str().map(|a| browserid_registrar::session::b64url_sha256_pub(a.trim().as_bytes())));
    if let Some(reset) = account_key.as_deref().and_then(|k| API_V1_LOGIN_FAILURES_PER_ACCOUNT.over(k)) {
        return slow_down(reset);
    }
    let resp = next.run(Request::from_parts(parts, Body::from(bytes))).await;
    if !resp.status().is_success() {
        API_V1_LOGIN_FAILURES_PER_IP.record(&ip);
        if let Some(k) = account_key.as_deref() {
            API_V1_LOGIN_FAILURES_PER_ACCOUNT.record(k);
        }
    }
    resp
}

/// Middleware for the verification API router: enforce the limit and stamp
/// the RateLimit headers on every response, 429s included.
pub async fn verification_api(req: Request, next: Next) -> Response {
    let ip = super::auth::client_ip(req.headers());
    let (allowed, remaining, reset) = take(&ip);
    let mut response = if allowed {
        next.run(req).await
    } else {
        let body = serde_json::json!({
            "error": {
                "code": "rate_limited",
                "message": format!(
                    "Rate limit exceeded: {LIMIT} requests per {}s per client IP.",
                    WINDOW.as_secs()
                ),
                "hint": "Wait Retry-After seconds, then self-throttle on the RateLimit-Remaining/RateLimit-Reset headers instead of retry-looping.",
                "docs": "https://browserid.me/openapi.json"
            }
        });
        let mut r = (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
        r.headers_mut().insert("retry-after", HeaderValue::from(reset));
        r
    };
    let headers = response.headers_mut();
    headers.insert("ratelimit-limit", HeaderValue::from(LIMIT));
    headers.insert("ratelimit-remaining", HeaderValue::from(remaining));
    headers.insert("ratelimit-reset", HeaderValue::from(reset));
    response
}
