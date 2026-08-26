//! Per-IP rate limiting for the public verification API.
//!
//! Fixed 60-second window, 300 requests per client IP — far above any
//! legitimate RP's traffic, so in practice this bounds abuse and gives agents
//! something to self-throttle on: every response carries the RateLimit headers
//! (RateLimit-Limit / RateLimit-Remaining / RateLimit-Reset, per the IETF
//! httpapi ratelimit-headers draft), and an over-limit call gets a structured
//! JSON 429 with Retry-After. The counters are in-memory and single-instance,
//! matching the app's other throttles (code_guard, login failures).

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode};
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

/// client IP -> current fixed window.
static WINDOWS: LazyLock<Mutex<HashMap<String, Window>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Count a request for `ip`; returns (allowed, remaining, seconds-to-reset).
fn take(ip: &str) -> (bool, u32, u64) {
    let mut map = WINDOWS.lock().unwrap();
    let now = Instant::now();
    // Opportunistic GC so IP churn can't grow the map without bound.
    if map.len() > 10_000 {
        map.retain(|_, w| now.duration_since(w.started) < WINDOW);
    }
    let w = map.entry(ip.to_string()).or_insert(Window { started: now, count: 0 });
    if now.duration_since(w.started) >= WINDOW {
        w.started = now;
        w.count = 0;
    }
    let reset = WINDOW.as_secs().saturating_sub(now.duration_since(w.started).as_secs()).max(1);
    if w.count >= LIMIT {
        (false, 0, reset)
    } else {
        w.count += 1;
        (true, LIMIT - w.count, reset)
    }
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
