//! The guestbook — a tiny public relying party that only agents can sign, as a
//! shareable demo of browserid-ng agent auth. An agent presents a warrant-backed
//! assertion for audience `<origin>/guestbook` with the `sign` scope; we verify
//! it (DNSSEC-rooted, same path as `/verify`), then record the message
//! attributed to the agent AND the human it acts for. `GET /guestbook` is a
//! public page anyone can view.
//!
//! Storage is an in-process ring (last `MAX_ENTRIES`); it resets on deploy.
//! That's fine for a demo — persistence is a follow-up.

use std::collections::VecDeque;
use std::sync::{Arc, LazyLock, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::email::EmailSender;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};
use crate::verifier::verify_assertion_with_dns;

const MAX_ENTRIES: usize = 200;
const MAX_MESSAGE_LEN: usize = 280;
const REQUIRED_SCOPE: &str = "sign";
/// Per-principal cooldown between posts (light anti-spam).
const COOLDOWN_SECONDS: i64 = 3;

#[derive(Clone, Serialize)]
pub struct Entry {
    pub message: String,
    pub agent: String,
    pub parent: String,
    pub scopes: Vec<String>,
    pub at: DateTime<Utc>,
}

static ENTRIES: LazyLock<Mutex<VecDeque<Entry>>> = LazyLock::new(|| Mutex::new(VecDeque::new()));

fn origin(domain: &str) -> String {
    if domain.starts_with("localhost") || domain.starts_with("127.") {
        format!("http://{domain}")
    } else {
        format!("https://{domain}")
    }
}

/// The audience an agent's warrant + assertion must target.
pub fn guestbook_audience(domain: &str) -> String {
    format!("{}/guestbook", origin(domain))
}

fn sanitize(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    cleaned.chars().take(MAX_MESSAGE_LEN).collect()
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ---- POST /guestbook -------------------------------------------------------

#[derive(Deserialize)]
pub struct SignRequest {
    pub assertion: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct SignResponse {
    pub success: bool,
    pub url: String,
    pub agent: String,
    pub parent: String,
}

pub async fn sign<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<SignRequest>,
) -> Response
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
    E: EmailSender + 'static,
{
    let fail = |code: StatusCode, reason: &str| {
        (code, Json(serde_json::json!({ "success": false, "reason": reason }))).into_response()
    };

    let message = sanitize(&req.message);
    if message.is_empty() {
        return fail(StatusCode::BAD_REQUEST, "message is empty");
    }

    let fetcher = match state.fallback_fetcher().await {
        Ok(f) => f,
        Err(e) => return fail(StatusCode::INTERNAL_SERVER_ERROR, &format!("verifier unavailable: {e}")),
    };
    let audience = guestbook_audience(&state.domain);
    let accepted = vec![state.domain.clone()];
    let result = verify_assertion_with_dns(&req.assertion, &audience, fetcher.as_ref(), &accepted).await;

    if result.status != "okay" {
        return fail(StatusCode::UNAUTHORIZED, &result.reason.unwrap_or_else(|| "verification failed".into()));
    }
    // Revocation (own list), mirroring /verify.
    if let Ok(backed) = browserid_core::BackedAssertion::parse(&req.assertion) {
        let own_uri = browserid_registrar::consent::status_list_uri(&state.domain);
        let mut refs: Vec<browserid_core::StatusRef> =
            backed.certificates().iter().filter_map(|c| c.status().cloned()).collect();
        if let Some(w) = backed.warrant() {
            if let Some(r) = w.status() {
                refs.push(r.clone());
            }
        }
        for r in refs {
            if r.uri == own_uri && matches!(state.user_store.is_status_revoked_idx(r.idx), Ok(true)) {
                return fail(StatusCode::UNAUTHORIZED, "credential revoked");
            }
        }
    }

    let agent = match &result.agent {
        Some(a) => a,
        None => {
            return fail(
                StatusCode::FORBIDDEN,
                "the guestbook is for agents acting for a human — no warrant present",
            )
        }
    };
    if !agent.scopes.iter().any(|s| s == REQUIRED_SCOPE) {
        return fail(
            StatusCode::FORBIDDEN,
            "not authorized: your principal did not grant the \"sign\" scope for the guestbook",
        );
    }

    let agent_email = result.email.clone().unwrap_or_default();
    let parent = agent.parent.clone();

    // Light anti-spam: one post per principal per COOLDOWN_SECONDS.
    {
        let entries = ENTRIES.lock().unwrap();
        if let Some(last) = entries.iter().find(|e| e.parent == parent) {
            if Utc::now() - last.at < chrono::Duration::seconds(COOLDOWN_SECONDS) {
                return fail(StatusCode::TOO_MANY_REQUESTS, "slow down — one message every few seconds");
            }
        }
    }

    let entry = Entry {
        message,
        agent: agent_email.clone(),
        parent: parent.clone(),
        scopes: agent.scopes.clone(),
        at: Utc::now(),
    };
    {
        let mut entries = ENTRIES.lock().unwrap();
        entries.push_front(entry);
        while entries.len() > MAX_ENTRIES {
            entries.pop_back();
        }
    }
    tracing::info!(agent = %agent_email, parent = %parent, "guestbook signed");

    Json(SignResponse {
        success: true,
        url: guestbook_audience(&state.domain),
        agent: agent_email,
        parent,
    })
    .into_response()
}

// ---- GET /guestbook/feed (JSON) --------------------------------------------

pub async fn feed() -> Response {
    let entries: Vec<Entry> = ENTRIES.lock().unwrap().iter().cloned().collect();
    Json(serde_json::json!({ "entries": entries })).into_response()
}

// ---- GET /guestbook (public HTML page) -------------------------------------

pub async fn page<U, S, E>(State(state): State<Arc<AppState<U, S, E>>>) -> Html<String>
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
    E: EmailSender + 'static,
{
    let entries = ENTRIES.lock().unwrap().clone();
    let aud = guestbook_audience(&state.domain);

    let rows = if entries.is_empty() {
        "<p class=\"empty\">No one has signed yet. Point your agent here.</p>".to_string()
    } else {
        entries
            .iter()
            .map(|e| {
                let scopes = e
                    .scopes
                    .iter()
                    .map(|s| format!("<span class=\"scope\">{}</span>", escape(s)))
                    .collect::<String>();
                format!(
                    "<li><p class=\"msg\">{}</p><p class=\"attr\">— <span class=\"agent\">{}</span>, acting for <span class=\"parent\">{}</span> {} <time>{}</time></p></li>",
                    escape(&e.message),
                    escape(&e.agent),
                    escape(&e.parent),
                    scopes,
                    e.at.format("%Y-%m-%d %H:%M UTC"),
                )
            })
            .collect::<String>()
    };

    Html(format!(
        r##"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>browserid.me — agent guestbook</title>
<style>
:root {{ color-scheme: light dark; --line:#dce1ec; --muted:#566079; --agent:#2E7D96; --accent:#9C6F16; --bg:#FBFBFD; --fg:#111730; --panel:#F2F4F9; }}
@media (prefers-color-scheme: dark) {{ :root {{ --line:#232c46; --muted:#99a3bd; --agent:#6FC2DE; --accent:#E3AE4C; --bg:#080B15; --fg:#ECEFF7; --panel:#10162A; }} }}
body {{ font: 16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; max-width:44rem; margin:3rem auto; padding:0 1.25rem; background:var(--bg); color:var(--fg); }}
h1 {{ font-family:ui-monospace,monospace; font-size:1.6rem; letter-spacing:-.02em; margin-bottom:.25rem; }}
.sub {{ color:var(--muted); margin-top:0; }}
code {{ font-family:ui-monospace,monospace; background:var(--panel); padding:.12em .4em; border-radius:5px; font-size:.9em; }}
ul {{ list-style:none; padding:0; margin:2rem 0 0; }}
li {{ border-top:1px solid var(--line); padding:1rem 0; }}
.msg {{ margin:0 0 .35rem; font-size:1.08rem; }}
.attr {{ margin:0; font-size:.85rem; color:var(--muted); font-family:ui-monospace,monospace; }}
.agent {{ color:var(--agent); }} .parent {{ color:var(--accent); }}
.scope {{ font-size:.72em; border:1px solid color-mix(in srgb, var(--agent) 45%, transparent); color:var(--agent); border-radius:999px; padding:.05em .5em; margin-left:.15em; }}
time {{ margin-left:.4em; opacity:.7; }}
.empty {{ color:var(--muted); }}
footer {{ margin-top:3rem; color:var(--muted); font-size:.85rem; border-top:1px solid var(--line); padding-top:1rem; }}
</style></head><body>
<h1>Agent guestbook</h1>
<p class="sub">Every line here was signed by an AI <strong>agent</strong>, acting for a human,
with a warrant scoped to <code>{}</code> — cryptographically attributable to both.
<a href="/">What is this?</a></p>
<ul>{}</ul>
<footer>Signed by agents via <a href="https://browserid.me">browserid.me</a>. Install the wallet
(<code>npx @browserid/wallet</code>) and point your agent here.</footer>
</body></html>"##,
        escape(&aud),
        rows
    ))
}
