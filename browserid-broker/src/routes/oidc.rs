//! The OIDC claim ceremony's two HTTP legs (browserid-ng-qer8): claim a
//! Google-hosted mailbox by signing in with Google instead of a mailed code.
//!
//! `GET /oidc/claim?email=` begins the flow: it gates on the authority
//! hierarchy (no-primary domain, Google-hosted mail), parks the PKCE/nonce
//! state server-side keyed by the single-use `state` token, and 302s to
//! Google. `GET /oidc/callback` finishes it: code exchange (server-side,
//! client secret + PKCE), JWKS/RS256 ID-token verification with the full
//! claim checks (`crate::oidc::verify_id_token`), then the same
//! session-attach match table as `complete_handle_claim` — with proof method
//! `oidc` and `<iss>#<sub>` as the stable proof subject.
//!
//! Browser binding (login-CSRF guard): the claim leg double-submits the
//! `state` token as a short-lived cookie, and the callback requires the
//! cookie to match the query parameter. Without it, an attacker could run
//! the Google leg themselves and hand the resulting callback URL to a
//! victim, attaching an attacker-proven identity to the victim's account —
//! which the attacker could later cold-reclaim, inheriting the victim's
//! session. The cookie proves the flow ends in the browser it began in.
//!
//! The callback never renders an error page: every outcome lands back on
//! the dialog's resume entry (`/dialog/dialog.html?resume=oidc_claim`) with
//! the result in the fragment, so sign-in state is never stranded on a bare
//! broker page. Scope is per-mailbox exactly like SMTP — the SMTP loop
//! stays an equal-strength fallback ceremony for the same domain.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::Redirect;
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::oidc as engine;
use crate::state::AppState;
use crate::store::{EmailType, ProofMethod, SessionStore, UserStore};

/// Double-submit cookie binding the flow to the initiating browser.
const FLOW_COOKIE: &str = "browserid_oidc_flow";
/// Where every callback outcome lands: the dialog's resume entry point.
const RESUME_PATH: &str = "/dialog/dialog.html?resume=oidc_claim";
/// Flow cookie lifetime — matches the server-side flow store TTL.
const FLOW_COOKIE_MAX_AGE_SECONDS: i64 = 600;

/// This broker's own absolute base URL (the OAuth `redirect_uri` must be
/// absolute and must match the Google console registration exactly).
fn base_url(domain: &str) -> String {
    let scheme = if super::session::cookie_secure(domain) { "https" } else { "http" };
    format!("{scheme}://{domain}")
}

pub(crate) fn redirect_uri(domain: &str) -> String {
    format!("{}/oidc/callback", base_url(domain))
}

/// The absolute claim-start URL `address_info` advertises (the dialog
/// appends `?email=`).
pub(crate) fn claim_url(domain: &str) -> String {
    format!("{}/oidc/claim", base_url(domain))
}

/// Percent-encode a value for the resume fragment. Unreserved chars plus
/// `@` (kept for readable emails) pass through.
fn frag_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn resume_ok(email: &str) -> Redirect {
    Redirect::to(&format!("{RESUME_PATH}#email={}&status=ok", frag_encode(email)))
}

fn resume_err(email: &str, reason: &str) -> Redirect {
    Redirect::to(&format!(
        "{RESUME_PATH}#email={}&oidc_error={}",
        frag_encode(email),
        frag_encode(reason)
    ))
}

fn set_flow_cookie(cookies: &Cookies, state_token: &str, secure: bool) {
    use tower_cookies::cookie::SameSite;
    use tower_cookies::Cookie;
    let cookie = Cookie::build((FLOW_COOKIE, state_token.to_string()))
        .path("/oidc")
        .http_only(true)
        .secure(secure)
        // Lax: the cookie must ride the top-level GET back from Google.
        .same_site(SameSite::Lax)
        .max_age(tower_cookies::cookie::time::Duration::seconds(
            FLOW_COOKIE_MAX_AGE_SECONDS,
        ))
        .build();
    cookies.add(cookie);
}

fn clear_flow_cookie(cookies: &Cookies, secure: bool) {
    use tower_cookies::cookie::SameSite;
    use tower_cookies::Cookie;
    let cookie = Cookie::build((FLOW_COOKIE, ""))
        .path("/oidc")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(tower_cookies::cookie::time::Duration::seconds(0))
        .build();
    cookies.add(cookie);
}

#[derive(Deserialize)]
pub struct OidcClaimQuery {
    pub email: String,
}

/// GET /oidc/claim?email= — begin the Google claim ceremony.
pub async fn oidc_claim<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Query(q): Query<OidcClaimQuery>,
) -> Result<Redirect, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let Some(rt) = state.oidc.as_ref() else {
        return Err(BrokerError::ValidationError(
            "Google sign-in is not enabled on this broker".into(),
        ));
    };

    let email = q.email.trim().to_lowercase();
    let (local, domain) = email.split_once('@').ok_or(BrokerError::InvalidEmail)?;
    if local.is_empty()
        || domain.is_empty()
        || !local.chars().all(|c| c.is_ascii_graphic())
        || local.contains('@')
    {
        return Err(BrokerError::InvalidEmail);
    }
    // The exact-equality check runs against the normalized form, so the flow
    // carries it from the start (claiming `d.a.n+x@gmail.com` attaches the
    // canonical `dan@gmail.com`).
    let normalized = engine::normalize_google_email(&email);
    // `+` stays out of attachable local parts (Gmail's normalization already
    // stripped any tag): `<label>+<tag>` is the agent sub-identity form, and
    // a Workspace mailbox literally named with `+` could impersonate one.
    if normalized.split('@').next().unwrap_or("").contains('+') {
        return Err(BrokerError::InvalidEmail);
    }

    // Hierarchy step 1: a primary domain issues for itself — the fallback
    // must not attach identities there, however its mail is hosted.
    // Discovery failure reads as secondary, same as `address_info`.
    if let Ok(fetcher) = state.fallback_fetcher().await {
        if let Ok(d) = fetcher.discover(domain).await {
            if d.is_primary {
                return Err(BrokerError::ValidationError(format!(
                    "{domain} is its own identity provider"
                )));
            }
        }
    }
    // Steps 2–4, plus the Google-hosted-mail check layered on Smtp.
    if !state.authority.google_oidc_domain(domain).await {
        return Err(BrokerError::ValidationError(format!(
            "{domain} does not use Google sign-in"
        )));
    }

    let pkce = engine::Pkce::generate();
    let state_token = engine::random_token();
    let nonce = engine::random_token();
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref());
    rt.flows.begin(
        state_token.clone(),
        nonce.clone(),
        pkce.verifier,
        normalized,
        session.map(|s| s.id.0),
    );
    set_flow_cookie(&cookies, &state_token, super::session::cookie_secure(&state.domain));

    let url = engine::build_auth_url(
        &rt.provider,
        &redirect_uri(&state.domain),
        &email,
        &state_token,
        &nonce,
        &pkce.challenge,
    );
    Ok(Redirect::to(&url))
}

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// GET /oidc/callback — Google's return leg. Always redirects to the dialog
/// resume entry; the fragment carries `status=ok` or `oidc_error=`.
pub async fn oidc_callback<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Query(q): Query<OidcCallbackQuery>,
) -> Redirect
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let secure = super::session::cookie_secure(&state.domain);
    let Some(rt) = state.oidc.as_ref() else {
        return resume_err("", "Google sign-in is not enabled on this broker");
    };
    let Some(state_token) = q.state.as_deref().filter(|s| !s.is_empty()) else {
        tracing::warn!("oidc callback without a state parameter");
        return resume_err("", "the sign-in response was malformed — try again");
    };
    // Single-use: the flow is consumed whatever happens next, so a replayed
    // callback URL is dead on arrival. A miss here is either a >10min-old
    // flow or a DUPLICATE delivery of the redirect (e.g. the user reloading
    // Google's page mid-login replays the response) — the first delivery
    // already won, or nothing did; either way the user just retries.
    let Some(flow) = rt.flows.take(state_token) else {
        tracing::warn!("oidc callback with unknown/expired/already-used state");
        return resume_err("", "the sign-in expired or was already used — try signing in again");
    };
    let email = flow.claimed_email.clone();

    // Browser binding (see module docs): the double-submit cookie must match.
    let bound = cookies.get(FLOW_COOKIE).map(|c| c.value().to_string());
    clear_flow_cookie(&cookies, secure);
    if bound.as_deref() != Some(state_token) {
        tracing::warn!("oidc callback state/cookie mismatch (possible forwarded callback URL)");
        return resume_err(&email, "the sign-in must finish in the browser it started in");
    }

    if let Some(err) = q.error.as_deref().filter(|e| !e.is_empty()) {
        // The user declined at Google (or Google refused) — not an attack.
        let reason = if err == "access_denied" {
            "Google sign-in was cancelled".to_string()
        } else {
            format!("Google sign-in failed ({err})")
        };
        return resume_err(&email, &reason);
    }
    let Some(code) = q.code.as_deref().filter(|c| !c.is_empty()) else {
        return resume_err(&email, "the sign-in response was malformed — try again");
    };

    let id_token = match engine::exchange_code(
        &rt.provider,
        &rt.http,
        code,
        &redirect_uri(&state.domain),
        &flow.code_verifier,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("oidc code exchange failed: {e}");
            return resume_err(&email, "Google sign-in could not be completed — try again");
        }
    };
    let jwks = match rt.jwks.get(&rt.http, &rt.provider.jwks_uri).await {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("oidc JWKS fetch failed: {e}");
            return resume_err(&email, "Google sign-in could not be completed — try again");
        }
    };
    let verified =
        match engine::verify_id_token(&id_token, &jwks, &rt.provider, &flow.nonce, &email) {
            Ok(v) => v,
            Err(engine::OidcError::EmailMismatch { claimed, .. }) => {
                return resume_err(
                    &email,
                    &format!("you signed in to Google as a different account than {claimed}"),
                );
            }
            Err(engine::OidcError::WorkspaceDomainMismatch) => {
                return resume_err(
                    &email,
                    "that Google account does not belong to this domain",
                );
            }
            Err(e) => {
                tracing::warn!("oidc id-token verification failed: {e}");
                return resume_err(&email, "Google sign-in could not be verified — try again");
            }
        };

    if let Err(e) = attach_verified(&state, &cookies, &verified) {
        // The one expected refusal: a password-backed account needs the
        // password confirmed before a Google proof may bind (kts0). The
        // stable reason string is what the dialog's step-up branches on.
        if matches!(e, BrokerError::PasswordRequired) {
            return resume_err(&email, "password required");
        }
        tracing::error!("oidc attach failed for a verified claim: {e}");
        return resume_err(&email, "sign-in could not be completed — try again");
    }
    resume_ok(&verified.email)
}

/// Attach a verified OIDC proof: the same match table as
/// `complete_handle_claim`, with `proof == Oidc` and the provider account id
/// (`<iss>#<sub>`) as the cold-reclaim identity — so a reassigned mailbox
/// (same address, different Google account) moves to a fresh account instead
/// of inheriting the old holder's other identities. No CSRF token here: the
/// state/cookie double-submit already proved the request comes from the
/// browser that began the claim.
fn attach_verified<U, S, E>(
    state: &AppState<U, S, E>,
    cookies: &Cookies,
    verified: &engine::VerifiedOidc,
) -> Result<(), BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let email = &verified.email;
    let session = super::session::get_session_from_cookies(cookies, state.session_store.as_ref());

    let existing = state.user_store.get_email(email)?;
    let user_id = match (&session, &existing) {
        // Adding to the signed-in account (possibly re-proving).
        (Some(s), Some(rec)) if rec.user_id == s.user_id => s.user_id,
        // Signed in, identity lives elsewhere: the prover holds the mailbox
        // *now*, so the identity transfers (Persona per-email semantics). The
        // former holder's certs for the address die with the transfer (hg2j).
        (Some(s), Some(rec)) => {
            state.user_store.revoke_user_certs_for_email(rec.user_id, email)?;
            state.user_store.transfer_email(email, s.user_id)?;
            s.user_id
        }
        (Some(s), None) => {
            state
                .user_store
                .add_email_with_type(s.user_id, email, true, EmailType::Secondary)?;
            s.user_id
        }
        // Cold claim of a known identity (kts0 rework of the reclaim table):
        // - the same Google account that linked it before → sign in (the E2
        //   experience: no password, lightweight session);
        // - a PASSWORD-BACKED account: mailbox proof alone neither signs in
        //   nor re-binds the address (epic shyj / 7ww7 — cold-transferring it
        //   would let an inbox compromise take the identity without the
        //   password, and it orphaned the owner's own upgrade attempt on a
        //   grandfathered Smtp-proven record). Refuse with PasswordRequired;
        //   the dialog confirms the password and re-runs the claim under that
        //   session, which lands in the attach arm above and upgrades the
        //   record. A genuinely new mailbox holder's channel into a
        //   password-backed account stays the reset flow (kgb9);
        // - a passwordless SMTP-proven record: the same mailbox authority
        //   proven by the stronger ceremony — continuity, not a change of
        //   hands. Sign into the owning account (the proof upgrade below
        //   makes it E2) instead of orphaning the account by transferring
        //   its address away;
        // - anything else (an Oidc record under a DIFFERENT Google subject)
        //   is the identifier changing hands: the identity moves to a fresh
        //   account instead of granting the new holder the old one.
        (None, Some(rec)) => {
            let same_subject = rec.proof == ProofMethod::Oidc
                && rec.proof_subject.as_deref() == Some(verified.proof_subject.as_str());
            if same_subject {
                rec.user_id
            } else if state.user_store.has_password(rec.user_id)? {
                return Err(BrokerError::PasswordRequired);
            } else if rec.proof == ProofMethod::Smtp {
                rec.user_id
            } else {
                let fresh = state.user_store.create_user_no_password()?;
                // Change of holder: the old account's certs for the departed
                // address must stop working (hg2j).
                state.user_store.revoke_user_certs_for_email(rec.user_id, email)?;
                state.user_store.transfer_email(email, fresh)?;
                fresh
            }
        }
        // Cold claim of a new identity: fresh (passwordless) account.
        (None, None) => {
            let fresh = state.user_store.create_user_no_password()?;
            state
                .user_store
                .add_email_with_type(fresh, email, true, EmailType::Secondary)?;
            fresh
        }
    };

    // Freshly proven, whatever its history.
    state.user_store.verify_email(email)?;
    state
        .user_store
        .set_email_proof(email, ProofMethod::Oidc, Some(&verified.proof_subject))?;

    // This ceremony IS the live bridge proof the chokepoint demands for an
    // E2 mint (pr3a): grant a single-use redemption at /device/issue with the
    // bridge's TTL decision (default ~1wk; OAuth hints may refine it later).
    state.record_bridge_grant(
        user_id,
        email,
        chrono::Duration::days(crate::state::BRIDGE_DEFAULT_TTL_DAYS),
    );

    // A cold claim ends signed in, like completing an email verification —
    // but only Lightweight: the bridge proof shows no account password.
    if session.is_none() {
        let new_session = state
            .session_store
            .create(user_id, crate::store::SessionLevel::Lightweight)?;
        super::session::set_session_cookie(
            cookies,
            &new_session.id.0,
            super::session::cookie_secure(&state.domain),
        );
    }

    state.analytics.capture(
        "oidc_claim_completed",
        crate::analytics::distinct_id_for_email(email),
        serde_json::json!({ "email_domain": crate::analytics::email_domain(email) }),
    );
    Ok(())
}
