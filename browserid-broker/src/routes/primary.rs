//! Primary-IdP authentication (device-cert model).
//!
//! A primary identity (e.g. danmills@sandmill.org) is rooted at its own IdP —
//! the broker never issues for it. But the CHOOSER lists the broker account's
//! emails, so a primary login must still join a broker account or it is
//! forgotten between dialogs. This is the device-model successor to the
//! classic `/wsapi/auth_with_assertion`: the dialog presents a 4-object
//! access presentation for the BROKER's own audience; we verify it
//! (DNSSEC-rooted, full conformance) and find/create/link the account
//! exactly as the classic endpoint did (mingo-1c6v / mingo-z8im semantics).

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{DeviceCertRecord, EmailType, SessionStore, UserStore};
use crate::verifier::verify_access_with_dns;

#[derive(Deserialize)]
pub struct AuthWithPresentationRequest {
    /// `access_cert~assertion~warrant~config_cert` for the broker's own origin
    pub presentation: String,
    #[serde(default)]
    pub ephemeral: bool,
}

#[derive(Serialize)]
pub struct AuthWithPresentationResponse {
    pub success: bool,
    pub email: String,
}

/// POST /wsapi/auth_with_presentation
pub async fn auth_with_presentation<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    headers: axum::http::HeaderMap,
    Json(req): Json<AuthWithPresentationRequest>,
) -> Result<Json<AuthWithPresentationResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let fetcher = state
        .fallback_fetcher()
        .await
        .map_err(|e| BrokerError::Internal(format!("DNS discovery not configured: {e}")))?;

    // Verify against the broker's OWN audience. Accepted fallback: just this
    // broker (a login here roots in a primary or this broker's own fallback).
    let audience = browserid_registrar::consent::public_origin(&state.domain);
    let accepted = vec![state.domain.clone()];
    let is_own_revoked =
        |idx: u64| state.user_store.is_status_revoked_idx(idx).map_err(|e| e.to_string());
    let status = crate::verifier::StatusCtx {
        own_uri: browserid_registrar::consent::status_list_uri(&state.domain),
        is_own_revoked: &is_own_revoked,
        cache: &state.foreign_status_lists,
        // Enforce the SSRF guard in production; relax only on localhost dev.
        allow_private_hosts: !crate::routes::session::cookie_secure(&state.domain),
    };
    let result =
        verify_access_with_dns(&req.presentation, &audience, fetcher.as_ref(), &accepted, status)
            .await;

    if result.status != "okay" {
        return Err(BrokerError::InvalidAssertion(
            result.reason.unwrap_or_else(|| "verification failed".to_string()),
        ));
    }
    // The old "user presentations only" gate is removed: `subject: user|agent`
    // was a self-asserted hint, not an enforceable claim (see
    // docs/plans/2026-07-20-holder-authorization-model.md). Any of the user's
    // holders presenting a valid login warrant for this audience authenticates
    // the browser session — they are all "you".
    let email = result
        .email
        .ok_or_else(|| BrokerError::InvalidAssertion("no email in presentation".to_string()))?;
    let issuer = result
        .issuer
        .ok_or_else(|| BrokerError::InvalidAssertion("no issuer in presentation".to_string()))?;

    // Secondary (broker-rooted) emails authenticate with their password — this
    // endpoint exists for identities the broker can't vouch for itself.
    if issuer == state.domain {
        return Err(BrokerError::InvalidAssertion(
            "cannot use auth_with_presentation for broker-rooted emails".to_string(),
        ));
    }

    // If the caller already holds an authenticated session, prefer LINKING the
    // verified email into that existing account rather than minting a separate
    // one — otherwise every primary-IdP email becomes its own orphan account
    // and the chooser only ever surfaces the last one authenticated
    // (mingo-1c6v). All issuers are peer IdPs, so linking a sandmill.org email
    // and a gmail.com email into one account is expected.
    let existing_session =
        super::session::get_session_from_cookies(&cookies, state.session_store.as_ref());

    let user_id = match state.user_store.get_email(&email)? {
        Some(email_record) => {
            state
                .user_store
                .update_email_last_used(&email, EmailType::Primary)?;
            match existing_session.as_ref() {
                // The email lives on a *different* account than the caller's
                // current session → transfer it (the verified presentation IS
                // the proof of ownership — per-email transfer-on-proof merge,
                // Persona semantics, mingo-z8im).
                Some(session) if session.user_id != email_record.user_id => {
                    let former = email_record.user_id;
                    state.user_store.transfer_email(&email, session.user_id)?;
                    // Clean up the former account if it has no emails left.
                    if state.user_store.list_emails(former)?.is_empty() {
                        state.user_store.delete_user(former)?;
                    }
                    session.user_id
                }
                // Same account, or no session → authenticate as the email's owner.
                _ => email_record.user_id,
            }
        }
        None => match existing_session.as_ref() {
            // Logged in + a brand-new email → attach it to the current account.
            Some(session) => {
                state.user_store.add_email_with_type(
                    session.user_id,
                    &email,
                    true,
                    EmailType::Primary,
                )?;
                session.user_id
            }
            // Not logged in → create a fresh account for this email.
            None => {
                let user_id = state.user_store.create_user_no_password()?;
                state
                    .user_store
                    .add_email_with_type(user_id, &email, true, EmailType::Primary)?;
                user_id
            }
        },
    };

    // Reuse the current session when we linked into it; otherwise start a new
    // one (either no prior session, or the email belongs to a different account).
    let reuse = existing_session
        .as_ref()
        .is_some_and(|s| s.user_id == user_id);
    if !reuse {
        // Lightweight: a primary presentation proves the identity (E1), not
        // the broker account password (ca29).
        let session = state
            .session_store
            .create(user_id, crate::store::SessionLevel::Lightweight)?;
        if !req.ephemeral {
            super::session::set_session_cookie(
                &cookies,
                &session.id.0,
                super::session::cookie_secure(&state.domain),
            );
        }
    }

    // (design note §3) Record the primary's config (authorization) device cert
    // in the holder registry so its holder surfaces in the account "Devices &
    // holders" view — the broker keeps a central record of every cert even for
    // identities it does not issue for (the revocation-record goal). Best-effort:
    // a parse/store hiccup must never fail the already-successful login. Only the
    // config cert is present in the presentation (not the auth device cert); its
    // holder is the shared device-slot holder, and recording it reads as
    // `trusted` in the UI. `insert_device_cert` upserts on pubkey, so re-login is
    // idempotent.
    //
    // Cold-first-login prefix adoption: the very first (account-creating) sign-in
    // has no session at cert-issuance time, so the client broker couldn't fetch
    // the account's `browsers` prefix and the IdP self-assigned one. Adopt the
    // cert's prefix as the account's `browsers` namespace while that namespace is
    // still unused, so the holder lands in Browsers instead of orphaning.
    if let Ok(pres) = browserid_core::device::AccessPresentation::parse(&req.presentation) {
        let cc = pres.config_cert.claims();
        // Account-driven namespace move: a stale device presenting its OLD
        // (moved-away, revoked-at-move) holder must not resurrect the old
        // registry row — skip recording; the dialog's holder_assignment check
        // re-issues it. A presentation under the move TARGET completes the
        // move (old rows deleted).
        if let Ok(Some(_)) = state.user_store.resolve_holder_move(user_id, cc.holder.as_str()) {
            tracing::debug!("presented holder was moved; not re-recording the old row");
            return Ok(Json(AuthWithPresentationResponse { success: true, email }));
        }
        super::holders::finish_holder_move(state.user_store.as_ref(), user_id, cc.holder.as_str());
        //
        // When adoption is refused the holder belongs to NO namespace, and an
        // uncategorized holder reads as an agent in the account view. Schedule a
        // move into `browsers` so it is categorized correctly from this moment,
        // whether or not any client-side repair lane survives (browserid-ng-i8a2).
        let mut move_target = None;
        if let Some((prefix, _)) = cc.holder.as_str().split_once('.') {
            match state.user_store.adopt_namespace_prefix(user_id, "browsers", prefix) {
                Ok(false) => {
                    tracing::debug!(
                        "browsers namespace already in use; cert holder keeps its own prefix"
                    );
                    move_target = super::holders::register_orphan_browser_move(
                        state.user_store.as_ref(),
                        user_id,
                        cc.holder.as_str(),
                    );
                }
                Ok(true) => {}
                Err(e) => tracing::warn!("browsers prefix adoption failed: {e}"),
            }
        }
        let rec = DeviceCertRecord {
            id: 0,
            user_id,
            identities: vec![email.clone()],
            purpose: "authorization".to_string(),
            holder: cc.holder.as_str().to_string(),
            pubkey: cc.public_key.to_base64(),
            iss: cc.iss.clone(),
            issued_at: chrono::DateTime::from_timestamp(cc.iat, 0).unwrap_or_else(chrono::Utc::now),
            expires_at: chrono::DateTime::from_timestamp(cc.exp, 0).unwrap_or_else(chrono::Utc::now),
            revoked_at: None,
            status_uri: cc.status.as_ref().map(|s| s.uri.clone()),
            status_idx: cc.status.as_ref().map(|s| s.idx),
        };
        if let Err(e) = state.user_store.insert_device_cert(rec) {
            tracing::warn!("failed to record primary device cert holder: {e}");
        }
        // First sight of this holder → UA-derived default label; best-effort.
        super::holders::maybe_label_holder_from_ua(
            state.user_store.as_ref(), user_id, cc.holder.as_str(), &headers,
        );
        // A scheduled move takes the same label along, so the device keeps its
        // name once it re-issues (completion deletes the old holder's rows).
        if let Some(target) = move_target {
            super::holders::maybe_label_holder_from_ua(
                state.user_store.as_ref(), user_id, &target, &headers,
            );
        }
    }

    Ok(Json(AuthWithPresentationResponse { success: true, email }))
}

#[derive(serde::Deserialize)]
pub struct RecordDeviceCertRequest {
    pub config_cert: String,
}

/// POST /wsapi/record_device_cert — self-healing holder registry (bean pbzn).
/// The dialog fire-and-forgets the config cert after every successful sign-in
/// so the account view converges to observed reality: rows removed or swept
/// while the device kept valid certs re-record on next use, instead of the
/// registry silently diverging from what can actually sign in.
///
/// Sessionless by design; the gate is cryptographic — issuer-conformant
/// signature (key from DNSSEC discovery), validity window, and a FAIL-CLOSED
/// status check at the cert's OWN authority (our list, a hosted tenant's
/// list, or a verified foreign list). A revoked or unverifiable cert records
/// nothing, so this endpoint can never resurrect a revoked credential — it
/// can only assert facts that verify right now.
pub async fn record_device_cert<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<RecordDeviceCertRequest>,
) -> Result<Json<serde_json::Value>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    use browserid_core::device::{DeviceCert, Purpose};
    let refuse = |reason: &str| Ok(Json(serde_json::json!({"success": false, "reason": reason})));

    let cert = DeviceCert::parse(&req.config_cert)
        .map_err(|e| BrokerError::InvalidAssertion(format!("config cert: {e}")))?;
    let cc = cert.claims();
    if cc.purpose != Purpose::Authorization {
        return refuse("only authorization (config) certs are recorded");
    }
    if cert.is_expired() {
        return refuse("cert expired");
    }

    // Whose registry row is this? The first concrete identity with an account
    // here. No account → nothing to record (not an error; the identity may
    // simply never have used this broker).
    let Some((identity, user_id)) = cc
        .identities
        .iter()
        .filter(|i| !i.contains('*'))
        .find_map(|i| {
            state
                .user_store
                .get_email(i)
                .ok()
                .flatten()
                .map(|rec| (i.clone(), rec.user_id))
        })
    else {
        return refuse("no account holds this identity");
    };
    let Some(domain) = identity.split('@').nth(1).map(str::to_string) else {
        return refuse("malformed identity");
    };

    // Issuer-conformant key from DNSSEC discovery; signature must verify.
    let fetcher = state
        .fallback_fetcher()
        .await
        .map_err(|e| BrokerError::Internal(format!("DNS discovery not configured: {e}")))?;
    let accepted = vec![state.domain.clone()];
    let key = crate::verifier::resolve_conformant_key(fetcher.as_ref(), &accepted, &domain, &cc.iss)
        .await
        .map_err(BrokerError::InvalidAssertion)?;
    if cert.verify(&key).is_err() {
        return refuse("signature does not verify under the issuer's key");
    }

    // Status: FAIL-CLOSED at the cert's own authority.
    if let Some(r) = &cc.status {
        let own_uri = browserid_registrar::consent::status_list_uri(&state.domain);
        let idp_status_prefix = format!(
            "{}/status/",
            browserid_registrar::consent::public_origin(&state.idp_host)
        );
        let revoked = if r.uri == own_uri {
            state.user_store.is_status_revoked_idx(r.idx)?
        } else if let Some(tenant) = r
            .uri
            .strip_prefix(&idp_status_prefix)
            .and_then(|d| state.user_store.get_tenant(&d.to_lowercase()).ok().flatten())
        {
            state.user_store.tenant_status_is_revoked(tenant.id, r.idx)?
        } else {
            crate::verifier::check_foreign_status_fresh(
                r,
                fetcher.as_ref(),
                &state.foreign_status_lists,
                !crate::routes::session::cookie_secure(&state.domain),
            )
            .await
            .map_err(|e| BrokerError::InvalidAssertion(format!("status unverifiable: {e}")))?
        };
        if revoked {
            return refuse("cert is revoked");
        }
    }

    // A holder mid-move must not resurrect its old row (same guard as the
    // session-join recording path).
    if let Ok(Some(_)) = state.user_store.resolve_holder_move(user_id, cc.holder.as_str()) {
        return refuse("holder was moved; re-issue pending");
    }

    let rec = crate::store::DeviceCertRecord {
        id: 0,
        user_id,
        identities: cc.identities.clone(),
        purpose: "authorization".into(),
        holder: cc.holder.as_str().to_string(),
        pubkey: cc.public_key.to_base64(),
        iss: cc.iss.clone(),
        issued_at: chrono::DateTime::from_timestamp(cc.iat, 0).unwrap_or_else(chrono::Utc::now),
        expires_at: chrono::DateTime::from_timestamp(cc.exp, 0).unwrap_or_else(chrono::Utc::now),
        revoked_at: None,
        status_uri: cc.status.as_ref().map(|s| s.uri.clone()),
        status_idx: cc.status.as_ref().map(|s| s.idx),
    };
    state.user_store.insert_device_cert(rec)?;
    Ok(Json(serde_json::json!({"success": true})))
}
