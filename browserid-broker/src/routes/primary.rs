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
    let result =
        verify_access_with_dns(&req.presentation, &audience, fetcher.as_ref(), &accepted).await;

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
        let session = state.session_store.create(user_id)?;
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
        if let Some((prefix, _)) = cc.holder.as_str().split_once('.') {
            match state.user_store.adopt_namespace_prefix(user_id, "browsers", prefix) {
                Ok(false) => tracing::debug!(
                    "browsers namespace already in use; cert holder keeps its own prefix"
                ),
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
            status_idx: cc.status.as_ref().map(|s| s.idx),
        };
        if let Err(e) = state.user_store.insert_device_cert(rec) {
            tracing::warn!("failed to record primary device cert holder: {e}");
        }
        // First sight of this holder → UA-derived default label; best-effort.
        super::holders::maybe_label_holder_from_ua(
            state.user_store.as_ref(), user_id, cc.holder.as_str(), &headers,
        );
    }

    Ok(Json(AuthWithPresentationResponse { success: true, email }))
}
