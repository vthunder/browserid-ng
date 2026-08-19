//! Completing a handle-identity claim (browserid-ng-tsqk, bean 77mw).
//!
//! The bridge ran the atproto OAuth hop and the bidirectional handle↔DID
//! resolution, and signed an attestation: "DID X holds handle H, verified at
//! T". This route is where the broker — the issuer — consumes it and
//! attaches `<label>@<handle>` to an account as a verified identity with
//! proof method `atproto`. From that point on the identity is an ordinary
//! broker-issued fallback identity: device certs issue from the existing
//! fallback path with `iss = browserid.me`, and the verifier never changes.
//!
//! The scope asymmetry lives here by construction: the attestation proves
//! the *whole domain*, so any label at the proven handle is attachable in
//! one hop — where the SMTP loop only ever verifies the exact mailbox it
//! mailed. What the attestation is NOT: proof of an account. A cold claim
//! of an existing identity signs into the owning account only when the same
//! DID proved it last time; a different DID means the handle changed hands,
//! and the identity moves to a fresh account rather than handing the new
//! holder the old holder's other identities.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use browserid_core::attestation::HandleAttestation;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{EmailType, ProofMethod, SessionStore, UserStore};

#[derive(Deserialize)]
pub struct CompleteHandleClaimRequest {
    /// The identity to attach: `<label>@<handle>`. The domain half must be
    /// exactly the attested handle.
    pub email: String,
    /// The bridge's signed attestation, verbatim.
    pub attestation: String,
    /// Required when the claim runs on an authenticated session (adding an
    /// identity to that account). A cold claim has no session and no CSRF.
    #[serde(default)]
    pub csrf: String,
}

#[derive(Serialize)]
pub struct CompleteHandleClaimResponse {
    pub success: bool,
    /// The normalized identity that was attached.
    pub email: String,
}

/// POST /wsapi/complete_handle_claim
pub async fn complete_handle_claim<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<CompleteHandleClaimRequest>,
) -> Result<Json<CompleteHandleClaimResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Which attestor this deployment trusts is configuration, not content:
    // the bridge is a trusted internal component of the fallback, and only
    // the configured one may vouch for handles.
    let attestor = state
        .handle_attestor
        .clone()
        .ok_or_else(|| BrokerError::ValidationError("handle identities are not enabled".into()))?;

    let attestation = HandleAttestation::parse(&req.attestation)
        .map_err(|e| BrokerError::ValidationError(e.to_string()))?;
    let claims = attestation.claims().clone();
    if claims.iss != attestor {
        return Err(BrokerError::ValidationError(format!(
            "attestations from '{}' are not accepted here",
            claims.iss
        )));
    }

    // The attestor's key is DNSSEC-rooted, same as every issuer key: the
    // bridge domain publishes `_browserid`, so the ordinary primary
    // discovery yields the one key its zone vouches for.
    let key = match &state.handle_attestor_key_override {
        Some(k) => k.clone(),
        None => {
            let fetcher = state
                .fallback_fetcher()
                .await
                .map_err(BrokerError::Internal)?;
            let discovered = fetcher.discover(&claims.iss).await?;
            if !discovered.is_primary {
                return Err(BrokerError::ValidationError(format!(
                    "attestor '{}' has no DNSSEC-published key",
                    claims.iss
                )));
            }
            discovered.document.public_key.ok_or_else(|| {
                BrokerError::Internal(format!("attestor '{}' discovery had no key", claims.iss))
            })?
        }
    };

    attestation
        .verify(&key, &state.domain)
        .map_err(|e| BrokerError::ValidationError(e.to_string()))?;

    // One redemption per attestation. In-memory is enough: the window is
    // minutes, and a restart inside it still leaves signature+expiry+aud
    // standing.
    {
        let now = Utc::now().timestamp();
        let mut used = state.used_attestation_jtis.write().unwrap();
        used.retain(|_, exp| *exp > now);
        if used.insert(claims.jti.clone(), claims.exp).is_some() {
            return Err(BrokerError::ValidationError(
                "attestation already redeemed".into(),
            ));
        }
    }

    // The identity must sit at the proven handle — any label (the proof
    // covers the domain), exactly that domain.
    let email = req.email.trim().to_lowercase();
    let (label, domain) = email.split_once('@').ok_or(BrokerError::InvalidEmail)?;
    if label.is_empty()
        || label.contains(['@', ' ', '+'])
        || !label.chars().all(|c| c.is_ascii_graphic())
    {
        // `+` stays out of labels: `<label>+<tag>` is the agent sub-identity
        // form, and a label containing `+` could impersonate one.
        return Err(BrokerError::InvalidEmail);
    }
    if domain != claims.handle {
        return Err(BrokerError::ValidationError(format!(
            "the attestation proves '{}', not '{}'",
            claims.handle, domain
        )));
    }

    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref());
    if let Some(ref s) = session {
        super::session::require_csrf(s, &req.csrf)?;
    }

    let existing = state.user_store.get_email(&email)?;
    let user_id = match (&session, &existing) {
        // Adding to the signed-in account (possibly re-proving).
        (Some(s), Some(rec)) if rec.user_id == s.user_id => s.user_id,
        // Signed in, identity lives elsewhere: the prover holds the handle
        // *now*, so the identity transfers (Persona per-email semantics).
        (Some(s), Some(_)) => {
            state.user_store.transfer_email(&email, s.user_id)?;
            s.user_id
        }
        (Some(s), None) => {
            state
                .user_store
                .add_email_with_type(s.user_id, &email, true, EmailType::Secondary)?;
            s.user_id
        }
        // Cold claim of a known identity: sign into the owning account only
        // if the same DID proved it before. Anything else — a DID mismatch,
        // or an identity that used to be SMTP-proven — is the identifier
        // changing hands: the identity moves to a fresh account instead of
        // granting the new holder the old account.
        (None, Some(rec)) => {
            if rec.proof == ProofMethod::Atproto
                && rec.proof_subject.as_deref() == Some(claims.did.as_str())
            {
                rec.user_id
            } else {
                let fresh = state.user_store.create_user_no_password()?;
                state.user_store.transfer_email(&email, fresh)?;
                fresh
            }
        }
        // Cold claim of a new identity: fresh (passwordless) account.
        (None, None) => {
            let fresh = state.user_store.create_user_no_password()?;
            state
                .user_store
                .add_email_with_type(fresh, &email, true, EmailType::Secondary)?;
            fresh
        }
    };

    // Freshly proven, whatever its history.
    state.user_store.verify_email(&email)?;
    state
        .user_store
        .set_email_proof(&email, ProofMethod::Atproto, Some(&claims.did))?;

    // This attestation IS the live bridge proof the chokepoint demands for an
    // E2 mint (pr3a): grant a single-use redemption at /device/issue with the
    // bridge's TTL decision (default ~1wk).
    state.record_bridge_grant(
        user_id,
        &email,
        chrono::Duration::days(crate::state::BRIDGE_DEFAULT_TTL_DAYS),
    );

    // A cold claim ends signed in, like completing an email verification —
    // but only Lightweight: the bridge proof shows no account password.
    if session.is_none() {
        let new_session = state
            .session_store
            .create(user_id, crate::store::SessionLevel::Lightweight)?;
        super::session::set_session_cookie(
            &cookies,
            &new_session.id.0,
            super::session::cookie_secure(&state.domain),
        );
    }

    state.analytics.capture(
        "handle_claim_completed",
        crate::analytics::distinct_id_for_email(&email),
        serde_json::json!({ "email_domain": crate::analytics::email_domain(&email) }),
    );

    Ok(Json(CompleteHandleClaimResponse {
        success: true,
        email,
    }))
}
