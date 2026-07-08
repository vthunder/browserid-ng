//! Certificate issuance endpoint

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use browserid_core::{Certificate, KeyPair, PublicKey};

/// Duration for which a verified email can have certificates reissued without re-verification
const VERIFICATION_VALIDITY_DAYS: i64 = 90;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{Email, EmailType, SessionStore, UserStore};

#[derive(Deserialize)]
pub struct CertKeyRequest {
    pub email: String,
    pub pubkey: PublicKeyJson,
    #[serde(default)]
    pub ephemeral: bool,
}

#[derive(Deserialize)]
pub struct PublicKeyJson {
    pub algorithm: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

#[derive(Serialize)]
pub struct CertKeyResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Shared certificate issuance: verified check + re-verification window +
/// pubkey parse + `Certificate::create`. Callers are responsible for
/// authentication and proving the account owns `email_record` — this is the
/// single code path behind both the browser (`/wsapi/cert_key`) and headless
/// agent (`/agent/*`) front doors.
pub(crate) fn issue_certificate(
    domain: &str,
    keypair: &KeyPair,
    email_record: &Email,
    pubkey: &PublicKeyJson,
    ephemeral: bool,
) -> Result<String, BrokerError> {
    if !email_record.verified {
        return Err(BrokerError::EmailNotVerified);
    }

    // The 90-day window bounds staleness of SMTP/primary verification. Agent
    // identities skip it: their standing credential (the API key) is checked
    // live at every mint, so there is no stale proof to bound.
    if email_record.email_type != EmailType::Agent {
        // If verified_at is missing, treat as expired (require re-verification)
        let verified_at = email_record
            .verified_at
            .ok_or(BrokerError::EmailVerificationExpired)?;
        let verification_age = Utc::now() - verified_at;
        if verification_age > Duration::days(VERIFICATION_VALIDITY_DAYS) {
            return Err(BrokerError::EmailVerificationExpired);
        }
    }

    if pubkey.algorithm != "Ed25519" {
        return Err(BrokerError::Internal(format!(
            "Unsupported algorithm: {}",
            pubkey.algorithm
        )));
    }

    let user_pubkey = PublicKey::from_base64(&pubkey.public_key)
        .map_err(|e| BrokerError::Internal(format!("Invalid public key: {}", e)))?;

    // Certificate validity: 24 hours for normal, 1 hour for ephemeral
    // Certificates are short-lived, but can be silently reissued within the window
    let validity = if ephemeral {
        Duration::hours(1)
    } else {
        Duration::hours(24)
    };

    let cert = Certificate::create(domain, &email_record.email, &user_pubkey, validity, keypair)
        .map_err(|e| BrokerError::Internal(format!("Failed to create certificate: {}", e)))?;

    Ok(cert.encoded().to_string())
}

/// POST /wsapi/cert_key
/// Issue a certificate for a verified email
pub async fn cert_key<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<CertKeyRequest>,
) -> Result<Json<CertKeyResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Verify authenticated
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;

    // Verify user owns this email (case-insensitive)
    let normalized_email = req.email.to_lowercase();
    let emails = state.user_store.list_emails(session.user_id)?;
    let email_record = emails
        .iter()
        .find(|e| e.email.to_lowercase() == normalized_email)
        .ok_or(BrokerError::EmailNotFound)?;

    let cert = issue_certificate(
        &state.domain,
        &state.keypair,
        email_record,
        &req.pubkey,
        req.ephemeral,
    )?;

    Ok(Json(CertKeyResponse {
        success: true,
        cert: Some(cert),
        reason: None,
    }))
}
