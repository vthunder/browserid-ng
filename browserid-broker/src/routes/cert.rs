//! Certificate issuance endpoint

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use browserid_core::{Certificate, KeyPair, PublicKey, StatusRef};

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
    #[serde(default)]
    pub csrf: String,
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
pub(crate) fn issue_certificate<U: UserStore>(
    domain: &str,
    keypair: &KeyPair,
    user_store: &U,
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

    // Every cert carries a status ref (core §6.4): one stable index per
    // *identity*, so revoking the identity kills all outstanding re-mints at
    // once, within a verifier cache window.
    let status = Some(StatusRef {
        uri: browserid_registrar::consent::status_list_uri(domain),
        idx: user_store
            .get_or_allocate_status("identity", &email_record.email.to_lowercase())?,
    });

    // Agent identities get an agent certificate (spec §5.1): distinct typ +
    // issuer-set `agent.parent` attribution from the account record. Their
    // credentials are only usable with a user-signed warrant (spec §5.3).
    let cert = if email_record.email_type == EmailType::Agent {
        let parent = email_record.parent_email.as_deref().ok_or_else(|| {
            BrokerError::Internal(format!(
                "agent identity {} has no parent_email",
                email_record.email
            ))
        })?;
        // GUARDRAIL (defense in depth): never stamp an agent cert unless its
        // email is a canonical derivation of a VERIFIED email this same account
        // owns. Ownership/verification are already enforced at reservation, but
        // this is the single issuance choke point — so the fallback IdP can
        // never certify an address (e.g. a bare `victim@gmail.com`) that the
        // owner has not proven they control.
        let parent_rec = user_store
            .get_email(parent)?
            .ok_or_else(|| BrokerError::PolicyRefused("agent parent is not a known email".into()))?;
        if parent_rec.user_id != email_record.user_id || !parent_rec.verified {
            return Err(BrokerError::PolicyRefused(
                "agent parent is not a verified email on this account".into(),
            ));
        }
        // The agent email must be `<permitted-name>@<parent's domain>`: same
        // domain as the owner's verified email, and a name the fallback/primary
        // rule allows. So the fallback IdP can never stamp an address (e.g. a
        // bare `victim@gmail.com`) the owner hasn't proven.
        let (a_local, a_domain) = email_record
            .email
            .rsplit_once('@')
            .ok_or_else(|| BrokerError::PolicyRefused("agent email is malformed".into()))?;
        let p_domain = parent.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
        if !a_domain.eq_ignore_ascii_case(p_domain)
            || !browserid_registrar::agent_name_allowed(a_local, parent, domain)
        {
            return Err(BrokerError::PolicyRefused(
                "agent email is not a permitted identity for its owner".into(),
            ));
        }
        // The broker is IdP + registrar in one process, so an agent it mints
        // is registered here: the cert's registrar (spec §5.1) is the broker's
        // own origin, matching the status list its consent flow publishes.
        Certificate::create_agent_with_status(
            domain,
            &email_record.email,
            parent,
            &user_pubkey,
            validity,
            keypair,
            Some(browserid_registrar::consent::public_origin(domain)),
            status,
        )
    } else {
        Certificate::create_with_status(
            domain,
            &email_record.email,
            &user_pubkey,
            validity,
            keypair,
            status,
        )
    }
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
    super::session::require_csrf(&session, &req.csrf)?;

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
        state.user_store.as_ref(),
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

// ---------------------------------------------------------------------------
// POST /wsapi/admin/cert_key  (X-Admin-Token) — demo seeding (mingo-b2yz)
//
// Mint a fallback cert for a DEMO principal without an account, session, or
// email verification. This is impersonation-grade power, so it is caged
// twice: the route only mounts when `BROKER_ADMIN_TOKEN` is set (and the
// header must match), AND the principal must match the hard allowlist in
// `BROKER_ADMIN_MINT_ALLOWLIST` — the broker must never be seen attesting an
// address that could belong to a real third party. No allowlist = mint
// nothing. The cert itself is identical to a /wsapi/cert_key fallback cert
// (24h validity, status-listed, revocable like any identity).
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AdminCertKeyRequest {
    pub email: String,
    pub pubkey: PublicKeyJson,
}

/// Whether `email` is covered by the allowlist: an entry containing `@` must
/// match the full address; a bare-domain entry matches any local part at
/// exactly that domain. Case-insensitive; an empty list matches nothing.
pub(crate) fn admin_mint_allowed(allowlist: &[String], email: &str) -> bool {
    let email = email.to_ascii_lowercase();
    let Some((_, domain)) = email.rsplit_once('@') else {
        return false;
    };
    allowlist.iter().any(|entry| {
        let entry = entry.trim().to_ascii_lowercase();
        if entry.is_empty() {
            false
        } else if entry.contains('@') {
            entry == email
        } else {
            entry == domain
        }
    })
}

pub async fn admin_cert_key<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AdminCertKeyRequest>,
) -> Result<Json<CertKeyResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let expected = state
        .admin_mint_token
        .as_deref()
        .ok_or(BrokerError::NotAuthenticated)?; // unmounted normally; belt & braces
    let presented = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Constant-time-ish compare: length check + full XOR fold, no early exit.
    let token_ok = presented.len() == expected.len()
        && presented
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    if !token_ok {
        return Err(BrokerError::NotAuthenticated);
    }
    if !admin_mint_allowed(&state.admin_mint_allowlist, &req.email) {
        return Err(BrokerError::PolicyRefused(format!(
            "'{}' is not in the admin mint allowlist",
            req.email
        )));
    }
    if req.pubkey.algorithm != "Ed25519" {
        return Err(BrokerError::Internal(format!(
            "Unsupported algorithm: {}",
            req.pubkey.algorithm
        )));
    }
    let user_pubkey = PublicKey::from_base64(&req.pubkey.public_key)
        .map_err(|e| BrokerError::Internal(format!("Invalid public key: {}", e)))?;
    let email = req.email.to_ascii_lowercase();
    // Same status-ref scheme as ordinary issuance: one stable index per
    // identity, so a demo identity is revocable like any other.
    let status = Some(StatusRef {
        uri: browserid_registrar::consent::status_list_uri(&state.domain),
        idx: state
            .user_store
            .get_or_allocate_status("identity", &email)?,
    });
    let cert = Certificate::create_with_status(
        &state.domain,
        &email,
        &user_pubkey,
        Duration::hours(24),
        &state.keypair,
        status,
    )
    .map_err(|e| BrokerError::Internal(format!("Failed to create certificate: {}", e)))?;
    tracing::warn!(email = %email, "admin cert-mint issued (demo seeding)");
    Ok(Json(CertKeyResponse {
        success: true,
        cert: Some(cert.encoded().to_string()),
        reason: None,
    }))
}

#[cfg(test)]
mod admin_mint_tests {
    use super::admin_mint_allowed;

    #[test]
    fn allowlist_semantics() {
        let list = vec!["example.com".to_string(), "vthunder@gmail.com".to_string()];
        // Bare domain matches any local part at exactly that domain.
        assert!(admin_mint_allowed(&list, "petra@example.com"));
        assert!(admin_mint_allowed(&list, "PETRA@EXAMPLE.COM"));
        assert!(!admin_mint_allowed(&list, "petra@sub.example.com"));
        assert!(!admin_mint_allowed(&list, "petra@notexample.com"));
        // Full-address entry matches only that address.
        assert!(admin_mint_allowed(&list, "vthunder@gmail.com"));
        assert!(!admin_mint_allowed(&list, "someone-else@gmail.com"));
        // Junk and empties.
        assert!(!admin_mint_allowed(&list, "no-at-sign"));
        assert!(!admin_mint_allowed(&[], "petra@example.com"));
        assert!(!admin_mint_allowed(&["".to_string()], "petra@example.com"));
    }
}
