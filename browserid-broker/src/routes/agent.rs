//! Delegation-chain agent provisioning (tdxf, spec v0.2).
//!
//! The broker plays two roles here, both gated on `agent_provisioning_enabled`:
//!
//! - **Broker/endorser** — registers provisioning certs created in-browser
//!   (`/wsapi/provisioning_certs*`, session + CSRF), and endorses signed
//!   provisioning requests per account policy (`POST /provision/endorse`). The
//!   broker holds only public delegation data; the "API key" (`P_priv`) never
//!   reaches it.
//! - **Target IdP** — for `@<broker-domain>` agent identities (whose parent is
//!   a broker-rooted/fallback identity), verifies the dual-signed request +
//!   endorsement and mints (`POST /provision/{mint,list,revoke}`). This is the
//!   fallback path folded into the primary one: endorser and issuer are the
//!   same party.
//!
//! Agent identities remain ordinary `EmailType::Agent` emails with a
//! `parent_email` attribution root; RPs verify the certs as plain browserid.
//! Revocation is soft: revoke the provisioning cert (broker stops endorsing)
//! or the identity (mints fail), and outstanding certs age out (≤24h).

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use browserid_core::provisioning::{Action, Endorsement, RequestBundle, VerifiedRequest};
use browserid_core::{Certificate, ProvisioningCert};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{EmailType, Session, SessionStore, UserStore};

use super::cert::{issue_certificate, PublicKeyJson};

/// Endorsements and requests are short-lived (spec: ≤10 min)
const ENDORSEMENT_VALIDITY_MINUTES: i64 = 10;

fn require_enabled<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
) -> Result<(), BrokerError> {
    if state.agent_provisioning_enabled {
        Ok(())
    } else {
        Err(BrokerError::AgentProvisioningDisabled)
    }
}

fn require_session<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    cookies: &Cookies,
) -> Result<Session, BrokerError> {
    super::session::get_session_from_cookies(cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)
}

fn agent_pubkey_json(pk: &browserid_core::PublicKey) -> PublicKeyJson {
    PublicKeyJson {
        algorithm: "Ed25519".to_string(),
        public_key: pk.to_base64(),
    }
}

// ===========================================================================
// Browser-side: provisioning-cert registry management (session + CSRF)
// ===========================================================================

#[derive(Serialize)]
pub struct ProvisioningCertInfo {
    pub id: u64,
    pub label: String,
    pub delegator_email: String,
    pub created_at: DateTime<Utc>,
    pub last_endorsed_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

#[derive(Serialize)]
pub struct ListCertsResponse {
    pub success: bool,
    pub certs: Vec<ProvisioningCertInfo>,
}

/// GET /wsapi/provisioning_certs — list the account's registered agent keys
pub async fn list_provisioning_certs<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Result<Json<ListCertsResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    require_enabled(&state)?;
    let session = require_session(&state, &cookies)?;
    let certs = state
        .user_store
        .list_provisioning_certs(session.user_id)?
        .into_iter()
        .map(|c| ProvisioningCertInfo {
            id: c.id,
            label: c.label,
            delegator_email: c.delegator_email,
            created_at: c.created_at,
            last_endorsed_at: c.last_endorsed_at,
            revoked: c.revoked_at.is_some(),
        })
        .collect();
    Ok(Json(ListCertsResponse { success: true, certs }))
}

#[derive(Deserialize)]
pub struct RegisterCertRequest {
    pub csrf: String,
    pub label: String,
    /// The `U_cert~P_cert` delegation bundle the page just built
    pub bundle: String,
}

#[derive(Serialize)]
pub struct RegisterCertResponse {
    pub success: bool,
    pub id: u64,
    pub delegator_email: String,
}

/// POST /wsapi/register_provisioning_cert — validate + register a delegation
/// the browser page just created. The page signs `P_cert` with the identity
/// key; the broker checks the delegation is well-formed and that the delegator
/// is a verified email on this account (the human-authorization gate), then
/// stores only public data. `P_priv` is never sent.
pub async fn register_provisioning_cert<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<RegisterCertRequest>,
) -> Result<Json<RegisterCertResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    require_enabled(&state)?;
    let session = require_session(&state, &cookies)?;
    if session.csrf_token != req.csrf {
        return Err(BrokerError::InvalidCsrf);
    }

    let label = req.label.trim();
    if label.is_empty() || label.len() > 64 {
        return Err(BrokerError::ValidationError(
            "label must be 1-64 characters".into(),
        ));
    }

    // Parse the U_cert~P_cert bundle and validate the delegation locally.
    let (user_cert_str, p_cert_str) = req
        .bundle
        .split_once('~')
        .ok_or_else(|| BrokerError::ValidationError("bundle must be U_cert~P_cert".into()))?;
    if p_cert_str.contains('~') {
        return Err(BrokerError::ValidationError(
            "bundle must be exactly U_cert~P_cert".into(),
        ));
    }
    let user_cert = Certificate::parse(user_cert_str)
        .map_err(|e| BrokerError::ValidationError(format!("bad user cert: {e}")))?;
    let p_cert = ProvisioningCert::parse(p_cert_str)
        .map_err(|e| BrokerError::ValidationError(format!("bad provisioning cert: {e}")))?;

    // P_cert must be signed by the identity key U_cert certifies, and name the
    // same email. (We do not re-verify U_cert's issuer signature here — the
    // human authorization is that the delegator is a verified email on this
    // session's account; the target IdP verifies U_cert cryptographically at
    // mint time.)
    p_cert
        .verify(user_cert.public_key())
        .map_err(|e| BrokerError::ValidationError(format!("provisioning cert not signed by the identity key: {e}")))?;
    if p_cert.is_expired() {
        return Err(BrokerError::ValidationError("provisioning cert expired".into()));
    }
    let delegator = user_cert
        .email()
        .ok_or_else(|| BrokerError::ValidationError("user cert has no email".into()))?;
    if p_cert.delegator() != delegator {
        return Err(BrokerError::ValidationError(
            "provisioning cert delegator does not match the identity cert".into(),
        ));
    }

    // Human-authorization gate: the delegated identity must be a verified email
    // on this account.
    let owns = state
        .user_store
        .list_emails(session.user_id)?
        .iter()
        .any(|e| e.email.eq_ignore_ascii_case(delegator) && e.verified);
    if !owns {
        return Err(BrokerError::ValidationError(
            "the delegated identity is not a verified email on this account".into(),
        ));
    }

    let rec = state.user_store.register_provisioning_cert(
        session.user_id,
        delegator,
        &p_cert.public_key().to_base64(),
        &req.bundle,
        label,
    )?;

    tracing::info!(delegator = %delegator, cert_id = rec.id, "registered provisioning cert");
    Ok(Json(RegisterCertResponse {
        success: true,
        id: rec.id,
        delegator_email: rec.delegator_email,
    }))
}

#[derive(Deserialize)]
pub struct RevokeCertRequest {
    pub csrf: String,
    pub id: u64,
}

#[derive(Serialize)]
pub struct SuccessResponse {
    pub success: bool,
}

/// POST /wsapi/revoke_provisioning_cert
pub async fn revoke_provisioning_cert<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<RevokeCertRequest>,
) -> Result<Json<SuccessResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    require_enabled(&state)?;
    let session = require_session(&state, &cookies)?;
    if session.csrf_token != req.csrf {
        return Err(BrokerError::InvalidCsrf);
    }
    state
        .user_store
        .revoke_provisioning_cert(session.user_id, req.id)?;
    Ok(Json(SuccessResponse { success: true }))
}

// ===========================================================================
// Broker-as-endorser: POST /provision/endorse
// ===========================================================================

#[derive(Deserialize)]
pub struct EndorseRequest {
    pub request_bundle: String,
}

#[derive(Serialize)]
pub struct EndorseResponse {
    pub success: bool,
    pub endorsement: String,
}

/// POST /provision/endorse — verify a signed request against a registered,
/// unrevoked provisioning cert, apply account policy, and return a broker
/// endorsement bound to exactly this request bundle. No auth beyond the bundle
/// itself; the registry is the gate.
pub async fn endorse<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<EndorseRequest>,
) -> Result<Json<EndorseResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    require_enabled(&state)?;

    let bundle = RequestBundle::parse(&req.request_bundle)
        .map_err(|e| BrokerError::InvalidProvisioningRequest(e.to_string()))?;

    // The request signature (P_priv over R) and P_cert→U_cert delegation must
    // hold. We look the cert up by P_pub in the registry, which recorded the
    // delegation at registration, so we don't need U_cert's issuer key here.
    let p_pub = bundle.provisioning_cert().public_key().to_base64();
    let rec = state
        .user_store
        .get_provisioning_cert_by_pub(&p_pub)?
        .ok_or(BrokerError::ProvisioningCertNotFound)?;
    if !rec.is_active() {
        return Err(BrokerError::PolicyRefused(
            "provisioning certificate revoked".into(),
        ));
    }

    // Verify the request signature + delegation using the registered U_cert
    // pubkey as the chain root would be circular; instead verify the request
    // against P_pub directly and trust the registry for the delegation.
    let request = bundle.request();
    request
        .verify(bundle.provisioning_cert().public_key())
        .map_err(|e| BrokerError::InvalidProvisioningRequest(format!("bad request signature: {e}")))?;
    if request.is_expired() {
        return Err(BrokerError::InvalidProvisioningRequest("request expired".into()));
    }

    // Account-level policy would live here (rate limits, aggregate sybil
    // signals). The registry membership check above is the v1 gate.

    let endorsement = Endorsement::create(
        &state.domain,
        &request.claims().domain,
        &bundle,
        &rec.delegator_email,
        Duration::minutes(ENDORSEMENT_VALIDITY_MINUTES),
        &state.keypair,
    )
    .map_err(|e| BrokerError::Internal(format!("endorsement sign: {e}")))?;

    state.user_store.touch_provisioning_cert(rec.id)?;

    tracing::info!(delegator = %rec.delegator_email, target = %request.claims().domain, "endorsed provisioning request");
    Ok(Json(EndorseResponse {
        success: true,
        endorsement: endorsement.encoded().to_string(),
    }))
}

// ===========================================================================
// Broker-as-target-IdP: POST /provision/{mint,list,revoke}
// (for @<broker-domain> agent identities — fallback-rooted parents)
// ===========================================================================

#[derive(Deserialize)]
pub struct ProvisionRequest {
    pub request_bundle: String,
    pub endorsement: String,
}

/// Verify a dual-signed provisioning request as the target IdP: full chain
/// against the broker's own key (we issued the U_cert), plus a fresh
/// broker-signed endorsement bound to this exact bundle. Returns the verified
/// request for the caller to act on.
fn verify_as_target_idp<U: UserStore, S: SessionStore, E: EmailSender>(
    state: &AppState<U, S, E>,
    req: &ProvisionRequest,
    expected_action: Action,
) -> Result<(RequestBundle, VerifiedRequest), BrokerError> {
    let bundle = RequestBundle::parse(&req.request_bundle)
        .map_err(|e| BrokerError::InvalidProvisioningRequest(e.to_string()))?;

    // The broker is the target IdP only for identities it roots. The U_cert
    // issuer must be our domain; then we verify the whole chain with our key.
    let verified = bundle
        .verify(&state.keypair.public_key())
        .map_err(|e| BrokerError::InvalidProvisioningRequest(e.to_string()))?;
    if verified.issuer != state.domain {
        return Err(BrokerError::InvalidProvisioningRequest(format!(
            "identity is rooted at '{}', not this IdP",
            verified.issuer
        )));
    }
    if verified.request.domain != state.domain {
        return Err(BrokerError::InvalidProvisioningRequest(
            "request domain does not target this IdP".into(),
        ));
    }
    if verified.request.action != expected_action {
        return Err(BrokerError::InvalidProvisioningRequest(
            "request action does not match this endpoint".into(),
        ));
    }

    // Endorsement: signed by us (broker == this IdP for its own domain), fresh,
    // bound to this exact bundle.
    let endorsement = Endorsement::parse(&req.endorsement)
        .map_err(|e| BrokerError::NotEndorsed(e.to_string()))?;
    endorsement
        .verify_for(&state.keypair.public_key(), &state.domain, &bundle)
        .map_err(|e| BrokerError::NotEndorsed(e.to_string()))?;

    Ok((bundle, verified))
}

#[derive(Serialize)]
pub struct MintResponse {
    pub success: bool,
    pub email: String,
    pub cert: String,
}

/// POST /provision/mint
pub async fn mint<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<MintResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    require_enabled(&state)?;
    let (_bundle, verified) = verify_as_target_idp(&state, &req, Action::Mint)?;

    let name = verified
        .request
        .name
        .as_deref()
        .ok_or_else(|| BrokerError::InvalidProvisioningRequest("mint requires a name".into()))?;
    if !valid_agent_name(name) {
        return Err(BrokerError::ValidationError(
            "name must be 1-32 chars of [a-z0-9-], not starting/ending with '-'".into(),
        ));
    }
    let agent_pub = verified
        .request
        .agent_key
        .as_ref()
        .ok_or_else(|| BrokerError::InvalidProvisioningRequest("mint requires an agent-key".into()))?;

    // Resolve the account from the delegator (its verified email).
    let delegator = &verified.delegator;
    let account = state
        .user_store
        .get_user_by_email(delegator)?
        .ok_or_else(|| BrokerError::Internal("delegator email has no account".into()))?;

    let email = format!("{}@{}", name, state.domain);
    let record = match state.user_store.get_email(&email)? {
        // Restart / re-mint: same account, active agent identity.
        Some(rec) if rec.user_id == account.id && rec.email_type == EmailType::Agent => {
            if !rec.verified {
                return Err(BrokerError::EmailNotVerified); // revoked; sticks
            }
            rec
        }
        Some(_) => return Err(BrokerError::EmailAlreadyExists),
        None => {
            let active = state
                .user_store
                .list_emails(account.id)?
                .iter()
                .filter(|e| e.email_type == EmailType::Agent && e.verified)
                .count();
            if active >= state.max_agent_identities_per_user {
                return Err(BrokerError::QuotaExceeded);
            }
            state
                .user_store
                .add_email_with_type(account.id, &email, true, EmailType::Agent)?;
            state.user_store.set_parent_email(&email, Some(delegator))?;
            state
                .user_store
                .get_email(&email)?
                .ok_or_else(|| BrokerError::Internal("identity vanished after insert".into()))?
        }
    };

    let ephemeral = verified.request.ephemeral.unwrap_or(false);
    let cert = issue_certificate(
        &state.domain,
        &state.keypair,
        &record,
        &agent_pubkey_json(agent_pub),
        ephemeral,
    )?;

    tracing::info!(email = %record.email, delegator = %delegator, "minted agent identity (delegation chain)");
    Ok(Json(MintResponse {
        success: true,
        email: record.email,
        cert,
    }))
}

#[derive(Serialize)]
pub struct AgentIdentityInfo {
    pub email: String,
    pub parent_email: Option<String>,
    pub active: bool,
    pub verified_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct ListResponse {
    pub success: bool,
    pub identities: Vec<AgentIdentityInfo>,
}

/// POST /provision/list
pub async fn list<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<ListResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    require_enabled(&state)?;
    let (_bundle, verified) = verify_as_target_idp(&state, &req, Action::List)?;

    let account = state
        .user_store
        .get_user_by_email(&verified.delegator)?
        .ok_or_else(|| BrokerError::Internal("delegator email has no account".into()))?;

    let identities = state
        .user_store
        .list_emails(account.id)?
        .into_iter()
        .filter(|e| e.email_type == EmailType::Agent)
        .map(|e| AgentIdentityInfo {
            email: e.email,
            parent_email: e.parent_email,
            active: e.verified,
            verified_at: e.verified_at,
        })
        .collect();

    Ok(Json(ListResponse { success: true, identities }))
}

/// POST /provision/revoke
pub async fn revoke<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<SuccessResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    require_enabled(&state)?;
    let (_bundle, verified) = verify_as_target_idp(&state, &req, Action::Revoke)?;

    let name = verified
        .request
        .name
        .as_deref()
        .ok_or_else(|| BrokerError::InvalidProvisioningRequest("revoke requires a name".into()))?;
    let account = state
        .user_store
        .get_user_by_email(&verified.delegator)?
        .ok_or_else(|| BrokerError::Internal("delegator email has no account".into()))?;
    let email = format!("{}@{}", name, state.domain);
    let record = state
        .user_store
        .get_email(&email)?
        .filter(|e| e.user_id == account.id && e.email_type == EmailType::Agent)
        .ok_or(BrokerError::EmailNotFound)?;

    state.user_store.unverify_email(&record.email)?;
    tracing::info!(email = %record.email, "revoked agent identity (delegation chain)");
    Ok(Json(SuccessResponse { success: true }))
}

/// Agent identity local-part: 1–32 chars of [a-z0-9-], no leading/trailing '-'
fn valid_agent_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_name_validation() {
        assert!(valid_agent_name("checkpoint-attestor"));
        assert!(valid_agent_name("a"));
        assert!(!valid_agent_name(""));
        assert!(!valid_agent_name("-x"));
        assert!(!valid_agent_name("x-"));
        assert!(!valid_agent_name("Ab"));
        assert!(!valid_agent_name("a b"));
        assert!(!valid_agent_name(&"x".repeat(33)));
    }
}
