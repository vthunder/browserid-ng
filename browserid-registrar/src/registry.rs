//! Provisioning-cert registry management + endorsement signing (tdxf, spec
//! v0.2; unbundled from the broker per 1pnf).
//!
//! - Registry (session + CSRF): registers delegations created in-browser
//!   (`/wsapi/provisioning_certs*`). The registrar holds only public
//!   delegation data; the "API key" (`P_priv`) never reaches it.
//! - Endorser: endorses signed provisioning requests per account policy
//!   (`POST /provision/endorse`). No auth beyond the bundle itself; the
//!   registry is the gate.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use browserid_core::provisioning::{Action, Endorsement, RequestBundle};
use browserid_core::{Certificate, ProvisioningCert};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::error::RegistrarError;
use crate::host::require_csrf;
use crate::RegistrarState;

/// Endorsements and requests are short-lived (spec: ≤10 min)
const ENDORSEMENT_VALIDITY_MINUTES: i64 = 10;

pub(crate) fn require_enabled(state: &RegistrarState) -> Result<(), RegistrarError> {
    if state.enabled {
        Ok(())
    } else {
        Err(RegistrarError::AgentProvisioningDisabled)
    }
}

pub(crate) fn require_session(
    state: &RegistrarState,
    cookies: &Cookies,
) -> Result<crate::host::AuthedUser, RegistrarError> {
    state
        .host
        .resolve_session(cookies)
        .ok_or(RegistrarError::NotAuthenticated)
}

// ===========================================================================
// Browser-side: provisioning-cert registry management (session + CSRF)
// ===========================================================================

#[derive(Serialize)]
pub struct ProvisioningCertInfo {
    pub id: u64,
    pub label: String,
    pub delegator_email: String,
    /// Bound agent identities (`<name>@<domain>`) — legible because they live
    /// in the P_cert constraint the registrar stores, no mint-tracking needed.
    pub names: Vec<String>,
    /// `<prefix>+*` subaddress grants this key may mint under.
    pub patterns: Vec<String>,
    pub domain: String,
    pub created_at: DateTime<Utc>,
    pub last_endorsed_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

/// The `<domain>` an identity delegated by `delegator_email` mints under —
/// the domain of the IdP rooting that identity (the email's domain).
fn idp_domain_of(delegator_email: &str) -> &str {
    delegator_email.split('@').nth(1).unwrap_or("")
}

#[derive(Serialize)]
pub struct ListCertsResponse {
    pub success: bool,
    pub certs: Vec<ProvisioningCertInfo>,
}

/// GET /wsapi/provisioning_certs — list the account's registered agent keys
pub async fn list_provisioning_certs(
    State(state): State<Arc<RegistrarState>>,
    cookies: Cookies,
) -> Result<Json<ListCertsResponse>, RegistrarError> {
    require_enabled(&state)?;
    let user = require_session(&state, &cookies)?;
    let certs = state
        .store
        .list_provisioning_certs(user.user_id)?
        .into_iter()
        .map(|c| {
            // The bound identities live in the stored delegation's P_cert.
            let constraint = c
                .bundle
                .split_once('~')
                .and_then(|(_, p)| ProvisioningCert::parse(p).ok())
                .map(|p| p.constraint().clone())
                .unwrap_or_default();
            ProvisioningCertInfo {
                id: c.id,
                domain: idp_domain_of(&c.delegator_email).to_string(),
                label: c.label,
                delegator_email: c.delegator_email,
                names: constraint.names,
                patterns: constraint.patterns,
                created_at: c.created_at,
                last_endorsed_at: c.last_endorsed_at,
                revoked: c.revoked_at.is_some(),
            }
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
/// key; the registrar checks the delegation is well-formed and that the
/// delegator is a verified email on this account (the human-authorization
/// gate), then stores only public data. `P_priv` is never sent.
pub async fn register_provisioning_cert(
    State(state): State<Arc<RegistrarState>>,
    cookies: Cookies,
    Json(req): Json<RegisterCertRequest>,
) -> Result<Json<RegisterCertResponse>, RegistrarError> {
    require_enabled(&state)?;
    let user = require_session(&state, &cookies)?;
    require_csrf(&user, &req.csrf)?;

    let label = req.label.trim();
    if label.is_empty() || label.len() > 64 {
        return Err(RegistrarError::ValidationError(
            "label must be 1-64 characters".into(),
        ));
    }

    // Parse the U_cert~P_cert bundle and validate the delegation locally.
    let (user_cert_str, p_cert_str) = req
        .bundle
        .split_once('~')
        .ok_or_else(|| RegistrarError::ValidationError("bundle must be U_cert~P_cert".into()))?;
    if p_cert_str.contains('~') {
        return Err(RegistrarError::ValidationError(
            "bundle must be exactly U_cert~P_cert".into(),
        ));
    }
    let user_cert = Certificate::parse(user_cert_str)
        .map_err(|e| RegistrarError::ValidationError(format!("bad user cert: {e}")))?;
    let p_cert = ProvisioningCert::parse(p_cert_str)
        .map_err(|e| RegistrarError::ValidationError(format!("bad provisioning cert: {e}")))?;

    // P_cert must be signed by the identity key U_cert certifies, and name the
    // same email. (We do not re-verify U_cert's issuer signature here — the
    // human authorization is that the delegator is a verified email on this
    // session's account; the target IdP verifies U_cert cryptographically at
    // mint time.)
    p_cert
        .verify(user_cert.public_key())
        .map_err(|e| RegistrarError::ValidationError(format!("provisioning cert not signed by the identity key: {e}")))?;
    if p_cert.is_expired() {
        return Err(RegistrarError::ValidationError("provisioning cert expired".into()));
    }
    // The constraint must be valid (≥1 name/pattern, well-formed patterns) and
    // every requested name must be a valid agent handle.
    p_cert
        .constraint()
        .validate()
        .map_err(|e| RegistrarError::ValidationError(e.to_string()))?;
    for n in &p_cert.constraint().names {
        if !valid_agent_name(n) {
            return Err(RegistrarError::ValidationError(format!("invalid name '{n}' in constraint")));
        }
    }
    let delegator = user_cert
        .email()
        .ok_or_else(|| RegistrarError::ValidationError("user cert has no email".into()))?;
    if p_cert.delegator() != delegator {
        return Err(RegistrarError::ValidationError(
            "provisioning cert delegator does not match the identity cert".into(),
        ));
    }

    // Human-authorization gate: the delegated identity must be a verified email
    // on this account.
    if !state.host.owns_verified_email(user.user_id, delegator)? {
        return Err(RegistrarError::ValidationError(
            "the delegated identity is not a verified email on this account".into(),
        ));
    }

    let rec = state.store.register_provisioning_cert(
        user.user_id,
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
pub async fn revoke_provisioning_cert(
    State(state): State<Arc<RegistrarState>>,
    cookies: Cookies,
    Json(req): Json<RevokeCertRequest>,
) -> Result<Json<SuccessResponse>, RegistrarError> {
    require_enabled(&state)?;
    let user = require_session(&state, &cookies)?;
    require_csrf(&user, &req.csrf)?;
    // Look the cert up first (list is small) so we can also flip status bits
    // for the agent identities it covers — "revoke the key" should mean the
    // agents stop working in minutes, not within a cert TTL.
    let cert_rec = state
        .store
        .list_provisioning_certs(user.user_id)?
        .into_iter()
        .find(|c| c.id == req.id);
    state
        .store
        .revoke_provisioning_cert(user.user_id, req.id)?;
    if let Some(cert_rec) = cert_rec {
        let constraint = cert_rec
            .bundle
            .split_once('~')
            .and_then(|(_, p)| ProvisioningCert::parse(p).ok())
            .map(|p| p.constraint().clone())
            .unwrap_or_default();
        for identity in state.host.agent_identities(user.user_id)? {
            if identity.parent_email.as_deref() != Some(cert_rec.delegator_email.as_str()) {
                continue;
            }
            let local = identity.email.split('@').next().unwrap_or_default();
            if constraint.authorizes(local) {
                state
                    .store
                    .set_status_revoked("identity", &identity.email.to_lowercase())?;
                tracing::info!(email = %identity.email, "status bit set (key revoked)");
            }
        }
    }
    Ok(Json(SuccessResponse { success: true }))
}

// ===========================================================================
// Registrar-as-endorser: POST /provision/endorse
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
/// unrevoked provisioning cert, apply account policy, and return a registrar
/// endorsement bound to exactly this request bundle. No auth beyond the
/// bundle itself; the registry is the gate.
pub async fn endorse(
    State(state): State<Arc<RegistrarState>>,
    Json(req): Json<EndorseRequest>,
) -> Result<Json<EndorseResponse>, RegistrarError> {
    require_enabled(&state)?;

    let bundle = RequestBundle::parse(&req.request_bundle)
        .map_err(|e| RegistrarError::InvalidProvisioningRequest(e.to_string()))?;

    // The request signature (P_priv over R) and P_cert→U_cert delegation must
    // hold. We look the cert up by P_pub in the registry, which recorded the
    // delegation at registration, so we don't need U_cert's issuer key here.
    let p_pub = bundle.provisioning_cert().public_key().to_base64();
    let rec = state
        .store
        .get_provisioning_cert_by_pub(&p_pub)?
        .ok_or(RegistrarError::ProvisioningCertNotFound)?;
    if !rec.is_active() {
        return Err(RegistrarError::PolicyRefused(
            "provisioning certificate revoked".into(),
        ));
    }

    // Verify the request signature + delegation using the registered U_cert
    // pubkey as the chain root would be circular; instead verify the request
    // against P_pub directly and trust the registry for the delegation.
    let request = bundle.request();
    request
        .verify(bundle.provisioning_cert().public_key())
        .map_err(|e| RegistrarError::InvalidProvisioningRequest(format!("bad request signature: {e}")))?;
    if request.is_expired() {
        return Err(RegistrarError::InvalidProvisioningRequest("request expired".into()));
    }

    // The endorsement affirms the request is within policy — so a mint whose
    // name the constraint doesn't authorize is refused here too (defense in
    // depth; the target IdP also checks).
    if request.claims().action == Action::Mint {
        if let Some(name) = &request.claims().name {
            if !bundle.provisioning_cert().constraint().authorizes(name) {
                return Err(RegistrarError::PolicyRefused(format!(
                    "'{name}' is not authorized by this key's constraint"
                )));
            }
        }
    }

    // Account-level policy would live here (rate limits, aggregate sybil
    // signals). The registry membership check above is the v1 gate.

    // Name our own origin as the registrar (agent spec §4.2): the target IdP
    // copies it into the minted cert's `registrar` claim, so the agent knows
    // where to raise consent requests and an RP can pin revocation to it.
    let endorsement = Endorsement::create(
        &state.domain,
        &request.claims().domain,
        &bundle,
        &rec.delegator_email,
        &crate::consent::public_origin(&state.domain),
        Duration::minutes(ENDORSEMENT_VALIDITY_MINUTES),
        &state.keypair,
    )
    .map_err(|e| RegistrarError::Internal(format!("endorsement sign: {e}")))?;

    state.store.touch_provisioning_cert(rec.id)?;

    tracing::info!(delegator = %rec.delegator_email, target = %request.claims().domain, "endorsed provisioning request");
    Ok(Json(EndorseResponse {
        success: true,
        endorsement: endorsement.encoded().to_string(),
    }))
}

/// Agent identity local-part: 1–64 chars of [a-z0-9._+-] (the `+` enables
/// `<handle>+<suffix>` subaddressing), starting alphanumeric.
pub fn valid_agent_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'+' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_name_validation() {
        assert!(valid_agent_name("checkpoint-attestor"));
        assert!(valid_agent_name("a"));
        assert!(valid_agent_name("dan+ci"), "subaddressing allowed");
        assert!(valid_agent_name("svc+1a2b"));
        assert!(!valid_agent_name(""));
        assert!(!valid_agent_name("-x"), "must start alphanumeric");
        assert!(!valid_agent_name("+x"));
        assert!(!valid_agent_name("Ab"), "no uppercase");
        assert!(!valid_agent_name("a b"), "no spaces");
        assert!(!valid_agent_name(&"x".repeat(65)));
    }
}
