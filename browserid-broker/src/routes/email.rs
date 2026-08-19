//! Email management endpoints

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::crypto::generate_verification_code;
use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{EmailType, PendingVerification, SessionStore, UserStore, VerificationType};

#[derive(Serialize)]
pub struct DerivedIdentity {
    /// A subordinate/derived identity in the caller's account.
    pub email: String,
    /// The parent (controlling) identity it is subordinate to.
    pub parent_email: String,
}

#[derive(Serialize)]
pub struct ListEmailsResponse {
    pub success: bool,
    /// Just the email addresses as strings (for compatibility with original BrowserID protocol)
    pub emails: Vec<String>,
    /// Subordinate/derived identities in this account paired with their controlling
    /// parent (mingo-cm8z). Session-gated own-account only, same privacy scope as
    /// `parent_of`; lets the chooser label derived identities ("signs in via …").
    pub derived: Vec<DerivedIdentity>,
    /// The subset of `emails` that are agent identities (EmailType::Agent) —
    /// derived (cm8z) subordinates are NOT agents, so consumers must not
    /// infer agent-ness from `derived` alone.
    pub agents: Vec<String>,
    /// Per-agent PUBLIC bylines (bean tmk8), for the account edit UI. Only
    /// identities with a name actually set appear; absence = the local-part
    /// fallback applies. Own-account only, like everything here.
    pub public_names: Vec<PublicNameEntry>,
    /// The subset of `emails` whose domain is an ACTIVE hosted tenant with
    /// managed identities enabled, each with its managing domain — the
    /// account page's "managed" indicators. Absence = unmanaged.
    pub managed: Vec<ManagedAddress>,
    /// Whether this account has a password set. Session-gated own-account
    /// info; lets the dialog/account page chain a first-password prompt after
    /// an SMTP add instead of mailing a second code (browserid-ng-iudv).
    pub has_password: bool,
}

#[derive(Serialize)]
pub struct PublicNameEntry {
    pub email: String,
    pub public_name: String,
}

#[derive(Serialize)]
pub struct ManagedAddress {
    /// An account email whose domain runs managed identities here.
    pub email: String,
    /// The managing domain — it can see and limit where the address is used.
    pub domain: String,
}

/// GET /wsapi/list_emails
pub async fn list_emails<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
) -> Result<Json<ListEmailsResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;

    let emails = state.user_store.list_emails(session.user_id)?;

    let derived = emails
        .iter()
        .filter_map(|e| {
            e.parent_email.as_ref().map(|parent| DerivedIdentity {
                email: e.email.clone(),
                parent_email: parent.clone(),
            })
        })
        .collect();

    let agents = emails
        .iter()
        .filter(|e| e.email_type == EmailType::Agent)
        .map(|e| e.email.clone())
        .collect();

    let public_names = emails
        .iter()
        .filter_map(|e| {
            e.public_name.as_ref().map(|n| PublicNameEntry {
                email: e.email.clone(),
                public_name: n.clone(),
            })
        })
        .collect();

    // Managed indicator: an address is managed when its domain is an active
    // hosted tenant with managed identities enabled. One store lookup per
    // distinct domain.
    let mut managed_domains: std::collections::HashMap<String, bool> =
        std::collections::HashMap::new();
    let mut managed = Vec::new();
    for e in &emails {
        let Some((_, domain)) = e.email.rsplit_once('@') else {
            continue;
        };
        let domain = domain.to_lowercase();
        let is_managed = match managed_domains.get(&domain) {
            Some(v) => *v,
            None => {
                let v = state
                    .user_store
                    .get_tenant(&domain)?
                    .is_some_and(|t| {
                        t.status == crate::store::TenantStatus::Active
                            && t.management.as_ref().is_some_and(|m| m.enabled)
                    });
                managed_domains.insert(domain.clone(), v);
                v
            }
        };
        if is_managed {
            managed.push(ManagedAddress { email: e.email.clone(), domain });
        }
    }

    let has_password = state.user_store.has_password(session.user_id)?;

    Ok(Json(ListEmailsResponse {
        success: true,
        emails: emails.into_iter().map(|e| e.email).collect(),
        derived,
        agents,
        public_names,
        managed,
        has_password,
    }))
}

#[derive(Deserialize)]
pub struct ParentOfQuery {
    pub email: String,
}

#[derive(Serialize)]
pub struct ParentOfResponse {
    /// The controlling parent identity, if this email is subordinate. Null otherwise.
    pub parent_email: Option<String>,
}

/// GET /wsapi/parent_of?email= — the parent of a subordinate identity, if any.
/// Session-gated and scoped to the caller's OWN account emails, so a user can
/// only see the parent of their own identities (never a public lookup). Used by
/// the dialog to decide whether to substitute the parent when logging into the
/// identity's issuer (mingo-cm8z).
pub async fn parent_of<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    axum::extract::Query(q): axum::extract::Query<ParentOfQuery>,
) -> Result<Json<ParentOfResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    let email = state
        .user_store
        .get_email(&q.email)?
        .ok_or(BrokerError::EmailNotFound)?;
    if email.user_id != session.user_id {
        return Err(BrokerError::NotAuthenticated);
    }
    Ok(Json(ParentOfResponse { parent_email: email.parent_email }))
}

#[derive(Deserialize)]
pub struct SetPublicNameRequest {
    pub email: String,
    /// The new public byline; empty or absent clears it (services fall back
    /// to the email local-part).
    #[serde(default)]
    pub public_name: Option<String>,
    #[serde(default)]
    pub csrf: String,
}

#[derive(Serialize)]
pub struct SetPublicNameResponse {
    pub success: bool,
    /// The stored value after the update (None = cleared).
    pub public_name: Option<String>,
}

/// POST /wsapi/set_public_name — set or clear an identity's PUBLIC byline
/// (bean tmk8): the name services display next to the identity's actions.
/// Session-gated to the owning account. Distinct from the internal
/// display_name/holder label, which are never published; this field is the
/// only human-editable name that is.
pub async fn set_public_name<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<SetPublicNameRequest>,
) -> Result<Json<SetPublicNameResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;

    let rec = state
        .user_store
        .get_email(&req.email)?
        .ok_or(BrokerError::EmailNotFound)?;
    if rec.user_id != session.user_id {
        return Err(BrokerError::NotAuthenticated);
    }

    let name: Option<String> = req
        .public_name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(|n| n.chars().take(64).collect());
    state
        .user_store
        .set_email_public_name(&req.email, name.as_deref())?;

    Ok(Json(SetPublicNameResponse { success: true, public_name: name }))
}

#[derive(Deserialize)]
pub struct SetParentRequest {
    pub email: String,
    pub parent_email: String,
    #[serde(default)]
    pub csrf: String,
}

#[derive(Serialize)]
pub struct SetParentResponse {
    pub success: bool,
}

/// POST /wsapi/set_parent — record that `email` is a subordinate/derived identity
/// controlled by `parent_email` (mingo-cm8z). Session-gated: BOTH emails must
/// belong to the caller's account, so a caller can only relate their own
/// identities. The mapping is private account metadata — readable only by the
/// owning session (via `parent_of` / `list_emails`), never by another account,
/// an unauthenticated caller, or in a cert/assertion sent to an RP.
pub async fn set_parent<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<SetParentRequest>,
) -> Result<Json<SetParentResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;

    if req.email.eq_ignore_ascii_case(&req.parent_email) {
        return Err(BrokerError::ValidationError(
            "an identity cannot be its own parent".to_string(),
        ));
    }

    // Both the child and parent must belong to the authenticated account.
    let child = state
        .user_store
        .get_email(&req.email)?
        .ok_or(BrokerError::EmailNotFound)?;
    let parent = state
        .user_store
        .get_email(&req.parent_email)?
        .ok_or(BrokerError::EmailNotFound)?;
    if child.user_id != session.user_id || parent.user_id != session.user_id {
        return Err(BrokerError::NotAuthenticated);
    }

    state
        .user_store
        .set_parent_email(&req.email, Some(&req.parent_email))?;

    Ok(Json(SetParentResponse { success: true }))
}

/// Gate on the claim-time authority hierarchy (browserid-ng-tsqk): a
/// verification code may only be mailed to a domain whose authority IS the
/// mailbox. A resolved atproto handle domain is proven at the bridge — a
/// mailbox there is not the owner — and a domain with no MX cannot prove
/// anything by mail. Every route that stages an outbound
/// verification/reset email must pass here first.
pub(crate) async fn require_smtp_authority<U, S, E>(
    state: &AppState<U, S, E>,
    email: &str,
) -> Result<(), BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let domain = email
        .rsplit('@')
        .next()
        .filter(|d| !d.is_empty() && *d != email)
        .ok_or(BrokerError::InvalidEmail)?
        .to_ascii_lowercase();
    match state.authority.no_primary_authority(&domain).await {
        crate::authority::SecondaryAuthority::Smtp => Ok(()),
        crate::authority::SecondaryAuthority::Atproto { .. } => {
            Err(BrokerError::DomainProvenByAtproto(domain))
        }
        crate::authority::SecondaryAuthority::Unprovable => {
            Err(BrokerError::DomainUnprovable(domain))
        }
    }
}

#[derive(Deserialize)]
pub struct StageEmailRequest {
    pub email: String,
    #[serde(default)]
    pub csrf: String,
}

#[derive(Serialize)]
pub struct StageEmailResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/stage_email
pub async fn stage_email<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<StageEmailRequest>,
) -> Result<Json<StageEmailResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;

    // Check if email already exists
    if state.user_store.get_user_by_email(&req.email)?.is_some() {
        return Err(BrokerError::EmailAlreadyExists);
    }

    // The SMTP loop only proves ownership where the mailbox is the
    // authority (browserid-ng-tsqk).
    require_smtp_authority(&state, &req.email).await?;

    // One verification email per address per cooldown.
    if let Err(secs) = state.throttle_email(&req.email, "add_email").await {
        return Err(BrokerError::EmailRateLimited(secs));
    }

    // Generate verification code
    let code = generate_verification_code();

    // Store pending verification
    let pending = PendingVerification {
        secret: code.clone(),
        email: req.email.clone(),
        user_id: Some(session.user_id),
        password_hash: None,
        verification_type: VerificationType::AddEmail,
        created_at: Utc::now(),
    };
    state.user_store.create_pending(pending)?;

    // Send verification email
    state
        .email_sender
        .send_verification(&req.email, &code)
        .map_err(|e| BrokerError::Internal(e))?;

    Ok(Json(StageEmailResponse {
        success: true,
        reason: None,
    }))
}

#[derive(Deserialize)]
pub struct CompleteEmailRequest {
    /// Target email the code was issued to — binds the guess to one pending
    /// record so the code space can't be walked globally (audit C1).
    pub email: String,
    pub token: String,
    #[serde(default)]
    pub csrf: String,
}

#[derive(Serialize)]
pub struct CompleteEmailResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/complete_email_addition
pub async fn complete_email_addition<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<CompleteEmailRequest>,
) -> Result<Json<CompleteEmailResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    // Session-mutating endpoint → require the CSRF token like every other one
    // (audit L7). The account page's `post()` helper already sends it.
    super::session::require_csrf(&session, &req.csrf)?;

    // Look up the pending record by its target email and verify the code with
    // the brute-force guard (binds the guess to one record, burns after N wrong
    // tries). Expiry is enforced inside the guard.
    let pending = super::code_guard::verify_pending_code(
        state.user_store.as_ref(),
        &req.email,
        VerificationType::AddEmail,
        &req.token,
    )?;

    // Verify this is for the current user
    if pending.user_id != Some(session.user_id) {
        return Err(BrokerError::InvalidVerificationCode);
    }

    // Add email to user
    state
        .user_store
        .add_email(session.user_id, &pending.email, true)?;

    // Clean up
    state.user_store.delete_pending(&pending.secret)?;

    // Funnel: an additional email was verified and added to an existing account.
    state.analytics.capture(
        "email_verified",
        crate::analytics::distinct_id_for_email(&pending.email),
        serde_json::json!({ "email_domain": crate::analytics::email_domain(&pending.email) }),
    );

    Ok(Json(CompleteEmailResponse {
        success: true,
        reason: None,
    }))
}

#[derive(Deserialize)]
pub struct RemoveEmailRequest {
    pub email: String,
    #[serde(default)]
    pub csrf: String,
}

#[derive(Serialize)]
pub struct RemoveEmailResponse {
    pub success: bool,
}

/// POST /wsapi/remove_email
pub async fn remove_email<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<RemoveEmailRequest>,
) -> Result<Json<RemoveEmailResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let session = super::session::get_session_from_cookies(&cookies, state.session_store.as_ref())
        .ok_or(BrokerError::NotAuthenticated)?;
    super::session::require_csrf(&session, &req.csrf)?;

    // Ensure user has at least one other email
    let emails = state.user_store.list_emails(session.user_id)?;
    if emails.len() <= 1 {
        return Err(BrokerError::Internal(
            "Cannot remove last email".to_string(),
        ));
    }

    state.user_store.remove_email(session.user_id, &req.email)?;

    Ok(Json(RemoveEmailResponse { success: true }))
}

#[derive(Deserialize)]
pub struct AddressInfoQuery {
    pub email: String,
}

#[derive(Serialize)]
pub struct AddressInfoResponse {
    /// Type of identity provider ("primary" or "secondary")
    #[serde(rename = "type")]
    pub addr_type: String,
    /// State of the email ("known", "unknown", "transition_to_primary", etc.)
    pub state: String,
    /// The issuing domain
    pub issuer: String,
    /// Whether this domain is disabled
    pub disabled: bool,
    /// Normalized form of the email
    #[serde(rename = "normalizedEmail")]
    pub normalized_email: String,
    /// Authentication URL (primary IdP only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// Provisioning URL (primary IdP only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prov: Option<String>,
    /// Device-authorization page URL (primary IdP, device-cert model): the
    /// dialog opens this in a popup to obtain the user+config device certs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_auth: Option<String>,
    /// Headless access-cert mint URL (primary IdP, device-cert model).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_mint: Option<String>,
    /// Agent-mode device-authorization URL (primary IdP): where the approval
    /// page has NAMED-agent certs signed. Absent on a primary = named agents
    /// unsupported there (secondary identities are registrar-signed and always
    /// support them).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_device_auth: Option<String>,
    /// Secondary (no-primary) domains only: which proof the fallback demands
    /// before issuing for this domain — `"smtp"` (the email verification
    /// loop), `"oidc"` (Google-hosted mail; ownership is proven by signing
    /// in with Google, with the SMTP loop as an equal-strength fallback
    /// ceremony), `"atproto"` (the domain is a resolved handle binding;
    /// ownership is proven via atproto OAuth at the bridge), or `"none"` (no
    /// proof method; claims are refused). The claim-time authority
    /// hierarchy, browserid-ng-tsqk; the OIDC ceremony, browserid-ng-qer8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// Where the proof happens when it is a navigation: the bridge's claim
    /// page (`proof == "atproto"`) or this broker's `/oidc/claim` endpoint
    /// (`proof == "oidc"`; the dialog appends `?email=`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
}

/// Determine state based on password_known, last_used_as, current_type
fn compute_state(
    password_known: bool,
    last_used_as: Option<EmailType>,
    current_type: EmailType,
) -> &'static str {
    match (password_known, last_used_as, current_type) {
        // User has password
        (true, Some(EmailType::Primary), EmailType::Primary) => "known",
        (true, Some(EmailType::Primary), EmailType::Secondary) => "transition_to_secondary",
        (true, Some(EmailType::Secondary), EmailType::Primary) => "transition_to_primary",
        (true, Some(EmailType::Secondary), EmailType::Secondary) => "known",

        // User has no password
        (false, Some(EmailType::Primary), EmailType::Primary) => "known",
        (false, Some(EmailType::Primary), EmailType::Secondary) => "transition_no_password",
        (false, Some(EmailType::Secondary), EmailType::Primary) => "transition_to_primary",
        (false, Some(EmailType::Secondary), EmailType::Secondary) => "transition_no_password",

        // Agent identities (l8lw) are broker-issued and never transition
        (_, Some(EmailType::Agent), _) => "known",
        (_, Some(_), EmailType::Agent) => "known",

        // Email not in database
        (_, None, _) => "unknown",
    }
}

/// GET /wsapi/address_info
/// Get information about an email address
pub async fn address_info<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Query(query): Query<AddressInfoQuery>,
) -> Result<Json<AddressInfoResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Normalize email (lowercase)
    let normalized = query.email.to_lowercase();

    // Extract domain from email
    let domain = normalized
        .split('@')
        .nth(1)
        .ok_or(BrokerError::InvalidEmail)?;

    // Check mock primary IdP registry first (for testing)
    let mock_idp = state.get_mock_primary_idp(domain).await;

    // Determine type and URLs based on mock or DNS discovery
    let mut device_auth = None;
    let mut access_mint = None;
    let mut agent_device_auth = None;
    let (addr_type, current_type, auth, prov, issuer) = if let Some(mock) = mock_idp {
        // Mock primary IdP configured for testing
        tracing::debug!("Using mock primary IdP for domain: {}", domain);
        let auth_url = Some(format!("{}{}", mock.base_url, mock.auth_path));
        let prov_url = Some(format!("{}{}", mock.base_url, mock.prov_path));
        // Device-model endpoints follow the same base (tests may serve them).
        device_auth = Some(format!("{}/device-authorize", mock.base_url));
        access_mint = Some(format!("{}/access/mint", mock.base_url));
        (
            "primary",
            EmailType::Primary,
            auth_url,
            prov_url,
            domain.to_string(),
        )
    } else {
        // Use DNS discovery to determine if domain is a primary IdP
        let discovery = match state.fallback_fetcher().await {
            Ok(fetcher) => match fetcher.discover(domain).await {
                Ok(result) => Some(result),
                Err(e) => {
                    tracing::warn!("DNS discovery failed for {}: {}", domain, e);
                    None
                }
            },
            Err(e) => {
                tracing::debug!("DNS fetcher not available: {}", e);
                None
            }
        };

        if let Some(ref result) = discovery {
            if result.is_primary {
                // Primary IdP - use domain as issuer. Support-doc paths are
                // served from the DNS record's `host=` when set (a hosted
                // primary's pages live on its provider, bean g5qt), else from
                // the domain itself.
                let base = result.serving_host.as_deref().unwrap_or(domain);
                let auth_url = result
                    .document
                    .authentication
                    .as_ref()
                    .map(|path| format!("https://{}{}", base, path));
                let prov_url = result
                    .document
                    .provisioning
                    .as_ref()
                    .map(|path| format!("https://{}{}", base, path));
                // Device-cert model endpoints from the discovery document.
                device_auth = result
                    .document
                    .device_authorization
                    .as_ref()
                    .map(|path| format!("https://{}{}", base, path));
                access_mint = result
                    .document
                    .access_cert
                    .as_ref()
                    .map(|path| format!("https://{}{}", base, path));
                agent_device_auth = result
                    .document
                    .agent_device_authorization
                    .as_ref()
                    .map(|path| format!("https://{}{}", base, path));
                (
                    "primary",
                    EmailType::Primary,
                    auth_url,
                    prov_url,
                    domain.to_string(),
                )
            } else {
                // Secondary (fallback to broker)
                ("secondary", EmailType::Secondary, None, None, state.domain.clone())
            }
        } else {
            // No discovery available - treat as secondary
            ("secondary", EmailType::Secondary, None, None, state.domain.clone())
        }
    };

    // For a no-primary domain, report which proof the hierarchy demands so
    // the dialog can route the claim (SMTP loop vs. the bridge's atproto
    // hop) without re-deriving the decision client-side.
    let (proof, claim) = if addr_type == "secondary" {
        match state.authority.no_primary_authority(domain).await {
            crate::authority::SecondaryAuthority::Atproto { .. } => {
                (Some("atproto".to_string()), state.authority.claim_url())
            }
            crate::authority::SecondaryAuthority::Smtp => {
                // Google-hosted mail upgrades the *ceremony* (sign in with
                // Google instead of a mailed code, browserid-ng-qer8) — the
                // authority is still the mailbox, and the SMTP loop stays
                // available as the escape hatch.
                if state.oidc.is_some() && state.authority.google_oidc_domain(domain).await {
                    (
                        Some("oidc".to_string()),
                        Some(super::oidc::claim_url(&state.domain)),
                    )
                } else {
                    (Some("smtp".to_string()), None)
                }
            }
            crate::authority::SecondaryAuthority::Unprovable => (Some("none".to_string()), None),
        }
    } else {
        (None, None)
    };

    // Look up email in database
    let email_record = state.user_store.get_email(&normalized)?;

    let email_state = if let Some(ref email) = email_record {
        // Email exists - compute state based on password and type history
        let password_known = state.user_store.has_password(email.user_id)?;
        compute_state(password_known, Some(email.last_used_as), current_type)
    } else {
        // Email not in database
        "unknown"
    };

    Ok(Json(AddressInfoResponse {
        addr_type: addr_type.to_string(),
        state: email_state.to_string(),
        issuer,
        disabled: false,
        normalized_email: normalized,
        auth,
        prov,
        device_auth,
        access_mint,
        agent_device_auth,
        proof,
        claim,
    }))
}

#[derive(Deserialize)]
pub struct EmailAdditionStatusQuery {
    pub email: String,
}

#[derive(Serialize)]
pub struct EmailAdditionStatusResponse {
    pub status: String,
}

/// GET /wsapi/email_addition_status
/// Check the status of a pending email addition
pub async fn email_addition_status<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Query(query): Query<EmailAdditionStatusQuery>,
) -> Json<EmailAdditionStatusResponse>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Check if email already exists (complete)
    if state
        .user_store
        .get_user_by_email(&query.email)
        .ok()
        .flatten()
        .is_some()
    {
        // Check if user has this email verified
        if let Ok(Some(user)) = state.user_store.get_user_by_email(&query.email) {
            if let Ok(emails) = state.user_store.list_emails(user.id) {
                if emails.iter().any(|e| e.email == query.email && e.verified) {
                    return Json(EmailAdditionStatusResponse {
                        status: "complete".to_string(),
                    });
                }
            }
        }
    }

    // Check for pending email addition
    if state
        .user_store
        .get_pending_by_email(&query.email, VerificationType::AddEmail)
        .ok()
        .flatten()
        .is_some()
    {
        return Json(EmailAdditionStatusResponse {
            status: "pending".to_string(),
        });
    }

    // No pending and not complete = failed
    Json(EmailAdditionStatusResponse {
        status: "failed".to_string(),
    })
}
