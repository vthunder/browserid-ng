//! Test-only endpoints for E2E testing
//!
//! These endpoints should only be enabled in development/test environments.
//! They expose internal state that would be a security risk in production.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::email::EmailSender;
use crate::state::{AppState, MockPrimaryIdp};
use crate::store::{SessionStore, UserStore, VerificationType};

#[derive(Debug, Deserialize)]
pub struct GetPendingQuery {
    pub email: String,
    #[serde(rename = "type")]
    pub verification_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GetPendingResponse {
    pub success: bool,
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_type: Option<String>,
}

/// GET /wsapi/test/pending_verification
/// Returns the verification code for an email (for E2E testing)
pub async fn get_pending_verification<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Query(query): Query<GetPendingQuery>,
) -> Json<GetPendingResponse>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let verification_type = match query.verification_type.as_deref() {
        Some("new_account") | None => VerificationType::NewAccount,
        Some("add_email") => VerificationType::AddEmail,
        Some("password_reset") => VerificationType::PasswordReset,
        Some(_) => VerificationType::NewAccount,
    };

    match state
        .user_store
        .get_pending_by_email(&query.email, verification_type.clone())
    {
        Ok(Some(pending)) => Json(GetPendingResponse {
            success: true,
            code: Some(pending.secret),
            email: Some(pending.email),
            verification_type: Some(format!("{:?}", verification_type)),
        }),
        _ => Json(GetPendingResponse {
            success: false,
            code: None,
            email: None,
            verification_type: None,
        }),
    }
}

#[derive(Debug, Deserialize)]
pub struct SetMockPrimaryIdpRequest {
    /// Domain to register as primary IdP (e.g., "test-idp.example")
    pub domain: String,
    /// Base URL where the mock IdP is running (e.g., "http://localhost:4000")
    pub base_url: String,
    /// Authentication path (default: "/browserid/auth")
    #[serde(default = "default_auth_path")]
    pub auth_path: String,
    /// Provisioning path (default: "/browserid/provision")
    #[serde(default = "default_prov_path")]
    pub prov_path: String,
}

fn default_auth_path() -> String {
    "/browserid/auth".to_string()
}

fn default_prov_path() -> String {
    "/browserid/provision".to_string()
}

#[derive(Debug, Serialize)]
pub struct SetMockPrimaryIdpResponse {
    pub success: bool,
}

/// POST /wsapi/test/set_mock_primary_idp
/// Register a domain as a mock primary IdP for testing
pub async fn set_mock_primary_idp<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<SetMockPrimaryIdpRequest>,
) -> Json<SetMockPrimaryIdpResponse>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let config = MockPrimaryIdp {
        auth_path: req.auth_path,
        prov_path: req.prov_path,
        base_url: req.base_url,
    };

    state
        .register_mock_primary_idp(req.domain.clone(), config)
        .await;

    tracing::info!("Registered mock primary IdP for domain: {}", req.domain);

    Json(SetMockPrimaryIdpResponse { success: true })
}

#[derive(Debug, Serialize)]
pub struct ClearMockPrimaryIdpsResponse {
    pub success: bool,
}

/// POST /wsapi/test/clear_mock_primary_idps
/// Clear all mock primary IdP registrations
pub async fn clear_mock_primary_idps<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
) -> Json<ClearMockPrimaryIdpsResponse>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    state.clear_mock_primary_idps().await;
    tracing::info!("Cleared all mock primary IdPs");
    Json(ClearMockPrimaryIdpsResponse { success: true })
}
