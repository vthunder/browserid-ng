//! Test-only endpoints for E2E testing
//!
//! These endpoints should only be enabled in development/test environments.
//! They expose internal state that would be a security risk in production.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::email::EmailSender;
use crate::state::AppState;
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
