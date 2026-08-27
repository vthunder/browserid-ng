//! Registrar error type. Mirrors the broker's JSON error shape
//! (`{"success": false, "reason": ...}`) so mounting the registrar in the
//! broker changes nothing on the wire.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistrarError {
    #[error("Not authenticated")]
    NotAuthenticated,

    #[error("Invalid CSRF token")]
    InvalidCsrf,

    #[error("Validation error: {0}")]
    ValidationError(String),

    /// A consent-approval artifact (client-signed warrant / admission record,
    /// config cert, or the claim precondition) failed the validation bar.
    /// Carries the registry-api-v1 §7.1 machine reason so the token lane can
    /// surface it; the cookie lane renders it exactly like a
    /// [`RegistrarError::ValidationError`].
    #[error("Validation error: {message}")]
    WarrantValidation { reason: &'static str, message: String },

    /// A state refusal (registry-api-v1 §7 `conflict`), e.g. revoking a
    /// warrant that has no status ref. 409 on both lanes; the token lane
    /// additionally surfaces the machine reason.
    #[error("Conflict: {message}")]
    Conflict { reason: &'static str, message: String },

    #[error("Internal error: {0}")]
    Internal(String),

    /// Owner-scoped holder miss (registry-api-v1 §5.4): the holder appears on
    /// none of the account's device certs. 404 on the token lane; the cookie
    /// lane renders its legacy "no such holder" refusal.
    #[error("No such holder")]
    HolderNotFound,

    /// Owner-scoped namespace miss (registry-api-v1 §5.4).
    #[error("No such namespace")]
    NamespaceNotFound,

    #[error("Invalid provisioning request: {0}")]
    InvalidProvisioningRequest(String),

    #[error("Provisioning not endorsed: {0}")]
    NotEndorsed(String),

    #[error("Provisioning certificate not found")]
    ProvisioningCertNotFound,

    #[error("Provisioning refused by policy: {0}")]
    PolicyRefused(String),

    #[error("Agent provisioning is not enabled")]
    AgentProvisioningDisabled,

    #[error("Warrant request not found")]
    WarrantRequestNotFound,

    #[error("Polling too fast")]
    PollTooFast,

    #[error("Provision request not found")]
    ProvisionRequestNotFound,

    #[error("Handles already taken: {0:?}")]
    NamesTaken(Vec<String>),

    #[error("Device certificate not found")]
    DeviceCertNotFound,
}

impl IntoResponse for RegistrarError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            RegistrarError::NotAuthenticated => (StatusCode::UNAUTHORIZED, "Not authenticated"),
            RegistrarError::InvalidCsrf => (StatusCode::FORBIDDEN, "Invalid CSRF token"),
            RegistrarError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            RegistrarError::WarrantValidation { message, .. } => {
                (StatusCode::BAD_REQUEST, message.as_str())
            }
            RegistrarError::Conflict { message, .. } => (StatusCode::CONFLICT, message.as_str()),
            RegistrarError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            RegistrarError::InvalidProvisioningRequest(msg) => {
                (StatusCode::BAD_REQUEST, msg.as_str())
            }
            RegistrarError::NotEndorsed(msg) => (StatusCode::UNAUTHORIZED, msg.as_str()),
            RegistrarError::ProvisioningCertNotFound => {
                (StatusCode::NOT_FOUND, "Provisioning certificate not found")
            }
            RegistrarError::PolicyRefused(msg) => (StatusCode::FORBIDDEN, msg.as_str()),
            RegistrarError::AgentProvisioningDisabled => {
                (StatusCode::NOT_FOUND, "Agent provisioning is not enabled")
            }
            RegistrarError::WarrantRequestNotFound => {
                (StatusCode::NOT_FOUND, "Warrant request not found")
            }
            RegistrarError::PollTooFast => (StatusCode::TOO_MANY_REQUESTS, "Polling too fast"),
            RegistrarError::ProvisionRequestNotFound => {
                (StatusCode::NOT_FOUND, "Provision request not found or expired")
            }
            RegistrarError::NamesTaken(names) => {
                return (
                    StatusCode::CONFLICT,
                    axum::Json(json!({
                        "success": false,
                        "error": "names_taken",
                        "reason": format!("already taken: {}", names.join(", ")),
                        "taken": names,
                    })),
                )
                    .into_response();
            }
            RegistrarError::DeviceCertNotFound => {
                (StatusCode::NOT_FOUND, "Device certificate not found")
            }
            RegistrarError::HolderNotFound => (StatusCode::NOT_FOUND, "No such holder"),
            RegistrarError::NamespaceNotFound => (StatusCode::NOT_FOUND, "No such namespace"),
        };

        let body = json!({
            "success": false,
            "reason": message,
        });

        (status, axum::Json(body)).into_response()
    }
}
