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

    #[error("Internal error: {0}")]
    Internal(String),

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
        };

        let body = json!({
            "success": false,
            "reason": message,
        });

        (status, axum::Json(body)).into_response()
    }
}
