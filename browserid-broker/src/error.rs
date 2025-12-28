//! Broker error types

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("User not found")]
    UserNotFound,

    #[error("Email not found")]
    EmailNotFound,

    #[error("Email already exists")]
    EmailAlreadyExists,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Invalid verification code")]
    InvalidVerificationCode,

    #[error("Verification code expired")]
    VerificationExpired,

    #[error("Not authenticated")]
    NotAuthenticated,

    #[error("Invalid CSRF token")]
    InvalidCsrf,

    #[error("Email not verified")]
    EmailNotVerified,

    #[error("Email verification expired (re-verification required)")]
    EmailVerificationExpired,

    #[error("Password too short (minimum 8 characters)")]
    PasswordTooShort,

    #[error("Password too long (maximum 80 characters)")]
    PasswordTooLong,

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("DNSSEC validation failed for domain {domain}")]
    DnssecValidationFailed { domain: String },

    #[error("Discovery failed: {0}")]
    Discovery(String),
}

impl IntoResponse for BrokerError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            BrokerError::UserNotFound => (StatusCode::NOT_FOUND, "User not found"),
            BrokerError::EmailNotFound => (StatusCode::NOT_FOUND, "Email not found"),
            BrokerError::EmailAlreadyExists => (StatusCode::CONFLICT, "Email already exists"),
            BrokerError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials"),
            BrokerError::InvalidVerificationCode => {
                (StatusCode::BAD_REQUEST, "Invalid verification code")
            }
            BrokerError::VerificationExpired => {
                (StatusCode::BAD_REQUEST, "Verification code expired")
            }
            BrokerError::NotAuthenticated => (StatusCode::UNAUTHORIZED, "Not authenticated"),
            BrokerError::InvalidCsrf => (StatusCode::FORBIDDEN, "Invalid CSRF token"),
            BrokerError::EmailNotVerified => (StatusCode::FORBIDDEN, "Email not verified"),
            BrokerError::EmailVerificationExpired => {
                (StatusCode::FORBIDDEN, "Email verification expired (re-verification required)")
            }
            BrokerError::PasswordTooShort => {
                (StatusCode::BAD_REQUEST, "Password too short (minimum 8 characters)")
            }
            BrokerError::PasswordTooLong => {
                (StatusCode::BAD_REQUEST, "Password too long (maximum 80 characters)")
            }
            BrokerError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            BrokerError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            BrokerError::DnssecValidationFailed { domain } => {
                tracing::warn!("DNSSEC validation failed for domain: {}", domain);
                (StatusCode::BAD_REQUEST, "DNSSEC validation failed")
            }
            BrokerError::Discovery(msg) => {
                tracing::error!("Discovery failed: {}", msg);
                (StatusCode::BAD_GATEWAY, "Discovery failed")
            }
        };

        let body = json!({ "success": false, "reason": message });
        (status, axum::Json(body)).into_response()
    }
}
