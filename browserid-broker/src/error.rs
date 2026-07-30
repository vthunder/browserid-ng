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

    #[error("Invalid email address")]
    InvalidEmail,

    /// Too many verification/reset emails to an address; the value is the number
    /// of seconds the caller must wait before requesting another.
    #[error("Too many requests; retry in {0}s")]
    EmailRateLimited(i64),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("DNSSEC validation failed for domain {domain}")]
    DnssecValidationFailed { domain: String },

    #[error("Discovery failed: {0}")]
    Discovery(String),

    #[error("Invalid assertion: {0}")]
    InvalidAssertion(String),

    #[error("Invalid provisioning request: {0}")]
    InvalidProvisioningRequest(String),

    #[error("Provisioning not endorsed: {0}")]
    NotEndorsed(String),

    #[error("Provisioning certificate not found")]
    ProvisioningCertNotFound,

    #[error("Provisioning refused by policy: {0}")]
    PolicyRefused(String),

    /// Reservation collision — carries the specific unavailable names so the
    /// UI can tell the user which handles to change.
    #[error("some requested handles are unavailable")]
    NamesTaken(Vec<String>),

    #[error("Agent identity quota exceeded")]
    QuotaExceeded,

    #[error("Agent provisioning is not enabled")]
    AgentProvisioningDisabled,

    #[error("Warrant request not found")]
    WarrantRequestNotFound,

    #[error("Device certificate not found")]
    DeviceCertNotFound,

    #[error("Polling too fast")]
    PollTooFast,

    /// The domain's claim-time authority is atproto (browserid-ng-tsqk): its
    /// identities are proven at the bridge via atproto OAuth, never by
    /// mailing a code — a mailbox at a handle domain is not the owner.
    #[error("{0} is a Bluesky handle — sign in with it instead of a verification email")]
    DomainProvenByAtproto(String),

    /// No proof method for the domain: no primary, no handle binding, no MX.
    #[error("{0} does not accept mail, so ownership of an address there cannot be verified")]
    DomainUnprovable(String),
}

impl IntoResponse for BrokerError {
    fn into_response(self) -> Response {
        // Reservation collisions carry the specific unavailable names.
        if let BrokerError::NamesTaken(taken) = &self {
            let body = json!({
                "success": false,
                "reason": "some requested handles are unavailable",
                "taken": taken,
            });
            return (StatusCode::CONFLICT, axum::Json(body)).into_response();
        }
        // Rate limiting carries a human message + machine-readable retry_after.
        if let BrokerError::EmailRateLimited(secs) = &self {
            let mins = (*secs + 59) / 60;
            let wait = if *secs >= 60 {
                format!("about {mins} minute{}", if mins == 1 { "" } else { "s" })
            } else {
                format!("{secs} seconds")
            };
            let body = json!({
                "success": false,
                "reason": format!("A code was just sent — please wait {wait} before requesting another."),
                "retry_after": secs,
            });
            return (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
        }
        // The Display strings for these carry the domain, so borrow them
        // into the match's lifetime.
        let reason_buf = self.to_string();
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
            BrokerError::InvalidEmail => (StatusCode::BAD_REQUEST, "Invalid email address"),
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
            BrokerError::InvalidAssertion(msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            BrokerError::InvalidProvisioningRequest(msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            BrokerError::NotEndorsed(msg) => (StatusCode::UNAUTHORIZED, msg.as_str()),
            BrokerError::ProvisioningCertNotFound => {
                (StatusCode::NOT_FOUND, "Provisioning certificate not found")
            }
            BrokerError::PolicyRefused(msg) => (StatusCode::FORBIDDEN, msg.as_str()),
            // Handled above with a structured body; unreachable here.
            BrokerError::NamesTaken(_) => (StatusCode::CONFLICT, "handles unavailable"),
            BrokerError::EmailRateLimited(_) => (StatusCode::TOO_MANY_REQUESTS, "too many requests"),
            BrokerError::QuotaExceeded => {
                (StatusCode::TOO_MANY_REQUESTS, "Agent identity quota exceeded")
            }
            BrokerError::AgentProvisioningDisabled => {
                (StatusCode::NOT_FOUND, "Agent provisioning is not enabled")
            }
            BrokerError::WarrantRequestNotFound => {
                (StatusCode::NOT_FOUND, "Warrant request not found")
            }
            BrokerError::DeviceCertNotFound => {
                (StatusCode::NOT_FOUND, "Device certificate not found")
            }
            BrokerError::PollTooFast => (StatusCode::TOO_MANY_REQUESTS, "Polling too fast"),
            BrokerError::DomainProvenByAtproto(_) | BrokerError::DomainUnprovable(_) => {
                (StatusCode::FORBIDDEN, reason_buf.as_str())
            }
        };

        let body = json!({ "success": false, "reason": message });
        (status, axum::Json(body)).into_response()
    }
}
