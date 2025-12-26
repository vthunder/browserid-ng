//! Assertion verification endpoint

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::email::EmailSender;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};
use crate::verifier::{verify_assertion, HttpFetcher, VerificationResult};

/// Request body for verification
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// The backed assertion to verify (certificate~assertion format)
    pub assertion: String,

    /// The expected audience (relying party origin)
    pub audience: String,
}

/// Response from verification endpoint
#[derive(Debug, Serialize)]
pub struct VerifyResponse(VerificationResult);

/// POST /verify
///
/// Verify a backed identity assertion and return the verified email.
pub async fn verify<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<VerifyRequest>,
) -> Json<VerifyResponse>
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
    E: EmailSender + 'static,
{
    // Get the broker's domain (this is the trusted fallback broker)
    let trusted_broker = state.domain.clone();

    // Run blocking HTTP fetcher in a separate thread pool
    let result = tokio::task::spawn_blocking(move || {
        // Use HTTP fetcher that allows HTTP for local development
        // In production, you'd want to use HttpFetcher::new() to require HTTPS
        let fetcher = HttpFetcher::allow_http();
        verify_assertion(&req.assertion, &req.audience, &trusted_broker, &fetcher)
    })
    .await
    .unwrap_or_else(|e| VerificationResult::failure(format!("Internal error: {}", e)));

    Json(VerifyResponse(result))
}
