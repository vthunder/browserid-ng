//! Assertion verification endpoint

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::email::EmailSender;
use crate::state::AppState;
use crate::store::{SessionStore, UserStore};
use crate::verifier::{verify_assertion_with_dns, VerificationResult};

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
    // Get the fallback fetcher (lazy-initialized)
    let fallback_fetcher = match state.fallback_fetcher().await {
        Ok(f) => f,
        Err(e) => {
            return Json(VerifyResponse(VerificationResult::failure(
                format!("Failed to create fetcher: {}", e),
            )));
        }
    };

    // Use DNS-first verification
    let result = verify_assertion_with_dns(
        &req.assertion,
        &req.audience,
        &fallback_fetcher,
        &state.domain,
    )
    .await;

    Json(VerifyResponse(result))
}
