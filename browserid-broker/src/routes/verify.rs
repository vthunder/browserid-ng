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
        fallback_fetcher.as_ref(),
        &state.domain,
    )
    .await;

    // Status check (core §6.4): for credentials whose status list is OUR
    // list, the DB is the authoritative source — no fetch, no cache window.
    // Foreign-issuer lists would need an HTTP fetch + cache; not yet needed
    // (no federated IdP issues status claims today).
    if result.status == "okay" {
        let own_uri = super::warrant::status_list_uri(&state.domain);
        if let Ok(backed) = browserid_core::BackedAssertion::parse(&req.assertion) {
            let mut refs: Vec<browserid_core::StatusRef> = backed
                .certificates()
                .iter()
                .filter_map(|c| c.status().cloned())
                .collect();
            if let Some(w) = backed.warrant() {
                if let Some(r) = w.status() {
                    refs.push(r.clone());
                }
            }
            for r in refs {
                if r.uri == own_uri {
                    match state.user_store.is_status_revoked_idx(r.idx) {
                        Ok(true) => {
                            return Json(VerifyResponse(VerificationResult::failure(
                                "Credential revoked (status list)".to_string(),
                            )));
                        }
                        Ok(false) => {}
                        Err(e) => {
                            tracing::warn!("status check failed: {e}");
                        }
                    }
                }
            }
        }
    }

    Json(VerifyResponse(result))
}
