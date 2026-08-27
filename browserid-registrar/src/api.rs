//! Registry API v1 (docs/specs/registry-api-v1.md): the token-authenticated
//! wire surface that makes a native wallet a first-class registry client.
//!
//! Authentication is a two-step (§3): `POST /api/v1/token` exchanges a
//! presentation bundle addressed to the registry's own origin for a
//! short-lived, sender-constrained access token; every subsequent call
//! carries the token plus a DPoP-style proof signed with the same config-cert
//! key the presentation proved. There are no refresh tokens — re-exchanging a
//! fresh presentation IS the refresh — and revocation rides the bound config
//! cert's status bit, re-checked fail-closed on every call.
//!
//! Errors are OAuth-shaped (§7): `{ "error": ..., "error_description": ...,
//! "reason"?: ... }` — a deliberate departure from the legacy
//! `{"success": false}` envelope, which does not exist on this surface.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::extract::{FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::consent::{public_origin, status_list_uri};
use crate::models::ApiTokenRecord;
use crate::RegistrarState;

/// Token lifetime ceiling (§3.1): `expires_in` SHOULD be at most 3600s, and
/// the token MUST NOT outlive the config cert it is bound to.
const TOKEN_TTL_SECONDS: i64 = 3600;
/// Proof `iat` acceptance window (§3.2, RECOMMENDED ±300s).
const PROOF_IAT_WINDOW_SECONDS: i64 = 300;
/// Request body cap, API-wide (§3.1, RECOMMENDED 64 KiB).
pub(crate) const API_BODY_LIMIT: usize = 64 * 1024;
/// The proof's domain-separating JWS `typ` (§3.2).
pub const PROOF_TYP: &str = "browserid-registry-proof-v1";

// ===========================================================================
// Host-provided verification
// ===========================================================================

/// What the §3.1 exchange learns from a fully verified presentation.
#[derive(Debug, Clone)]
pub struct VerifiedPresentation {
    /// The attributed identity — the warrant grantor.
    pub email: String,
    /// The acting identity — the warrant grantee (== access-cert identity).
    pub grantee: String,
    /// The attributed identity's issuer (config cert's `iss`).
    pub issuer: String,
    /// The presented opaque holder id.
    pub holder: String,
    /// The warrant's scope strings.
    pub scopes: Vec<String>,
}

/// The host's core §6 verification stack, seen through the registry API's
/// eyes. The registrar deliberately does not verify presentations itself —
/// DNSSEC-rooted discovery, conformance rules, and fail-closed status
/// fetching live with the host (the broker's `verify_access_with_dns`), and
/// the exchange MUST NOT be weaker in any respect than the cookie sibling.
pub trait PresentationVerifier: Send + Sync {
    /// Verify `presentation` exactly as core §6 requires, with the registry's
    /// own public origin as audience. `Err(reason)` = verification failed;
    /// the reason is logged server-side, never surfaced (§7.1 — the anonymous
    /// exchange must not become a verification oracle).
    fn verify_presentation<'a>(
        &'a self,
        presentation: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<VerifiedPresentation, String>> + Send + 'a>>;

    /// Fail-closed revocation check of one status ref (core §6.3): own-list
    /// refs answered authoritatively, foreign refs by authenticated fetch.
    /// `Ok(true)` = revoked; `Err` = uncheckable, which callers MUST treat as
    /// revoked.
    fn check_status_ref<'a>(
        &'a self,
        uri: &'a str,
        idx: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>>;
}

// ===========================================================================
// Errors (§7)
// ===========================================================================

#[derive(Debug)]
pub enum ApiError {
    /// 400 — malformed JSON, missing/unknown fields, grammar violations.
    InvalidRequest(String),
    /// 400 — the token exchange refused the presented credential.
    InvalidGrant { reason: Option<&'static str>, description: String },
    /// 400 — a requested scope the registry does not recognize.
    InvalidScope(String),
    /// 401 — missing/expired/revoked token (incl. a dead bound cert).
    InvalidToken(String),
    /// 401 — the DPoP proof failed one of the §3.2 checks.
    InvalidProof(String),
    /// 403 — token scope does not cover the endpoint.
    InsufficientScope,
    /// 404 — owner-scoped miss, or the API is not served here.
    NotFound,
    /// 500 — a deployment fault, never a caller error.
    Internal(String),
}

impl ApiError {
    /// The §7.1 catch-all for a failed core §6 verification: one coarse
    /// reason, no finer detail (verification-oracle rule).
    pub(crate) fn verification_failed() -> Self {
        ApiError::InvalidGrant {
            reason: Some("verification_failed"),
            description: "the presentation failed verification".into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error, description, reason) = match self {
            ApiError::InvalidRequest(d) => (StatusCode::BAD_REQUEST, "invalid_request", d, None),
            ApiError::InvalidGrant { reason, description } => {
                (StatusCode::BAD_REQUEST, "invalid_grant", description, reason)
            }
            ApiError::InvalidScope(d) => (StatusCode::BAD_REQUEST, "invalid_scope", d, None),
            ApiError::InvalidToken(d) => (StatusCode::UNAUTHORIZED, "invalid_token", d, None),
            ApiError::InvalidProof(d) => (StatusCode::UNAUTHORIZED, "invalid_proof", d, None),
            ApiError::InsufficientScope => (
                StatusCode::FORBIDDEN,
                "insufficient_scope",
                "the token's scope does not cover this endpoint".to_string(),
                None,
            ),
            ApiError::NotFound => {
                (StatusCode::NOT_FOUND, "not_found", "not found".to_string(), None)
            }
            ApiError::Internal(d) => {
                tracing::error!("registry API internal error: {d}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "internal error".to_string(),
                    None,
                )
            }
        };
        let mut body = serde_json::json!({ "error": error, "error_description": description });
        if let Some(r) = reason {
            body["reason"] = serde_json::Value::String(r.to_string());
        }
        let mut resp = (status, Json(body)).into_response();
        if status == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("DPoP"),
            );
        }
        resp
    }
}

// ===========================================================================
// Replay cache (proof `jti`s + exchange assertions)
// ===========================================================================

/// In-memory single-use tracking (§3.1/§3.2): proof `jti`s keyed by proof
/// key, and exchange assertions keyed by their hash. Entries retain at least
/// as long as the acceptance window. Single-process by design (the handoff's
/// frontloaded decision) — a multi-node registry needs a shared cache, which
/// the spec leaves to the implementation.
///
/// Growth is bounded by construction: entries are inserted only after a
/// signature verified (proofs) or a full core §6 verification passed
/// (assertions), and every insert prunes expired rows first.
#[derive(Default)]
pub struct ReplayCache {
    inner: std::sync::Mutex<std::collections::HashMap<String, i64>>,
}

impl ReplayCache {
    /// Record `key` unless a live entry exists. `true` = fresh (recorded),
    /// `false` = replayed.
    pub fn insert_once(&self, key: &str, retain_until: i64) -> bool {
        let now = Utc::now().timestamp();
        let mut map = self.inner.lock().unwrap();
        map.retain(|_, exp| *exp > now);
        if map.contains_key(key) {
            return false;
        }
        map.insert(key.to_string(), retain_until);
        true
    }
}

fn b64url_sha256(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(data))
}

// ===========================================================================
// POST /api/v1/token — the presentation → token exchange (§3.1)
// ===========================================================================

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRequest {
    /// `access_cert~assertion~warrant~config_cert`, audience = this origin.
    presentation: String,
    /// Space-separated scope list; v1 defines the single scope `registry`
    /// (the default).
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub scope: String,
}

pub async fn token_exchange(
    State(state): State<Arc<RegistrarState>>,
    body: axum::body::Bytes,
) -> Result<Json<TokenResponse>, ApiError> {
    if !state.enabled {
        return Err(ApiError::NotFound);
    }
    let req: TokenRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("bad request body: {e}")))?;

    let scopes: Vec<&str> = match req.scope.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => vec!["registry"],
        Some(s) => s.split_ascii_whitespace().collect(),
    };
    if let Some(unknown) = scopes.iter().find(|s| **s != "registry") {
        return Err(ApiError::InvalidScope(format!("unknown scope '{unknown}'")));
    }

    let verifier = state.presentation_verifier.as_ref().ok_or_else(|| {
        ApiError::Internal("presentation verification is not configured on this host".into())
    })?;
    let verified = match verifier.verify_presentation(&req.presentation).await {
        Ok(v) => v,
        Err(reason) => {
            tracing::info!(%reason, "token exchange: presentation verification failed");
            return Err(ApiError::verification_failed());
        }
    };

    // Beyond core §6 (§3.1): the bundle re-parses (it just verified) for the
    // claims the token binds to and the exchange's extra checks. Note the
    // deliberate ABSENCE of the cookie lane's issuer-is-self rejection:
    // self-issued (registry-rooted) presentations are accepted here — the
    // token's authority is a strict subset of the session that lane refuses
    // to mint (§10 decision 7).
    let pres = browserid_core::device::AccessPresentation::parse(&req.presentation)
        .map_err(|e| ApiError::Internal(format!("verified presentation failed to re-parse: {e}")))?;
    let wc = pres.warrant.claims();
    if wc.grantor != wc.grantee {
        return Err(ApiError::InvalidGrant {
            reason: Some("delegated_presentation"),
            description: "the exchange requires a self-presentation (grantor == grantee)".into(),
        });
    }
    for s in &scopes {
        if !verified.scopes.iter().any(|have| have == s) {
            return Err(ApiError::InvalidGrant {
                reason: Some("scope_missing"),
                description: format!("the presented warrant does not carry the '{s}' scope"),
            });
        }
    }

    // Single-use per assertion (§3.1 abuse controls). Assertions carry no
    // `jti`, so the key is the hash of the signed assertion itself — same
    // semantics: one assertion redeems at most one token. Recorded only
    // after full verification, so the cache can't be grown anonymously.
    let assertion_jws = req.presentation.split('~').nth(1).unwrap_or_default();
    let retain = Utc::now().timestamp() + 2 * PROOF_IAT_WINDOW_SECONDS;
    if !state
        .api_replay
        .insert_once(&format!("xchg|{}", b64url_sha256(assertion_jws.as_bytes())), retain)
    {
        return Err(ApiError::InvalidGrant {
            reason: None,
            description: "this assertion was already exchanged".into(),
        });
    }

    // Account resolution (§3.1): existing owner, or a fresh account holding
    // exactly this identity — never linking, transfer, or merge.
    let user_id = state
        .host
        .account_for_presented_identity(&verified.email)
        .map_err(|e| ApiError::Internal(format!("account resolution: {e}")))?;

    let cc = pres.config_cert.claims();
    let now = Utc::now();
    let cert_exp = DateTime::from_timestamp(cc.exp, 0).unwrap_or(now);
    let expires_at = std::cmp::min(now + Duration::seconds(TOKEN_TTL_SECONDS), cert_exp);
    let expires_in = (expires_at - now).num_seconds();
    if expires_in <= 0 {
        // Verification already enforces cert validity; this only trips on a
        // cert expiring within the same second.
        return Err(ApiError::verification_failed());
    }

    let token = new_token();
    let scope_str = scopes.join(" ");
    state
        .store
        .create_api_token(ApiTokenRecord {
            token_hash: b64url_sha256(token.as_bytes()),
            user_id,
            proof_key: cc.public_key.to_base64(),
            cert_status_uri: cc.status.as_ref().map(|s| s.uri.clone()),
            cert_status_idx: cc.status.as_ref().map(|s| s.idx),
            scope: scope_str.clone(),
            created_at: now,
            expires_at,
        })
        .map_err(|e| ApiError::Internal(format!("token store: {e}")))?;
    state.store.cleanup_expired_api_tokens().ok();

    tracing::info!(identity = %verified.email, holder = %verified.holder,
        "registry API token minted");
    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "DPoP",
        expires_in,
        scope: scope_str,
    }))
}

/// A fresh opaque token: 32 random bytes, base64url (≥128-bit entropy, §3.1).
fn new_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

// ===========================================================================
// The request-proof extractor (§3.2)
// ===========================================================================

/// The authenticated caller of a token-authed endpoint: token + proof
/// verified to the §3.2 bar, bound cert status re-checked fail-closed.
pub struct ApiUser {
    pub user_id: u64,
    /// The bound config cert's public key (base64) — the proof key.
    pub proof_key: String,
}

#[derive(Deserialize)]
struct ProofClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    ath: String,
}

/// Parse + verify one proof JWS against the token's bound key: exact `typ`,
/// `alg` pinned to EdDSA, signature under `proof_key_b64`.
fn verify_proof_jws(jws: &str, proof_key_b64: &str) -> Result<ProofClaims, ApiError> {
    let bad = |m: &str| ApiError::InvalidProof(m.to_string());
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(bad("proof is not a compact JWS"));
    }
    let header_bytes =
        URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| bad("bad proof header encoding"))?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| bad("bad proof header"))?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
        return Err(bad("proof alg must be EdDSA"));
    }
    if header.get("typ").and_then(|v| v.as_str()) != Some(PROOF_TYP) {
        return Err(bad("wrong proof typ"));
    }
    let key = browserid_core::PublicKey::from_base64(proof_key_b64)
        .map_err(|e| ApiError::Internal(format!("stored proof key unparseable: {e}")))?;
    let message = format!("{}.{}", parts[0], parts[1]);
    let signature =
        URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| bad("bad proof signature encoding"))?;
    key.verify(message.as_bytes(), &signature)
        .map_err(|_| bad("proof signature does not verify against the token's key"))?;
    let claims_bytes =
        URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| bad("bad proof payload encoding"))?;
    serde_json::from_slice(&claims_bytes).map_err(|_| bad("bad proof claims"))
}

/// Build a request proof (§3.2) — the client half, used by tests and SDKs.
pub fn build_proof(
    method: &str,
    htu: &str,
    access_token: &str,
    key: &browserid_core::KeyPair,
) -> String {
    build_proof_at(method, htu, access_token, key, Utc::now().timestamp(), &new_token())
}

/// [`build_proof`] with explicit `iat` and `jti` (window / replay tests).
pub fn build_proof_at(
    method: &str,
    htu: &str,
    access_token: &str,
    key: &browserid_core::KeyPair,
    iat: i64,
    jti: &str,
) -> String {
    let header =
        URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"EdDSA","typ":"{PROOF_TYP}"}}"#));
    let claims = serde_json::json!({
        "htm": method,
        "htu": htu,
        "iat": iat,
        "jti": jti,
        "ath": b64url_sha256(access_token.as_bytes()),
    });
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let message = format!("{header}.{payload}");
    let sig = URL_SAFE_NO_PAD.encode(key.sign(message.as_bytes()));
    format!("{message}.{sig}")
}

#[axum::async_trait]
impl FromRequestParts<Arc<RegistrarState>> for ApiUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<RegistrarState>,
    ) -> Result<Self, ApiError> {
        if !state.enabled {
            return Err(ApiError::NotFound);
        }
        // Verification order per §3.2: token exists and is unexpired → proof
        // signature under the bound key → typ/htm/htu/iat/ath → jti replay →
        // bound cert status fail-closed → scope. Any failure rejects.
        let auth = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ApiError::InvalidToken("missing Authorization header".into()))?;
        let (scheme, token) = auth
            .split_once(' ')
            .ok_or_else(|| ApiError::InvalidToken("malformed Authorization header".into()))?;
        if !scheme.eq_ignore_ascii_case("dpop") {
            return Err(ApiError::InvalidToken("Authorization scheme must be DPoP".into()));
        }
        let token = token.trim();
        let rec = state
            .store
            .get_api_token(&b64url_sha256(token.as_bytes()))
            .map_err(|e| ApiError::Internal(format!("token lookup: {e}")))?
            .ok_or_else(|| ApiError::InvalidToken("unknown token".into()))?;
        if rec.is_expired() {
            return Err(ApiError::InvalidToken("token expired".into()));
        }

        let proof = parts
            .headers
            .get("dpop")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ApiError::InvalidProof("missing DPoP header".into()))?;
        let claims = verify_proof_jws(proof, &rec.proof_key)?;
        if claims.htm != parts.method.as_str() {
            return Err(ApiError::InvalidProof("htm does not match the request method".into()));
        }
        // Compared against the advertised PUBLIC origin, never the
        // server-observed URI (§3.2 canonicalization).
        let expected_htu = format!("{}{}", public_origin(&state.domain), parts.uri.path());
        if claims.htu != expected_htu {
            return Err(ApiError::InvalidProof("htu does not match this endpoint".into()));
        }
        let now = Utc::now().timestamp();
        if (claims.iat - now).abs() > PROOF_IAT_WINDOW_SECONDS {
            return Err(ApiError::InvalidProof("iat outside the acceptance window".into()));
        }
        if claims.ath != b64url_sha256(token.as_bytes()) {
            return Err(ApiError::InvalidProof("ath does not bind this token".into()));
        }
        if claims.jti.is_empty()
            || !state.api_replay.insert_once(
                &format!("proof|{}|{}", rec.proof_key, claims.jti),
                now + 2 * PROOF_IAT_WINDOW_SECONDS,
            )
        {
            return Err(ApiError::InvalidProof("jti replayed".into()));
        }

        // Revocation rides the cert (§3.1): the bound config cert's status
        // ref is re-checked on EVERY call, fail-closed (invariant 3).
        if let (Some(uri), Some(idx)) = (rec.cert_status_uri.as_deref(), rec.cert_status_idx) {
            let verifier = state.presentation_verifier.as_ref().ok_or_else(|| {
                ApiError::Internal("status checking is not configured on this host".into())
            })?;
            match verifier.check_status_ref(uri, idx).await {
                Ok(false) => {}
                Ok(true) => {
                    return Err(ApiError::InvalidToken("the bound device cert is revoked".into()))
                }
                Err(e) => {
                    tracing::warn!(uri, idx, error = %e,
                        "token auth: bound cert status unavailable (fail-closed)");
                    return Err(ApiError::InvalidToken(
                        "the bound cert's status is unavailable (fail-closed)".into(),
                    ));
                }
            }
        }

        // v1: every §5 endpoint requires the `registry` scope.
        if !rec.scope.split_ascii_whitespace().any(|s| s == "registry") {
            return Err(ApiError::InsufficientScope);
        }

        Ok(ApiUser { user_id: rec.user_id, proof_key: rec.proof_key })
    }
}

// ===========================================================================
// GET /api/v1/requests — the consent inbox (§5.1)
// ===========================================================================

#[derive(Deserialize)]
pub struct ApiRequestsQuery {
    /// External requests are surfaced only through their code (§5.1).
    pub code: Option<String>,
    /// Long-poll hint — currently ignored, which §5.1 makes conformant.
    #[allow(dead_code)]
    pub wait: Option<u64>,
}

#[derive(Serialize)]
pub struct ApiRequestsResponse {
    pub status_uri: String,
    pub requests: Vec<crate::consent::PendingRequestInfo>,
}

/// A pure GET (§4): no claim side effect — claiming a record request is the
/// separate `POST /api/v1/requests/claim`. Unclaimed record requests are
/// therefore not listed here until claimed.
pub async fn list_requests(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
    Query(query): Query<ApiRequestsQuery>,
) -> Result<Json<ApiRequestsResponse>, ApiError> {
    let requests = state
        .store
        .list_pending_warrant_requests(user.user_id)
        .map_err(|e| ApiError::Internal(format!("inbox: {e}")))?
        .into_iter()
        .filter(|r| !r.external || query.code.as_deref() == Some(r.code.as_str()))
        .map(|r| crate::consent::pending_info(&state, user.user_id, r))
        .collect();
    Ok(Json(ApiRequestsResponse {
        status_uri: status_list_uri(&state.domain),
        requests,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use browserid_core::KeyPair;

    #[test]
    fn proof_round_trips_and_pins_typ_and_alg() {
        let kp = KeyPair::generate();
        let pub_b64 = kp.public_key().to_base64();
        let proof = build_proof("GET", "https://r.example/api/v1/requests", "tok123", &kp);
        let claims = verify_proof_jws(&proof, &pub_b64).expect("valid proof verifies");
        assert_eq!(claims.htm, "GET");
        assert_eq!(claims.htu, "https://r.example/api/v1/requests");
        assert_eq!(claims.ath, b64url_sha256(b"tok123"));

        // A proof signed by a DIFFERENT key is rejected.
        let other = KeyPair::generate();
        let forged = build_proof("GET", "https://r.example/api/v1/requests", "tok123", &other);
        assert!(matches!(verify_proof_jws(&forged, &pub_b64), Err(ApiError::InvalidProof(_))));

        // Wrong typ is rejected even with a valid signature (domain
        // separation, core §4): re-sign the same claims under typ JWT.
        let parts: Vec<&str> = proof.split('.').collect();
        let jwt_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let msg = format!("{}.{}", jwt_header, parts[1]);
        let sig = URL_SAFE_NO_PAD.encode(kp.sign(msg.as_bytes()));
        let wrong_typ = format!("{msg}.{sig}");
        assert!(matches!(verify_proof_jws(&wrong_typ, &pub_b64), Err(ApiError::InvalidProof(_))));

        // alg: none (signature still over the tampered header) is rejected.
        let none_header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"none","typ":"{PROOF_TYP}"}}"#));
        let msg = format!("{}.{}", none_header, parts[1]);
        let sig = URL_SAFE_NO_PAD.encode(kp.sign(msg.as_bytes()));
        let alg_none = format!("{msg}.{sig}");
        assert!(matches!(verify_proof_jws(&alg_none, &pub_b64), Err(ApiError::InvalidProof(_))));
    }

    #[test]
    fn replay_cache_is_single_use_until_expiry() {
        let cache = ReplayCache::default();
        let later = Utc::now().timestamp() + 60;
        assert!(cache.insert_once("k1", later));
        assert!(!cache.insert_once("k1", later), "second use is a replay");
        assert!(cache.insert_once("k2", later), "distinct keys are independent");
        // An EXPIRED entry is pruned and the key becomes fresh again.
        let cache = ReplayCache::default();
        assert!(cache.insert_once("k", Utc::now().timestamp() - 1));
        assert!(cache.insert_once("k", later), "expired entries do not block");
    }

    #[test]
    fn tokens_are_high_entropy_and_hash_stable() {
        let t1 = new_token();
        let t2 = new_token();
        assert_ne!(t1, t2);
        assert!(t1.len() >= 43, "32 bytes b64url = 43 chars, got {}", t1.len());
        assert_eq!(b64url_sha256(t1.as_bytes()), b64url_sha256(t1.as_bytes()));
        assert_ne!(b64url_sha256(t1.as_bytes()), b64url_sha256(t2.as_bytes()));
    }
}
