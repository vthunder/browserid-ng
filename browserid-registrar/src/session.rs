//! Sessions and request proofs (registry-api-v1 §4.4–§4.5). A session is
//! an opaque token on one account, opened by a login (§4.2) or by
//! `accounts` (§5.2.1) and bound to the device's login key that call
//! carried. Every call carries `Authorization: Bearer <token>` and a
//! `Proof` JWS signed by that key; POST proofs bind the body by `bh`. The
//! key is re-checked on every call: revoked or expired is
//! `401 invalid_session`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::api::{ApiError, ApiUser, PROOF_IAT_WINDOW_SECONDS, PROOF_TYP};
use crate::consent::public_origin;
use crate::models::{LoginCertRecord, SessionRecord};
use crate::RegistrarState;

/// Session lifetime (§4.5: RECOMMENDED ≤ 24 h).
pub const SESSION_TTL_SECONDS: i64 = 24 * 3600;

pub(crate) fn b64url_sha256(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(data))
}

/// base64url(SHA-256(data)) — the token-hash function, for hosts minting
/// guard tokens the registry looks up.
pub fn b64url_sha256_pub(data: &[u8]) -> String {
    b64url_sha256(data)
}

/// base64url(SHA-256(body bytes)) of the request, computed once by
/// [`buffer_body`] so the proof extractor can check `bh` without
/// consuming the body the handler still needs.
#[derive(Clone, Debug)]
pub struct BodyHash(pub String);

/// Buffers the request body (bounded), records its hash in the request
/// extensions, hands the body back to the handler untouched, and logs the
/// call (method, path, status) — the operator's view of the wire.
pub async fn buffer_body(req: Request, next: Next) -> Response {
    let (mut parts, body) = req.into_parts();
    let method = parts.method.clone();
    let path = parts.uri.path().to_string();
    let bytes = match axum::body::to_bytes(body, crate::api::API_BODY_LIMIT).await {
        Ok(b) => b,
        Err(_) => return ApiError::InvalidRequest("request body too large".into()).into_response(),
    };
    parts.extensions.insert(BodyHash(b64url_sha256(&bytes)));
    let resp = next.run(Request::from_parts(parts, Body::from(bytes))).await;
    tracing::info!(%method, %path, status = resp.status().as_u16(), "registry api");
    resp
}

// ---------------------------------------------------------------------------
// Proof JWS (§4.4)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ProofClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    #[serde(default)]
    bh: Option<String>,
}

/// A parsed, not-yet-verified proof.
pub(crate) struct Proof {
    pub kid: String,
    pub htm: String,
    pub htu: String,
    pub iat: i64,
    pub jti: String,
    pub bh: Option<String>,
    message: String,
    signature: Vec<u8>,
}

impl Proof {
    pub fn parse(jws: &str) -> Result<Self, ApiError> {
        let bad = |m: &str| ApiError::InvalidProof(m.to_string());
        let parts: Vec<&str> = jws.trim().split('.').collect();
        if parts.len() != 3 {
            return Err(bad("proof is not a compact JWS"));
        }
        let header: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| bad("bad proof header encoding"))?,
        )
        .map_err(|_| bad("bad proof header"))?;
        if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
            return Err(bad("proof alg must be EdDSA"));
        }
        if header.get("typ").and_then(|v| v.as_str()) != Some(PROOF_TYP) {
            return Err(bad("wrong proof typ"));
        }
        let kid = header
            .get("kid")
            .and_then(|v| v.as_str())
            .filter(|k| !k.is_empty())
            .ok_or_else(|| bad("proof header carries no kid"))?
            .to_string();
        let claims: ProofClaims = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| bad("bad proof payload encoding"))?,
        )
        .map_err(|_| bad("bad proof claims"))?;
        if claims.jti.is_empty() {
            return Err(bad("empty jti"));
        }
        let signature =
            URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| bad("bad proof signature encoding"))?;
        Ok(Proof {
            kid,
            htm: claims.htm,
            htu: claims.htu,
            iat: claims.iat,
            jti: claims.jti,
            bh: claims.bh,
            message: format!("{}.{}", parts[0], parts[1]),
            signature,
        })
    }

    pub fn verify(&self, pubkey_b64: &str) -> Result<(), ApiError> {
        let key = browserid_core::PublicKey::from_base64(pubkey_b64)
            .map_err(|e| ApiError::Internal(format!("stored key unparseable: {e}")))?;
        key.verify(self.message.as_bytes(), &self.signature)
            .map_err(|_| ApiError::InvalidProof("proof signature does not verify".into()))
    }

    /// The claim checks every proof shares (§4.4 step 5): method, request
    /// URI against the PUBLIC origin, `iat` window; `bh` against the body
    /// hash when one is expected.
    pub fn check_claims(
        &self,
        state: &RegistrarState,
        method: &str,
        path: &str,
        expect_bh: Option<&str>,
    ) -> Result<(), ApiError> {
        let bad = |m: &str| ApiError::InvalidProof(m.to_string());
        if self.htm != method {
            return Err(bad("htm does not match the request method"));
        }
        if self.htu != format!("{}{}", public_origin(&state.domain), path) {
            return Err(bad("htu does not match this endpoint"));
        }
        if (self.iat - Utc::now().timestamp()).abs() > PROOF_IAT_WINDOW_SECONDS {
            return Err(bad("iat outside the acceptance window"));
        }
        match (expect_bh, self.bh.as_deref()) {
            (Some(want), Some(have)) if want == have => {}
            (Some(_), Some(_)) => return Err(bad("bh does not match the request body")),
            (Some(_), None) => return Err(bad("bh is required on this proof")),
            (None, Some(_)) => return Err(bad("bh is not allowed on this proof")),
            (None, None) => {}
        }
        Ok(())
    }
}

/// The `Proof` request header, parsed.
pub(crate) fn header_proof(headers: &axum::http::HeaderMap) -> Result<Proof, ApiError> {
    let raw = headers
        .get("proof")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::InvalidProof("missing Proof header".into()))?;
    Proof::parse(raw)
}

/// Single-use `jti` per key (§4.4), whether or not the key is recorded.
pub(crate) fn replay_check(state: &RegistrarState, kid: &str, jti: &str) -> Result<(), ApiError> {
    let retain = Utc::now().timestamp() + 2 * PROOF_IAT_WINDOW_SECONDS;
    if !state.api_replay.insert_once(&format!("proof|{kid}|{jti}"), retain) {
        return Err(ApiError::InvalidProof("jti replayed".into()));
    }
    Ok(())
}

pub(crate) fn kid_of(pubkey_b64: &str) -> Option<String> {
    browserid_core::PublicKey::from_base64(pubkey_b64).ok().map(|k| k.kid())
}

// ---------------------------------------------------------------------------
// Sessions (§4.5)
// ---------------------------------------------------------------------------

/// The login key a session is bound to, as of now: live (unrevoked,
/// unexpired) or the session is invalid.
fn session_key(state: &RegistrarState, rec: &SessionRecord) -> Result<LoginCertRecord, ApiError> {
    let Some(id) = rec.login_key_id else {
        return Err(ApiError::InvalidSession("this session predates login keys; log in again".into()));
    };
    state
        .store
        .list_login_certs(rec.user_id)
        .map_err(|e| ApiError::Internal(format!("login keys: {e}")))?
        .into_iter()
        .find(|k| k.id == id)
        .filter(|k| k.is_live())
        .ok_or_else(|| ApiError::InvalidSession("this session's login key is revoked or expired".into()))
}

/// The session behind `Authorization: Bearer` and its live login key.
pub(crate) async fn bearer_session(
    state: &RegistrarState,
    headers: &axum::http::HeaderMap,
) -> Result<(SessionRecord, LoginCertRecord), ApiError> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::InvalidSession("missing Authorization header".into()))?;
    let Some((scheme, token)) = auth.split_once(' ') else {
        return Err(ApiError::InvalidSession("malformed Authorization header".into()));
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(ApiError::InvalidSession("Authorization scheme must be Bearer".into()));
    }
    let rec = state
        .store
        .get_session(&b64url_sha256(token.trim().as_bytes()))
        .map_err(|e| ApiError::Internal(format!("session lookup: {e}")))?
        .ok_or_else(|| ApiError::InvalidSession("unknown session".into()))?;
    if rec.is_expired() {
        return Err(ApiError::InvalidSession("session expired".into()));
    }
    let key = session_key(state, &rec)?;
    Ok((rec, key))
}

/// The whole §4.4 session path for one call: token → key → the header
/// proof by that key → claims (`bh` when a body is expected) → replay.
pub(crate) async fn verify_session_call(
    state: &RegistrarState,
    headers: &axum::http::HeaderMap,
    method: &str,
    path: &str,
    expect_bh: Option<&str>,
) -> Result<(SessionRecord, LoginCertRecord, Proof), ApiError> {
    let (rec, key) = bearer_session(state, headers).await?;
    let proof = header_proof(headers)?;
    if proof.kid != key.kid {
        return Err(ApiError::InvalidSession("the Proof key is not this session's login key".into()));
    }
    proof.verify(&key.pubkey)?;
    proof.check_claims(state, method, path, expect_bh)?;
    replay_check(state, &proof.kid, &proof.jti)?;
    Ok((rec, key, proof))
}

/// Mint a session bound to `key` and answer its §4.5 body.
pub(crate) async fn open(
    state: &RegistrarState,
    user_id: u64,
    key: &LoginCertRecord,
) -> Result<serde_json::Value, ApiError> {
    let now = Utc::now();
    let expires_at = now + Duration::seconds(SESSION_TTL_SECONDS);
    let token = crate::api::new_token();
    state
        .store
        .create_session(SessionRecord {
            token_hash: b64url_sha256(token.as_bytes()),
            user_id,
            login_key_id: Some(key.id),
            created_at: now,
            expires_at,
        })
        .map_err(|e| ApiError::Internal(format!("session store: {e}")))?;
    state.store.cleanup_expired_sessions().ok();
    let roster = state
        .host
        .roster(user_id)
        .map_err(|e| ApiError::Internal(format!("roster: {e}")))?;
    let account = state
        .host
        .account_public_id(user_id)
        .map_err(|e| ApiError::Internal(format!("account id: {e}")))?;
    Ok(serde_json::json!({
        "token": token,
        "expires_at": expires_at.to_rfc3339(),
        "account": account,
        "key": { "id": key.id, "kid": key.kid, "label": key.label },
        "roster": roster.iter().map(|(identity, state)| serde_json::json!({
            "identity": identity, "state": state,
        })).collect::<Vec<_>>(),
    }))
}

/// Ends the session the call carries.
pub async fn end_session(
    State(state): State<Arc<RegistrarState>>,
    user: ApiUser,
) -> Result<StatusCode, ApiError> {
    state
        .store
        .delete_session(&user.session_token_hash)
        .map_err(|e| ApiError::Internal(format!("session store: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Client half (tests, SDKs)
// ---------------------------------------------------------------------------

/// Build a §4.4 proof: `kid` from the key, `bh` from `body` when given
/// (the header proof of a POST), none otherwise (GETs and possession
/// proofs).
pub fn build_proof(
    method: &str,
    htu: &str,
    body: Option<&[u8]>,
    key: &browserid_core::KeyPair,
    iat: i64,
    jti: &str,
) -> String {
    let kid = key.public_key().kid();
    let header = URL_SAFE_NO_PAD.encode(format!(
        r#"{{"alg":"EdDSA","typ":"{PROOF_TYP}","kid":"{kid}"}}"#
    ));
    let mut claims = serde_json::json!({ "htm": method, "htu": htu, "iat": iat, "jti": jti });
    if let Some(b) = body {
        claims["bh"] = serde_json::Value::String(b64url_sha256(b));
    }
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let message = format!("{header}.{payload}");
    let sig = URL_SAFE_NO_PAD.encode(key.sign(message.as_bytes()));
    format!("{message}.{sig}")
}

/// [`build_proof`] now, with a fresh `jti`.
pub fn build_proof_now(
    method: &str,
    htu: &str,
    body: Option<&[u8]>,
    key: &browserid_core::KeyPair,
) -> String {
    build_proof(method, htu, body, key, Utc::now().timestamp(), &crate::api::new_token())
}
