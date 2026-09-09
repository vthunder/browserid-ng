//! Sessions and request proofs (registry-api-v1 §4.4–§4.5). A session is
//! an opaque token on one account, opened by a login (§4.2) or by
//! `accounts` (§5.2.1). Its members are the keys that may sign its
//! proofs: the login key that opened it and the identity certs proven
//! under it. Every call carries `Authorization: Bearer <token>` and a
//! `Proof` JWS signed by one member, whose `kid` says which; POST proofs
//! bind the body by `bh`. Members are re-checked on every call and
//! dropped as they fail; a session with none left is `401 invalid_session`.

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
use crate::models::{DeviceCertRecord, SessionRecord};
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
// Members
// ---------------------------------------------------------------------------

/// A session member that passed the per-call re-check: an identity cert
/// proven under the session, or the login key that opened it.
#[derive(Clone, Debug)]
pub enum Member {
    Cert { cert: DeviceCertRecord, kid: String },
    Login { rec: crate::models::LoginCertRecord },
}

impl Member {
    pub fn kid(&self) -> &str {
        match self {
            Member::Cert { kid, .. } => kid,
            Member::Login { rec } => &rec.kid,
        }
    }
    pub fn pubkey(&self) -> &str {
        match self {
            Member::Cert { cert, .. } => &cert.pubkey,
            Member::Login { rec } => &rec.pubkey,
        }
    }
}

/// The member set of a session as of now: each recorded cert re-checked
/// for retirement, expiry and status (fail-closed), failing ones dropped;
/// the login key while its cert is live.
pub(crate) async fn resolve_members(
    state: &RegistrarState,
    user_id: u64,
    cert_ids: &[u64],
    login_key_id: Option<u64>,
) -> Result<Vec<Member>, ApiError> {
    let mut out = Vec::new();
    if let Some(id) = login_key_id {
        let live = state
            .store
            .list_login_certs(user_id)
            .map_err(|e| ApiError::Internal(format!("login certs: {e}")))?
            .into_iter()
            .find(|c| c.id == id)
            .filter(|c| c.is_live());
        if let Some(rec) = live {
            if !rec.status_idx.map_or(false, |i| state.store.is_status_revoked_idx(i).unwrap_or(true)) {
                out.push(Member::Login { rec });
            }
        }
    }
    let certs = state
        .store
        .list_device_certs(user_id)
        .map_err(|e| ApiError::Internal(format!("certs: {e}")))?;
    for id in cert_ids {
        let Some(cert) = certs.iter().find(|c| c.id == *id) else { continue };
        if !passes_bar(state, cert).await {
            continue;
        }
        let Some(kid) = kid_of(&cert.pubkey) else { continue };
        out.push(Member::Cert { cert: cert.clone(), kid });
    }
    Ok(out)
}

/// Unretired, unexpired, and not revoked at its status ref (uncheckable =
/// revoked). Re-checks are refreshed within the host's list cache lifetime.
pub(crate) async fn passes_bar(state: &RegistrarState, cert: &DeviceCertRecord) -> bool {
    if !cert.is_active() || cert.expires_at <= Utc::now() {
        return false;
    }
    match (cert.status_uri.as_deref(), cert.status_idx) {
        (Some(uri), Some(idx)) => match state.presentation_verifier.as_ref() {
            Some(v) => matches!(v.check_status_ref(uri, idx).await, Ok(false)),
            None => false,
        },
        _ => true,
    }
}

/// The session behind `Authorization: Bearer`, with its live members —
/// possibly none: a page login proves no key until the first `attach`
/// (§4.5), which is why `attach` resolves its own signer.
pub(crate) async fn bearer_session(
    state: &RegistrarState,
    headers: &axum::http::HeaderMap,
) -> Result<(SessionRecord, Vec<Member>), ApiError> {
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
    let members = resolve_members(state, rec.user_id, &rec.member_cert_ids, rec.login_key_id).await?;
    Ok((rec, members))
}

/// Mint a session and answer its §4.5 body.
pub(crate) async fn open(
    state: &RegistrarState,
    user_id: u64,
    member_ids: Vec<u64>,
    login_key_id: Option<u64>,
) -> Result<serde_json::Value, ApiError> {
    let now = Utc::now();
    let expires_at = now + Duration::seconds(SESSION_TTL_SECONDS);
    let token = crate::api::new_token();
    state
        .store
        .create_session(SessionRecord {
            token_hash: b64url_sha256(token.as_bytes()),
            user_id,
            member_cert_ids: member_ids.clone(),
            login_key_id,
            created_at: now,
            expires_at,
        })
        .map_err(|e| ApiError::Internal(format!("session store: {e}")))?;
    state.store.cleanup_expired_sessions().ok();
    session_body(state, user_id, &token, expires_at, &member_ids, login_key_id).await
}

/// The §4.5 session body.
pub(crate) async fn session_body(
    state: &RegistrarState,
    user_id: u64,
    token: &str,
    expires_at: chrono::DateTime<Utc>,
    member_ids: &[u64],
    login_key_id: Option<u64>,
) -> Result<serde_json::Value, ApiError> {
    let members = resolve_members(state, user_id, member_ids, login_key_id).await?;
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
        "members": members.iter().map(|m| match m {
            Member::Login { rec } => serde_json::json!({ "kid": rec.kid, "kind": "login" }),
            Member::Cert { cert, kid } => serde_json::json!({ "id": cert.id, "kid": kid, "kind": "cert", "purpose": cert.purpose }),
        }).collect::<Vec<_>>(),
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
    let Some(hash) = user.session_token_hash.as_deref() else {
        return Err(ApiError::InvalidRequest("this call needs a session, not a legacy token".into()));
    };
    state
        .store
        .delete_session(hash)
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
