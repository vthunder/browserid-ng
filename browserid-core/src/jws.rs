//! Shared minimal JWS helpers (EdDSA, three b64url parts) — the same idiom as
//! `certificate.rs`. Extracted so the device-cert model (`device.rs`) and the
//! warrant model (`warrant.rs`) can sign/verify/decode this shape without
//! depending on any particular credential type.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{de::DeserializeOwned, Serialize};

use crate::{Error, KeyPair, PublicKey, Result};

pub(crate) fn invalid(what: &str, msg: impl std::fmt::Display) -> Error {
    Error::InvalidProvisioning(format!("{what}: {msg}"))
}

pub(crate) fn jws_sign<C: Serialize>(claims: &C, key: &KeyPair) -> Result<String> {
    let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(claims)?);
    let message = format!("{}.{}", header_b64, claims_b64);
    let sig_b64 = URL_SAFE_NO_PAD.encode(key.sign(message.as_bytes()));
    Ok(format!("{}.{}", message, sig_b64))
}

pub(crate) fn jws_decode<C: DeserializeOwned>(encoded: &str, what: &str) -> Result<C> {
    let parts: Vec<&str> = encoded.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid(what, "expected 3 JWT parts"));
    }
    let bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn jws_verify(encoded: &str, key: &PublicKey, what: &str) -> Result<()> {
    let parts: Vec<&str> = encoded.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid(what, "expected 3 JWT parts"));
    }
    let message = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD.decode(parts[2])?;
    key.verify(message.as_bytes(), &signature)
}

