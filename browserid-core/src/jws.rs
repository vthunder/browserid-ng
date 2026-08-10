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
    // Validate the JOSE header algorithm is exactly EdDSA (defense-in-depth,
    // bean ya11): the protocol is Ed25519-only, so reject `alg: none` and any
    // other value up front rather than relying solely on the signature check.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| invalid(what, format!("bad header b64: {e}")))?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|e| invalid(what, format!("bad header: {e}")))?;
    if header.get("alg").and_then(|a| a.as_str()) != Some("EdDSA") {
        return Err(invalid(what, "unexpected JWS alg (only EdDSA is accepted)"));
    }
    let message = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD.decode(parts[2])?;
    key.verify(message.as_bytes(), &signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize)]
    struct Claim {
        v: u32,
    }

    #[test]
    fn round_trips_and_rejects_wrong_alg() {
        let kp = KeyPair::generate();
        let token = jws_sign(&Claim { v: 7 }, &kp).unwrap();
        // Valid token verifies and decodes.
        jws_verify(&token, &kp.public_key(), "test").unwrap();
        let c: Claim = jws_decode(&token, "test").unwrap();
        assert_eq!(c.v, 7);

        // Re-sign the same payload under a tampered header (alg: none) — the
        // signature is over the tampered header, so it is cryptographically
        // valid, but the alg gate must still reject it.
        let parts: Vec<&str> = token.split('.').collect();
        let bad_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let msg = format!("{}.{}", bad_header, parts[1]);
        let sig = URL_SAFE_NO_PAD.encode(kp.sign(msg.as_bytes()));
        let forged = format!("{}.{}", msg, sig);
        assert!(jws_verify(&forged, &kp.public_key(), "test").is_err());
    }
}

