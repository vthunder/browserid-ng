//! Cryptographic key types for BrowserID-NG
//!
//! Uses Ed25519 for all signing operations.

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{Error, Result};

/// A public key that can verify signatures
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    inner: VerifyingKey,
}

impl PublicKey {
    /// Create a public key from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("public key must be 32 bytes".into()))?;
        let inner = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Get the raw bytes of this public key
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.inner.as_bytes()
    }

    /// Encode as base64url (no padding)
    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.as_bytes())
    }

    /// Decode from base64url
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(s)?;
        Self::from_bytes(&bytes)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| Error::InvalidKey("signature must be 64 bytes".into()))?;
        let signature = Signature::from_bytes(&sig_bytes);
        self.inner
            .verify(message, &signature)
            .map_err(|_| Error::SignatureVerificationFailed)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as JWK-like structure
        #[derive(Serialize)]
        struct JwkPublicKey<'a> {
            algorithm: &'static str,
            #[serde(rename = "publicKey")]
            public_key: &'a str,
        }

        let b64 = self.to_base64();
        JwkPublicKey {
            algorithm: "Ed25519",
            public_key: &b64,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct JwkPublicKey {
            algorithm: String,
            #[serde(rename = "publicKey")]
            public_key: String,
        }

        let jwk = JwkPublicKey::deserialize(deserializer)?;
        if jwk.algorithm != "Ed25519" {
            return Err(serde::de::Error::custom(format!(
                "unsupported algorithm: {}",
                jwk.algorithm
            )));
        }
        PublicKey::from_base64(&jwk.public_key).map_err(serde::de::Error::custom)
    }
}

/// A keypair that can sign and verify
#[derive(Debug)]
pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create a keypair from a seed (32 bytes)
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| Error::InvalidKey("seed must be 32 bytes".into()))?;
        let signing_key = SigningKey::from_bytes(&seed);
        Ok(Self { signing_key })
    }

    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.signing_key.verifying_key(),
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    /// Get the secret key bytes (for storage)
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_roundtrip() {
        let kp = KeyPair::generate();
        let message = b"hello world";
        let signature = kp.sign(message);

        // Verify with public key
        let pk = kp.public_key();
        pk.verify(message, &signature).unwrap();
    }

    #[test]
    fn test_public_key_serialization() {
        let kp = KeyPair::generate();
        let pk = kp.public_key();

        let json = serde_json::to_string(&pk).unwrap();
        let pk2: PublicKey = serde_json::from_str(&json).unwrap();

        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let kp = KeyPair::generate();
        let pk = kp.public_key();

        let message = b"hello world";
        let mut signature = kp.sign(message);
        signature[0] ^= 0xff; // corrupt signature

        assert!(pk.verify(message, &signature).is_err());
    }
}
