//! Custodial tenant signing keys, sealed at rest (bean g5qt).
//!
//! Each hosted-primary tenant gets its own Ed25519 keypair; the public half
//! is published in the tenant's `_browserid` DNSSEC record, the private half
//! lives in the broker's database sealed with XChaCha20-Poly1305 under a
//! deployment secret (`TENANT_KEYSTORE_KEY`, 64 hex chars = 32 bytes,
//! declared in sandmill-infra's `id.env.age`). Sealing keeps a database
//! exfiltration from also being a mass tenant-key compromise; the env secret
//! and the DB never travel together in backups.
//!
//! Wire form: `xchacha20:<b64url(nonce)>:<b64url(ciphertext)>`, AAD = the
//! tenant domain, so a sealed blob cannot be replayed onto another tenant row.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use browserid_core::KeyPair;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;

const PREFIX: &str = "xchacha20";

/// The deployment sealing key, parsed from `TENANT_KEYSTORE_KEY`.
#[derive(Clone)]
pub struct KeystoreKey([u8; 32]);

impl KeystoreKey {
    /// Parse a 64-char hex secret. `None` input means the keystore is not
    /// configured — tenant onboarding is refused, nothing else is affected.
    pub fn from_env_value(hex: &str) -> Result<Self, String> {
        let hex = hex.trim();
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("TENANT_KEYSTORE_KEY must be 64 hex characters (32 bytes)".into());
        }
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("TENANT_KEYSTORE_KEY: {e}"))?;
        }
        Ok(Self(key))
    }

    /// Generate + seal a fresh tenant keypair. Returns (public b64url, sealed).
    pub fn generate_sealed(&self, domain: &str) -> Result<(String, String), String> {
        let keypair = KeyPair::generate();
        let public = keypair.public_key().to_base64();
        let sealed = self.seal(domain, keypair.secret_bytes())?;
        Ok((public, sealed))
    }

    /// Seal a 32-byte Ed25519 seed for the given tenant domain.
    pub fn seal(&self, domain: &str, seed: &[u8; 32]) -> Result<String, String> {
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let mut nonce_bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: seed, aad: domain.as_bytes() })
            .map_err(|e| format!("seal: {e}"))?;
        Ok(format!(
            "{PREFIX}:{}:{}",
            URL_SAFE_NO_PAD.encode(nonce_bytes),
            URL_SAFE_NO_PAD.encode(ciphertext)
        ))
    }

    /// Unseal a tenant's signing keypair.
    pub fn unseal(&self, domain: &str, sealed: &str) -> Result<KeyPair, String> {
        let mut parts = sealed.splitn(3, ':');
        let (prefix, nonce_b64, ct_b64) = (
            parts.next().unwrap_or_default(),
            parts.next().ok_or("sealed key: missing nonce")?,
            parts.next().ok_or("sealed key: missing ciphertext")?,
        );
        if prefix != PREFIX {
            return Err(format!("sealed key: unknown scheme '{prefix}'"));
        }
        let nonce_bytes = URL_SAFE_NO_PAD
            .decode(nonce_b64)
            .map_err(|e| format!("sealed key nonce: {e}"))?;
        if nonce_bytes.len() != 24 {
            return Err("sealed key: nonce must be 24 bytes".into());
        }
        let ciphertext = URL_SAFE_NO_PAD
            .decode(ct_b64)
            .map_err(|e| format!("sealed key ciphertext: {e}"))?;
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let seed = cipher
            .decrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload { msg: ciphertext.as_slice(), aad: domain.as_bytes() },
            )
            .map_err(|_| "sealed key: decryption failed (wrong TENANT_KEYSTORE_KEY?)".to_string())?;
        let seed: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| "sealed key: seed must be 32 bytes".to_string())?;
        KeyPair::from_seed(&seed).map_err(|e| format!("sealed key: {e}"))
    }
}

impl std::fmt::Debug for KeystoreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeystoreKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> KeystoreKey {
        KeystoreKey::from_env_value(&"ab".repeat(32)).unwrap()
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let ks = test_key();
        let (public, sealed) = ks.generate_sealed("example.com").unwrap();
        let keypair = ks.unseal("example.com", &sealed).unwrap();
        assert_eq!(keypair.public_key().to_base64(), public);
    }

    #[test]
    fn domain_binding_is_enforced() {
        let ks = test_key();
        let (_, sealed) = ks.generate_sealed("example.com").unwrap();
        assert!(ks.unseal("evil.com", &sealed).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let ks = test_key();
        let (_, sealed) = ks.generate_sealed("example.com").unwrap();
        let other = KeystoreKey::from_env_value(&"cd".repeat(32)).unwrap();
        assert!(other.unseal("example.com", &sealed).is_err());
    }

    #[test]
    fn rejects_bad_env_values() {
        assert!(KeystoreKey::from_env_value("short").is_err());
        assert!(KeystoreKey::from_env_value(&"zz".repeat(32)).is_err());
        assert!(KeystoreKey::from_env_value(&"ab".repeat(32)).is_ok());
    }
}
