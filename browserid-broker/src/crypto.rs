//! Cryptographic utilities for the broker

use rand::Rng;

/// Default bcrypt cost factor
pub const BCRYPT_COST: u32 = 12;

/// Hash a password with bcrypt
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    bcrypt::hash(password, BCRYPT_COST)
}

/// Verify a password against a bcrypt hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    bcrypt::verify(password, hash)
}

/// Generate a random 6-digit verification code
pub fn generate_verification_code() -> String {
    let code: u32 = rand::thread_rng().gen_range(100000..1000000);
    code.to_string()
}

/// Generate a random secret for verification tokens
pub fn generate_secret() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Lowercase base32-ish alphabet (no padding, no ambiguous chars) for the
/// opaque, per-user-random holder ids and namespace prefixes.
const HOLDER_ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";

fn random_token(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| HOLDER_ALPHABET[rng.gen_range(0..HOLDER_ALPHABET.len())] as char)
        .collect()
}

/// A fresh random namespace prefix (8 chars). Stored per-user-per-namespace so
/// a `<prefix>.*` warrant matcher can wildcard the whole namespace.
pub fn generate_namespace_prefix() -> String {
    random_token(8)
}

/// An opaque, stable id for a log line (audit 2026-11 W7-11, Q10 (a)): the
/// first 12 chars of sha256 over a fixed prefix and the value. Correlates
/// across lines (same address, same tag) without printing the address.
pub fn log_id(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"browserid-log-id\0");
    h.update(value.trim().to_lowercase().as_bytes());
    let digest = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, h.finalize());
    digest[..12].to_string()
}

/// Assemble a broker-assigned holder id `<prefix>.<random>` under a namespace
/// prefix. The random suffix (10 chars) makes the holder unforgeable and
/// unguessable; the requester never chooses it.
pub fn assign_holder_id(prefix: &str) -> String {
    format!("{prefix}.{}", random_token(10))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_and_verify() {
        let password = "correct horse battery staple";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong password", &hash).unwrap());
    }

    #[test]
    fn test_verification_code_format() {
        for _ in 0..100 {
            let code = generate_verification_code();
            assert_eq!(code.len(), 6);
            assert!(code.parse::<u32>().is_ok());
        }
    }

    #[test]
    fn test_secret_uniqueness() {
        let s1 = generate_secret();
        let s2 = generate_secret();
        assert_ne!(s1, s2);
    }
}

/// Random base64url salt for managed-identity audience hashing (spec §4.7).
/// Generated once per tenant policy and kept stable across saves so the
/// hashes in outstanding certs stay checkable.
pub fn generate_salt_b64() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
