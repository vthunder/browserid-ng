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
