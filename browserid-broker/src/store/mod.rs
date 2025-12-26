//! Storage abstractions for the broker

pub mod models;
pub mod memory;

pub use models::*;
pub use memory::{InMemorySessionStore, InMemoryUserStore};

use crate::error::BrokerError;

/// Result type for store operations
pub type StoreResult<T> = Result<T, BrokerError>;

/// Trait for user and email storage
pub trait UserStore: Send + Sync {
    /// Create a new user with the given password hash
    fn create_user(&self, password_hash: &str) -> StoreResult<UserId>;

    /// Get a user by ID
    fn get_user(&self, user_id: UserId) -> StoreResult<Option<User>>;

    /// Get a user by email address
    fn get_user_by_email(&self, email: &str) -> StoreResult<Option<User>>;

    /// Add an email to a user's account
    fn add_email(&self, user_id: UserId, email: &str, verified: bool) -> StoreResult<()>;

    /// List all emails for a user
    fn list_emails(&self, user_id: UserId) -> StoreResult<Vec<Email>>;

    /// Mark an email as verified
    fn verify_email(&self, email: &str) -> StoreResult<()>;

    /// Remove an email from a user's account
    fn remove_email(&self, user_id: UserId, email: &str) -> StoreResult<()>;

    /// Store a pending verification
    fn create_pending(&self, pending: PendingVerification) -> StoreResult<()>;

    /// Get a pending verification by secret
    fn get_pending(&self, secret: &str) -> StoreResult<Option<PendingVerification>>;

    /// Delete a pending verification
    fn delete_pending(&self, secret: &str) -> StoreResult<()>;

    /// Delete expired pending verifications (older than given duration)
    fn cleanup_expired_pending(&self, max_age_minutes: i64) -> StoreResult<u64>;

    /// Update a user's password hash
    fn update_password(&self, user_id: UserId, password_hash: &str) -> StoreResult<()>;

    /// Check if there's a pending password reset for an email
    fn has_pending_reset(&self, email: &str) -> StoreResult<bool>;

    /// Delete a user and all their associated data (emails, pending verifications)
    fn delete_user(&self, user_id: UserId) -> StoreResult<()>;

    /// Get pending verification by email and type
    fn get_pending_by_email(
        &self,
        email: &str,
        verification_type: VerificationType,
    ) -> StoreResult<Option<PendingVerification>>;
}

/// Trait for session storage
pub trait SessionStore: Send + Sync {
    /// Create a new session for a user
    fn create(&self, user_id: UserId) -> StoreResult<Session>;

    /// Get a session by ID
    fn get(&self, session_id: &SessionId) -> StoreResult<Option<Session>>;

    /// Delete a session
    fn delete(&self, session_id: &SessionId) -> StoreResult<()>;
}
