//! SQLite-based storage implementation

use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use super::{
    Email, PendingVerification, Session, SessionId, SessionStore, StoreResult, User, UserId,
    UserStore, VerificationType,
};
use crate::error::BrokerError;

/// Current schema version
const SCHEMA_VERSION: i32 = 1;

/// SQLite-based store implementing both UserStore and SessionStore
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open or create a SQLite database at the given path
    pub fn open(path: &str) -> Result<Self, BrokerError> {
        let conn = Connection::open(path).map_err(|e| BrokerError::Internal(e.to_string()))?;

        // Enable foreign keys
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        // Run migrations
        Self::migrate(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Run database migrations
    fn migrate(conn: &Connection) -> Result<(), BrokerError> {
        // Check current schema version
        let current_version = Self::get_schema_version(conn)?;

        if current_version < SCHEMA_VERSION {
            tracing::info!(
                current = current_version,
                target = SCHEMA_VERSION,
                "Running database migrations"
            );

            if current_version < 1 {
                Self::migrate_v1(conn)?;
            }

            // Update schema version
            conn.execute(
                "INSERT OR REPLACE INTO schema_version (version) VALUES (?1)",
                params![SCHEMA_VERSION],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

            tracing::info!("Database migrations complete");
        }

        Ok(())
    }

    /// Get current schema version (0 if no schema exists)
    fn get_schema_version(conn: &Connection) -> Result<i32, BrokerError> {
        // Check if schema_version table exists
        let table_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version')",
                [],
                |row| row.get(0),
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        if !table_exists {
            return Ok(0);
        }

        conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get::<_, Option<i32>>(0).map(|v| v.unwrap_or(0))
        })
        .map_err(|e| BrokerError::Internal(e.to_string()))
    }

    /// Migration to version 1: initial schema
    fn migrate_v1(conn: &Connection) -> Result<(), BrokerError> {
        conn.execute_batch(
            r#"
            -- Schema version tracking
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );

            -- Users table
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            -- Emails table (multiple per user)
            CREATE TABLE IF NOT EXISTS emails (
                email TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                verified INTEGER NOT NULL DEFAULT 0,
                verified_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_emails_user_id ON emails(user_id);

            -- Pending verifications
            CREATE TABLE IF NOT EXISTS pending_verifications (
                secret TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                password_hash TEXT,
                verification_type TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_pending_email ON pending_verifications(email);

            -- Sessions
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            "#,
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

        Ok(())
    }
}

// Helper to convert VerificationType to/from string
impl VerificationType {
    fn as_str(&self) -> &'static str {
        match self {
            VerificationType::NewAccount => "new_account",
            VerificationType::AddEmail => "add_email",
            VerificationType::PasswordReset => "password_reset",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "new_account" => Some(VerificationType::NewAccount),
            "add_email" => Some(VerificationType::AddEmail),
            "password_reset" => Some(VerificationType::PasswordReset),
            _ => None,
        }
    }
}

impl UserStore for SqliteStore {
    fn create_user(&self, password_hash: &str) -> StoreResult<UserId> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO users (password_hash, created_at) VALUES (?1, ?2)",
            params![password_hash, now],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

        let id = conn.last_insert_rowid() as u64;
        Ok(UserId(id))
    }

    fn get_user(&self, user_id: UserId) -> StoreResult<Option<User>> {
        let conn = self.conn.lock().unwrap();

        conn.query_row(
            "SELECT id, password_hash, created_at FROM users WHERE id = ?1",
            params![user_id.0 as i64],
            |row| {
                let id: i64 = row.get(0)?;
                let password_hash: String = row.get(1)?;
                let created_at: String = row.get(2)?;
                Ok(User {
                    id: UserId(id as u64),
                    password_hash,
                    created_at: DateTime::parse_from_rfc3339(&created_at)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            },
        )
        .optional()
        .map_err(|e| BrokerError::Internal(e.to_string()))
    }

    fn get_user_by_email(&self, email: &str) -> StoreResult<Option<User>> {
        let normalized = email.to_lowercase();
        let conn = self.conn.lock().unwrap();

        let user_id: Option<i64> = conn
            .query_row(
                "SELECT user_id FROM emails WHERE email = ?1",
                params![normalized],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        drop(conn); // Release lock before calling get_user

        match user_id {
            Some(id) => self.get_user(UserId(id as u64)),
            None => Ok(None),
        }
    }

    fn add_email(&self, user_id: UserId, email: &str, verified: bool) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let conn = self.conn.lock().unwrap();
        let verified_at = if verified {
            Some(Utc::now().to_rfc3339())
        } else {
            None
        };

        conn.execute(
            "INSERT INTO emails (email, user_id, verified, verified_at) VALUES (?1, ?2, ?3, ?4)",
            params![normalized, user_id.0 as i64, verified as i32, verified_at],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref err, _) = e {
                if err.code == rusqlite::ErrorCode::ConstraintViolation {
                    return BrokerError::EmailAlreadyExists;
                }
            }
            BrokerError::Internal(e.to_string())
        })?;

        Ok(())
    }

    fn list_emails(&self, user_id: UserId) -> StoreResult<Vec<Email>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn
            .prepare("SELECT email, user_id, verified, verified_at FROM emails WHERE user_id = ?1")
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        let emails = stmt
            .query_map(params![user_id.0 as i64], |row| {
                let email: String = row.get(0)?;
                let uid: i64 = row.get(1)?;
                let verified: i32 = row.get(2)?;
                let verified_at: Option<String> = row.get(3)?;
                Ok(Email {
                    email,
                    user_id: UserId(uid as u64),
                    verified: verified != 0,
                    verified_at: verified_at.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|dt| dt.with_timezone(&Utc))
                            .ok()
                    }),
                })
            })
            .map_err(|e| BrokerError::Internal(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        Ok(emails)
    }

    fn verify_email(&self, email: &str) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();

        let rows_affected = conn
            .execute(
                "UPDATE emails SET verified = 1, verified_at = ?1 WHERE email = ?2",
                params![now, normalized],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        if rows_affected == 0 {
            return Err(BrokerError::EmailNotFound);
        }

        Ok(())
    }

    fn remove_email(&self, user_id: UserId, email: &str) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let conn = self.conn.lock().unwrap();

        let rows_affected = conn
            .execute(
                "DELETE FROM emails WHERE email = ?1 AND user_id = ?2",
                params![normalized, user_id.0 as i64],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        if rows_affected == 0 {
            return Err(BrokerError::EmailNotFound);
        }

        Ok(())
    }

    fn create_pending(&self, pending: PendingVerification) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO pending_verifications (secret, email, user_id, password_hash, verification_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                pending.secret,
                pending.email,
                pending.user_id.map(|id| id.0 as i64),
                pending.password_hash,
                pending.verification_type.as_str(),
                pending.created_at.to_rfc3339(),
            ],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

        Ok(())
    }

    fn get_pending(&self, secret: &str) -> StoreResult<Option<PendingVerification>> {
        let conn = self.conn.lock().unwrap();

        conn.query_row(
            "SELECT secret, email, user_id, password_hash, verification_type, created_at
             FROM pending_verifications WHERE secret = ?1",
            params![secret],
            |row| {
                let secret: String = row.get(0)?;
                let email: String = row.get(1)?;
                let user_id: Option<i64> = row.get(2)?;
                let password_hash: Option<String> = row.get(3)?;
                let vtype: String = row.get(4)?;
                let created_at: String = row.get(5)?;
                Ok(PendingVerification {
                    secret,
                    email,
                    user_id: user_id.map(|id| UserId(id as u64)),
                    password_hash,
                    verification_type: VerificationType::from_str(&vtype)
                        .unwrap_or(VerificationType::NewAccount),
                    created_at: DateTime::parse_from_rfc3339(&created_at)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            },
        )
        .optional()
        .map_err(|e| BrokerError::Internal(e.to_string()))
    }

    fn delete_pending(&self, secret: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "DELETE FROM pending_verifications WHERE secret = ?1",
            params![secret],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

        Ok(())
    }

    fn cleanup_expired_pending(&self, max_age_minutes: i64) -> StoreResult<u64> {
        let conn = self.conn.lock().unwrap();
        let cutoff = (Utc::now() - chrono::Duration::minutes(max_age_minutes)).to_rfc3339();

        let rows_deleted = conn
            .execute(
                "DELETE FROM pending_verifications WHERE created_at < ?1",
                params![cutoff],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        Ok(rows_deleted as u64)
    }

    fn update_password(&self, user_id: UserId, password_hash: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();

        let rows_affected = conn
            .execute(
                "UPDATE users SET password_hash = ?1 WHERE id = ?2",
                params![password_hash, user_id.0 as i64],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        if rows_affected == 0 {
            return Err(BrokerError::UserNotFound);
        }

        Ok(())
    }

    fn has_pending_reset(&self, email: &str) -> StoreResult<bool> {
        let conn = self.conn.lock().unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_verifications WHERE email = ?1 AND verification_type = ?2",
                params![email, VerificationType::PasswordReset.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        Ok(count > 0)
    }

    fn delete_user(&self, user_id: UserId) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();

        // Foreign keys with ON DELETE CASCADE will handle emails and sessions
        conn.execute("DELETE FROM users WHERE id = ?1", params![user_id.0 as i64])
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        // Also clean up pending verifications for this user
        conn.execute(
            "DELETE FROM pending_verifications WHERE user_id = ?1",
            params![user_id.0 as i64],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

        Ok(())
    }

    fn get_pending_by_email(
        &self,
        email: &str,
        verification_type: VerificationType,
    ) -> StoreResult<Option<PendingVerification>> {
        let normalized = email.to_lowercase();
        let conn = self.conn.lock().unwrap();

        conn.query_row(
            "SELECT secret, email, user_id, password_hash, verification_type, created_at
             FROM pending_verifications
             WHERE LOWER(email) = ?1 AND verification_type = ?2",
            params![normalized, verification_type.as_str()],
            |row| {
                let secret: String = row.get(0)?;
                let email: String = row.get(1)?;
                let user_id: Option<i64> = row.get(2)?;
                let password_hash: Option<String> = row.get(3)?;
                let vtype: String = row.get(4)?;
                let created_at: String = row.get(5)?;
                Ok(PendingVerification {
                    secret,
                    email,
                    user_id: user_id.map(|id| UserId(id as u64)),
                    password_hash,
                    verification_type: VerificationType::from_str(&vtype)
                        .unwrap_or(VerificationType::NewAccount),
                    created_at: DateTime::parse_from_rfc3339(&created_at)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            },
        )
        .optional()
        .map_err(|e| BrokerError::Internal(e.to_string()))
    }
}

impl SessionStore for SqliteStore {
    fn create(&self, user_id: UserId) -> StoreResult<Session> {
        let conn = self.conn.lock().unwrap();
        let session = Session {
            id: SessionId(Uuid::new_v4().to_string()),
            user_id,
            csrf_token: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
        };

        conn.execute(
            "INSERT INTO sessions (id, user_id, csrf_token, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                session.id.0,
                session.user_id.0 as i64,
                session.csrf_token,
                session.created_at.to_rfc3339(),
            ],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

        Ok(session)
    }

    fn get(&self, session_id: &SessionId) -> StoreResult<Option<Session>> {
        let conn = self.conn.lock().unwrap();

        conn.query_row(
            "SELECT id, user_id, csrf_token, created_at FROM sessions WHERE id = ?1",
            params![session_id.0],
            |row| {
                let id: String = row.get(0)?;
                let user_id: i64 = row.get(1)?;
                let csrf_token: String = row.get(2)?;
                let created_at: String = row.get(3)?;
                Ok(Session {
                    id: SessionId(id),
                    user_id: UserId(user_id as u64),
                    csrf_token,
                    created_at: DateTime::parse_from_rfc3339(&created_at)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            },
        )
        .optional()
        .map_err(|e| BrokerError::Internal(e.to_string()))
    }

    fn delete(&self, session_id: &SessionId) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute("DELETE FROM sessions WHERE id = ?1", params![session_id.0])
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        Ok(())
    }
}

// Implement traits for Arc<SqliteStore> so the same store can be used for both UserStore and SessionStore
impl UserStore for std::sync::Arc<SqliteStore> {
    fn create_user(&self, password_hash: &str) -> StoreResult<UserId> {
        (**self).create_user(password_hash)
    }

    fn get_user(&self, user_id: UserId) -> StoreResult<Option<User>> {
        (**self).get_user(user_id)
    }

    fn get_user_by_email(&self, email: &str) -> StoreResult<Option<User>> {
        (**self).get_user_by_email(email)
    }

    fn add_email(&self, user_id: UserId, email: &str, verified: bool) -> StoreResult<()> {
        (**self).add_email(user_id, email, verified)
    }

    fn list_emails(&self, user_id: UserId) -> StoreResult<Vec<Email>> {
        (**self).list_emails(user_id)
    }

    fn verify_email(&self, email: &str) -> StoreResult<()> {
        (**self).verify_email(email)
    }

    fn remove_email(&self, user_id: UserId, email: &str) -> StoreResult<()> {
        (**self).remove_email(user_id, email)
    }

    fn create_pending(&self, pending: PendingVerification) -> StoreResult<()> {
        (**self).create_pending(pending)
    }

    fn get_pending(&self, secret: &str) -> StoreResult<Option<PendingVerification>> {
        (**self).get_pending(secret)
    }

    fn delete_pending(&self, secret: &str) -> StoreResult<()> {
        (**self).delete_pending(secret)
    }

    fn cleanup_expired_pending(&self, max_age_minutes: i64) -> StoreResult<u64> {
        (**self).cleanup_expired_pending(max_age_minutes)
    }

    fn update_password(&self, user_id: UserId, password_hash: &str) -> StoreResult<()> {
        (**self).update_password(user_id, password_hash)
    }

    fn has_pending_reset(&self, email: &str) -> StoreResult<bool> {
        (**self).has_pending_reset(email)
    }

    fn delete_user(&self, user_id: UserId) -> StoreResult<()> {
        (**self).delete_user(user_id)
    }

    fn get_pending_by_email(
        &self,
        email: &str,
        verification_type: VerificationType,
    ) -> StoreResult<Option<PendingVerification>> {
        (**self).get_pending_by_email(email, verification_type)
    }
}

impl SessionStore for std::sync::Arc<SqliteStore> {
    fn create(&self, user_id: UserId) -> StoreResult<Session> {
        (**self).create(user_id)
    }

    fn get(&self, session_id: &SessionId) -> StoreResult<Option<Session>> {
        (**self).get(session_id)
    }

    fn delete(&self, session_id: &SessionId) -> StoreResult<()> {
        (**self).delete(session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_store() -> (SqliteStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let store = SqliteStore::open(path.to_str().unwrap()).unwrap();
        (store, dir) // Return dir to keep it alive
    }

    #[test]
    fn test_create_user_and_email() {
        let (store, _dir) = create_test_store();

        let user_id = store.create_user("hashed_password").unwrap();
        store.add_email(user_id, "test@example.com", false).unwrap();

        let user = store.get_user_by_email("test@example.com").unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().id, user_id);
    }

    #[test]
    fn test_email_case_insensitive() {
        let (store, _dir) = create_test_store();

        let user_id = store.create_user("hashed_password").unwrap();
        store.add_email(user_id, "Test@Example.COM", false).unwrap();

        let user = store.get_user_by_email("test@example.com").unwrap();
        assert!(user.is_some());

        let user = store.get_user_by_email("TEST@EXAMPLE.COM").unwrap();
        assert!(user.is_some());
    }

    #[test]
    fn test_verify_email() {
        let (store, _dir) = create_test_store();

        let user_id = store.create_user("hashed_password").unwrap();
        store.add_email(user_id, "test@example.com", false).unwrap();

        let emails = store.list_emails(user_id).unwrap();
        assert!(!emails[0].verified);

        store.verify_email("test@example.com").unwrap();

        let emails = store.list_emails(user_id).unwrap();
        assert!(emails[0].verified);
        assert!(emails[0].verified_at.is_some());
    }

    #[test]
    fn test_pending_verification() {
        let (store, _dir) = create_test_store();

        let pending = PendingVerification {
            secret: "123456".to_string(),
            email: "test@example.com".to_string(),
            user_id: None,
            password_hash: Some("hashed".to_string()),
            verification_type: VerificationType::NewAccount,
            created_at: Utc::now(),
        };

        store.create_pending(pending.clone()).unwrap();

        let retrieved = store.get_pending("123456").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().email, "test@example.com");

        store.delete_pending("123456").unwrap();
        assert!(store.get_pending("123456").unwrap().is_none());
    }

    #[test]
    fn test_session_lifecycle() {
        let (store, _dir) = create_test_store();

        let user_id = store.create_user("hashed_password").unwrap();
        let session = store.create(user_id).unwrap();

        assert!(store.get(&session.id).unwrap().is_some());

        store.delete(&session.id).unwrap();
        assert!(store.get(&session.id).unwrap().is_none());
    }

    #[test]
    fn test_delete_user_cascades() {
        let (store, _dir) = create_test_store();

        let user_id = store.create_user("hashed_password").unwrap();
        store.add_email(user_id, "test@example.com", true).unwrap();
        let session = store.create(user_id).unwrap();

        // Delete user
        store.delete_user(user_id).unwrap();

        // User should be gone
        assert!(store.get_user(user_id).unwrap().is_none());

        // Email should be gone
        assert!(store.get_user_by_email("test@example.com").unwrap().is_none());

        // Session should be gone
        assert!(store.get(&session.id).unwrap().is_none());
    }

    #[test]
    fn test_duplicate_email_rejected() {
        let (store, _dir) = create_test_store();

        let user_id = store.create_user("hashed_password").unwrap();
        store.add_email(user_id, "test@example.com", false).unwrap();

        let result = store.add_email(user_id, "test@example.com", false);
        assert!(matches!(result, Err(BrokerError::EmailAlreadyExists)));
    }
}
