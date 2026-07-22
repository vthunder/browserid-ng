//! SQLite-based storage implementation

use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use super::{
    DeviceCertRecord, Email, EmailType, Namespace, PendingVerification, Session,
    SessionId, SessionStore, StoreResult, User, UserId, UserStore, VerificationType, WarrantRecord,
    WarrantRequestRecord, WarrantRequestStatus,
};
use crate::error::BrokerError;
use std::collections::HashMap;

/// Current schema version
const SCHEMA_VERSION: i32 = 17;

/// SQLite-based store implementing both UserStore and SessionStore
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open or create a SQLite database at the given path
    pub fn open(path: &str) -> Result<Self, BrokerError> {
        let conn = Connection::open(path).map_err(|e| BrokerError::Internal(e.to_string()))?;

        // Enable WAL mode for better concurrency
        conn.execute_batch("PRAGMA journal_mode = WAL;")
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        // Enable foreign keys
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        // Set busy timeout to wait for locks instead of failing immediately
        conn.busy_timeout(std::time::Duration::from_secs(5))
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

            if current_version < 2 {
                Self::migrate_v2(conn)?;
            }

            if current_version < 3 {
                Self::migrate_v3(conn)?;
            }

            if current_version < 4 {
                Self::migrate_v4(conn)?;
            }

            if current_version < 5 {
                Self::migrate_v5(conn)?;
            }
            if current_version < 6 {
                Self::migrate_v6(conn)?;
            }
            if current_version < 7 {
                Self::migrate_v7(conn)?;
            }
            if current_version < 8 {
                Self::migrate_v8(conn)?;
            }
            if current_version < 9 {
                Self::migrate_v9(conn)?;
            }
            if current_version < 10 {
                Self::migrate_v10(conn)?;
            }
            if current_version < 11 {
                Self::migrate_v11(conn)?;
            }
            if current_version < 12 {
                Self::migrate_v12(conn)?;
            }
            if current_version < 13 {
                Self::migrate_v13(conn)?;
            }
            if current_version < 14 {
                Self::migrate_v14(conn)?;
            }
            if current_version < 15 {
                Self::migrate_v15(conn)?;
            }
            if current_version < 16 {
                Self::migrate_v16(conn)?;
            }
            if current_version < 17 {
                Self::migrate_v17(conn)?;
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

    /// Migration to version 2: add email type tracking for primary IdP support
    fn migrate_v2(conn: &Connection) -> Result<(), BrokerError> {
        conn.execute_batch(
            r#"
            -- Add type column (primary or secondary)
            ALTER TABLE emails ADD COLUMN email_type TEXT NOT NULL DEFAULT 'secondary';

            -- Add last_used_as column (tracks type at last use for transitions)
            ALTER TABLE emails ADD COLUMN last_used_as TEXT NOT NULL DEFAULT 'secondary';
            "#,
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

        Ok(())
    }

    fn migrate_v3(conn: &Connection) -> Result<(), BrokerError> {
        // Parent email for subordinate/derived identities (mingo-cm8z). Nullable;
        // references another email in the same account. Private account metadata.
        conn.execute_batch("ALTER TABLE emails ADD COLUMN parent_email TEXT;")
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn migrate_v4(conn: &Connection) -> Result<(), BrokerError> {
        // Per-user API keys for headless agent provisioning (l8lw). Only the
        // SHA-256 of the secret is stored; parent_email is the attribution
        // root for identities minted with the key.
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                key_hash TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                parent_email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
            "#,
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn migrate_v5(conn: &Connection) -> Result<(), BrokerError> {
        // Registered provisioning certificates (tdxf, spec v0.2). Replaces the
        // v4 bearer-key scheme: the broker holds only public delegation data,
        // never a secret. The dead `api_keys` table (v4) is left in place —
        // it never carried real users, and a DROP is riskier than an unused
        // table.
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS provisioning_certs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                delegator_email TEXT NOT NULL,
                provisioning_pub TEXT NOT NULL UNIQUE,
                bundle TEXT NOT NULL,
                label TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_endorsed_at TEXT,
                revoked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_prov_certs_user ON provisioning_certs(user_id);
            "#,
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn migrate_v6(conn: &Connection) -> Result<(), BrokerError> {
        // Warrant consent requests (agent spec §6, v0.4). Short-lived rows:
        // deleted on delivery (privacy: the broker keeps no record of where
        // warrants apply) and swept when expired. Scopes stored as a JSON
        // array string.
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS warrant_requests (
                code TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                delegator_email TEXT NOT NULL,
                agent_email TEXT NOT NULL,
                label TEXT NOT NULL,
                audience TEXT NOT NULL,
                scopes TEXT NOT NULL,
                status TEXT NOT NULL,
                warrant TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_polled_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_warrant_requests_user ON warrant_requests(user_id);
            "#,
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn migrate_v7(conn: &Connection) -> Result<(), BrokerError> {
        // Batch consent (g0ba): a request now carries N grants and N signed
        // warrants. Rows are 15-minute ephemera, so drop-and-recreate is
        // safe — no data worth migrating can exist.
        conn.execute_batch(
            r#"
            DROP TABLE IF EXISTS warrant_requests;
            CREATE TABLE warrant_requests (
                code TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                delegator_email TEXT NOT NULL,
                agent_email TEXT NOT NULL,
                label TEXT NOT NULL,
                grants TEXT NOT NULL,
                status TEXT NOT NULL,
                warrants TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_polled_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_warrant_requests_user ON warrant_requests(user_id);
            "#,
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn migrate_v8(conn: &Connection) -> Result<(), BrokerError> {
        // Warrant registry (jipx): the delegator's own record of issued
        // warrants — reviewable cross-browser, upserted per
        // (user, agent, audience) so reissues replace their predecessor.
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS warrants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                delegator_email TEXT NOT NULL,
                agent_email TEXT NOT NULL,
                audience TEXT NOT NULL,
                scopes TEXT NOT NULL,
                warrant TEXT NOT NULL,
                signed_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                UNIQUE(user_id, agent_email, audience)
            );
            CREATE INDEX IF NOT EXISTS idx_warrants_user ON warrants(user_id);
            "#,
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn migrate_v9(conn: &Connection) -> Result<(), BrokerError> {
        // Status entries (egr7): the revocation bitmap's index space. One
        // stable index per (kind, subject) — identity emails and warrant
        // grants — so a single bit covers every outstanding credential for
        // its subject. Also: warrants learn their status index.
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS status_entries (
                idx INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                subject TEXT NOT NULL,
                revoked_at TEXT,
                UNIQUE(kind, subject)
            );
            ALTER TABLE warrants ADD COLUMN status_idx INTEGER;
            "#,
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn migrate_v10(conn: &Connection) -> Result<(), BrokerError> {
        // e85i: a grant's identity is (audience, scopes), not audience alone
        // — the same agent may hold two warrants at one audience differing
        // only in scopes. Rebuild the warrants UNIQUE key with an opaque
        // scope fingerprint (the broker hashes scopes, never interprets
        // them), backfilling existing rows.
        conn.execute_batch(
            r#"
            BEGIN IMMEDIATE;
            ALTER TABLE warrants RENAME TO warrants_v9;
            CREATE TABLE warrants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                delegator_email TEXT NOT NULL,
                agent_email TEXT NOT NULL,
                audience TEXT NOT NULL,
                scopes TEXT NOT NULL,
                scope_hash TEXT NOT NULL DEFAULT '',
                warrant TEXT NOT NULL,
                signed_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status_idx INTEGER,
                UNIQUE(user_id, agent_email, audience, scope_hash)
            );
            INSERT INTO warrants (id, user_id, delegator_email, agent_email, audience, scopes, warrant, signed_at, expires_at, status_idx)
                SELECT id, user_id, delegator_email, agent_email, audience, scopes, warrant, signed_at, expires_at, status_idx FROM warrants_v9;
            DROP TABLE warrants_v9;
            CREATE INDEX IF NOT EXISTS idx_warrants_user ON warrants(user_id);
            COMMIT;
            "#,
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;

        // Backfill the fingerprint from each row's scopes JSON.
        let mut stmt = conn
            .prepare("SELECT id, scopes FROM warrants")
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        let rows: Vec<(i64, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| BrokerError::Internal(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        drop(stmt);
        for (id, scopes_json) in rows {
            let scopes: Vec<String> = serde_json::from_str(&scopes_json).unwrap_or_default();
            conn.execute(
                "UPDATE warrants SET scope_hash = ?1 WHERE id = ?2",
                params![browserid_registrar::scope_fingerprint(&scopes), id],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        }
        Ok(())
    }

    fn migrate_v11(conn: &Connection) -> Result<(), BrokerError> {
        // External warrant requests (§6.6): the pending row records whether
        // it was raised by a foreign-IdP service (redirect-tied, excluded
        // from the inbox, rate-limited per delegator).
        conn.execute_batch(
            "ALTER TABLE warrant_requests ADD COLUMN external INTEGER NOT NULL DEFAULT 0;",
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn migrate_v12(conn: &Connection) -> Result<(), BrokerError> {
        // Device-cert model (DC Phase 3/4): the durable, revocable record of
        // IdP-signed device/config certs, plus device-model columns on the
        // warrant registry. `status_entries.kind` gains 'device'/'access'/
        // 'config' usage (free-text — no schema change).
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS device_certs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                identities TEXT NOT NULL,
                purpose TEXT NOT NULL,
                subject TEXT NOT NULL,
                pubkey TEXT NOT NULL UNIQUE,
                iss TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                status_idx INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_device_certs_user ON device_certs(user_id);
            ALTER TABLE warrants ADD COLUMN subject TEXT;
            ALTER TABLE warrants ADD COLUMN config_cert TEXT;
            "#,
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn migrate_v13(conn: &Connection) -> Result<(), BrokerError> {
        // Retire the legacy delegation chain (device-cert model replaces it):
        // drop the provisioning-cert registry and the long-dead api_keys table.
        // Irreversible under the clean cutover — in-flight agent delegations are
        // orphaned server-side, which is intended.
        conn.execute_batch(
            r#"
            DROP TABLE IF EXISTS provisioning_certs;
            DROP TABLE IF EXISTS api_keys;
            "#,
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn migrate_v14(conn: &Connection) -> Result<(), BrokerError> {
        // Holder-authorization model: the device-cert `subject` axis
        // (user|agent) becomes an opaque broker-assigned `holder`, and warrants
        // carry a holder matcher instead of a subject. Rename the columns in
        // place, and add the per-user namespace registry that stores the random
        // prefix each holder id is minted under (persisted so re-categorize can
        // rotate it later).
        conn.execute_batch(
            r#"
            ALTER TABLE device_certs RENAME COLUMN subject TO holder;
            ALTER TABLE warrants RENAME COLUMN subject TO holder;
            CREATE TABLE IF NOT EXISTS namespaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                prefix TEXT NOT NULL,
                label TEXT NOT NULL,
                UNIQUE(user_id, name)
            );
            CREATE INDEX IF NOT EXISTS idx_namespaces_user ON namespaces(user_id);
            "#,
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn migrate_v15(conn: &Connection) -> Result<(), BrokerError> {
        // Holder-authorization model, account UI (stage 2b): friendly labels for
        // opaque holder ids — the logical-slot name ("Main Laptop"). The holder
        // id itself lives on device_certs; this is a pure display-name side table.
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS holder_labels (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                holder_id TEXT NOT NULL,
                label TEXT NOT NULL,
                UNIQUE(user_id, holder_id)
            );
            CREATE INDEX IF NOT EXISTS idx_holder_labels_user ON holder_labels(user_id);
            "#,
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn migrate_v16(conn: &Connection) -> Result<(), BrokerError> {
        // Holder-authorization model (stage 3): a warrant request carries the
        // requesting agent's opaque holder (from its device cert) so the consent
        // page can bind the signed warrant to it (`<id>`) or its `<ns>.*` prefix.
        conn.execute(
            "ALTER TABLE warrant_requests ADD COLUMN holder TEXT NOT NULL DEFAULT '';",
            [],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn migrate_v17(conn: &Connection) -> Result<(), BrokerError> {
        // Holder-authorization model: drop pre-migration device-cert / warrant
        // rows whose `holder` is the old subject value (`user`/`agent`, renamed
        // in place by migrate_v14). Their stored JWS still carries the removed
        // `subject` field, so they are unverifiable against the new core and only
        // clutter the account "Devices & holders" view. Real holders are always a
        // dotted `<prefix>.<rand>`, so this can never match a live holder.
        conn.execute_batch(
            r#"
            DELETE FROM device_certs WHERE holder IN ('user', 'agent');
            DELETE FROM warrants WHERE holder IN ('user', 'agent');
            "#,
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }
}

// Row → DeviceCertRecord mapping (DC Phase 3/4)
fn device_cert_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceCertRecord> {
    let parse_ts = |s: String| {
        DateTime::parse_from_rfc3339(&s)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now())
    };
    let parse_ts_opt = |s: Option<String>| {
        s.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        })
    };
    let id: i64 = row.get(0)?;
    let user_id: i64 = row.get(1)?;
    let identities_json: String = row.get(2)?;
    let status_idx: Option<i64> = row.get(10)?;
    Ok(DeviceCertRecord {
        id: id as u64,
        user_id: UserId(user_id as u64),
        identities: serde_json::from_str(&identities_json).unwrap_or_default(),
        purpose: row.get(3)?,
        holder: row.get(4)?,
        pubkey: row.get(5)?,
        iss: row.get(6)?,
        issued_at: parse_ts(row.get(7)?),
        expires_at: parse_ts(row.get(8)?),
        revoked_at: parse_ts_opt(row.get(9)?),
        status_idx: status_idx.map(|i| i as u64),
    })
}

const DEVICE_CERT_COLUMNS: &str =
    "id, user_id, identities, purpose, holder, pubkey, iss, issued_at, expires_at, revoked_at, status_idx";

// Row → WarrantRecord mapping (jipx registry)
fn warrant_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WarrantRecord> {
    let parse_ts = |s: String| {
        DateTime::parse_from_rfc3339(&s)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now())
    };
    let id: i64 = row.get(0)?;
    let user_id: i64 = row.get(1)?;
    let scopes_json: String = row.get(5)?;
    let status_idx: Option<i64> = row.get(9)?;
    Ok(WarrantRecord {
        id: id as u64,
        user_id: UserId(user_id as u64),
        delegator_email: row.get(2)?,
        agent_email: row.get(3)?,
        audience: row.get(4)?,
        scopes: serde_json::from_str(&scopes_json).unwrap_or_default(),
        warrant: row.get(6)?,
        status_idx: status_idx.map(|i| i as u64),
        holder: row.get(10)?,
        config_cert: row.get(11)?,
        signed_at: parse_ts(row.get(7)?),
        expires_at: parse_ts(row.get(8)?),
    })
}

const WARRANT_COLUMNS: &str =
    "id, user_id, delegator_email, agent_email, audience, scopes, warrant, signed_at, expires_at, status_idx, holder, config_cert";

// Row → WarrantRequestRecord mapping
fn warrant_request_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WarrantRequestRecord> {
    let parse_ts_opt = |s: Option<String>| {
        s.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        })
    };
    let parse_ts = |s: String| {
        DateTime::parse_from_rfc3339(&s)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now())
    };
    let user_id: i64 = row.get(1)?;
    let grants_json: String = row.get(5)?;
    let status_str: String = row.get(6)?;
    let warrants_json: Option<String> = row.get(7)?;
    Ok(WarrantRequestRecord {
        code: row.get(0)?,
        user_id: UserId(user_id as u64),
        delegator_email: row.get(2)?,
        agent_email: row.get(3)?,
        label: row.get(4)?,
        grants: serde_json::from_str(&grants_json).unwrap_or_default(),
        status: WarrantRequestStatus::from_str(&status_str)
            .unwrap_or(WarrantRequestStatus::Pending),
        warrants: warrants_json.and_then(|w| serde_json::from_str(&w).ok()),
        external: row.get::<_, i64>(11)? != 0,
        holder: row.get(12)?,
        created_at: parse_ts(row.get(8)?),
        expires_at: parse_ts(row.get(9)?),
        last_polled_at: parse_ts_opt(row.get(10)?),
    })
}

const WARRANT_REQ_COLUMNS: &str = "code, user_id, delegator_email, agent_email, label, grants, status, warrants, created_at, expires_at, last_polled_at, external, holder";

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

    fn create_user_no_password(&self) -> StoreResult<UserId> {
        // Use empty string as sentinel for "no password"
        self.create_user("")
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
        // Default to secondary type for backwards compatibility
        self.add_email_with_type(user_id, email, verified, EmailType::Secondary)
    }

    fn add_email_with_type(
        &self,
        user_id: UserId,
        email: &str,
        verified: bool,
        email_type: EmailType,
    ) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let conn = self.conn.lock().unwrap();
        let verified_at = if verified {
            Some(Utc::now().to_rfc3339())
        } else {
            None
        };
        let type_str = email_type.as_str();

        conn.execute(
            "INSERT INTO emails (email, user_id, verified, verified_at, email_type, last_used_as) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![normalized, user_id.0 as i64, verified as i32, verified_at, type_str, type_str],
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
            .prepare("SELECT email, user_id, verified, verified_at, email_type, last_used_as, parent_email FROM emails WHERE user_id = ?1")
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        let emails = stmt
            .query_map(params![user_id.0 as i64], |row| {
                let email: String = row.get(0)?;
                let uid: i64 = row.get(1)?;
                let verified: i32 = row.get(2)?;
                let verified_at: Option<String> = row.get(3)?;
                let email_type_str: String = row.get(4)?;
                let last_used_as_str: String = row.get(5)?;
                Ok(Email {
                    email,
                    user_id: UserId(uid as u64),
                    verified: verified != 0,
                    verified_at: verified_at.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|dt| dt.with_timezone(&Utc))
                            .ok()
                    }),
                    email_type: EmailType::from_str(&email_type_str)
                        .unwrap_or(EmailType::Secondary),
                    last_used_as: EmailType::from_str(&last_used_as_str)
                        .unwrap_or(EmailType::Secondary),
                    parent_email: row.get::<_, Option<String>>(6)?,
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

    fn transfer_email(&self, email: &str, to_user_id: UserId) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .execute(
                "UPDATE emails SET user_id = ?1 WHERE email = ?2",
                params![to_user_id.0 as i64, normalized],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        if rows == 0 {
            return Err(BrokerError::EmailNotFound);
        }
        Ok(())
    }

    fn set_parent_email(&self, email: &str, parent_email: Option<&str>) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let parent = parent_email.map(|p| p.to_lowercase());
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .execute(
                "UPDATE emails SET parent_email = ?1 WHERE email = ?2",
                params![parent, normalized],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        if rows == 0 {
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

    fn update_email_last_used(&self, email: &str, email_type: EmailType) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let conn = self.conn.lock().unwrap();

        let rows_affected = conn
            .execute(
                "UPDATE emails SET last_used_as = ?1 WHERE email = ?2",
                params![email_type.as_str(), normalized],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        if rows_affected == 0 {
            return Err(BrokerError::EmailNotFound);
        }

        Ok(())
    }

    fn get_email(&self, email: &str) -> StoreResult<Option<Email>> {
        let normalized = email.to_lowercase();
        let conn = self.conn.lock().unwrap();

        conn.query_row(
            "SELECT email, user_id, verified, verified_at, email_type, last_used_as, parent_email FROM emails WHERE email = ?1",
            params![normalized],
            |row| {
                let email: String = row.get(0)?;
                let uid: i64 = row.get(1)?;
                let verified: i32 = row.get(2)?;
                let verified_at: Option<String> = row.get(3)?;
                let email_type_str: String = row.get(4)?;
                let last_used_as_str: String = row.get(5)?;
                Ok(Email {
                    email,
                    user_id: UserId(uid as u64),
                    verified: verified != 0,
                    verified_at: verified_at.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|dt| dt.with_timezone(&Utc))
                            .ok()
                    }),
                    email_type: EmailType::from_str(&email_type_str)
                        .unwrap_or(EmailType::Secondary),
                    last_used_as: EmailType::from_str(&last_used_as_str)
                        .unwrap_or(EmailType::Secondary),
                    parent_email: row.get::<_, Option<String>>(6)?,
                })
            },
        )
        .optional()
        .map_err(|e| BrokerError::Internal(e.to_string()))
    }

    fn has_password(&self, user_id: UserId) -> StoreResult<bool> {
        let conn = self.conn.lock().unwrap();

        let password_hash: Option<String> = conn
            .query_row(
                "SELECT password_hash FROM users WHERE id = ?1",
                params![user_id.0 as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| BrokerError::Internal(e.to_string()))?;

        // User has a password if password_hash exists and is non-empty
        Ok(password_hash.map(|h| !h.is_empty()).unwrap_or(false))
    }

    fn set_password(&self, user_id: UserId, password_hash: &str) -> StoreResult<()> {
        // Delegate to update_password which has the same behavior
        self.update_password(user_id, password_hash)
    }

    fn unverify_email(&self, email: &str) -> StoreResult<()> {
        let normalized = email.to_lowercase();
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .execute(
                "UPDATE emails SET verified = 0, verified_at = NULL WHERE email = ?1",
                params![normalized],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        if rows == 0 {
            return Err(BrokerError::EmailNotFound);
        }
        Ok(())
    }

    fn create_warrant_request(&self, req: WarrantRequestRecord) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO warrant_requests (code, user_id, delegator_email, agent_email, label, grants, status, warrants, created_at, expires_at, external, holder)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                req.code,
                req.user_id.0 as i64,
                req.delegator_email,
                req.agent_email,
                req.label,
                serde_json::to_string(&req.grants).unwrap_or_else(|_| "[]".into()),
                req.status.as_str(),
                req.warrants.as_ref().map(|w| serde_json::to_string(w).unwrap_or_else(|_| "[]".into())),
                req.created_at.to_rfc3339(),
                req.expires_at.to_rfc3339(),
                req.external as i64,
                req.holder,
            ],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn get_warrant_request(&self, code: &str) -> StoreResult<Option<WarrantRequestRecord>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            &format!("SELECT {WARRANT_REQ_COLUMNS} FROM warrant_requests WHERE code = ?1"),
            params![code],
            warrant_request_from_row,
        )
        .optional()
        .map_err(|e| BrokerError::Internal(e.to_string()))
    }

    fn list_pending_warrant_requests(
        &self,
        user_id: UserId,
    ) -> StoreResult<Vec<WarrantRequestRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {WARRANT_REQ_COLUMNS} FROM warrant_requests
                 WHERE user_id = ?1 AND status = 'pending' AND expires_at > ?2
                 ORDER BY created_at"
            ))
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        let reqs = stmt
            .query_map(
                params![user_id.0 as i64, Utc::now().to_rfc3339()],
                warrant_request_from_row,
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(reqs)
    }

    fn respond_warrant_request(
        &self,
        user_id: UserId,
        code: &str,
        warrants: Option<&[String]>,
    ) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let (status, warrants_val) = match warrants {
            Some(w) => (
                "approved",
                Some(serde_json::to_string(w).unwrap_or_else(|_| "[]".into())),
            ),
            None => ("denied", None),
        };
        let rows = conn
            .execute(
                "UPDATE warrant_requests SET status = ?1, warrants = ?2
                 WHERE code = ?3 AND user_id = ?4 AND status = 'pending' AND expires_at > ?5",
                params![status, warrants_val, code, user_id.0 as i64, Utc::now().to_rfc3339()],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        if rows == 0 {
            return Err(BrokerError::WarrantRequestNotFound);
        }
        Ok(())
    }

    fn touch_warrant_poll(&self, code: &str) -> StoreResult<Option<DateTime<Utc>>> {
        let conn = self.conn.lock().unwrap();
        let prev: Option<Option<String>> = conn
            .query_row(
                "SELECT last_polled_at FROM warrant_requests WHERE code = ?1",
                params![code],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        let Some(prev) = prev else {
            return Err(BrokerError::WarrantRequestNotFound);
        };
        conn.execute(
            "UPDATE warrant_requests SET last_polled_at = ?1 WHERE code = ?2",
            params![Utc::now().to_rfc3339(), code],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(prev.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        }))
    }

    fn delete_warrant_request(&self, code: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM warrant_requests WHERE code = ?1", params![code])
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn cleanup_expired_warrant_requests(&self) -> StoreResult<u64> {
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .execute(
                "DELETE FROM warrant_requests WHERE expires_at <= ?1",
                params![Utc::now().to_rfc3339()],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(rows as u64)
    }

    fn upsert_warrant(&self, record: WarrantRecord) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO warrants (user_id, delegator_email, agent_email, audience, scopes, scope_hash, warrant, signed_at, expires_at, status_idx, holder, config_cert)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(user_id, agent_email, audience, scope_hash) DO UPDATE SET
               delegator_email = excluded.delegator_email,
               scopes = excluded.scopes,
               warrant = excluded.warrant,
               signed_at = excluded.signed_at,
               expires_at = excluded.expires_at,
               status_idx = excluded.status_idx,
               holder = excluded.holder,
               config_cert = excluded.config_cert",
            params![
                record.user_id.0 as i64,
                record.delegator_email,
                record.agent_email,
                record.audience,
                serde_json::to_string(&record.scopes).unwrap_or_else(|_| "[]".into()),
                browserid_registrar::scope_fingerprint(&record.scopes),
                record.warrant,
                record.signed_at.to_rfc3339(),
                record.expires_at.to_rfc3339(),
                record.status_idx.map(|i| i as i64),
                record.holder,
                record.config_cert,
            ],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn list_warrants(&self, user_id: UserId) -> StoreResult<Vec<WarrantRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {WARRANT_COLUMNS} FROM warrants WHERE user_id = ?1 ORDER BY signed_at DESC"
            ))
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        let records = stmt
            .query_map(params![user_id.0 as i64], warrant_record_from_row)
            .map_err(|e| BrokerError::Internal(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(records)
    }

    fn delete_warrant(&self, user_id: UserId, warrant_id: u64) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .execute(
                "DELETE FROM warrants WHERE id = ?1 AND user_id = ?2",
                params![warrant_id as i64, user_id.0 as i64],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        if rows == 0 {
            return Err(BrokerError::WarrantRequestNotFound);
        }
        Ok(())
    }

    fn get_or_allocate_status(&self, kind: &str, subject: &str) -> StoreResult<u64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO status_entries (kind, subject) VALUES (?1, ?2)",
            params![kind, subject],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        let idx: i64 = conn
            .query_row(
                "SELECT idx FROM status_entries WHERE kind = ?1 AND subject = ?2",
                params![kind, subject],
                |r| r.get(0),
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(idx as u64)
    }

    fn set_status_revoked(&self, kind: &str, subject: &str) -> StoreResult<bool> {
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .execute(
                "UPDATE status_entries SET revoked_at = COALESCE(revoked_at, ?1) WHERE kind = ?2 AND subject = ?3",
                params![Utc::now().to_rfc3339(), kind, subject],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(rows > 0)
    }

    fn set_status_revoked_idx(&self, idx: u64) -> StoreResult<bool> {
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .execute(
                "UPDATE status_entries SET revoked_at = COALESCE(revoked_at, ?1) WHERE idx = ?2",
                params![Utc::now().to_rfc3339(), idx as i64],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(rows > 0)
    }

    fn is_status_revoked_idx(&self, idx: u64) -> StoreResult<bool> {
        let conn = self.conn.lock().unwrap();
        let revoked: Option<Option<String>> = conn
            .query_row(
                "SELECT revoked_at FROM status_entries WHERE idx = ?1",
                params![idx as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(matches!(revoked, Some(Some(_))))
    }

    fn revoked_status_indices(&self) -> StoreResult<(Vec<u64>, u64)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT idx FROM status_entries WHERE revoked_at IS NOT NULL")
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        let revoked = stmt
            .query_map([], |r| r.get::<_, i64>(0))
            .map_err(|e| BrokerError::Internal(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| BrokerError::Internal(e.to_string()))?
            .into_iter()
            .map(|i| i as u64)
            .collect();
        let max: i64 = conn
            .query_row("SELECT COALESCE(MAX(idx), 0) FROM status_entries", [], |r| r.get(0))
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok((revoked, max as u64))
    }

    fn insert_device_cert(&self, mut rec: DeviceCertRecord) -> StoreResult<u64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO device_certs (user_id, identities, purpose, holder, pubkey, iss, issued_at, expires_at, revoked_at, status_idx)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(pubkey) DO UPDATE SET
               identities = excluded.identities,
               purpose = excluded.purpose,
               holder = excluded.holder,
               iss = excluded.iss,
               issued_at = excluded.issued_at,
               expires_at = excluded.expires_at,
               status_idx = excluded.status_idx",
            params![
                rec.user_id.0 as i64,
                serde_json::to_string(&rec.identities).unwrap_or_else(|_| "[]".into()),
                rec.purpose,
                rec.holder,
                rec.pubkey,
                rec.iss,
                rec.issued_at.to_rfc3339(),
                rec.expires_at.to_rfc3339(),
                rec.revoked_at.map(|t| t.to_rfc3339()),
                rec.status_idx.map(|i| i as i64),
            ],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        let id: i64 = conn
            .query_row(
                "SELECT id FROM device_certs WHERE pubkey = ?1",
                params![rec.pubkey],
                |r| r.get(0),
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        rec.id = id as u64;
        Ok(rec.id)
    }

    fn get_device_cert_by_pubkey(&self, pubkey: &str) -> StoreResult<Option<DeviceCertRecord>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            &format!("SELECT {DEVICE_CERT_COLUMNS} FROM device_certs WHERE pubkey = ?1"),
            params![pubkey],
            device_cert_from_row,
        )
        .optional()
        .map_err(|e| BrokerError::Internal(e.to_string()))
    }

    fn list_device_certs(&self, user_id: UserId) -> StoreResult<Vec<DeviceCertRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {DEVICE_CERT_COLUMNS} FROM device_certs WHERE user_id = ?1 ORDER BY id"
            ))
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        let certs = stmt
            .query_map(params![user_id.0 as i64], device_cert_from_row)
            .map_err(|e| BrokerError::Internal(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(certs)
    }

    fn revoke_device_cert(&self, user_id: UserId, cert_id: u64) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .execute(
                "UPDATE device_certs SET revoked_at = COALESCE(revoked_at, ?1) WHERE id = ?2 AND user_id = ?3",
                params![Utc::now().to_rfc3339(), cert_id as i64, user_id.0 as i64],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        if rows == 0 {
            return Err(BrokerError::DeviceCertNotFound);
        }
        Ok(())
    }

    fn forget_holder(&self, user_id: UserId, holder: &str) -> StoreResult<u64> {
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .execute(
                "DELETE FROM device_certs WHERE user_id = ?1 AND holder = ?2",
                params![user_id.0 as i64, holder],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        conn.execute(
            "DELETE FROM holder_labels WHERE user_id = ?1 AND holder_id = ?2",
            params![user_id.0 as i64, holder],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(rows as u64)
    }

    fn get_or_create_namespace(&self, user_id: UserId, name: &str) -> StoreResult<String> {
        let conn = self.conn.lock().unwrap();
        // Insert a fresh prefix on first use; ignore on conflict so concurrent
        // callers converge on one row, then read the stored prefix back.
        let label = title_case(name);
        conn.execute(
            "INSERT OR IGNORE INTO namespaces (user_id, name, prefix, label) VALUES (?1, ?2, ?3, ?4)",
            params![
                user_id.0 as i64,
                name,
                crate::crypto::generate_namespace_prefix(),
                label,
            ],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        conn.query_row(
            "SELECT prefix FROM namespaces WHERE user_id = ?1 AND name = ?2",
            params![user_id.0 as i64, name],
            |row| row.get(0),
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))
    }

    fn adopt_namespace_prefix(
        &self,
        user_id: UserId,
        name: &str,
        new_prefix: &str,
    ) -> StoreResult<bool> {
        let conn = self.conn.lock().unwrap();
        // Ensure the row exists (same converge-on-one-row insert as get_or_create).
        conn.execute(
            "INSERT OR IGNORE INTO namespaces (user_id, name, prefix, label) VALUES (?1, ?2, ?3, ?4)",
            params![
                user_id.0 as i64,
                name,
                crate::crypto::generate_namespace_prefix(),
                title_case(name),
            ],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        let current: String = conn
            .query_row(
                "SELECT prefix FROM namespaces WHERE user_id = ?1 AND name = ?2",
                params![user_id.0 as i64, name],
                |row| row.get(0),
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        if current == new_prefix {
            return Ok(true);
        }
        // Only adopt while the namespace is unused — no recorded cert carries
        // its current prefix (a fresh account's first cold login). Otherwise
        // existing holders/warrants under the current prefix would orphan.
        let in_use: i64 = conn
            .query_row(
                // `current` is our own generated base32 prefix — no LIKE metachars.
                "SELECT COUNT(*) FROM device_certs WHERE user_id = ?1 AND holder LIKE ?2",
                params![user_id.0 as i64, format!("{current}.%")],
                |row| row.get(0),
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        if in_use > 0 {
            return Ok(false);
        }
        conn.execute(
            "UPDATE namespaces SET prefix = ?3 WHERE user_id = ?1 AND name = ?2",
            params![user_id.0 as i64, name, new_prefix],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(true)
    }

    fn list_namespaces(&self, user_id: UserId) -> StoreResult<Vec<Namespace>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT name, prefix, label FROM namespaces WHERE user_id = ?1 ORDER BY name")
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        let rows = stmt
            .query_map(params![user_id.0 as i64], |row| {
                Ok(Namespace { name: row.get(0)?, prefix: row.get(1)?, label: row.get(2)? })
            })
            .map_err(|e| BrokerError::Internal(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(rows)
    }

    fn set_namespace_label(&self, user_id: UserId, name: &str, label: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .execute(
                "UPDATE namespaces SET label = ?1 WHERE user_id = ?2 AND name = ?3",
                params![label, user_id.0 as i64, name],
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        if rows == 0 {
            return Err(BrokerError::PolicyRefused("no such namespace".into()));
        }
        Ok(())
    }

    fn create_namespace(&self, user_id: UserId, name: &str, label: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO namespaces (user_id, name, prefix, label) VALUES (?1, ?2, ?3, ?4)",
            params![
                user_id.0 as i64,
                name,
                crate::crypto::generate_namespace_prefix(),
                label,
            ],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn delete_namespace(&self, user_id: UserId, name: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        // Block if non-empty: any device-cert holder living under this prefix.
        let prefix: Option<String> = conn
            .query_row(
                "SELECT prefix FROM namespaces WHERE user_id = ?1 AND name = ?2",
                params![user_id.0 as i64, name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        let Some(prefix) = prefix else {
            return Err(BrokerError::PolicyRefused("no such namespace".into()));
        };
        // Prefixes are base32 (no SQL-LIKE metacharacters), so a plain LIKE is safe.
        let like = format!("{prefix}.%");
        let in_use: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM device_certs WHERE user_id = ?1 AND holder LIKE ?2",
                params![user_id.0 as i64, like],
                |row| row.get(0),
            )
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        if in_use > 0 {
            return Err(BrokerError::PolicyRefused(
                "namespace is not empty — revoke its holders first".into(),
            ));
        }
        conn.execute(
            "DELETE FROM namespaces WHERE user_id = ?1 AND name = ?2",
            params![user_id.0 as i64, name],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn set_holder_label(&self, user_id: UserId, holder_id: &str, label: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO holder_labels (user_id, holder_id, label) VALUES (?1, ?2, ?3)
             ON CONFLICT(user_id, holder_id) DO UPDATE SET label = excluded.label",
            params![user_id.0 as i64, holder_id, label],
        )
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(())
    }

    fn get_holder_labels(&self, user_id: UserId) -> StoreResult<HashMap<String, String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT holder_id, label FROM holder_labels WHERE user_id = ?1")
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        let rows = stmt
            .query_map(params![user_id.0 as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| BrokerError::Internal(e.to_string()))?
            .collect::<Result<HashMap<_, _>, _>>()
            .map_err(|e| BrokerError::Internal(e.to_string()))?;
        Ok(rows)
    }
}

/// Title-case a namespace name for its default label ("browsers" → "Browsers").
fn title_case(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
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

    fn transfer_email(&self, email: &str, to_user_id: UserId) -> StoreResult<()> {
        (**self).transfer_email(email, to_user_id)
    }

    fn set_parent_email(&self, email: &str, parent_email: Option<&str>) -> StoreResult<()> {
        (**self).set_parent_email(email, parent_email)
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

    fn create_user_no_password(&self) -> StoreResult<UserId> {
        (**self).create_user_no_password()
    }

    fn add_email_with_type(
        &self,
        user_id: UserId,
        email: &str,
        verified: bool,
        email_type: EmailType,
    ) -> StoreResult<()> {
        (**self).add_email_with_type(user_id, email, verified, email_type)
    }

    fn update_email_last_used(&self, email: &str, email_type: EmailType) -> StoreResult<()> {
        (**self).update_email_last_used(email, email_type)
    }

    fn get_email(&self, email: &str) -> StoreResult<Option<Email>> {
        (**self).get_email(email)
    }

    fn has_password(&self, user_id: UserId) -> StoreResult<bool> {
        (**self).has_password(user_id)
    }

    fn set_password(&self, user_id: UserId, password_hash: &str) -> StoreResult<()> {
        (**self).set_password(user_id, password_hash)
    }

    fn unverify_email(&self, email: &str) -> StoreResult<()> {
        (**self).unverify_email(email)
    }

    fn create_warrant_request(&self, req: WarrantRequestRecord) -> StoreResult<()> {
        (**self).create_warrant_request(req)
    }

    fn get_warrant_request(&self, code: &str) -> StoreResult<Option<WarrantRequestRecord>> {
        (**self).get_warrant_request(code)
    }

    fn list_pending_warrant_requests(
        &self,
        user_id: UserId,
    ) -> StoreResult<Vec<WarrantRequestRecord>> {
        (**self).list_pending_warrant_requests(user_id)
    }

    fn respond_warrant_request(
        &self,
        user_id: UserId,
        code: &str,
        warrants: Option<&[String]>,
    ) -> StoreResult<()> {
        (**self).respond_warrant_request(user_id, code, warrants)
    }

    fn touch_warrant_poll(&self, code: &str) -> StoreResult<Option<DateTime<Utc>>> {
        (**self).touch_warrant_poll(code)
    }

    fn delete_warrant_request(&self, code: &str) -> StoreResult<()> {
        (**self).delete_warrant_request(code)
    }

    fn cleanup_expired_warrant_requests(&self) -> StoreResult<u64> {
        (**self).cleanup_expired_warrant_requests()
    }

    fn upsert_warrant(&self, record: WarrantRecord) -> StoreResult<()> {
        (**self).upsert_warrant(record)
    }

    fn list_warrants(&self, user_id: UserId) -> StoreResult<Vec<WarrantRecord>> {
        (**self).list_warrants(user_id)
    }

    fn delete_warrant(&self, user_id: UserId, warrant_id: u64) -> StoreResult<()> {
        (**self).delete_warrant(user_id, warrant_id)
    }

    fn get_or_allocate_status(&self, kind: &str, subject: &str) -> StoreResult<u64> {
        (**self).get_or_allocate_status(kind, subject)
    }

    fn set_status_revoked(&self, kind: &str, subject: &str) -> StoreResult<bool> {
        (**self).set_status_revoked(kind, subject)
    }

    fn set_status_revoked_idx(&self, idx: u64) -> StoreResult<bool> {
        (**self).set_status_revoked_idx(idx)
    }

    fn is_status_revoked_idx(&self, idx: u64) -> StoreResult<bool> {
        (**self).is_status_revoked_idx(idx)
    }

    fn revoked_status_indices(&self) -> StoreResult<(Vec<u64>, u64)> {
        (**self).revoked_status_indices()
    }

    fn insert_device_cert(&self, rec: DeviceCertRecord) -> StoreResult<u64> {
        (**self).insert_device_cert(rec)
    }

    fn get_device_cert_by_pubkey(&self, pubkey: &str) -> StoreResult<Option<DeviceCertRecord>> {
        (**self).get_device_cert_by_pubkey(pubkey)
    }

    fn list_device_certs(&self, user_id: UserId) -> StoreResult<Vec<DeviceCertRecord>> {
        (**self).list_device_certs(user_id)
    }

    fn revoke_device_cert(&self, user_id: UserId, cert_id: u64) -> StoreResult<()> {
        (**self).revoke_device_cert(user_id, cert_id)
    }

    fn forget_holder(&self, user_id: UserId, holder: &str) -> StoreResult<u64> {
        (**self).forget_holder(user_id, holder)
    }

    fn get_or_create_namespace(&self, user_id: UserId, name: &str) -> StoreResult<String> {
        (**self).get_or_create_namespace(user_id, name)
    }

    fn adopt_namespace_prefix(
        &self,
        user_id: UserId,
        name: &str,
        new_prefix: &str,
    ) -> StoreResult<bool> {
        (**self).adopt_namespace_prefix(user_id, name, new_prefix)
    }

    fn list_namespaces(&self, user_id: UserId) -> StoreResult<Vec<Namespace>> {
        (**self).list_namespaces(user_id)
    }

    fn set_namespace_label(&self, user_id: UserId, name: &str, label: &str) -> StoreResult<()> {
        (**self).set_namespace_label(user_id, name, label)
    }

    fn create_namespace(&self, user_id: UserId, name: &str, label: &str) -> StoreResult<()> {
        (**self).create_namespace(user_id, name, label)
    }

    fn delete_namespace(&self, user_id: UserId, name: &str) -> StoreResult<()> {
        (**self).delete_namespace(user_id, name)
    }

    fn set_holder_label(&self, user_id: UserId, holder_id: &str, label: &str) -> StoreResult<()> {
        (**self).set_holder_label(user_id, holder_id, label)
    }

    fn get_holder_labels(&self, user_id: UserId) -> StoreResult<HashMap<String, String>> {
        (**self).get_holder_labels(user_id)
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
    fn test_transfer_email_moves_ownership() {
        let (store, _dir) = create_test_store();

        // Two separate accounts, each with its own email (the U1/U2 split from
        // mingo-1c6v): a sandmill.org email and a mingo.place email.
        let u1 = store.create_user("pw1").unwrap();
        store.add_email(u1, "danmills@sandmill.org", true).unwrap();
        let u2 = store.create_user("pw2").unwrap();
        store.add_email(u2, "dan@mingo.place", true).unwrap();

        // Prove the sandmill.org email under u2's session → transfer it onto u2.
        store.transfer_email("danmills@sandmill.org", u2).unwrap();

        // Ownership moved to u2; both emails now list under u2; u1 is empty.
        assert_eq!(
            store.get_email("danmills@sandmill.org").unwrap().unwrap().user_id,
            u2
        );
        let u2_emails: Vec<String> =
            store.list_emails(u2).unwrap().into_iter().map(|e| e.email).collect();
        assert!(u2_emails.contains(&"danmills@sandmill.org".to_string()));
        assert!(u2_emails.contains(&"dan@mingo.place".to_string()));
        assert!(store.list_emails(u1).unwrap().is_empty());

        // Transferring an unknown email errors (EmailNotFound).
        assert!(store.transfer_email("nope@nowhere.test", u2).is_err());
    }

    #[test]
    fn set_parent_email_records_and_clears() {
        let (store, _dir) = create_test_store();
        let u = store.create_user("pw").unwrap();
        store.add_email(u, "danmills@sandmill.org", true).unwrap();
        store.add_email(u, "dan@mingo.place", true).unwrap();

        // No parent initially.
        assert_eq!(store.get_email("dan@mingo.place").unwrap().unwrap().parent_email, None);

        // Set + read back (normalized).
        store.set_parent_email("dan@mingo.place", Some("danmills@sandmill.org")).unwrap();
        assert_eq!(
            store.get_email("dan@mingo.place").unwrap().unwrap().parent_email.as_deref(),
            Some("danmills@sandmill.org")
        );
        // Also visible via list_emails.
        let listed = store.list_emails(u).unwrap();
        let child = listed.iter().find(|e| e.email == "dan@mingo.place").unwrap();
        assert_eq!(child.parent_email.as_deref(), Some("danmills@sandmill.org"));

        // Clearing works; unknown email errors.
        store.set_parent_email("dan@mingo.place", None).unwrap();
        assert_eq!(store.get_email("dan@mingo.place").unwrap().unwrap().parent_email, None);
        assert!(store.set_parent_email("nope@nowhere.test", Some("x@y.z")).is_err());
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
    fn unverify_email_clears_verification() {
        let (store, _dir) = create_test_store();
        let u = store.create_user("pw").unwrap();
        store
            .add_email_with_type(u, "bot@localhost:3000", true, EmailType::Agent)
            .unwrap();

        store.unverify_email("bot@localhost:3000").unwrap();
        let rec = store.get_email("bot@localhost:3000").unwrap().unwrap();
        assert!(!rec.verified);
        assert!(rec.verified_at.is_none());
        assert_eq!(rec.email_type, EmailType::Agent);

        assert!(store.unverify_email("missing@x.y").is_err());
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
