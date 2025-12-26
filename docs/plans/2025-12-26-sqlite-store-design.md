# SQLite Store Implementation Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace in-memory storage with SQLite for persistent user and session data.

**Architecture:** Single SQLite database file with auto-migration on startup. One `SqliteStore` struct implements both `UserStore` and `SessionStore` traits, sharing a mutex-protected connection.

**Tech Stack:** rusqlite with bundled SQLite

---

## Database Schema

```sql
-- Schema version tracking
CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY
);

-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL  -- ISO8601 timestamp
);

-- Emails table (multiple per user)
CREATE TABLE emails (
    email TEXT PRIMARY KEY,  -- normalized lowercase
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    verified INTEGER NOT NULL DEFAULT 0,  -- boolean
    verified_at TEXT  -- ISO8601 timestamp, nullable
);
CREATE INDEX idx_emails_user_id ON emails(user_id);

-- Pending verifications (signup, add-email, password reset)
CREATE TABLE pending_verifications (
    secret TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,  -- nullable for new signups
    password_hash TEXT,  -- nullable, only for new signups
    verification_type TEXT NOT NULL,  -- 'new_account', 'add_email', 'password_reset'
    created_at TEXT NOT NULL
);
CREATE INDEX idx_pending_email ON pending_verifications(email);

-- Sessions
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL
);
```

## Module Structure

```
browserid-broker/src/store/
├── mod.rs          # Traits (unchanged) + re-exports
├── models.rs       # Data models (unchanged)
├── memory.rs       # InMemory implementations (keep for tests)
└── sqlite.rs       # NEW: SqliteStore implementing both traits
```

## Connection Handling

- Single `rusqlite::Connection` wrapped in `Mutex<Connection>`
- Created once at startup, shared across requests
- SQLite handles concurrent reads; mutex serializes writes

```rust
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        Self::migrate(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }
}
```

## Configuration

Add to `Config`:
```rust
pub database_path: String,  // defaults to "browserid.db"
```

Environment variable: `DATABASE_PATH`

## main.rs Integration

```rust
let store = SqliteStore::open(&config.database_path)?;
let store = Arc::new(store);

let state = Arc::new(AppState::new(
    keypair,
    config.domain.clone(),
    store.clone(),  // implements UserStore
    store.clone(),  // implements SessionStore
    ConsoleEmailSender::new(),
));
```

## Error Handling

Map rusqlite errors to BrokerError:
- Constraint violations → `EmailAlreadyExists`
- Other errors → `Internal(message)`

## Dependencies

```toml
rusqlite = { version = "0.32", features = ["bundled"] }
```

## Testing

- Unit tests: use `tempfile::NamedTempFile` for isolated DB
- E2E tests: use real SQLite (tests persistence)
- Keep `InMemoryUserStore` for fast unit tests elsewhere
