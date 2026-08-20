//! Session levels (browserid-ng-ca29, epic shyj): sessions carry HOW they
//! were established — Full (the account password was presented) vs Lightweight
//! (E1/E2 proof / emailed code) — instead of pretending everything is a
//! password login. Same 30d TTL; the level gates capability, not lifetime.

mod common;

use browserid_broker::store::{
    SessionId, SessionLevel, SessionStore, SqliteStore, UserStore,
};
use common::{create_test_context, create_user, get_csrf, TestContext};
use serde_json::{json, Value};

async fn session_context(ctx: &TestContext, session: &str) -> Value {
    ctx.server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new(
            "browserid_session",
            session.to_string(),
        ))
        .await
        .json()
}

/// Password login → Full session; session_context reports it and maps the
/// legacy auth_level to "password".
#[tokio::test]
async fn password_login_yields_full_session() {
    let ctx = create_test_context();
    let email = "full@example.com";
    create_user(&ctx.server, &ctx.email_sender, email, "password123").await;

    let response = ctx
        .server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": email, "pass": "password123" }))
        .await;
    let session = response
        .maybe_cookie("browserid_session")
        .expect("login sets a session cookie")
        .value()
        .to_string();

    let body = session_context(&ctx, &session).await;
    assert_eq!(body["session_level"], "full");
    assert_eq!(body["auth_level"], "password");
}

/// Completing user creation proves the MAILBOX (emailed code), not the
/// password typed at staging — so that session is only Lightweight (owner
/// decision on the ca29 bean).
#[tokio::test]
async fn user_creation_session_is_lightweight() {
    let ctx = create_test_context();
    // Inline stage → complete (the create_user helper re-authenticates and
    // would hand back a Full session — here the COMPLETION session matters).
    let email = "created@example.com";
    let response = ctx
        .server
        .post("/wsapi/stage_user")
        .json(&json!({ "email": email, "pass": "password123" }))
        .await;
    assert_eq!(response.status_code(), 200);
    let code = ctx.email_sender.get_code(email).unwrap();
    let response = ctx
        .server
        .post("/wsapi/complete_user_creation")
        .json(&json!({ "email": email, "token": code }))
        .await;
    assert_eq!(response.status_code(), 200);
    let session = response
        .maybe_cookie("browserid_session")
        .expect("completion sets a session cookie")
        .value()
        .to_string();

    let body = session_context(&ctx, &session).await;
    assert_eq!(body["authenticated"], true);
    assert_eq!(body["session_level"], "lightweight");
    assert_eq!(body["auth_level"], "assertion");
}

/// A store-minted Lightweight session (production analogue: primary
/// presentation / bridge claim) reports "lightweight".
#[tokio::test]
async fn lightweight_session_reported_in_context() {
    let ctx = create_test_context();
    let user_id = ctx.user_store.create_user_no_password().unwrap();
    ctx.user_store
        .add_email(user_id, "bridge@example.com", true)
        .unwrap();
    let session = ctx
        .session_store
        .create(user_id, SessionLevel::Lightweight)
        .unwrap()
        .id
        .0;

    let body = session_context(&ctx, &session).await;
    assert_eq!(body["session_level"], "lightweight");
}

/// set_password on a lightweight session upgrades it to Full — the caller
/// just chose (and so knows) the account password — and rotates the session
/// id so the old lightweight cookie dies.
#[tokio::test]
async fn set_password_upgrades_session_to_full() {
    let ctx = create_test_context();
    let user_id = ctx.user_store.create_user_no_password().unwrap();
    ctx.user_store
        .add_email(user_id, "upgrade@example.com", true)
        .unwrap();
    let session = ctx
        .session_store
        .create(user_id, SessionLevel::Lightweight)
        .unwrap()
        .id
        .0;
    let csrf = get_csrf(&ctx.server, &session).await;

    let response = ctx
        .server
        .post("/wsapi/set_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session.clone()))
        .json(&json!({ "pass": "chosen-password", "csrf": csrf }))
        .await;
    assert_eq!(response.status_code(), 200);
    let fresh = response
        .maybe_cookie("browserid_session")
        .expect("set_password re-mints the session")
        .value()
        .to_string();

    let body = session_context(&ctx, &fresh).await;
    assert_eq!(body["session_level"], "full");

    // The old lightweight session was deleted, not left behind.
    let body = session_context(&ctx, &session).await;
    assert_eq!(body["authenticated"], false);
}

/// update_password evicts everything and re-mints — still Full.
#[tokio::test]
async fn update_password_remint_is_full() {
    let ctx = create_test_context();
    let email = "remint@example.com";
    create_user(&ctx.server, &ctx.email_sender, email, "password123").await;
    let response = ctx
        .server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": email, "pass": "password123" }))
        .await;
    let session = response
        .maybe_cookie("browserid_session")
        .unwrap()
        .value()
        .to_string();
    let csrf = get_csrf(&ctx.server, &session).await;

    let response = ctx
        .server
        .post("/wsapi/update_password")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .json(&json!({ "oldpass": "password123", "newpass": "password456", "csrf": csrf }))
        .await;
    assert_eq!(response.status_code(), 200);
    let fresh = response
        .maybe_cookie("browserid_session")
        .expect("update_password re-mints the session")
        .value()
        .to_string();

    let body = session_context(&ctx, &fresh).await;
    assert_eq!(body["session_level"], "full");
}

/// The level survives a round-trip through the real SQLite store.
#[test]
fn sqlite_session_level_round_trips() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("test.db");
    let store = SqliteStore::open(path.to_str().unwrap()).unwrap();
    let user_id = store.create_user("hash").unwrap();

    for level in [SessionLevel::Full, SessionLevel::Lightweight] {
        let session = store.create(user_id, level).unwrap();
        let got = store.get(&session.id).unwrap().expect("session exists");
        assert_eq!(got.level, level);
    }
}

/// Rollout forces re-auth (owner decision): migrating a pre-level database
/// WIPES the sessions table — an existing session must not silently become
/// full OR lightweight.
#[test]
fn migration_v30_wipes_pre_level_sessions() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("old.db");

    // A v29-shaped database: sessions rows exist and have no level column.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
            INSERT INTO schema_version (version) VALUES (29);
            CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                csrf_token TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            INSERT INTO sessions VALUES ('stale-session', 1, 'tok', '2026-08-01T00:00:00Z');
            -- Later migrations touch other tables (v31 alters emails, v32
            -- alters device_certs); give the hand-built old DB the minimal
            -- shapes they expect.
            CREATE TABLE device_certs (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                identities TEXT,
                purpose TEXT,
                holder TEXT,
                pubkey TEXT UNIQUE,
                iss TEXT,
                issued_at TEXT,
                expires_at TEXT,
                revoked_at TEXT,
                status_idx INTEGER,
                status_uri TEXT
            );
            CREATE TABLE emails (
                email TEXT PRIMARY KEY,
                user_id INTEGER,
                verified INTEGER,
                verified_at TEXT,
                email_type TEXT,
                last_used_as TEXT,
                parent_email TEXT,
                display_name TEXT,
                public_name TEXT,
                proof TEXT,
                proof_subject TEXT
            );
            "#,
        )
        .unwrap();
    }

    let store = SqliteStore::open(path.to_str().unwrap()).unwrap();
    assert!(
        store
            .get(&SessionId("stale-session".to_string()))
            .unwrap()
            .is_none(),
        "pre-level session must be evicted by the migration"
    );
}
