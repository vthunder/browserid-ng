//! Common test utilities for broker integration tests

#![allow(unused)]

pub mod registry;

use std::sync::Arc;
use std::sync::RwLock;

use axum_test::TestServer;
use browserid_broker::{
    routes, AppState, EmailSender, InMemorySessionStore, InMemoryUserStore,
};
use browserid_core::KeyPair;
use serde_json::json;

/// Test server with access to underlying stores
pub struct TestContext {
    pub server: TestServer,
    pub email_sender: MockEmailSender,
    pub user_store: Arc<InMemoryUserStore>,
    /// Direct session-store access — lets tests mint a session for accounts
    /// that have no password (E1/E2-established sessions in production).
    pub session_store: Arc<InMemorySessionStore>,
    /// The broker's public key — in production an RP resolves this from the
    /// `_browserid` DNSSEC record (the served `.well-known` carries no key,
    /// bean zexp); tests that verify broker-issued certs use it directly.
    pub broker_key: browserid_core::PublicKey,
    /// The app state behind the server, for tests that drive host-side
    /// machinery directly (e.g. recording a bridge grant).
    pub state: Arc<AppState<InMemoryUserStore, InMemorySessionStore, MockEmailSender>>,
}

/// Mock email sender that captures verification codes
#[derive(Default, Clone)]
pub struct MockEmailSender {
    /// Captured (email, code) pairs
    pub sent: Arc<RwLock<Vec<(String, String)>>>,
}

impl MockEmailSender {
    pub fn new() -> Self {
        Self {
            sent: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get the last verification code sent to an email
    pub fn get_code(&self, email: &str) -> Option<String> {
        self.sent
            .read()
            .unwrap()
            .iter()
            .rev()
            .find(|(e, _)| e == email)
            .map(|(_, c)| c.clone())
    }
}

impl EmailSender for MockEmailSender {
    fn send_verification(&self, email: &str, code: &str) -> Result<(), String> {
        self.sent
            .write()
            .unwrap()
            .push((email.to_string(), code.to_string()));
        Ok(())
    }

    fn send_password_reset(&self, email: &str, code: &str) -> Result<(), String> {
        self.sent
            .write()
            .unwrap()
            .push((email.to_string(), code.to_string()));
        Ok(())
    }
}

/// Create a test server with mock email sender
pub fn create_test_server() -> (TestServer, MockEmailSender) {
    let ctx = create_test_context();
    (ctx.server, ctx.email_sender)
}

/// A test server whose broker domain is not localhost (production-shaped
/// behavior, e.g. the no-key support document).
#[allow(dead_code)]
pub fn create_test_server_with_domain(domain: &str) -> (TestServer, MockEmailSender) {
    let keypair = KeyPair::generate();
    let email_sender = Arc::new(MockEmailSender::new());
    let state = Arc::new(AppState::new_with_arcs(
        keypair,
        domain.to_string(),
        Arc::new(InMemoryUserStore::new()),
        Arc::new(InMemorySessionStore::new()),
        email_sender.clone(),
    ));
    let server = TestServer::new(routes::create_router(state)).expect("Failed to create test server");
    (server, MockEmailSender { sent: email_sender.sent.clone() })
}

/// Create a test context with access to underlying stores
pub fn create_test_context() -> TestContext {
    let keypair = KeyPair::generate();
    let broker_key = keypair.public_key();
    let email_sender = Arc::new(MockEmailSender::new());
    let user_store = Arc::new(InMemoryUserStore::new());
    let session_store = Arc::new(InMemorySessionStore::new());

    let state = Arc::new(AppState::new_with_arcs(
        keypair,
        "localhost:3000".to_string(),
        user_store.clone(),
        session_store.clone(),
        email_sender.clone(),
    ));

    let app = routes::create_router(state.clone());
    let server = TestServer::new(app).expect("Failed to create test server");

    TestContext {
        server,
        email_sender: MockEmailSender {
            sent: email_sender.sent.clone(),
        },
        user_store,
        session_store,
        broker_key,
        state,
    }
}

/// Create a test context with a specific claim-time authority checker
/// (browserid-ng-tsqk) instead of the permissive default.
pub fn create_test_context_with_authority(
    authority: browserid_broker::authority::AuthorityChecker,
) -> TestContext {
    create_test_context_customized(|state| state.authority = authority)
}

/// Create a test context after applying arbitrary state customization
/// (attestor config, authority checker, feature flags, …).
pub fn create_test_context_customized(
    customize: impl FnOnce(&mut AppState<InMemoryUserStore, InMemorySessionStore, MockEmailSender>),
) -> TestContext {
    let keypair = KeyPair::generate();
    let broker_key = keypair.public_key();
    let email_sender = Arc::new(MockEmailSender::new());
    let user_store = Arc::new(InMemoryUserStore::new());
    let session_store = Arc::new(InMemorySessionStore::new());

    let mut state = AppState::new_with_arcs(
        keypair,
        "localhost:3000".to_string(),
        user_store.clone(),
        session_store.clone(),
        email_sender.clone(),
    );
    customize(&mut state);

    let state = Arc::new(state);
    let app = routes::create_router(state.clone());
    let server = TestServer::new(app).expect("Failed to create test server");

    TestContext {
        server,
        email_sender: MockEmailSender {
            sent: email_sender.sent.clone(),
        },
        user_store,
        session_store,
        broker_key,
        state,
    }
}

/// Helper to create a user and return a FULL (password-authed) session
/// cookie, via the unified sign-in code lane (the only signup path since M7
/// retired stage_user, browserid-ng-8gqm). Completion mints no session, so
/// the helper signs in with the password afterwards, matching the dialog —
/// and, like the dialog, has the registry admit the browser (bean 160l):
/// a login key is enrolled and the cookie session bound to it, so the
/// account-wide cookie endpoints answer. For the bare identity session a
/// sign-in opens before admission, see [`create_user_unadmitted`].
pub async fn create_user(
    server: &TestServer,
    email_sender: &MockEmailSender,
    email: &str,
    password: &str,
) -> String {
    let cookie = create_user_unadmitted(server, email_sender, email, password).await;
    registry::admit_session(server, &cookie, password).await;
    cookie
}

/// [`create_user`] without the admission step: the session has proved the
/// password (so every broker-vouched address) but no registry login key is
/// bound — the state a browser is in until the add-a-device step succeeds.
pub async fn create_user_unadmitted(
    server: &TestServer,
    email_sender: &MockEmailSender,
    email: &str,
    password: &str,
) -> String {
    // Stage the unified sign-in code
    let response = server
        .post("/wsapi/stage_signin_code")
        .json(&json!({
            "email": email,
            "pass": password,
        }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Get verification code
    let code = email_sender.get_code(email).expect("No verification code sent");

    // Complete — creates the account with the staged password
    let response = server
        .post("/wsapi/complete_signin_code")
        .json(&json!({ "email": email, "token": code }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Sign in with the password → Full session.
    let response = server
        .post("/wsapi/authenticate_user")
        .json(&json!({ "email": email, "pass": password }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Extract session cookie
    response
        .maybe_cookie("browserid_session")
        .expect("No session cookie")
        .value()
        .to_string()
}

/// Fetch the session's CSRF token — required on state-changing wsapi posts.
pub async fn get_csrf(server: &TestServer, session: &str) -> String {
    let response = server
        .get("/wsapi/session_context")
        .add_cookie(cookie::Cookie::new("browserid_session", session.to_string()))
        .await;
    response.json::<serde_json::Value>()["csrf_token"]
        .as_str()
        .expect("session_context returned no csrf_token")
        .to_string()
}

/// Record `cert` as an unretired cert of `email`'s account — what
/// `/device/issue` does at login issuance. Since audit 2026-11 (D2) the
/// registrar signs approvals only with a config cert the account has
/// recorded, so a test that mints its own IdP-signed config cert enrols it
/// here before `respond` / `register` / `agent-provision/complete`.
pub fn record_config_cert(
    store: &InMemoryUserStore,
    email: &str,
    cert: &browserid_core::device::DeviceCert,
) {
    use browserid_broker::store::{DeviceCertRecord, UserStore};
    let user = store
        .get_user_by_email(email)
        .unwrap()
        .unwrap_or_else(|| panic!("no account for {email}"));
    let c = cert.claims();
    let ts = |secs: i64| chrono::DateTime::from_timestamp(secs, 0).unwrap();
    store
        .insert_device_cert(DeviceCertRecord {
            id: 0,
            user_id: user.id,
            identities: c.identities.clone(),
            purpose: match c.purpose {
                browserid_core::device::Purpose::Authentication => "authentication".into(),
                browserid_core::device::Purpose::Authorization => "authorization".into(),
            },
            holder: c.holder.as_str().to_string(),
            pubkey: c.public_key.to_base64(),
            iss: c.iss.clone(),
            issued_at: ts(c.iat),
            expires_at: ts(c.exp),
            revoked_at: None,
            status_uri: c.status.as_ref().map(|s| s.uri.clone()),
            status_idx: c.status.as_ref().map(|s| s.idx),
            prov: "smtp".into(),
            login_key_id: None,
        })
        .unwrap();
}
