//! Common test utilities for broker integration tests

#![allow(unused)]

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

/// Create a test context with access to underlying stores
pub fn create_test_context() -> TestContext {
    let keypair = KeyPair::generate();
    let email_sender = Arc::new(MockEmailSender::new());
    let user_store = Arc::new(InMemoryUserStore::new());
    let session_store = Arc::new(InMemorySessionStore::new());

    let state = Arc::new(AppState::new_with_arcs(
        keypair,
        "localhost:3000".to_string(),
        user_store.clone(),
        session_store,
        email_sender.clone(),
    ));

    let app = routes::create_router(state);
    let server = TestServer::new(app).expect("Failed to create test server");

    TestContext {
        server,
        email_sender: MockEmailSender {
            sent: email_sender.sent.clone(),
        },
        user_store,
    }
}

/// Helper to create a user and return the session cookie
pub async fn create_user(
    server: &TestServer,
    email_sender: &MockEmailSender,
    email: &str,
    password: &str,
) -> String {
    // Stage user
    let response = server
        .post("/wsapi/stage_user")
        .json(&json!({
            "email": email,
            "pass": password,
        }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Get verification code
    let code = email_sender.get_code(email).expect("No verification code sent");

    // Complete user creation
    let response = server
        .post("/wsapi/complete_user_creation")
        .json(&json!({ "token": code }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Extract session cookie
    response
        .maybe_cookie("browserid_session")
        .expect("No session cookie")
        .value()
        .to_string()
}
