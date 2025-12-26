//! Common test utilities for broker integration tests

use std::sync::Arc;
use std::sync::RwLock;

use axum_test::TestServer;
use browserid_broker::{
    routes, AppState, EmailSender, InMemorySessionStore, InMemoryUserStore,
};
use browserid_core::KeyPair;
use serde_json::json;

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
    let keypair = KeyPair::generate();
    let email_sender = MockEmailSender::new();

    let state = Arc::new(AppState::new(
        keypair,
        "localhost:3000".to_string(),
        InMemoryUserStore::new(),
        InMemorySessionStore::new(),
        email_sender.clone(),
    ));

    let app = routes::create_router(state);
    let server = TestServer::new(app).expect("Failed to create test server");

    (server, email_sender)
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
