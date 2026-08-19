//! Tests ported from browserid/tests/list-emails-wsapi-test.js

mod common;

use common::{create_test_server, create_user, get_csrf};
use serde_json::{json, Value};

/// Test: list_emails requires authentication
#[tokio::test]
async fn test_list_emails_requires_auth() {
    let (server, _) = create_test_server();

    let response = server.get("/wsapi/list_emails").await;

    // Should fail with 401 when not authenticated
    assert_eq!(response.status_code(), 401);
}

/// Test: list_emails returns the user's email after account creation
#[tokio::test]
async fn test_list_emails_after_creation() {
    let (server, email_sender) = create_test_server();
    let email = "listme@example.com";
    let password = "testpassword";

    // Create user
    let session_cookie = create_user(&server, &email_sender, email, password).await;

    // List emails
    let response = server
        .get("/wsapi/list_emails")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();
    assert_eq!(body["success"], true);

    // list_emails returns an array of email strings
    let emails = body["emails"].as_array().unwrap();
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0].as_str().unwrap(), email);
}

/// Test: list_emails returns multiple emails after adding one
#[tokio::test]
async fn test_list_emails_multiple() {
    let (server, email_sender) = create_test_server();
    let email1 = "first@example.com";
    let email2 = "second@example.com";
    let password = "testpassword";

    // Create user with first email
    let session_cookie = create_user(&server, &email_sender, email1, password).await;
    let csrf = get_csrf(&server, &session_cookie).await;

    // Stage second email
    let response = server
        .post("/wsapi/stage_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .json(&json!({ "email": email2, "csrf": csrf }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Get verification code for second email
    let code = email_sender.get_code(email2).expect("No code for second email");

    // Complete email addition
    let response = server
        .post("/wsapi/complete_email_addition")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .json(&json!({ "email": email2, "token": code, "csrf": csrf }))
        .await;
    assert_eq!(response.status_code(), 200);

    // List emails - should have both
    let response = server
        .get("/wsapi/list_emails")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .await;

    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();

    // list_emails returns an array of email strings
    let emails = body["emails"].as_array().unwrap();
    assert_eq!(emails.len(), 2);

    let email_addresses: Vec<&str> = emails
        .iter()
        .map(|e| e.as_str().unwrap())
        .collect();
    assert!(email_addresses.contains(&email1));
    assert!(email_addresses.contains(&email2));

    // No derived identities were declared → `derived` is present but empty.
    assert_eq!(body["derived"].as_array().unwrap().len(), 0);
}

/// Test: list_emails surfaces a subordinate/derived identity paired with its
/// parent so the chooser can label it (mingo-cm8z). Ordinary emails stay absent
/// from `derived`.
#[tokio::test]
async fn test_list_emails_reports_derived() {
    let (server, email_sender) = create_test_server();
    let parent = "parent@example.com";
    let child = "child@example.com";
    let password = "testpassword";

    // Create the account with the parent email, then add the child email.
    let session_cookie = create_user(&server, &email_sender, parent, password).await;
    let csrf = get_csrf(&server, &session_cookie).await;

    let response = server
        .post("/wsapi/stage_email")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .json(&json!({ "email": child, "csrf": csrf }))
        .await;
    assert_eq!(response.status_code(), 200);
    let code = email_sender.get_code(child).expect("No code for child email");
    let response = server
        .post("/wsapi/complete_email_addition")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .json(&json!({ "email": child, "token": code, "csrf": csrf }))
        .await;
    assert_eq!(response.status_code(), 200);

    // Mark the child as subordinate to the parent.
    let response = server
        .post("/wsapi/set_parent")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie.clone()))
        .json(&json!({ "email": child, "parent_email": parent, "csrf": csrf }))
        .await;
    assert_eq!(response.status_code(), 200);

    // list_emails now reports the derived pairing.
    let response = server
        .get("/wsapi/list_emails")
        .add_cookie(cookie::Cookie::new("browserid_session", session_cookie))
        .await;
    assert_eq!(response.status_code(), 200);
    let body: Value = response.json();

    // Both emails still listed as plain strings.
    assert_eq!(body["emails"].as_array().unwrap().len(), 2);

    // Exactly the child appears in `derived`, pointing at the parent.
    let derived = body["derived"].as_array().unwrap();
    assert_eq!(derived.len(), 1);
    assert_eq!(derived[0]["email"].as_str().unwrap(), child);
    assert_eq!(derived[0]["parent_email"].as_str().unwrap(), parent);
}

/// kts0 follow-up: list_emails exposes each address's proof method to the
/// OWNING session, so the dialog can spot a grandfathered SMTP-proven record
/// on a bridge-ceremony domain and run the upgrade claim.
#[tokio::test]
async fn list_emails_reports_per_address_proofs() {
    use browserid_broker::store::UserStore;
    let ctx = common::create_test_context();
    let session = common::create_user(
        &ctx.server, &ctx.email_sender, "plain@example.com", "password123").await;
    let user = ctx.user_store.get_user_by_email("plain@example.com").unwrap().unwrap();
    ctx.user_store
        .add_email_with_type(user.id, "bridge@example.com", true,
            browserid_broker::store::EmailType::Secondary)
        .unwrap();
    ctx.user_store
        .set_email_proof("bridge@example.com",
            browserid_broker::store::ProofMethod::Oidc, Some("s"))
        .unwrap();

    let body: serde_json::Value = ctx
        .server
        .get("/wsapi/list_emails")
        .add_cookie(cookie::Cookie::new("browserid_session", session))
        .await
        .json();
    let proofs: std::collections::HashMap<&str, &str> = body["proofs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["email"].as_str().unwrap(), p["proof"].as_str().unwrap()))
        .collect();
    assert_eq!(proofs["plain@example.com"], "smtp");
    assert_eq!(proofs["bridge@example.com"], "oidc");
}
