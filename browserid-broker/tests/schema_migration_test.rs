//! Tests for schema migration and new email type fields

use browserid_broker::store::{EmailType, SqliteStore, UserStore};
use tempfile::TempDir;

fn create_test_store() -> (SqliteStore, TempDir) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.db");
    let store = SqliteStore::open(path.to_str().unwrap()).unwrap();
    (store, dir) // Return dir to keep it alive
}

/// Test: create_user_no_password creates user with empty password_hash
#[test]
fn test_create_user_no_password() {
    let (store, _dir) = create_test_store();

    let user_id = store.create_user_no_password().unwrap();
    let user = store.get_user(user_id).unwrap().expect("User should exist");

    // password_hash should be empty string (sentinel for no password)
    assert!(user.password_hash.is_empty());
}

/// Test: has_password returns false for empty password_hash
#[test]
fn test_has_password_false_for_empty() {
    let (store, _dir) = create_test_store();

    let user_id = store.create_user_no_password().unwrap();

    // Should return false for user with no password
    assert!(!store.has_password(user_id).unwrap());
}

/// Test: has_password returns true for non-empty password_hash
#[test]
fn test_has_password_true_for_set_password() {
    let (store, _dir) = create_test_store();

    let user_id = store.create_user("hashed_password").unwrap();

    // Should return true for user with password
    assert!(store.has_password(user_id).unwrap());
}

/// Test: add_email_with_type stores email_type correctly
#[test]
fn test_add_email_with_type_primary() {
    let (store, _dir) = create_test_store();

    let user_id = store.create_user("password").unwrap();
    store
        .add_email_with_type(user_id, "test@example.com", true, EmailType::Primary)
        .unwrap();

    let email = store
        .get_email("test@example.com")
        .unwrap()
        .expect("Email should exist");

    assert_eq!(email.email_type, EmailType::Primary);
    assert_eq!(email.last_used_as, EmailType::Primary);
}

/// Test: add_email_with_type stores secondary type correctly
#[test]
fn test_add_email_with_type_secondary() {
    let (store, _dir) = create_test_store();

    let user_id = store.create_user("password").unwrap();
    store
        .add_email_with_type(user_id, "test@example.com", true, EmailType::Secondary)
        .unwrap();

    let email = store
        .get_email("test@example.com")
        .unwrap()
        .expect("Email should exist");

    assert_eq!(email.email_type, EmailType::Secondary);
    assert_eq!(email.last_used_as, EmailType::Secondary);
}

/// Test: default add_email uses secondary type
#[test]
fn test_add_email_defaults_to_secondary() {
    let (store, _dir) = create_test_store();

    let user_id = store.create_user("password").unwrap();
    store.add_email(user_id, "test@example.com", true).unwrap();

    let email = store
        .get_email("test@example.com")
        .unwrap()
        .expect("Email should exist");

    assert_eq!(email.email_type, EmailType::Secondary);
    assert_eq!(email.last_used_as, EmailType::Secondary);
}

/// Test: update_email_last_used updates the column
#[test]
fn test_update_email_last_used() {
    let (store, _dir) = create_test_store();

    let user_id = store.create_user("password").unwrap();
    store
        .add_email_with_type(user_id, "test@example.com", true, EmailType::Secondary)
        .unwrap();

    // Initially secondary
    let email = store.get_email("test@example.com").unwrap().unwrap();
    assert_eq!(email.last_used_as, EmailType::Secondary);

    // Update to primary
    store
        .update_email_last_used("test@example.com", EmailType::Primary)
        .unwrap();

    // Verify updated
    let email = store.get_email("test@example.com").unwrap().unwrap();
    assert_eq!(email.last_used_as, EmailType::Primary);
    // email_type should remain unchanged
    assert_eq!(email.email_type, EmailType::Secondary);
}

/// Test: get_email returns Email with correct type fields
#[test]
fn test_get_email_returns_correct_fields() {
    let (store, _dir) = create_test_store();

    let user_id = store.create_user("password").unwrap();
    store
        .add_email_with_type(user_id, "primary@example.com", true, EmailType::Primary)
        .unwrap();

    let email = store
        .get_email("primary@example.com")
        .unwrap()
        .expect("Email should exist");

    assert_eq!(email.email, "primary@example.com");
    assert_eq!(email.user_id, user_id);
    assert!(email.verified);
    assert!(email.verified_at.is_some());
    assert_eq!(email.email_type, EmailType::Primary);
    assert_eq!(email.last_used_as, EmailType::Primary);
}

/// Test: list_emails returns emails with correct type fields
#[test]
fn test_list_emails_with_type_fields() {
    let (store, _dir) = create_test_store();

    let user_id = store.create_user("password").unwrap();
    store
        .add_email_with_type(user_id, "primary@example.com", true, EmailType::Primary)
        .unwrap();
    store
        .add_email_with_type(user_id, "secondary@example.com", true, EmailType::Secondary)
        .unwrap();

    let emails = store.list_emails(user_id).unwrap();
    assert_eq!(emails.len(), 2);

    let primary = emails.iter().find(|e| e.email == "primary@example.com");
    let secondary = emails
        .iter()
        .find(|e| e.email == "secondary@example.com");

    assert!(primary.is_some());
    assert!(secondary.is_some());

    assert_eq!(primary.unwrap().email_type, EmailType::Primary);
    assert_eq!(secondary.unwrap().email_type, EmailType::Secondary);
}

/// Test: set_password updates user password
#[test]
fn test_set_password() {
    let (store, _dir) = create_test_store();

    // Create user without password
    let user_id = store.create_user_no_password().unwrap();
    assert!(!store.has_password(user_id).unwrap());

    // Set password
    store.set_password(user_id, "new_password_hash").unwrap();

    // Verify password is set
    assert!(store.has_password(user_id).unwrap());

    // Verify the actual hash
    let user = store.get_user(user_id).unwrap().unwrap();
    assert_eq!(user.password_hash, "new_password_hash");
}

/// Test: get_email returns None for non-existent email
#[test]
fn test_get_email_not_found() {
    let (store, _dir) = create_test_store();

    let result = store.get_email("nonexistent@example.com").unwrap();
    assert!(result.is_none());
}

/// Test: update_email_last_used returns error for non-existent email
#[test]
fn test_update_email_last_used_not_found() {
    let (store, _dir) = create_test_store();

    let result = store.update_email_last_used("nonexistent@example.com", EmailType::Primary);
    assert!(result.is_err());
}
