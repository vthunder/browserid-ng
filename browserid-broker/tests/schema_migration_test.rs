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

/// e85i: a grant's identity is (audience, scopes) — same-audience warrants
/// with different scopes coexist; a reissue with identical scopes replaces.
#[test]
fn test_warrant_upsert_keys_on_audience_and_scopes() {
    use browserid_broker::store::{UserId, WarrantRecord};
    use chrono::Utc;

    let (store, _dir) = create_test_store();
    let user_id = store.create_user("hash").unwrap();

    let warrant = |scopes: &[&str], jws: &str| WarrantRecord {
        id: 0,
        user_id: UserId(user_id.0),
        delegator_email: "dan@example.com".into(),
        agent_email: "bot@example.com".into(),
        audience: "https://rp.example".into(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        warrant: jws.into(),
        status_idx: None,
        holder: None,
        config_cert: None,
        binding_id: None,
        signed_at: Utc::now(),
        expires_at: Utc::now(),
    };

    store.upsert_warrant(warrant(&["path:/shared/*"], "jws-shared")).unwrap();
    store.upsert_warrant(warrant(&["as:you", "path:/u/you/*"], "jws-onbehalf")).unwrap();
    let listed = store.list_warrants(user_id).unwrap();
    assert_eq!(listed.len(), 2, "different scopes at one audience must coexist");

    // Identical scopes (any order) replace, not duplicate.
    store.upsert_warrant(warrant(&["path:/u/you/*", "as:you"], "jws-onbehalf-2")).unwrap();
    let listed = store.list_warrants(user_id).unwrap();
    assert_eq!(listed.len(), 2, "same-scope reissue replaces its predecessor");
    assert!(listed.iter().any(|w| w.warrant == "jws-onbehalf-2"));
    assert!(!listed.iter().any(|w| w.warrant == "jws-onbehalf"));
}

#[test]
fn test_primary_config_cert_holder_recorded() {
    // Design note §3: a primary identity's config (authorization) cert — recorded
    // on join by auth_with_presentation — must surface in the holder registry
    // (list_device_certs) with its opaque, IdP-assigned holder, so the account
    // "Devices & holders" view can show identities the broker doesn't issue for.
    use browserid_broker::store::DeviceCertRecord;
    use chrono::Utc;

    let (store, _dir) = create_test_store();
    let user_id = store.create_user("hash").unwrap();

    store
        .insert_device_cert(DeviceCertRecord {
            id: 0,
            user_id,
            identities: vec!["danmills@sandmill.org".into()],
            purpose: "authorization".into(),
            holder: "br1a2b3c.9f8e7d6c".into(), // the primary IdP's dotted holder
            pubkey: "cfg-pubkey-base64".into(),
            iss: "sandmill.org".into(),
            issued_at: Utc::now(),
            expires_at: Utc::now(),
            revoked_at: None,
            status_uri: None,
            status_idx: Some(3),
            prov: "smtp".to_string(),
        })
        .unwrap();

    let listed = store.list_device_certs(user_id).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].holder, "br1a2b3c.9f8e7d6c");
    assert_eq!(listed[0].purpose, "authorization");
    assert_eq!(listed[0].iss, "sandmill.org");
}

#[test]
fn test_reissued_cert_clears_stale_revocation_on_upsert() {
    // Device keys are long-lived, so a reissued cert upserts onto the same
    // pubkey row. After a revocation sweep (e.g. managed-identity
    // revoke-on-enable), recording a NEWLY VERIFIED cert must clear the stale
    // revoked_at — recording only happens post-verification, so a genuinely
    // revoked cert can never reach the upsert. Regression: the browser stayed
    // "inactive" in the account view forever after re-login.
    use browserid_broker::store::DeviceCertRecord;
    use chrono::Utc;

    let (store, _dir) = create_test_store();
    let user_id = store.create_user("hash").unwrap();
    let rec = |revoked_at| DeviceCertRecord {
        id: 0,
        user_id,
        identities: vec!["dan@tenant.example".into()],
        purpose: "authorization".into(),
        holder: "br1a2b3c.9f8e7d6c".into(),
        pubkey: "stable-device-pubkey".into(),
        iss: "tenant.example".into(),
        issued_at: Utc::now(),
        expires_at: Utc::now(),
        revoked_at,
        status_uri: None,
        status_idx: Some(7),
        prov: "smtp".to_string(),
    };

    store.insert_device_cert(rec(None)).unwrap();
    // The sweep stamps the row revoked.
    let swept = store.revoke_domain_device_certs("tenant.example").unwrap();
    assert_eq!(swept, 1);
    assert!(store.list_device_certs(user_id).unwrap()[0].revoked_at.is_some());

    // Re-login records the fresh cert for the SAME device key → row is live again.
    store.insert_device_cert(rec(None)).unwrap();
    let listed = store.list_device_certs(user_id).unwrap();
    assert_eq!(listed.len(), 1, "upsert, not a duplicate row");
    assert!(
        listed[0].revoked_at.is_none(),
        "a freshly recorded (verified) cert must clear the stale revoked_at"
    );
}

/// Record requests (spec §7.5) are unclaimed at creation (user_id 0 — no
/// account bound yet). The sqlite store must accept that row: the users(id)
/// foreign key was dropped in v29 after it rejected exactly this insert in
/// production (the in-memory test store has no FK, so only a sqlite-backed
/// test catches it).
#[test]
fn test_unclaimed_record_request_insertable() {
    use browserid_broker::store::{UserId, WarrantGrantItem, WarrantRequestRecord, WarrantRequestStatus};
    use chrono::{Duration, Utc};

    let (store, _dir) = create_test_store();
    let now = Utc::now();
    store
        .create_warrant_request(WarrantRequestRecord {
            code: "req_unclaimed".into(),
            kind: "connection".into(),
            meta: Some(r#"{"challenge":"c","proof_ok":false,"client_host":"claude.ai","binding_id":"cn_1"}"#.into()),
            user_id: UserId(0),
            delegator_email: String::new(),
            agent_email: String::new(),
            holder: String::new(),
            label: "https://gate.example".into(),
            grantor: "*".into(),
            message: None,
            grants: vec![WarrantGrantItem {
                audience: "https://gate.example/mcp".into(),
                scopes: vec!["tool:read".into()],
                status_idx: None,
                grantee: None,
            }],
            status: WarrantRequestStatus::Pending,
            warrants: None,
            external: true,
            return_url: None,
            created_at: now,
            expires_at: now + Duration::minutes(15),
            last_polled_at: None,
        })
        .expect("unclaimed record request (user_id 0) must insert");
    let rec = store.get_warrant_request("req_unclaimed").unwrap().expect("row exists");
    assert_eq!(rec.kind, "connection");
    assert!(rec.meta.is_some());

    // The claim rebinding (update_warrant_request) works on the sqlite path.
    let mut claimed = rec;
    claimed.user_id = UserId(1);
    claimed.grants[0].status_idx = Some(7);
    store.update_warrant_request(&claimed).expect("claim update");
    let rec = store.get_warrant_request("req_unclaimed").unwrap().unwrap();
    assert_eq!(rec.user_id, UserId(1));
    assert_eq!(rec.grants[0].status_idx, Some(7));
}
