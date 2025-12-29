# Primary IdP Support Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable email domains with DNSSEC-validated `_browserid` TXT records to act as their own identity providers, following the original BrowserID/Persona protocol exactly.

**Architecture:** DNS-first discovery determines primary vs secondary. Primary IdPs use hidden iframe provisioning with postMessage-based navigator.id APIs. Authentication redirects through primary's auth page. Broker maintains user records for email association tracking even for primary-only users (no password stored).

**Tech Stack:** Rust (axum), JavaScript (dialog.js), SQLite (schema migration)

**Design Document:** `docs/plans/2025-12-29-primary-idp-support-design.md`

---

## Task 1: Database Schema Migration

**Files:**
- Modify: `browserid-broker/src/store/sqlite.rs`
- Modify: `browserid-broker/src/store/models.rs`
- Modify: `browserid-broker/src/store/mod.rs`
- Create: `browserid-broker/tests/schema_migration_test.rs`

### Step 1: Update schema version constant and add migration

In `browserid-broker/src/store/sqlite.rs`, update `SCHEMA_VERSION` from 1 to 2.

```rust
const SCHEMA_VERSION: i32 = 2;
```

### Step 2: Add migration for new email columns

Add `migrate_v2` function that adds `email_type` and `last_used_as` columns to the emails table:

```rust
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
```

### Step 3: Call migrate_v2 in migrate function

Add the migration call:

```rust
if current_version < 2 {
    Self::migrate_v2(conn)?;
}
```

### Step 4: Allow nullable password_hash for primary-only users

Update `migrate_v1` to make `password_hash` nullable:

```sql
-- In migrate_v1, change:
password_hash TEXT NOT NULL
-- To:
password_hash TEXT  -- nullable for primary-only users
```

### Step 5: Update Email model in models.rs

```rust
#[derive(Debug, Clone)]
pub struct Email {
    pub email: String,
    pub user_id: UserId,
    pub verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub email_type: EmailType,      // New
    pub last_used_as: EmailType,    // New
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailType {
    Primary,
    Secondary,
}

impl EmailType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EmailType::Primary => "primary",
            EmailType::Secondary => "secondary",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "primary" => Some(EmailType::Primary),
            "secondary" => Some(EmailType::Secondary),
            _ => None,
        }
    }
}
```

### Step 6: Update User model for optional password

```rust
#[derive(Debug, Clone)]
pub struct User {
    pub id: UserId,
    pub password_hash: Option<String>,  // Changed from String
    pub created_at: DateTime<Utc>,
}
```

### Step 7: Update UserStore trait

Add new methods to `browserid-broker/src/store/mod.rs`:

```rust
/// Create a user without a password (for primary-only users)
fn create_user_no_password(&self) -> StoreResult<UserId>;

/// Add email with type tracking
fn add_email_with_type(
    &self,
    user_id: UserId,
    email: &str,
    verified: bool,
    email_type: EmailType,
) -> StoreResult<()>;

/// Update email's last_used_as when type changes
fn update_email_last_used(&self, email: &str, email_type: EmailType) -> StoreResult<()>;

/// Get email record by address
fn get_email(&self, email: &str) -> StoreResult<Option<Email>>;

/// Check if user has a password set
fn has_password(&self, user_id: UserId) -> StoreResult<bool>;

/// Set password for a user (for transition cases)
fn set_password(&self, user_id: UserId, password_hash: &str) -> StoreResult<()>;
```

### Step 8: Implement new methods in SqliteStore

Update `browserid-broker/src/store/sqlite.rs` with implementations for all new trait methods. Update existing methods to handle the new columns.

### Step 9: Write test for schema migration

Create `browserid-broker/tests/schema_migration_test.rs`:

```rust
#[test]
fn test_migration_v1_to_v2() {
    // Create v1 database
    // Run migration
    // Verify new columns exist with correct defaults
    // Verify existing data is preserved
}

#[test]
fn test_create_user_no_password() {
    // Create user without password
    // Verify user exists but has_password returns false
}

#[test]
fn test_add_email_with_type() {
    // Add email as primary
    // Verify email_type is primary
    // Verify last_used_as is primary
}
```

### Step 10: Run tests

```bash
cargo test -p browserid-broker schema_migration
cargo test -p browserid-broker
```

### Step 11: Commit

```bash
git add browserid-broker/src/store/
git add browserid-broker/tests/schema_migration_test.rs
git commit -m "feat(broker): add schema migration for primary IdP email tracking

- Add email_type and last_used_as columns to emails table
- Make password_hash nullable for primary-only users
- Add EmailType enum and related store methods"
```

---

## Task 2: Update /wsapi/address_info with DNS Discovery

**Files:**
- Modify: `browserid-broker/src/routes/email.rs`
- Modify: `browserid-broker/src/state.rs`
- Create: `browserid-broker/tests/address_info_primary_test.rs`

### Step 1: Add FallbackFetcher to AppState

In `browserid-broker/src/state.rs`, add `fallback_fetcher` field:

```rust
pub struct AppState<U, S, E> {
    pub user_store: U,
    pub session_store: S,
    pub email_sender: E,
    pub keypair: Keypair,
    pub domain: String,
    pub fallback_fetcher: Option<FallbackFetcher>,  // New
}
```

### Step 2: Update AddressInfoResponse

In `browserid-broker/src/routes/email.rs`:

```rust
#[derive(Serialize)]
pub struct AddressInfoResponse {
    #[serde(rename = "type")]
    pub addr_type: String,  // "primary" or "secondary"
    pub state: String,      // "known", "unknown", "transition_to_primary", etc.
    pub issuer: String,
    pub disabled: bool,
    #[serde(rename = "normalizedEmail")]
    pub normalized_email: String,
    // Primary-only fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prov: Option<String>,
}
```

### Step 3: Implement state table logic

Create helper function:

```rust
/// Determine state based on password_known, last_used_as, current_type
fn compute_state(
    password_known: bool,
    last_used_as: Option<EmailType>,
    current_type: EmailType,
) -> &'static str {
    match (password_known, last_used_as, current_type) {
        // User has password
        (true, Some(EmailType::Primary), EmailType::Primary) => "known",
        (true, Some(EmailType::Primary), EmailType::Secondary) => "transition_to_secondary",
        (true, Some(EmailType::Secondary), EmailType::Primary) => "transition_to_primary",
        (true, Some(EmailType::Secondary), EmailType::Secondary) => "known",

        // User has no password
        (false, Some(EmailType::Primary), EmailType::Primary) => "known",
        (false, Some(EmailType::Primary), EmailType::Secondary) => "transition_no_password",
        (false, Some(EmailType::Secondary), EmailType::Primary) => "transition_to_primary",
        (false, Some(EmailType::Secondary), EmailType::Secondary) => "transition_no_password",

        // Email not in database
        (_, None, _) => "unknown",
    }
}
```

### Step 4: Update address_info to use DNS discovery

Make `address_info` async and add discovery:

```rust
pub async fn address_info<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Query(query): Query<AddressInfoQuery>,
) -> Result<Json<AddressInfoResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let normalized = query.email.to_lowercase();
    let domain = normalized.split('@').nth(1)
        .ok_or_else(|| BrokerError::InvalidEmail)?;

    // Try DNS discovery
    let (addr_type, auth, prov, current_type) = if let Some(ref fetcher) = state.fallback_fetcher {
        match fetcher.discover(domain).await {
            Ok(result) if result.is_primary => {
                let auth_url = result.document.authentication
                    .map(|p| format!("https://{}{}", domain, p));
                let prov_url = result.document.provisioning
                    .map(|p| format!("https://{}{}", domain, p));
                ("primary".to_string(), auth_url, prov_url, EmailType::Primary)
            }
            Ok(_) => ("secondary".to_string(), None, None, EmailType::Secondary),
            Err(BrokerError::DnssecValidationFailed { .. }) => {
                return Err(BrokerError::DnssecValidationFailed { domain: domain.to_string() });
            }
            Err(_) => ("secondary".to_string(), None, None, EmailType::Secondary),
        }
    } else {
        ("secondary".to_string(), None, None, EmailType::Secondary)
    };

    // Look up email in database
    let (state_str, issuer) = match state.user_store.get_email(&normalized)? {
        Some(email_record) => {
            let user = state.user_store.get_user(email_record.user_id)?
                .ok_or(BrokerError::Internal("Orphaned email".to_string()))?;
            let password_known = user.password_hash.is_some();
            let state_str = compute_state(password_known, Some(email_record.last_used_as), current_type);
            let issuer = if current_type == EmailType::Primary {
                domain.to_string()
            } else {
                state.domain.clone()
            };
            (state_str, issuer)
        }
        None => {
            let issuer = if current_type == EmailType::Primary {
                domain.to_string()
            } else {
                state.domain.clone()
            };
            ("unknown", issuer)
        }
    };

    Ok(Json(AddressInfoResponse {
        addr_type,
        state: state_str.to_string(),
        issuer,
        disabled: false,
        normalized_email: normalized,
        auth,
        prov,
    }))
}
```

### Step 5: Write tests

Create `browserid-broker/tests/address_info_primary_test.rs`:

```rust
#[tokio::test]
async fn test_address_info_secondary_unknown() {
    // Setup with no fallback_fetcher
    // Query for unknown email
    // Expect: type=secondary, state=unknown
}

#[tokio::test]
async fn test_address_info_secondary_known() {
    // Setup with existing secondary user
    // Query for their email
    // Expect: type=secondary, state=known
}

// Additional tests for each state transition...
```

### Step 6: Run tests

```bash
cargo test -p browserid-broker address_info
```

### Step 7: Commit

```bash
git add browserid-broker/src/routes/email.rs
git add browserid-broker/src/state.rs
git add browserid-broker/tests/address_info_primary_test.rs
git commit -m "feat(broker): add DNS discovery to address_info endpoint

- Integrate FallbackFetcher for primary IdP detection
- Implement state table (known, unknown, transition_to_*)
- Return auth/prov URLs for primary IdPs"
```

---

## Task 3: Create /wsapi/auth_with_assertion Endpoint

**Files:**
- Create: `browserid-broker/src/routes/primary.rs`
- Modify: `browserid-broker/src/routes/mod.rs`
- Create: `browserid-broker/tests/auth_with_assertion_test.rs`

### Step 1: Create primary.rs module

Create `browserid-broker/src/routes/primary.rs`:

```rust
//! Primary IdP authentication endpoints

use std::sync::Arc;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::email::EmailSender;
use crate::error::BrokerError;
use crate::state::AppState;
use crate::store::{EmailType, SessionStore, UserStore};
use crate::verifier::verify_assertion_with_dns;

#[derive(Deserialize)]
pub struct AuthWithAssertionRequest {
    pub assertion: String,
    #[serde(default)]
    pub ephemeral: bool,
}

#[derive(Serialize)]
pub struct AuthWithAssertionResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// POST /wsapi/auth_with_assertion
/// Authenticate a user via a primary IdP assertion
pub async fn auth_with_assertion<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    cookies: Cookies,
    Json(req): Json<AuthWithAssertionRequest>,
) -> Result<Json<AuthWithAssertionResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    let fallback_fetcher = state.fallback_fetcher.as_ref()
        .ok_or_else(|| BrokerError::Internal("DNS discovery not configured".to_string()))?;

    // Verify the assertion - audience is the broker itself
    let result = verify_assertion_with_dns(
        &req.assertion,
        &format!("https://{}", state.domain),
        fallback_fetcher,
        &state.domain,
    ).await;

    if result.status != "okay" {
        return Err(BrokerError::InvalidAssertion(
            result.reason.unwrap_or_else(|| "Unknown error".to_string())
        ));
    }

    let email = result.email.ok_or_else(||
        BrokerError::InvalidAssertion("No email in assertion".to_string())
    )?;
    let issuer = result.issuer.ok_or_else(||
        BrokerError::InvalidAssertion("No issuer in assertion".to_string())
    )?;

    // Verify this is actually a primary IdP (issuer != broker)
    if issuer == state.domain {
        return Err(BrokerError::InvalidAssertion(
            "Cannot use auth_with_assertion for secondary emails".to_string()
        ));
    }

    // Find or create user
    let user_id = match state.user_store.get_email(&email)? {
        Some(email_record) => {
            // Update last_used_as to primary
            state.user_store.update_email_last_used(&email, EmailType::Primary)?;
            email_record.user_id
        }
        None => {
            // Create new user without password
            let user_id = state.user_store.create_user_no_password()?;
            state.user_store.add_email_with_type(user_id, &email, true, EmailType::Primary)?;
            user_id
        }
    };

    // Create session
    let session = state.session_store.create(user_id)?;
    if !req.ephemeral {
        super::session::set_session_cookie(&cookies, &session.id.0);
    }

    Ok(Json(AuthWithAssertionResponse {
        success: true,
        reason: None,
    }))
}
```

### Step 2: Add InvalidAssertion error variant

In `browserid-broker/src/error.rs`:

```rust
#[derive(Debug)]
pub enum BrokerError {
    // ... existing variants
    InvalidAssertion(String),
}
```

### Step 3: Register route

In `browserid-broker/src/routes/mod.rs`:

```rust
mod primary;

// In create_router_with_static_path:
.route("/wsapi/auth_with_assertion", post(primary::auth_with_assertion))
```

### Step 4: Write tests

Create `browserid-broker/tests/auth_with_assertion_test.rs`:

```rust
#[tokio::test]
async fn test_auth_with_assertion_creates_user() {
    // Setup with mock primary IdP
    // Send valid assertion
    // Verify user created without password
    // Verify session established
}

#[tokio::test]
async fn test_auth_with_assertion_existing_user() {
    // Setup with existing primary user
    // Send assertion
    // Verify session established
    // Verify last_used_as updated to primary
}

#[tokio::test]
async fn test_auth_with_assertion_rejects_secondary() {
    // Send assertion from broker itself
    // Expect error
}
```

### Step 5: Run tests

```bash
cargo test -p browserid-broker auth_with_assertion
```

### Step 6: Commit

```bash
git add browserid-broker/src/routes/primary.rs
git add browserid-broker/src/routes/mod.rs
git add browserid-broker/src/error.rs
git add browserid-broker/tests/auth_with_assertion_test.rs
git commit -m "feat(broker): add auth_with_assertion endpoint for primary IdPs

- Verify assertion from primary IdP
- Create user without password if new
- Establish broker session"
```

---

## Task 4: Create API Shim Static Files

**Files:**
- Create: `browserid-broker/static/provisioning_api.js`
- Create: `browserid-broker/static/authentication_api.js`
- Modify: `browserid-broker/src/routes/mod.rs`

### Step 1: Create provisioning_api.js

Create `browserid-broker/static/provisioning_api.js`:

```javascript
/*
 * BrowserID Provisioning API Shim
 * Include this on your primary IdP's provisioning page
 */

(function() {
  'use strict';

  if (typeof navigator.id === 'undefined') {
    navigator.id = {};
  }

  // Simple postMessage channel to parent (broker dialog)
  const channel = {
    _callbacks: {},
    _callId: 0,

    call: function(method, callback) {
      const id = ++this._callId;
      this._callbacks[id] = callback;
      window.parent.postMessage({
        type: 'browserid:provisioning',
        method: method,
        id: id
      }, '*');
    },

    notify: function(method, data) {
      window.parent.postMessage({
        type: 'browserid:provisioning',
        method: method,
        data: data
      }, '*');
    }
  };

  // Handle responses from parent
  window.addEventListener('message', function(event) {
    if (event.data && event.data.type === 'browserid:provisioning:response') {
      const callback = channel._callbacks[event.data.id];
      if (callback) {
        delete channel._callbacks[event.data.id];
        callback(event.data.result);
      }
    }
  });

  navigator.id.beginProvisioning = function(callback) {
    channel.call('beginProvisioning', function(params) {
      callback(params.email, params.cert_duration_s);
    });
  };

  navigator.id.genKeyPair = function(callback) {
    channel.call('genKeyPair', function(result) {
      callback(result.publicKey);
    });
  };

  navigator.id.registerCertificate = function(certificate) {
    channel.notify('registerCertificate', { certificate: certificate });
  };

  navigator.id.raiseProvisioningFailure = function(reason) {
    channel.notify('raiseProvisioningFailure', { reason: reason });
  };
})();
```

### Step 2: Create authentication_api.js

Create `browserid-broker/static/authentication_api.js`:

```javascript
/*
 * BrowserID Authentication API Shim
 * Include this on your primary IdP's authentication page
 */

(function() {
  'use strict';

  if (typeof navigator.id === 'undefined') {
    navigator.id = {};
  }

  // Get parameters from URL
  const params = new URLSearchParams(window.location.search);
  const email = params.get('email');

  // Determine return URL - either from param or referrer
  const returnTo = params.get('return_to') ||
    (document.referrer ? new URL(document.referrer).origin + '/sign_in' : null);

  navigator.id.beginAuthentication = function(callback) {
    // Call immediately with the email from URL params
    if (email) {
      callback(email);
    } else {
      console.error('BrowserID: No email parameter in URL');
    }
  };

  navigator.id.completeAuthentication = function() {
    if (returnTo) {
      window.location.href = returnTo + '#AUTH_RETURN';
    } else {
      console.error('BrowserID: No return URL available');
    }
  };

  navigator.id.raiseAuthenticationFailure = function(reason) {
    console.log('BrowserID: Authentication failed:', reason);
    if (returnTo) {
      window.location.href = returnTo + '#AUTH_RETURN_CANCEL';
    }
  };
})();
```

### Step 3: Register routes for shims

In `browserid-broker/src/routes/mod.rs`:

```rust
.route_service("/provisioning_api.js", ServeFile::new(format!("{}/provisioning_api.js", static_path)))
.route_service("/authentication_api.js", ServeFile::new(format!("{}/authentication_api.js", static_path)))
```

### Step 4: Test shims load correctly

```bash
cargo run -p browserid-broker &
curl http://localhost:3000/provisioning_api.js
curl http://localhost:3000/authentication_api.js
```

### Step 5: Commit

```bash
git add browserid-broker/static/provisioning_api.js
git add browserid-broker/static/authentication_api.js
git add browserid-broker/src/routes/mod.rs
git commit -m "feat(broker): add API shims for primary IdP pages

- provisioning_api.js for IdP provisioning pages
- authentication_api.js for IdP auth pages
- Implements navigator.id.* APIs via postMessage"
```

---

## Task 5: Dialog - Provisioning Module

**Files:**
- Create: `browserid-broker/static/dialog/provisioning.js`
- Modify: `browserid-broker/static/dialog.js`

### Step 1: Create provisioning.js module

Create `browserid-broker/static/dialog/provisioning.js`:

```javascript
/*
 * BrowserID Provisioning Module
 * Handles hidden iframe communication with primary IdP provisioning pages
 */

(function(global) {
  'use strict';

  const Provisioning = {
    _iframe: null,
    _iframeOrigin: null,
    _pendingCallbacks: {},
    _callId: 0,
    _onSuccess: null,
    _onFailure: null,

    /**
     * Attempt to provision a certificate from a primary IdP
     * @param {string} provisioningUrl - The IdP's provisioning endpoint
     * @param {string} email - The email to provision
     * @param {function} onSuccess - Called with certificate on success
     * @param {function} onFailure - Called with reason on failure
     */
    start: function(provisioningUrl, email, onSuccess, onFailure) {
      this._onSuccess = onSuccess;
      this._onFailure = onFailure;
      this._email = email;

      // Determine origin from URL
      const url = new URL(provisioningUrl);
      this._iframeOrigin = url.origin;

      // Create hidden iframe
      this._cleanup();
      this._iframe = document.createElement('iframe');
      this._iframe.style.display = 'none';
      this._iframe.src = provisioningUrl;
      document.body.appendChild(this._iframe);

      // Set timeout for provisioning
      this._timeout = setTimeout(() => {
        this._cleanup();
        onFailure('Provisioning timeout');
      }, 30000); // 30 second timeout
    },

    /**
     * Handle messages from provisioning iframe
     */
    handleMessage: function(event) {
      if (!this._iframe || event.source !== this._iframe.contentWindow) {
        return;
      }

      if (event.origin !== this._iframeOrigin) {
        return;
      }

      const data = event.data;
      if (!data || data.type !== 'browserid:provisioning') {
        return;
      }

      switch (data.method) {
        case 'beginProvisioning':
          // Respond with email and duration
          this._respond(data.id, {
            email: this._email,
            cert_duration_s: 24 * 60 * 60  // 24 hours
          });
          break;

        case 'genKeyPair':
          // Generate keypair and return public key
          this._generateKeyPair().then(keypair => {
            this._keypair = keypair;
            this._respond(data.id, { publicKey: keypair.publicKeyJson });
          }).catch(err => {
            this._fail('Key generation failed: ' + err.message);
          });
          break;

        case 'registerCertificate':
          // Success! Store certificate and notify
          clearTimeout(this._timeout);
          const cert = data.data.certificate;
          if (this._onSuccess) {
            this._onSuccess({
              certificate: cert,
              keypair: this._keypair
            });
          }
          this._cleanup();
          break;

        case 'raiseProvisioningFailure':
          // Provisioning failed
          clearTimeout(this._timeout);
          if (this._onFailure) {
            this._onFailure(data.data.reason || 'Provisioning failed');
          }
          this._cleanup();
          break;
      }
    },

    /**
     * Send response back to iframe
     */
    _respond: function(id, result) {
      if (this._iframe && this._iframe.contentWindow) {
        this._iframe.contentWindow.postMessage({
          type: 'browserid:provisioning:response',
          id: id,
          result: result
        }, this._iframeOrigin);
      }
    },

    /**
     * Generate Ed25519 keypair
     */
    _generateKeyPair: async function() {
      const keyPair = await crypto.subtle.generateKey(
        { name: 'Ed25519' },
        true,
        ['sign', 'verify']
      );

      const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
      const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

      return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        publicKeyJson: JSON.stringify({
          algorithm: 'Ed25519',
          publicKey: publicKeyJwk.x
        }),
        publicKeyJwk: publicKeyJwk,
        privateKeyJwk: privateKeyJwk
      };
    },

    /**
     * Clean up iframe and state
     */
    _cleanup: function() {
      if (this._iframe) {
        this._iframe.remove();
        this._iframe = null;
      }
      this._iframeOrigin = null;
      this._keypair = null;
      this._email = null;
      if (this._timeout) {
        clearTimeout(this._timeout);
        this._timeout = null;
      }
    },

    _fail: function(reason) {
      clearTimeout(this._timeout);
      if (this._onFailure) {
        this._onFailure(reason);
      }
      this._cleanup();
    }
  };

  // Listen for messages
  window.addEventListener('message', function(event) {
    Provisioning.handleMessage(event);
  });

  global.BrowserID = global.BrowserID || {};
  global.BrowserID.Provisioning = Provisioning;

})(window);
```

### Step 2: Add script tag to dialog.html

In `browserid-broker/static/dialog/dialog.html`, add before dialog.js:

```html
<script src="provisioning.js"></script>
```

### Step 3: Add provisioning flow to dialog.js

Add to `browserid-broker/static/dialog.js`:

```javascript
// After checkEmail function, add:

async function tryPrimaryProvisioning(email, provUrl, authUrl) {
  return new Promise((resolve, reject) => {
    BrowserID.Provisioning.start(
      provUrl,
      email,
      function onSuccess(result) {
        resolve(result);
      },
      function onFailure(reason) {
        // Provisioning failed - need to authenticate
        reject({ needsAuth: true, authUrl: authUrl, reason: reason });
      }
    );
  });
}

async function handlePrimaryIdP(email, addressInfo) {
  showScreen('loading');

  try {
    // Try provisioning first
    const result = await tryPrimaryProvisioning(email, addressInfo.prov, addressInfo.auth);

    // Got certificate! Create assertion
    const audience = state.origin;
    const expiresAt = Date.now() + (5 * 60 * 1000);

    const assertion = await createAssertionFromPrimary(
      result.keypair.privateKey,
      result.certificate,
      audience,
      expiresAt
    );

    // Store keypair for future use
    await storeEmailKeypair(
      email,
      result.keypair.publicKey,
      result.keypair.privateKey,
      result.certificate
    );

    // Authenticate with broker to establish session
    await apiCall('/wsapi/auth_with_assertion', 'POST', {
      assertion: assertion,
      ephemeral: false
    });

    storeLoggedInState(audience, email);
    showScreen('success');

    setTimeout(() => {
      sendResponse({ assertion });
    }, 1000);

  } catch (e) {
    if (e.needsAuth) {
      // Need to redirect to auth page
      redirectToPrimaryAuth(email, e.authUrl);
    } else {
      showError('Primary IdP provisioning failed: ' + e.message);
    }
  }
}

function redirectToPrimaryAuth(email, authUrl) {
  // Store state for return
  sessionStorage.setItem('browserid_pending_email', email);
  sessionStorage.setItem('browserid_pending_origin', state.origin);

  // Redirect to IdP auth page
  const url = new URL(authUrl);
  url.searchParams.set('email', email);
  url.searchParams.set('return_to', window.location.origin + '/sign_in');
  window.location.href = url.toString();
}

async function createAssertionFromPrimary(privateKey, certificate, audience, expiresAt) {
  const payload = { aud: audience, exp: expiresAt };
  const header = { alg: 'EdDSA', typ: 'JWT' };
  const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, '');
  const payloadB64 = btoa(JSON.stringify(payload)).replace(/=/g, '');
  const message = `${headerB64}.${payloadB64}`;

  const encoder = new TextEncoder();
  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    privateKey,
    encoder.encode(message)
  );

  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return `${certificate}~${message}.${signatureB64}`;
}
```

### Step 4: Update email form handler

Modify the email form submit handler in dialog.js:

```javascript
document.getElementById('email-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value.trim();

  if (!email) {
    document.getElementById('email-error').textContent = 'Email is required';
    return;
  }

  state.email = email;
  document.querySelectorAll('.email-display').forEach(el => el.textContent = email);

  showScreen('loading');

  try {
    const addressInfo = await fetch(`${API.addressInfo}?email=${encodeURIComponent(email)}`)
      .then(r => r.json());

    if (addressInfo.type === 'primary') {
      // Primary IdP flow
      if (addressInfo.state === 'transition_to_secondary') {
        // Was primary, now secondary with password
        showScreen('password');
      } else if (addressInfo.state === 'transition_no_password') {
        // Was primary, now secondary without password - need to set one
        showScreen('create');
      } else {
        // Normal primary flow
        await handlePrimaryIdP(email, addressInfo);
      }
    } else {
      // Secondary flow (existing logic)
      if (addressInfo.state === 'known') {
        showScreen('password');
      } else if (addressInfo.state === 'transition_to_primary') {
        // Was secondary, now primary
        await handlePrimaryIdP(email, addressInfo);
      } else {
        showScreen('create');
      }
    }
  } catch (e) {
    showError('Failed to check email: ' + e.message);
  }
});
```

### Step 5: Test provisioning flow

Manually test with a mock primary IdP (if available) or write unit tests for the module.

### Step 6: Commit

```bash
git add browserid-broker/static/dialog/provisioning.js
git add browserid-broker/static/dialog/dialog.html
git add browserid-broker/static/dialog.js
git commit -m "feat(dialog): add provisioning module for primary IdPs

- Hidden iframe management for IdP provisioning pages
- postMessage channel for navigator.id.* API calls
- Key generation and certificate storage"
```

---

## Task 6: Dialog - Authentication Return Handling

**Files:**
- Modify: `browserid-broker/static/dialog.js`

### Step 1: Add auth return detection on page load

Add to the initialization section of dialog.js:

```javascript
// Check for auth return from primary IdP
function checkAuthReturn() {
  const hash = window.location.hash;

  if (hash === '#AUTH_RETURN' || hash === '#AUTH_RETURN_CANCEL') {
    // Clear hash
    history.replaceState(null, '', window.location.pathname + window.location.search);

    // Restore state
    const email = sessionStorage.getItem('browserid_pending_email');
    const origin = sessionStorage.getItem('browserid_pending_origin');

    if (!email || !origin) {
      console.error('Missing auth return state');
      showScreen('email');
      return true;
    }

    state.email = email;
    state.origin = origin;

    // Clear stored state
    sessionStorage.removeItem('browserid_pending_email');
    sessionStorage.removeItem('browserid_pending_origin');

    // Update UI
    document.querySelectorAll('.email-display').forEach(el => el.textContent = email);
    document.querySelectorAll('.rp-name').forEach(el => {
      el.textContent = new URL(origin).hostname;
    });

    if (hash === '#AUTH_RETURN') {
      // Auth succeeded - retry provisioning
      retryProvisioningAfterAuth(email);
    } else {
      // Auth was cancelled
      showError('Authentication was cancelled');
    }

    return true;
  }

  return false;
}

async function retryProvisioningAfterAuth(email) {
  showScreen('loading');

  try {
    // Get address info again to get provisioning URL
    const addressInfo = await fetch(`${API.addressInfo}?email=${encodeURIComponent(email)}`)
      .then(r => r.json());

    if (addressInfo.type !== 'primary' || !addressInfo.prov) {
      throw new Error('Email is no longer a primary IdP');
    }

    // Retry provisioning (should succeed now that user is authenticated)
    const result = await tryPrimaryProvisioning(email, addressInfo.prov, addressInfo.auth);

    // Got certificate! Create assertion
    const audience = state.origin;
    const expiresAt = Date.now() + (5 * 60 * 1000);

    const assertion = await createAssertionFromPrimary(
      result.keypair.privateKey,
      result.certificate,
      audience,
      expiresAt
    );

    // Store keypair
    await storeEmailKeypair(
      email,
      result.keypair.publicKey,
      result.keypair.privateKey,
      result.certificate
    );

    // Authenticate with broker
    await apiCall('/wsapi/auth_with_assertion', 'POST', {
      assertion: assertion,
      ephemeral: false
    });

    storeLoggedInState(audience, email);
    showScreen('success');

    setTimeout(() => {
      sendResponse({ assertion });
    }, 1000);

  } catch (e) {
    if (e.needsAuth) {
      // Still needs auth? Something went wrong
      showError('Authentication failed. Please try again.');
    } else {
      showError('Provisioning failed after authentication: ' + e.message);
    }
  }
}
```

### Step 2: Call checkAuthReturn in initialization

At the end of dialog.js, before the existing init code:

```javascript
// Check for auth return before normal init
if (checkAuthReturn()) {
  // Auth return handled, don't run normal init
} else {
  // Normal initialization
  const params = new URLSearchParams(window.location.search);
  const origin = params.get('origin');

  if (origin) {
    state.origin = origin;
    document.querySelectorAll('.rp-name').forEach(el => {
      el.textContent = new URL(origin).hostname;
    });
    init();
  }

  // WinChan support...
}
```

### Step 3: Test auth return flow

Manually test the auth return flow with a mock primary IdP.

### Step 4: Commit

```bash
git add browserid-broker/static/dialog.js
git commit -m "feat(dialog): handle auth return from primary IdP

- Detect #AUTH_RETURN and #AUTH_RETURN_CANCEL in URL hash
- Restore state from sessionStorage
- Retry provisioning after successful auth"
```

---

## Task 7: Dialog - State Transition Screens

**Files:**
- Modify: `browserid-broker/static/dialog/dialog.html`
- Modify: `browserid-broker/static/dialog.js`

### Step 1: Add transition_no_password screen to HTML

In `browserid-broker/static/dialog/dialog.html`, add new screen:

```html
<div id="set-password-screen" class="screen">
  <h2>Set Your Password</h2>
  <p>Your email <strong class="email-display"></strong> was previously verified through your email provider.</p>
  <p>Since your email provider no longer supports BrowserID, please set a password for your account.</p>
  <form id="set-password-form">
    <div class="form-group">
      <input type="password" id="set-password" placeholder="Choose a password" required minlength="8">
      <span id="set-password-error" class="error"></span>
    </div>
    <div class="form-group">
      <input type="password" id="set-password-confirm" placeholder="Confirm password" required>
      <span id="set-password-confirm-error" class="error"></span>
    </div>
    <button type="submit" class="primary">Set Password</button>
    <button type="button" class="cancel">Cancel</button>
  </form>
</div>
```

### Step 2: Add transition_to_primary info screen

```html
<div id="primary-transition-screen" class="screen">
  <h2>Sign in with your email provider</h2>
  <p>Your email <strong class="email-display"></strong> can now be verified directly by your email provider.</p>
  <p>Click continue to sign in with <strong class="idp-name"></strong>.</p>
  <button id="continue-to-primary" class="primary">Continue</button>
  <button type="button" class="cancel">Cancel</button>
</div>
```

### Step 3: Add screens to screens object

In dialog.js:

```javascript
const screens = {
  // ... existing screens
  setPassword: document.getElementById('set-password-screen'),
  primaryTransition: document.getElementById('primary-transition-screen'),
};
```

### Step 4: Add event handler for set-password form

```javascript
document.getElementById('set-password-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = document.getElementById('set-password').value;
  const confirm = document.getElementById('set-password-confirm').value;

  if (password.length < 8) {
    document.getElementById('set-password-error').textContent = 'Password must be at least 8 characters';
    return;
  }

  if (password !== confirm) {
    document.getElementById('set-password-confirm-error').textContent = 'Passwords do not match';
    return;
  }

  showScreen('loading');

  try {
    // Set password for existing user
    await apiCall('/wsapi/set_password', 'POST', {
      email: state.email,
      pass: password
    });

    // Now sign in with the new password
    await apiCall(API.authenticate, 'POST', {
      email: state.email,
      pass: password,
      ephemeral: false
    });

    await completeSignIn(state.email);
  } catch (e) {
    showScreen('setPassword');
    document.getElementById('set-password-error').textContent = e.message;
  }
});
```

### Step 5: Add continue-to-primary handler

```javascript
document.getElementById('continue-to-primary').addEventListener('click', async () => {
  // Re-fetch address info to get current primary IdP info
  const addressInfo = await fetch(`${API.addressInfo}?email=${encodeURIComponent(state.email)}`)
    .then(r => r.json());

  if (addressInfo.type === 'primary') {
    await handlePrimaryIdP(state.email, addressInfo);
  } else {
    showError('This email is no longer a primary IdP');
  }
});
```

### Step 6: Update email form handler for transitions

Update the switch in the email form handler to use the new screens:

```javascript
if (addressInfo.type === 'primary') {
  if (addressInfo.state === 'transition_to_secondary') {
    showScreen('password');
  } else if (addressInfo.state === 'transition_no_password') {
    showScreen('setPassword');
  } else {
    await handlePrimaryIdP(email, addressInfo);
  }
} else {
  if (addressInfo.state === 'known') {
    showScreen('password');
  } else if (addressInfo.state === 'transition_to_primary') {
    // Show info screen before redirecting
    const domain = email.split('@')[1];
    document.querySelectorAll('.idp-name').forEach(el => el.textContent = domain);
    state.pendingAddressInfo = addressInfo;
    showScreen('primaryTransition');
  } else {
    showScreen('create');
  }
}
```

### Step 7: Add /wsapi/set_password endpoint

Create in `browserid-broker/src/routes/primary.rs`:

```rust
#[derive(Deserialize)]
pub struct SetPasswordRequest {
    pub email: String,
    pub pass: String,
}

#[derive(Serialize)]
pub struct SetPasswordResponse {
    pub success: bool,
}

/// POST /wsapi/set_password
/// Set password for a primary-only user transitioning to secondary
pub async fn set_password<U, S, E>(
    State(state): State<Arc<AppState<U, S, E>>>,
    Json(req): Json<SetPasswordRequest>,
) -> Result<Json<SetPasswordResponse>, BrokerError>
where
    U: UserStore,
    S: SessionStore,
    E: EmailSender,
{
    // Validate password
    if req.pass.len() < 8 {
        return Err(BrokerError::PasswordTooShort);
    }
    if req.pass.len() > 80 {
        return Err(BrokerError::PasswordTooLong);
    }

    // Find user by email
    let user = state.user_store.get_user_by_email(&req.email)?
        .ok_or(BrokerError::UserNotFound)?;

    // User must not already have a password
    if state.user_store.has_password(user.id)? {
        return Err(BrokerError::Internal("User already has a password".to_string()));
    }

    // Hash and set password
    let hash = hash_password(&req.pass)
        .map_err(|e| BrokerError::Internal(e.to_string()))?;
    state.user_store.set_password(user.id, &hash)?;

    // Update email type to secondary
    state.user_store.update_email_last_used(&req.email, EmailType::Secondary)?;

    Ok(Json(SetPasswordResponse { success: true }))
}
```

### Step 8: Register route

In `browserid-broker/src/routes/mod.rs`:

```rust
.route("/wsapi/set_password", post(primary::set_password))
```

### Step 9: Commit

```bash
git add browserid-broker/static/dialog/dialog.html
git add browserid-broker/static/dialog.js
git add browserid-broker/src/routes/primary.rs
git add browserid-broker/src/routes/mod.rs
git commit -m "feat(dialog): add state transition screens

- transition_no_password: set password for primary->secondary
- transition_to_primary: info screen before IdP redirect
- /wsapi/set_password endpoint for password-less users"
```

---

## Task 8: Integration Tests

**Files:**
- Create: `browserid-broker/tests/primary_idp_integration_test.rs`
- Modify: `e2e-tests/` as needed

### Step 1: Create integration test file

Create `browserid-broker/tests/primary_idp_integration_test.rs`:

```rust
//! Integration tests for primary IdP support

use browserid_broker::*;
// ... imports

#[tokio::test]
async fn test_full_primary_flow() {
    // 1. Setup broker with mock DNS returning primary IdP
    // 2. Call address_info - expect type=primary
    // 3. Mock provisioning (would require IdP)
    // 4. Call auth_with_assertion
    // 5. Verify session established
}

#[tokio::test]
async fn test_transition_to_secondary() {
    // 1. Create user with primary email
    // 2. Mock DNS to return no DNSSEC (fallback to secondary)
    // 3. Call address_info - expect transition_to_secondary
}

#[tokio::test]
async fn test_transition_no_password() {
    // 1. Create user with primary email (no password)
    // 2. Mock DNS to return no DNSSEC
    // 3. Call address_info - expect transition_no_password
    // 4. Call set_password
    // 5. Verify user can now authenticate
}

#[tokio::test]
async fn test_unknown_email_primary() {
    // 1. Mock DNS to return primary IdP
    // 2. Call address_info for unknown email
    // 3. Expect type=primary, state=unknown
}

#[tokio::test]
async fn test_dnssec_bogus_rejects() {
    // 1. Mock DNS to return BOGUS DNSSEC
    // 2. Call address_info
    // 3. Expect error, not fallback
}
```

### Step 2: Update existing tests for optional password

Review and update existing tests that assume password is always present.

### Step 3: Run all tests

```bash
cargo test -p browserid-broker
```

### Step 4: Consider E2E tests

For full E2E testing of the primary IdP flow, you would need a mock primary IdP. This could be added to e2e-tests later with a test IdP server.

### Step 5: Commit

```bash
git add browserid-broker/tests/primary_idp_integration_test.rs
git commit -m "test(broker): add integration tests for primary IdP flows

- Full primary flow test (mocked)
- State transition tests
- DNSSEC BOGUS rejection test"
```

---

## Final Steps

After all tasks are complete:

1. Run full test suite:
   ```bash
   cargo test --all
   cd e2e-tests && npm test
   ```

2. Test manually with a real or mock primary IdP

3. Update README.md if needed to document primary IdP setup

4. Create PR or merge to main
