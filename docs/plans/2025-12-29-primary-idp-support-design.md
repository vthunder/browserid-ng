# Primary IdP Support Design

## Overview

Implement full primary identity provider (IdP) support following the original BrowserID/Persona protocol exactly. This enables email domains with DNSSEC-validated `_browserid` TXT records to act as their own identity providers, issuing certificates directly to their users.

## Architecture

```
RP Page
  ↓
include.js + communication_iframe (broker)
  ↓
Dialog
  ├── /wsapi/address_info → discovers primary vs secondary
  ├── Hidden iframe → primary's /provision page (silent cert attempt)
  ├── If not authenticated → show primary's /auth page in dialog
  ├── After auth → retry provisioning
  └── /wsapi/auth_with_assertion → establish broker session
```

## Account Model

Users have broker-side accounts that track:
- User ID
- Associated emails (with type: primary or secondary)
- Password hash (only if they have secondary emails)
- Last password reset timestamp

**Key insight:** Primary-only users have broker accounts (for email association tracking) but NO password.

## State Machine

The `/wsapi/address_info` endpoint returns states based on:
- `passwordKnown` - does user have a broker password?
- `lastUsedAs` - was this email last used as primary or secondary?
- `currentType` - is the domain currently a primary IdP or secondary?

### State Table

```
passwordKnown → lastUsedAs → currentType → state

true (has password):
  primary → primary    = "known"
  primary → secondary  = "transition_to_secondary"
  secondary → primary  = "transition_to_primary"
  secondary → secondary = "known"

false (no password):
  primary → primary    = "known"
  primary → secondary  = "transition_no_password"
  secondary → primary  = "transition_to_primary"
  secondary → secondary = "transition_no_password"
```

### State Meanings

| State | Meaning | Dialog Action |
|-------|---------|---------------|
| `known` | Normal state, proceed with current type | Primary: provision. Secondary: password prompt |
| `unknown` | Email not in database | Primary: provision + create account. Secondary: signup flow |
| `transition_to_primary` | Was secondary, domain now primary | Authenticate with primary IdP |
| `transition_to_secondary` | Was primary, now secondary, user HAS password | Password prompt |
| `transition_no_password` | Now secondary but user has no broker password | Must set password |

## Discovery Integration

### Current: `/wsapi/address_info`

Only checks broker's local database.

### New: `/wsapi/address_info`

1. Extract domain from email
2. Use `FallbackFetcher.discover(domain)` for DNS-first discovery
3. If DNSSEC-validated (primary IdP):
   - Fetch `/.well-known/browserid` from host to get auth/prov paths
   - Look up email in broker DB to determine state
   - Return `type: "primary"` with auth/prov URLs and appropriate state
4. If not DNSSEC (fallback):
   - Look up email in broker DB
   - Return `type: "secondary"` with appropriate state
5. If BOGUS DNSSEC:
   - Return error (security failure)

### Response Format

```json
// Primary IdP
{
  "type": "primary",
  "issuer": "example.com",
  "state": "known|unknown|transition_to_primary",
  "auth": "https://example.com/browserid/auth",
  "prov": "https://example.com/browserid/provision",
  "normalizedEmail": "alice@example.com"
}

// Secondary (broker fallback)
{
  "type": "secondary",
  "issuer": "localhost:3000",
  "state": "known|unknown|transition_to_secondary|transition_no_password",
  "normalizedEmail": "alice@gmail.com"
}
```

## Provisioning Flow

### Step 1: Dialog Creates Hidden Iframe

```javascript
// Dialog loads primary's provisioning page in hidden iframe
const iframe = document.createElement('iframe');
iframe.src = provisioningUrl; // e.g., https://example.com/browserid/provision
iframe.style.display = 'none';
document.body.appendChild(iframe);

// Establish postMessage channel
const channel = new Channel(iframe.contentWindow, origin);
```

### Step 2: Provisioning Page Calls navigator.id APIs

The primary's provisioning page includes our shim and calls:

```javascript
// Primary's /browserid/provision page
<script src="https://broker.example/provisioning_api.js"></script>
<script>
navigator.id.beginProvisioning(function(email, cert_duration_s) {
  // Check if user is authenticated with primary
  fetch('/api/whoami')
    .then(r => r.json())
    .then(user => {
      if (user.email !== email) {
        navigator.id.raiseProvisioningFailure('user not authenticated');
        return;
      }

      // Generate keypair
      navigator.id.genKeyPair(function(publicKey) {
        // Sign with primary's key
        fetch('/api/cert_key', {
          method: 'POST',
          body: JSON.stringify({ pubkey: JSON.parse(publicKey), duration: cert_duration_s })
        })
        .then(r => r.json())
        .then(data => {
          navigator.id.registerCertificate(data.cert);
        });
      });
    });
});
</script>
```

### Step 3: Dialog Receives Certificate or Failure

- Success: `registerCertificate(cert)` → dialog stores cert, closes iframe
- Failure: `raiseProvisioningFailure(reason)` → dialog shows auth page

## Authentication Flow

When provisioning fails (user not authenticated with primary):

### Step 1: Dialog Redirects to Auth Page

```javascript
// Dialog redirects to primary's auth page
const authUrl = new URL(primaryAuthUrl);
authUrl.searchParams.set('email', email);
window.location = authUrl;
```

### Step 2: Primary's Auth Page

```html
<!-- Primary's /browserid/auth page -->
<script src="https://broker.example/authentication_api.js"></script>
<script>
navigator.id.beginAuthentication(function(email) {
  // Show login UI for this email
  document.getElementById('email-display').textContent = email;
});

function onLogin() {
  // Verify credentials with primary's backend
  fetch('/api/login', { method: 'POST', body: ... })
    .then(r => {
      if (r.ok) {
        navigator.id.completeAuthentication();
      } else {
        showError('Invalid credentials');
      }
    });
}

function onCancel() {
  navigator.id.raiseAuthenticationFailure('user cancelled');
}
</script>
```

### Step 3: Return to Broker

`completeAuthentication()` redirects to:
```
https://broker.example/sign_in#AUTH_RETURN
```

`raiseAuthenticationFailure()` redirects to:
```
https://broker.example/sign_in#AUTH_RETURN_CANCEL
```

### Step 4: Dialog Detects Return, Retries Provisioning

```javascript
// Dialog checks for AUTH_RETURN in URL hash
if (location.hash.includes('AUTH_RETURN')) {
  // User authenticated with primary, retry provisioning
  retryProvisioning();
}
```

## Auth With Assertion

After successful provisioning, establish broker session:

### Endpoint: `POST /wsapi/auth_with_assertion`

Request:
```json
{
  "assertion": "<backed-assertion>",
  "ephemeral": false
}
```

Response:
```json
{
  "success": true
}
```

This:
1. Verifies the assertion (including primary IdP certificate)
2. Extracts email from certificate
3. Creates or finds user account in broker DB
4. Establishes session (sets session cookie)

## API Shims

### `/provisioning_api.js`

Served by broker for primary IdPs to include:

```javascript
navigator.id = navigator.id || {};

(function() {
  // Establish postMessage channel with parent (broker dialog)
  const channel = new Channel(window.parent, '*');

  navigator.id.beginProvisioning = function(callback) {
    channel.call('beginProvisioning', function(params) {
      callback(params.email, params.cert_duration_s);
    });
  };

  navigator.id.genKeyPair = function(callback) {
    channel.call('genKeyPair', function(publicKey) {
      callback(publicKey);
    });
  };

  navigator.id.registerCertificate = function(certificate) {
    channel.notify('registerCertificate', certificate);
  };

  navigator.id.raiseProvisioningFailure = function(reason) {
    channel.notify('raiseProvisioningFailure', reason);
  };
})();
```

### `/authentication_api.js`

```javascript
navigator.id = navigator.id || {};

(function() {
  const params = new URLSearchParams(location.search);
  const email = params.get('email');
  const returnTo = 'https://broker.example/sign_in';

  navigator.id.beginAuthentication = function(callback) {
    callback(email);
  };

  navigator.id.completeAuthentication = function() {
    window.location = returnTo + '#AUTH_RETURN';
  };

  navigator.id.raiseAuthenticationFailure = function(reason) {
    window.location = returnTo + '#AUTH_RETURN_CANCEL';
  };
})();
```

## Database Changes

### New Fields

**emails table:**
- `type` - "primary" or "secondary"
- `last_used_as` - "primary" or "secondary" (tracks transitions)

### New/Modified Endpoints

| Endpoint | Change |
|----------|--------|
| `/wsapi/address_info` | Add DNS discovery, return primary/secondary type with state |
| `/wsapi/auth_with_assertion` | New - authenticate via primary IdP assertion |
| `/provisioning_api.js` | New - JavaScript shim for primary IdPs |
| `/authentication_api.js` | New - JavaScript shim for primary IdPs |

## Dialog Changes

### State Machine Updates

Handle new states in dialog.js:
- `transition_to_primary` → start primary IdP flow
- `transition_to_secondary` → show password prompt
- `transition_no_password` → show password creation prompt

### New Screens

- Primary IdP auth iframe/redirect handling
- Transition password creation

### New Modules

- `provisioning.js` - hidden iframe management, postMessage channel
- `primary_auth.js` - auth page redirect/return handling

## Security Considerations

1. **DNSSEC validation** - Only domains with DNSSEC-validated `_browserid` records can be primary IdPs
2. **BOGUS rejection** - DNSSEC validation failures are hard errors, not fallbacks
3. **Certificate verification** - Broker verifies primary IdP certificates using DNS-discovered public key
4. **postMessage origin checking** - Strict origin validation in channel communication
5. **HTTPS requirement** - Primary IdP pages must be served over HTTPS

## Testing Strategy

1. **Unit tests** - State table logic, discovery integration
2. **Integration tests** - Provisioning flow with mock primary IdP
3. **E2E tests** - Full flow with test primary IdP domain

## Implementation Order

1. Database schema changes (type, last_used_as)
2. `/wsapi/address_info` with DNS discovery and state machine
3. `/wsapi/auth_with_assertion` endpoint
4. `/provisioning_api.js` and `/authentication_api.js` shims
5. Dialog provisioning module (hidden iframe, postMessage)
6. Dialog auth module (redirect/return handling)
7. Dialog state machine updates
8. Tests

## Open Questions

1. Should we implement jschannel exactly or use a simpler postMessage protocol?
2. Certificate duration defaults (ephemeral vs persistent)?
3. How to handle primary IdP timeouts/errors gracefully?
