# BrowserID-NG Broker API Design

A direct port of Mozilla Persona's broker architecture to Rust, with simplifications for initial implementation.

## Overview

The broker serves as a fallback identity provider for domains that don't implement native BrowserID support. Users create accounts with email + password, verify email ownership via codes, and can then obtain certificates for their verified emails.

## Account Model

**User Account:**
- `user_id` - unique identifier
- `password_hash` - bcrypt hash of password
- `created_at` - account creation time

**Email:**
- `email` - the email address
- `user_id` - owner
- `verified` - boolean
- `verified_at` - when verified (null if not)

**Pending Verification:**
- `secret` - random verification token
- `email` - being verified
- `user_id` - who initiated (null for new accounts)
- `password_hash` - for new account creation
- `created_at` - for expiry (e.g., 24 hours)

A user can have multiple verified emails. Sessions track which user is logged in.

## API Endpoints

### Session
- `GET /wsapi/session_context` - returns CSRF token, auth status, user info

### Account Creation
- `POST /wsapi/stage_user` - start account creation (email, password) → sends verification code
- `POST /wsapi/complete_user_creation` - verify code, create account

### Authentication
- `POST /wsapi/authenticate_user` - login with email + password
- `POST /wsapi/logout` - clear session

### Email Management
- `GET /wsapi/list_emails` - list user's verified emails
- `POST /wsapi/stage_email` - add email to account → sends verification code
- `POST /wsapi/complete_email_addition` - verify code, add email
- `POST /wsapi/remove_email` - remove email from account

### Certificate Issuance
- `POST /wsapi/cert_key` - issue certificate for verified email (requires auth)

### Support Document
- `GET /.well-known/browserid` - broker's public key

## Authentication Flows

### New User Registration
1. User enters email + password in popup
2. `POST /wsapi/stage_user` - broker stores pending account, sends 6-digit code
3. User enters code
4. `POST /wsapi/complete_user_creation` - broker creates account, logs user in
5. Session cookie set with `user_id`

### Returning User Login
1. User enters email + password
2. `POST /wsapi/authenticate_user` - broker verifies password
3. Session cookie set with `user_id`

### Adding Email to Account
1. User logged in, clicks "add email"
2. `POST /wsapi/stage_email` - broker sends code to new email
3. User enters code
4. `POST /wsapi/complete_email_addition` - email added to account

### Getting an Assertion (for relying party)
1. Popup opens, user logs in (or already has session)
2. User picks which email to use
3. `POST /wsapi/cert_key` - broker issues certificate
4. Client-side JS creates assertion, signs with user's keypair
5. Assertion sent to relying party via postMessage

## Storage Abstractions

```rust
trait UserStore {
    fn create_user(&self, password_hash: &str) -> Result<UserId>;
    fn get_user(&self, user_id: UserId) -> Result<Option<User>>;
    fn get_user_by_email(&self, email: &str) -> Result<Option<User>>;
    fn verify_password(&self, user_id: UserId, password: &str) -> Result<bool>;

    fn add_email(&self, user_id: UserId, email: &str, verified: bool) -> Result<()>;
    fn list_emails(&self, user_id: UserId) -> Result<Vec<Email>>;
    fn remove_email(&self, user_id: UserId, email: &str) -> Result<()>;

    fn create_pending(&self, pending: PendingVerification) -> Result<String>;
    fn get_pending(&self, secret: &str) -> Result<Option<PendingVerification>>;
    fn delete_pending(&self, secret: &str) -> Result<()>;
}

trait EmailSender {
    fn send_verification(&self, email: &str, code: &str) -> Result<()>;
}

trait SessionStore {
    fn create(&self, user_id: UserId) -> Result<SessionId>;
    fn get(&self, session_id: SessionId) -> Result<Option<Session>>;
    fn delete(&self, session_id: SessionId) -> Result<()>;
}
```

### Initial Implementations
- `InMemoryUserStore` - HashMap-based
- `ConsoleEmailSender` - logs code to stdout
- `InMemorySessionStore` - HashMap-based

## Security Measures

### CSRF Protection
- Every session gets a CSRF token
- All POST requests must include matching token
- Token returned in `GET /wsapi/session_context`

### Password Security
- bcrypt with configurable work factor (default 12)
- Rehash on login if work factor changes

### Verification Codes
- 6-digit numeric codes
- Expire after 15 minutes
- Single use (deleted after verification)
- Rate limit: max 3 pending codes per email

### Session Security
- HttpOnly cookies (no JS access)
- Secure flag when over HTTPS
- Session expires after 30 days of inactivity

### Rate Limiting (future)
- Max 5 verification emails per email per hour
- Max 10 failed login attempts per account per hour

## Broker Configuration

- `--domain` / `BROKER_DOMAIN` - broker's domain (default: localhost:3000)
- `--port` / `BROKER_PORT` - HTTP port (default: 3000)
- `--key-file` / `BROKER_KEY_FILE` - path to keypair file (default: broker-key.json)

Keypair is auto-generated on first run if file doesn't exist.

## File Structure

```
browserid-broker/
├── src/
│   ├── main.rs              # Server startup, config loading
│   ├── config.rs            # Configuration (domain, port, key path)
│   ├── state.rs             # AppState (stores, keypair, config)
│   ├── routes/
│   │   ├── mod.rs           # Route registration
│   │   ├── well_known.rs    # GET /.well-known/browserid
│   │   ├── session.rs       # GET /wsapi/session_context
│   │   ├── auth.rs          # authenticate_user, logout
│   │   ├── account.rs       # stage_user, complete_user_creation
│   │   ├── email.rs         # stage_email, complete_email_addition, list_emails, remove_email
│   │   └── cert.rs          # cert_key
│   ├── store/
│   │   ├── mod.rs           # Trait definitions
│   │   ├── memory.rs        # In-memory implementations
│   │   └── models.rs        # User, Email, Session, PendingVerification
│   ├── email/
│   │   ├── mod.rs           # EmailSender trait
│   │   └── console.rs       # Console logger implementation
│   └── crypto.rs            # Password hashing, code generation
```

## Simplifications from Original Persona

- **Ed25519** instead of RS256/DS128
- **Single binary** - no separate keysigner service
- **In-memory storage** - with traits for future persistence
- **Console email** - with trait for future SMTP
- **No primary IdP support** - we're always the fallback broker
- **Certificate validity** - 30 days (original used 24 hours)

## Reference

Based on Mozilla Persona implementation at `~/src/browserid/`. Key reference files:
- `lib/wsapi/` - endpoint implementations
- `lib/db/` - database layer
- `resources/static/dialog/` - client-side JS
