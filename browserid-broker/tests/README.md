# Broker Test Porting Status

Tests ported from mozilla/persona (~/src/browserid/tests/).

## Ported

- [x] session_context_test.rs (from session-context-test.js) - CSRF token, auth status, server_time
- [x] logout_test.rs (from logout-test.js) - Logout flows, session invalidation
- [x] password_length_test.rs (from password-length-test.js) - Password validation (8-80 chars)
- [x] list_emails_wsapi_test.rs (from list-emails-wsapi-test.js) - Email listing
- [x] remove_email_test.rs (from remove-email-test.js) - Email removal
- [x] cert_key_test.rs (from cert-key-test.js) - Certificate issuance
- [x] authentication_test.rs (derived from multiple tests) - Login/auth flows
- [x] well_known_test.rs (from well-known-browserid.js) - Support document
- [x] stage_email_test.rs (derived) - Email staging endpoints
- [x] verification_test.rs (derived) - Verification code handling
- [x] forgotten_pass_test.rs (from forgotten-pass-test.js) - Password reset flow

## Not Yet Ported

- [ ] registration_status_wsapi_test.rs (from registration-status-wsapi-test.js) - Need user_creation_status endpoint
- [ ] authentication_lockout_test.rs (from authentication-lockout-test.js) - Need account lockout feature
- [ ] email_throttling_test.rs (from email-throttling-test.js) - Need rate limiting
- [ ] session_duration_test.rs (from session-duration-test.js) - Need session expiry
- [ ] session_prolong_test.rs (from session-prolong-test.js) - Need session refresh

## Not Applicable

- bcrypt-compatibility-test.js - Legacy bcrypt migration
- primary-secondary-transition-test.js - Primary IdP support (not implementing)
- primary-then-secondary-test.js - Primary IdP support (not implementing)
- proxy-idp-test.js - IdP proxy (not implementing)
- add-email-with-assertion-test.js - Primary IdP assertions (not implementing)
- auth-with-assertion-test.js - Primary IdP assertions (not implementing)

## Running Tests

```bash
# Run all broker tests
cargo test -p browserid-broker

# Run specific test file
cargo test -p browserid-broker --test session_context_test

# Run specific test
cargo test -p browserid-broker test_session_context_authenticated
```
