# Broker Integration Tests

Tests ported from mozilla/persona (`~/src/browserid/tests/`).

## Test Summary

**19 test files, 98 tests total**

## Ported Tests

### Authentication & Session

| Test File | Tests | Original |
|-----------|-------|----------|
| authentication_test.rs | 3 | (derived from multiple) |
| session_context_test.rs | 5 | session-context-test.js |
| logout_test.rs | 5 | logout-test.js |
| cookie_session_security_test.rs | 6 | cookie-session-security-test.js |

### Certificate & Verification

| Test File | Tests | Original |
|-----------|-------|----------|
| cert_key_test.rs | 7 | cert-key-test.js |
| verifier_test.rs | 13 | verifier-test.js |
| well_known_test.rs | 1 | well-known-test.js |

### Email Management

| Test File | Tests | Original |
|-----------|-------|----------|
| address_info_test.rs | 7 | address-info-test.js |
| list_emails_wsapi_test.rs | 4 | list-emails-wsapi-test.js |
| remove_email_test.rs | 5 | remove-email-test.js |
| stage_email_test.rs | 3 | (derived) |
| email_addition_status_test.rs | 4 | email-addition-status-test.js |

### Password Management

| Test File | Tests | Original |
|-----------|-------|----------|
| password_length_test.rs | 3 | password-length-test.js |
| password_update_test.rs | 8 | password-update-test.js |
| forgotten_pass_test.rs | 12 | forgotten-pass-test.js |

### Account & Registration

| Test File | Tests | Original |
|-----------|-------|----------|
| account_cancel_test.rs | 8 | account-cancel-test.js |
| registration_status_test.rs | 6 | registration-status-wsapi-test.js |
| verification_test.rs | 3 | (derived) |

## Verifier Test Coverage

The verifier_test.rs covers key security scenarios from the original verifier-test.js:

- [x] Valid assertion verification (fallback broker)
- [x] Untrusted issuer rejection
- [x] Cross-domain issuer rejection
- [x] Audience mismatch (wrong host, port, scheme)
- [x] Expired assertion/certificate handling
- [x] Bad signature detection (certificate and assertion)
- [x] Missing certificate handling
- [x] Invalid format handling

### Edge Cases Not Yet Covered

- [ ] Default port equivalence (http:80 ≡ http)
- [ ] POST format variations (form-urlencoded, JSON)
- [ ] Malformed assertion handling (truncated, prepended data)
- [ ] Certificate chain rejection
- [ ] Wildcard/empty audience rejection

## Not Ported

### Deferred (nice to have)

| Original | Reason |
|----------|--------|
| authentication-lockout-test.js | Need rate limiting infrastructure |
| email-throttling-test.js | Need rate limiting infrastructure |
| session-duration-test.js | Need session expiry feature |
| session-prolong-test.js | Need prolong_session endpoint |

### Not Applicable

| Original | Reason |
|----------|--------|
| bcrypt-compatibility-test.js | Legacy bcrypt migration |
| primary-*.js | Primary IdP support not implemented |
| proxy-idp-test.js | IdP proxy not implemented |
| add-email-with-assertion-test.js | Primary IdP assertions not implemented |
| auth-with-assertion-test.js | Primary IdP assertions not implemented |

## Running Tests

```bash
# Run all broker tests
cargo test -p browserid-broker

# Run specific test file
cargo test -p browserid-broker --test session_context_test

# Run specific test
cargo test -p browserid-broker test_session_context_authenticated

# Run with output
cargo test -p browserid-broker -- --nocapture
```
