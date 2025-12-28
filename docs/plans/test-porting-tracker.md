# BrowserID Test Porting Tracker

This document tracks the porting of tests from Mozilla Persona (~/src/browserid) to browserid-ng.

## Summary

| Category | Original | Ported | Coverage |
|----------|----------|--------|----------|
| Backend API Tests | ~60 files | 19 files (98 tests) | Core features covered |
| Frontend QUnit Tests | 59 files | 0 | Covered by E2E tests |
| E2E Tests (Selenium → Playwright) | 11 files | 10 files (61 tests) | Core flows covered |
| Core Protocol Tests | (in verifier-test.js) | 5 files (77 tests) | Comprehensive |

**Total: 236 tests across 34 test files**

---

## Backend API Tests

### Ported (19 test files, 98 tests)

| Original (browserid/tests/) | Ported To | Tests |
|----------------------------|-----------|-------|
| account-cancel-test.js | account_cancel_test.rs | 8 |
| address-info-test.js | address_info_test.rs | 7 |
| authentication-test.js (derived) | authentication_test.rs | 3 |
| cert-key-test.js | cert_key_test.rs | 7 |
| cookie-session-security-test.js | cookie_session_security_test.rs | 6 |
| email-addition-status-test.js | email_addition_status_test.rs | 4 |
| forgotten-pass-test.js | forgotten_pass_test.rs | 12 |
| list-emails-wsapi-test.js | list_emails_wsapi_test.rs | 4 |
| logout-test.js | logout_test.rs | 5 |
| password-length-test.js | password_length_test.rs | 3 |
| password-update-test.js | password_update_test.rs | 8 |
| registration-status-wsapi-test.js | registration_status_test.rs | 6 |
| remove-email-test.js | remove_email_test.rs | 5 |
| session-context-test.js | session_context_test.rs | 5 |
| stage-email (derived) | stage_email_test.rs | 3 |
| verification (derived) | verification_test.rs | 3 |
| verifier-test.js | verifier_test.rs | 13 |
| well-known-test.js | well_known_test.rs | 1 |

### Not Ported - Security/Rate Limiting (nice to have)

| Original | Description | Reason Deferred |
|----------|-------------|-----------------|
| authentication-lockout-test.js | Brute force protection | Need rate limiting infrastructure |
| email-throttling-test.js | Email rate limiting | Need rate limiting infrastructure |
| post-limiting-test.js | POST request limiting | Need rate limiting infrastructure |

### Not Ported - Session Management (nice to have)

| Original | Description | Reason Deferred |
|----------|-------------|-----------------|
| session-prolong-test.js | Session extension on activity | Need prolong_session endpoint |
| session-duration-test.js | Session expiration | Need ephemeral param, UA detection |

### Not Applicable (infrastructure-specific)

| Original | Reason |
|----------|--------|
| db-test.js | MySQL-specific (we use SQLite) |
| stalled-mysql-test.js | MySQL connection handling |
| bcrypt-compatibility-test.js | Legacy bcrypt migration |
| password-bcrypt-update-test.js | bcrypt auto-upgrade |
| jshint-test.js | JavaScript linting |
| statsd-test.js | StatsD metrics |
| metrics-header-test.js | Metrics headers |
| kpi-test.js | KPI event tracking |
| heartbeat-test.js | Health check (trivial) |
| software-version-test.js | Version endpoint |
| no-cookie-test.js | Cookie-disabled handling |
| p3p-header-test.js | P3P privacy header (obsolete) |
| secrets-test.js | Secret key handling |
| coarse-user-agent-parser-test.js | UA parsing utility |
| fonts-request-test.js | Font file serving |
| static-resource-test.js | Static file serving |
| page-requests-test.js | Page rendering |
| rp-branded-emails-test.js | RP-specific email templates |
| i18n-tests.js | Internationalization |
| header-tests.js | HTTP headers (covered by framework) |

### Not Applicable - Primary IdP (not implementing)

| Original | Description |
|----------|-------------|
| add-email-with-assertion-test.js | Add email via IdP assertion |
| auth-with-assertion-test.js | Auth via IdP assertion |
| discovery-test.js | IdP discovery (core has this) |
| idp-seen-test.js | Track seen IdPs |
| proxy-idp-test.js | Proxy IdP support |
| primary-then-secondary-test.js | Primary to secondary transition |
| primary-secondary-transition-test.js | IdP transition handling |
| primary-secondary-transition-forgot-password-test.js | Password reset during transition |
| used-address-as-primary-test.js | Email previously at primary |
| two-level-auth-test.js | Two-factor auth |

### Partially Covered

| Original | Coverage |
|----------|----------|
| unverified-email-test.js | Covered in verification_test.rs |
| conformance-test.js | Moved to browserid-core |
| ca-test.js | Moved to browserid-core |
| internal-wsapi-test.js | Covered by /test/ endpoints |
| verify-in-different-browser-test.js | Covered by E2E tests |

---

## Core Protocol Tests (browserid-core)

### Ported (5 test files, 77 tests)

| Test File | Tests | Coverage |
|-----------|-------|----------|
| ca_test.rs | 6 | Keypair generation, certificate creation, signature verification |
| verifier_test.rs | 23 | Assertion verification, security checks, audience matching |
| discovery_test.rs | 13 | Domain discovery, .well-known handling, delegation |
| conformance_test.rs | 22 | JWT format compliance, field validation, encoding |
| well_known_test.rs | 13 | Support document format, disabled domains, public keys |

These cover the protocol-level tests from:
- verifier-test.js (assertion verification)
- conformance-test.js (JWT format)
- ca-test.js (certificate authority)
- well-known-test.js (support documents)
- discovery-test.js (IdP discovery)

---

## Frontend QUnit Tests (59 original files)

### Status: Not Ported (covered by E2E tests)

The original browserid had extensive QUnit unit tests for JavaScript modules in:
- `resources/static/test/js/` - Common JS modules (18 files)
- `resources/static/test/dialog/js/modules/` - Dialog modules (21 files)
- `resources/static/test/dialog/js/misc/` - Dialog helpers (3 files)

**Decision**: These are not being ported directly because:
1. E2E tests cover the same user flows
2. Our dialog is simpler (vanilla JS vs complex module system)
3. The include.js API is tested via include-api.spec.ts

Key QUnit test areas now covered by E2E:
- Dialog initialization → dialog-loads.spec.ts
- Authentication flow → sign-in.spec.ts
- Email management → new-user-signup.spec.ts, remove-email.spec.ts
- Password flows → change-password.spec.ts, reset-password.spec.ts
- navigator.id API → include-api.spec.ts, silent-assertion.spec.ts

---

## E2E Tests (Selenium → Playwright)

### Ported (10 test files, 61 tests)

| Original (automation-tests/) | Ported To | Tests |
|------------------------------|-----------|-------|
| sign-in-test.js | sign-in.spec.ts | 7 |
| new-user/new-user-secondary-test.js | new-user-signup.spec.ts | 8 |
| returning-user.js | returning-user.spec.ts | 5 |
| change-password-test.js | change-password.spec.ts | 4 |
| reset-password-test.js | reset-password.spec.ts | 6 |
| cancel-account.js | cancel-account.spec.ts | 5 |
| remove-email.js | remove-email.spec.ts | 5 |
| (dialog loading) | dialog-loads.spec.ts | 5 |
| include.js QUnit tests | include-api.spec.ts | 9 |
| (silent assertion) | silent-assertion.spec.ts | 7 |

### Not Ported - Nice to Have

| Original | Description | Reason |
|----------|-------------|--------|
| public-terminals.js | Public terminal handling | Ephemeral sessions not implemented |
| health-check-tests.js | Health endpoint checks | Low priority |
| frontend-qunit-test.js | Run QUnit in browser | Separate infrastructure |
| api-tests/oncancel.js | Cancel callback testing | Requires RP integration |

### Not Ported - Primary IdP (not implementing)

| Original | Description |
|----------|-------------|
| new-user/new-user-primary-test.js | Primary IdP signup |
| add-primary-to-primary.js | Add primary to primary |
| add-primary-to-secondary.js | Add primary to secondary |
| idp-transition/broken-primary.js | Broken IdP handling |
| idp-transition/primary-shuts-down-single-email.js | IdP shutdown |
| idp-transition/primary-starts-up-single-email.js | IdP startup |
| idp-transition/transition-to-secondary.js | Transition to secondary |
| idp-transition/transition-to-secondary-forgot-password.js | Transition + reset |

---

## Verifier Test Coverage Comparison

The original `verifier-test.js` (42KB) had extensive tests. Here's what's covered:

### Covered in browserid-core/tests/verifier_test.rs

- [x] Valid assertion verification
- [x] Fallback broker support
- [x] Untrusted issuer rejection
- [x] Cross-domain issuer rejection (security)
- [x] Audience mismatch (wrong host)
- [x] Audience mismatch (wrong port)
- [x] Audience mismatch (wrong scheme)
- [x] Expired assertion
- [x] Expired certificate
- [x] Bad certificate signature
- [x] Bad assertion signature
- [x] Missing certificate
- [x] Invalid format

### Not Covered (edge cases)

- [ ] Audience matching with default ports (http:80 ≡ http, https:443 ≡ https)
- [ ] POST format variations (form-urlencoded, JSON, query params)
- [ ] Malformed assertion (truncated, prepended data)
- [ ] Certificate chain rejection (multi-cert chains)
- [ ] Wildcard audience rejection
- [ ] Empty domain in audience
- [ ] Proxy IDP verification (delegation)
- [ ] Uppercase domain normalization

---

## Running Tests

```bash
# All Rust tests (core + broker)
cargo test

# Core protocol tests only
cargo test -p browserid-core

# Broker API tests only
cargo test -p browserid-broker

# Specific test file
cargo test -p browserid-broker --test session_context_test

# E2E tests
cd e2e-tests && npm test

# Specific E2E test
cd e2e-tests && npx playwright test sign-in.spec.ts

# E2E with browser visible
cd e2e-tests && npx playwright test --headed
```

---

## What's Left to Consider

### High Value (if implementing)
1. **Rate limiting tests** - authentication-lockout, email-throttling, post-limiting
2. **Session expiration tests** - session-duration, session-prolong

### Low Priority
1. **Edge case verifier tests** - default port matching, malformed input
2. **Health check endpoint** - trivial to implement

### Not Implementing
1. **Primary IdP support** - All primary-* tests
2. **Legacy infrastructure** - MySQL, bcrypt migration, StatsD
