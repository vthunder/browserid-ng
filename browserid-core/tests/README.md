# Test Porting Status

Tests ported from mozilla/persona (~/src/browserid/tests/).

## Ported (browserid-core)

- [x] ca_test.rs (from ca-test.js) - Certificate authority / signing
- [x] verifier_test.rs (from verifier-test.js) - Assertion verification
- [x] discovery_test.rs (from discovery-test.js) - Domain discovery
- [x] conformance_test.rs (from conformance-test.js) - JWT format compliance
- [x] well_known_test.rs (from well-known-test.js) - Support document format, delegation, disabled domains

## Ported (browserid-broker)

See `browserid-broker/tests/README.md` for the full list. Key tests:

- [x] cert_key_test.rs (from cert-key-test.js) - Certificate issuance
- [x] session_context_test.rs (from session-context-test.js) - Session management
- [x] logout_test.rs (from logout-test.js) - Logout flows
- [x] password_length_test.rs (from password-length-test.js) - Password validation
- [x] list_emails_wsapi_test.rs (from list-emails-wsapi-test.js) - Email listing
- [x] remove_email_test.rs (from remove-email-test.js) - Email removal

## Not Yet Ported

- [ ] authentication_lockout_test.rs (from authentication-lockout-test.js) - Needs account lockout feature
- [ ] registration_status_wsapi_test.rs (from registration-status-wsapi-test.js) - Needs status endpoint

## Ported to browserid-broker

- [x] forgotten_pass_test.rs (from forgotten-pass-test.js) - Password reset (broker-level feature)

## Not Applicable

- bcrypt-compatibility-test.js - Legacy bcrypt migration
- cef-logging.js - CEF logging specific
- coarse-user-agent-parser-test.js - UA parsing specific
- cookie-session-security-test.js - Covered by our session tests
- fonts-request-test.js - Static assets
- header-tests.js - HTTP headers
- heartbeat-test.js - Health checks
- i18n-tests.js - Internationalization
- jshint-test.js - JS linting
- kpi-test.js - Metrics
- statsd-test.js - Metrics
- primary-*.js - Primary IdP support (not implementing)
- proxy-idp-test.js - IdP proxy (not implementing)
