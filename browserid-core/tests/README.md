# Test Porting Status

Tests ported from mozilla/persona (~/src/browserid/tests/).

## Ported

- [x] ca_test.rs (from ca-test.js) - Certificate authority / signing
- [x] verifier_test.rs (from verifier-test.js) - Assertion verification
- [x] discovery_test.rs (from discovery-test.js) - Domain discovery
- [x] conformance_test.rs (from conformance-test.js) - JWT format compliance
- [x] well_known_test.rs (from well-known-test.js) - Support document format, delegation, disabled domains

## Not Yet Ported (require server infrastructure)

- [ ] cert_key_test.rs (from cert-key-test.js) - Needs WSAPI server
- [ ] account_cancel_test.rs - Needs database
- [ ] add_email_with_assertion_test.rs - Needs WSAPI
- [ ] address_info_test.rs - Needs database
- [ ] auth_with_assertion_test.rs - Needs WSAPI
- [ ] authentication_lockout_test.rs - Needs database
- [ ] db_test.rs - Needs database
- [ ] forgotten_pass_test.rs - Needs database + email
- [ ] primary_then_secondary_test.rs - Needs full server
- [ ] well_known_browserid_test.rs (from well-known-browserid.js) - Needs HTTP server

## Not Applicable

- bcrypt-compatibility-test.js - We use Ed25519, not bcrypt for passwords
- cef-logging.js - CEF logging specific
- coarse-user-agent-parser-test.js - UA parsing specific
- cookie-session-security-test.js - Session management
- fonts-request-test.js - Static assets
- header-tests.js - HTTP headers
- heartbeat-test.js - Health checks
- i18n-tests.js - Internationalization
- jshint-test.js - JS linting
- kpi-test.js - Metrics
- statsd-test.js - Metrics
