# BrowserID Test Porting Tracker

## Summary

| Category | Total | Ported | Remaining |
|----------|-------|--------|-----------|
| Backend API Tests | 53 | 17 | 36 |
| QUnit Dialog Tests | 19 | 0 | 19 |
| Selenium E2E Tests | 19 | 0 | 19 |

---

## Backend API Tests (53 total)

### Ported (14)

| Original | Ported To | Tests |
|----------|-----------|-------|
| account-cancel-test.js | account_cancel_test.rs | 8 |
| address-info-test.js | address_info_test.rs | 7 |
| cert-key-test.js | cert_key_test.rs | 3 |
| forgotten-pass-test.js | forgotten_pass_test.rs | 12 |
| list-emails-wsapi-test.js | list_emails_wsapi_test.rs | 4 |
| logout-test.js | logout_test.rs | 5 |
| password-length-test.js | password_length_test.rs | 3 |
| password-update-test.js | password_update_test.rs | 8 |
| remove-email-test.js | remove_email_test.rs | 5 |
| session-context-test.js | session_context_test.rs | 5 |
| well-known-test.js | well_known_test.rs | 1 |
| (user creation) | authentication_test.rs | 3 |
| (email staging) | stage_email_test.rs | 3 |
| (verification) | verification_test.rs | 3 |
| email-addition-status-test.js | email_addition_status_test.rs | 4 |
| registration-status-wsapi-test.js | registration_status_test.rs | 6 |
| cookie-session-security-test.js | cookie_session_security_test.rs | 6 |

### Ready to Port

All "ready to port" tests have been ported!

### Deferred (ephemeral sessions - nice to have)

| Test | Description | Needed |
|------|-------------|--------|
| session-prolong-test.js | Session extension on activity | ephemeral param, prolong_session endpoint |
| session-duration-test.js | Session expiration | ephemeral param, primary IdP, UA detection |

### Not Applicable (infrastructure-specific)

| Test | Reason |
|------|--------|
| db-test.js | MySQL-specific database tests |
| stalled-mysql-test.js | MySQL connection handling |
| bcrypt-compatibility-test.js | bcrypt version migration |
| password-bcrypt-update-test.js | bcrypt auto-upgrade |
| jshint-test.js | JavaScript linting |
| statsd-test.js | StatsD metrics infrastructure |
| metrics-header-test.js | Metrics header handling |
| kpi-test.js | KPI event tracking |
| heartbeat-test.js | Health check endpoint |
| software-version-test.js | Version endpoint |
| post-limiting-test.js | Rate limiting middleware |
| email-throttling-test.js | Email rate limiting |
| authentication-lockout-test.js | Brute force protection |
| no-cookie-test.js | Cookie-disabled handling |
| p3p-header-test.js | P3P privacy header (obsolete) |
| secrets-test.js | Secret key handling |
| coarse-user-agent-parser-test.js | UA parsing utility |
| fonts-request-test.js | Font file serving |
| static-resource-test.js | Static file serving |
| page-requests-test.js | Page rendering |
| rp-branded-emails-test.js | RP-specific email templates |

### Primary IdP Support (future work)

| Test | Description |
|------|-------------|
| add-email-with-assertion-test.js | Add email via IdP assertion |
| auth-with-assertion-test.js | Auth via IdP assertion |
| discovery-test.js | IdP discovery via .well-known |
| idp-seen-test.js | Track seen IdPs |
| proxy-idp-test.js | Proxy IdP support |
| primary-then-secondary-test.js | Primary to secondary transition |
| primary-secondary-transition-test.js | IdP transition handling |
| primary-secondary-transition-forgot-password-test.js | Password reset during transition |
| used-address-as-primary-test.js | Email previously at primary |

### Complex/Multi-browser (need review)

| Test | Description |
|------|-------------|
| verify-in-different-browser-test.js | Cross-browser verification |
| unverified-email-test.js | Unverified email handling |
| conformance-test.js | Protocol conformance |
| ca-test.js | Certificate authority tests |
| internal-wsapi-test.js | Internal API endpoints |
| two-level-auth-test.js | Two-factor auth |

---

## QUnit Dialog Tests (19 total)

### Not Started

| Test Module | Description | Priority |
|-------------|-------------|----------|
| dialog.js | Main dialog initialization and flow | High |
| authenticate.js | Authentication module | High |
| actions.js | Dialog action handlers | High |
| pick_email.js | Email selection UI | High |
| add_email.js | Add email flow | High |
| set_password.js | Password setting UI | High |
| forgot_password.js | Forgot password UI | Medium |
| check_registration.js | Registration status checking | Medium |
| complete_sign_in.js | Sign-in completion | Medium |
| generate_assertion.js | Assertion generation | Medium |
| validate_rp_params.js | RP parameter validation | Medium |
| rp_info.js | RP information display | Medium |
| inline_tospp.js | Terms/Privacy inline display | Low |
| is_this_your_computer.js | Public terminal prompt | Low |
| provision_primary_user.js | Primary IdP provisioning | Future |
| primary_user_provisioned.js | Primary user handling | Future |
| primary_user_not_provisioned.js | Primary user fallback | Future |
| verify_primary_user.js | Primary user verification | Future |
| primary_offline.js | Primary IdP offline handling | Future |

---

## Selenium E2E Tests (19 total)

### Not Started

| Test | Description | Priority |
|------|-------------|----------|
| sign-in-test.js | Basic sign-in flow | High |
| new-user/new-user-secondary-test.js | New secondary user signup | High |
| returning-user.js | Returning user login | High |
| change-password-test.js | Password change flow | High |
| cancel-account.js | Account cancellation | High |
| remove-email.js | Email removal | Medium |
| reset-password-test.js | Password reset flow | Medium |
| public-terminals.js | Public terminal handling | Medium |
| health-check-tests.js | Health endpoint checks | Low |
| frontend-qunit-test.js | Run QUnit in browser | Low |
| api-tests/oncancel.js | Cancel callback testing | Medium |
| new-user/new-user-primary-test.js | Primary IdP signup | Future |
| add-primary-to-primary.js | Add primary to primary | Future |
| add-primary-to-secondary.js | Add primary to secondary | Future |
| idp-transition/broken-primary.js | Broken IdP handling | Future |
| idp-transition/primary-shuts-down-single-email.js | IdP shutdown | Future |
| idp-transition/primary-starts-up-single-email.js | IdP startup | Future |
| idp-transition/transition-to-secondary.js | Transition to secondary | Future |
| idp-transition/transition-to-secondary-forgot-password.js | Transition + reset | Future |

---

## Testing Infrastructure Needed

### For QUnit Tests
- [ ] Set up wasm-bindgen-test or similar for browser JS testing
- [ ] Create test harness HTML page
- [ ] Port test helpers (mocks, assertions)
- [ ] Decide: test Rust WASM or keep JS tests separate

### For Selenium/Playwright Tests
- [ ] Add Playwright as dev dependency
- [ ] Create test fixtures (test user creation)
- [ ] Set up test RP (simple HTML page)
- [ ] Create page objects for dialog
- [ ] Configure CI for headless browser tests

---

## Next Steps

1. **Backend**: Port remaining "Ready to Port" tests
2. **Dialog Unit Tests**: Set up QUnit/JS test infrastructure
3. **E2E Tests**: Set up Playwright infrastructure
4. **Primary IdP**: Defer until primary IdP support is implemented
