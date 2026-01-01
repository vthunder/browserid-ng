# Test Coverage Audit: Cryptographic Validation Gaps

**Date:** 2026-01-01
**Context:** Discovered after fixing audience mismatch bug in auth_with_assertion

## Summary

The tests have **significant gaps** in the integration between the dialog (creates assertions) and the broker (verifies assertions). Individual components are well-tested, but the integration is not.

The audience mismatch bug (dialog sending RP audience to auth_with_assertion which expects broker audience) was not caught because:
1. Unit tests for verifier construct assertions correctly (they don't use dialog.js)
2. E2E tests use mock certificates that can't be cryptographically verified
3. auth_with_assertion endpoint tests only check error paths

---

## Critical Gaps

### 1. `auth_with_assertion_test.rs` - NO valid assertion tests

**File:** `browserid-broker/tests/auth_with_assertion_test.rs`

The file explicitly acknowledges this gap:

```rust
//! These tests focus on error cases that don't require valid cryptographic assertions.
//! Full end-to-end testing with valid primary IdP assertions is deferred to Task 8.
```

**Missing tests:**
- Valid assertion creates session
- Audience validation (the bug we just fixed!)
- Email extraction from valid assertion
- Issuer authority validation (primary vs broker)
- Cryptographic signature verification at endpoint level

### 2. E2E `primary-idp.spec.ts` - Fake certificates

**File:** `e2e-tests/tests/primary-idp.spec.ts` (lines 412-424)

The mock IdP creates certificates with fake signatures:

```typescript
const signature = 'mock-signature-for-testing';  // Not a real signature!
res.end(JSON.stringify({ certificate: `${header}.${payload}.${signature}` }));
```

**Impact:**
- Provisioning flow is tested
- Certificate generation request is tested
- **Cryptographic validation is NEVER tested**
- The assertions returned to RP are not valid

### 3. `verifier_dns_test.rs` - Empty placeholder

**File:** `browserid-broker/tests/verifier_dns_test.rs`

Contains only a placeholder test with no actual assertions:

```rust
#[test]
fn test_placeholder() {
    assert!(true);  // No actual tests
}
```

### 4. `cert_key_test.rs` - No signature verification

**File:** `browserid-broker/tests/cert_key_test.rs`

Tests check JWT format but never verify cryptographic validity:

```rust
// Only checks JWT has 3 parts, not that signature is correct
assert_eq!(cert.split('.').count(), 3);
```

**Missing:**
- Verify certificate signature against broker's public key
- Round-trip test (generate cert → verify cert signature)
- Verify all required fields have correct values

---

## What IS Well-Tested

### `browserid-broker/tests/verifier_test.rs` - Comprehensive unit tests
- Signature verification (bad cert signature, bad assertion signature)
- Issuer authority (domain speaking for wrong email)
- Audience matching (wrong domain, wrong port, wrong scheme)
- Expiration handling
- Fallback broker logic

### `browserid-core/tests/conformance_test.rs` - JWT structure tests
- Field presence (exp, aud, iss, principal, public-key)
- Base64url encoding
- Certificate/assertion round-trip

### `browserid-core/tests/verifier_test.rs` - Full verification logic
- All verification tests at the core library level

---

## The Gap Pattern

```
┌─────────────────────────────────────────────────────────────────┐
│  dialog.js creates assertion  →  auth_with_assertion verifies   │
│                                                                 │
│  TESTED:                        TESTED:                         │
│  - E2E: Flow works              - Unit: verifier logic          │
│  - E2E: Messages sent           - Unit: signature checking      │
│                                                                 │
│  NOT TESTED:                    NOT TESTED:                     │
│  - Assertion audience correct   - Endpoint with VALID assertion │
│  - Signature cryptographically  - Audience mismatch detected    │
│    valid                        - Session created correctly     │
│                                                                 │
│     ↑ THIS IS WHERE THE BUG WAS ↑                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tests Needed

### Priority 1: Integration test with REAL cryptographic assertions

**File:** `browserid-broker/tests/auth_with_assertion_test.rs`

```rust
#[tokio::test]
async fn test_auth_with_assertion_valid_primary() {
    // 1. Create a test keypair for the "primary IdP"
    // 2. Register it with the broker's mock primary IdP system
    // 3. Create a valid certificate signed by that keypair
    // 4. Create a valid assertion with audience = broker domain
    // 5. Bundle into backed assertion
    // 6. POST to /wsapi/auth_with_assertion
    // 7. Verify session is created
    // 8. Verify email is correctly extracted
}

#[tokio::test]
async fn test_auth_with_assertion_wrong_audience() {
    // Assertion audience = RP origin, but endpoint expects broker
    // Should FAIL with audience mismatch error
}

#[tokio::test]
async fn test_auth_with_assertion_untrusted_issuer() {
    // Assertion from domain that isn't the email's domain or trusted broker
    // Should FAIL with issuer not authorized error
}
```

### Priority 2: Certificate validation in cert_key tests

**File:** `browserid-broker/tests/cert_key_test.rs`

```rust
#[tokio::test]
async fn test_cert_key_certificate_cryptographically_valid() {
    // 1. Get certificate from cert_key endpoint
    // 2. Decode and verify signature against broker's public key
    // 3. Verify all required fields present with correct values
    // 4. Verify email matches requested email
    // 5. Verify public-key matches the one we sent
}

#[tokio::test]
async fn test_cert_key_certificate_can_be_used_for_assertion() {
    // Full round-trip test:
    // 1. Get certificate from cert_key
    // 2. Create assertion using the keypair
    // 3. Verify the backed assertion
}
```

### Priority 3: E2E with real cryptographic validation

Either:
- Use a real test keypair in mock IdP and verify signatures
- Or add an E2E test that verifies the final assertion returned to RP is valid
- Or add a test endpoint that validates assertions and use it in E2E

### Priority 4: DNS verification tests

**File:** `browserid-broker/tests/verifier_dns_test.rs`

- Test with mock DNS resolver
- Verify DNSSEC status affects trust decisions
- Test fallback to HTTPS when DNS fails

---

## Root Cause Analysis

The testing strategy has good **unit test coverage** for individual components, but lacks **integration tests** that exercise the full path through the system with real cryptographic operations.

The mock IdP approach in E2E tests is valuable for testing the protocol flow, but it created a blind spot where cryptographic validation was never exercised end-to-end.

## Recommendations

1. **Add integration tests for auth_with_assertion with valid assertions** - This is the highest priority as it would have caught the audience mismatch bug.

2. **Add certificate round-trip tests** - Verify that certificates generated by cert_key can be used to create valid assertions.

3. **Consider a "crypto validation" E2E test mode** - Where the mock IdP uses real keys and the broker actually validates signatures.

4. **Fill in DNS verification tests** - Currently just a placeholder.
