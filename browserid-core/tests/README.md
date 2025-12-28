# Core Protocol Tests

Tests for the BrowserID protocol primitives, ported from mozilla/persona.

## Test Summary

**5 test files, 77 tests total**

## Test Files

### ca_test.rs (6 tests)

Certificate Authority operations, from `ca-test.js`:

- Keypair generation (Ed25519)
- Certificate creation and signing
- Certificate structure validation (3 JWT parts)
- Signature verification with correct key
- Signature rejection with wrong key
- Certificate claims validation

### verifier_test.rs (23 tests)

Assertion verification, from `verifier-test.js`:

**Core Verification:**
- Valid assertion verification
- Fallback broker support
- Primary IdP support (native domains)

**Security Checks:**
- Untrusted issuer rejection
- Cross-domain issuer rejection (IdP can't speak for other domains)
- Audience mismatch detection (wrong host, port, scheme)

**Expiration Handling:**
- Expired assertion rejection
- Expired certificate rejection

**Signature Validation:**
- Bad certificate signature detection
- Bad assertion signature detection

**Format Validation:**
- Missing certificate handling
- Invalid format handling
- No certificates error

### discovery_test.rs (13 tests)

Domain discovery, from `discovery-test.js`:

- Email domain extraction
- Well-known URL construction
- Support document parsing
- Delegation chain following
- Disabled domain detection
- Fallback IdP handling
- Public key retrieval

### conformance_test.rs (22 tests)

JWT format compliance, from `conformance-test.js`:

**Structure Validation:**
- Assertion format (3 JWT parts)
- Certificate format (3 JWT parts)
- Base64url encoding validation

**Header Validation:**
- Algorithm field (EdDSA)
- Type field (JWT)

**Payload Validation:**
- Issuer (iss) field
- Expiration (exp) timestamp
- Issued-at (iat) timestamp
- Audience (aud) field
- Principal/email claims
- Public key format

### well_known_test.rs (13 tests)

Support document format, from `well-known-test.js`:

- Full document structure
- Delegation configuration
- Disabled domain handling
- Public key format
- Authority metadata
- Issuer information

## Original Test Mapping

| browserid-ng | Original (browserid/tests/) |
|--------------|----------------------------|
| ca_test.rs | ca-test.js |
| verifier_test.rs | verifier-test.js (partial) |
| discovery_test.rs | discovery-test.js |
| conformance_test.rs | conformance-test.js |
| well_known_test.rs | well-known-test.js |

## Coverage Notes

The original `verifier-test.js` was 42KB with extensive edge case testing. Key scenarios are covered, but some edge cases remain:

### Covered
- [x] Basic verification flow
- [x] Issuer validation
- [x] Audience matching
- [x] Expiration checking
- [x] Signature validation
- [x] Fallback broker support

### Not Yet Covered
- [ ] Default port equivalence (http:80 ≡ http, https:443 ≡ https)
- [ ] Malformed input handling (truncated, prepended data)
- [ ] Certificate chain rejection (multi-cert chains)
- [ ] Wildcard audience rejection
- [ ] Proxy IdP verification (delegation chains)

## Running Tests

```bash
# Run all core tests
cargo test -p browserid-core

# Run specific test file
cargo test -p browserid-core --test verifier_test

# Run specific test
cargo test -p browserid-core test_verify_assertion_success

# Run with output
cargo test -p browserid-core -- --nocapture
```
