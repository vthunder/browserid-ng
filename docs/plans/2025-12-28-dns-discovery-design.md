# DNS-Based Key Discovery with DNSSEC

## Implementation Status

**Implemented:** 2025-12-29

See commits in main branch for implementation details. Key files:
- `browserid-core/src/dns.rs` - DNS record parsing and DNSSEC status types
- `browserid-broker/src/dns_fetcher.rs` - DNSSEC-validating DNS fetcher
- `browserid-broker/src/fallback_fetcher.rs` - DNS-first discovery with broker fallback
- `browserid-broker/src/verifier.rs` - `verify_assertion_with_dns` async function

## Overview

Diverge from the original BrowserID spec by using DNS TXT records with DNSSEC validation for primary IdP key discovery, instead of the `.well-known/browserid` HTTP approach.

**Key difference from original spec:**
- Original: Fetch `https://<domain>/.well-known/browserid` JSON document
- New: Query `_browserid.<domain>` TXT record with DNSSEC validation required

**Rationale:**
- DNS is more fundamental infrastructure than HTTP endpoints
- DNSSEC provides cryptographic authentication of records
- Reduces attack surface (no HTTP/TLS dependencies)
- Simpler for domain operators (DNS record vs. hosted JSON file)

## Current Implementation Analysis

### Files Requiring Changes

| File | Change Type | Description |
|------|-------------|-------------|
| `browserid-core/src/discovery.rs` | Extend | Add DNS record format, DNSSEC result type |
| `browserid-broker/src/verifier.rs` | Major | Add DnsFetcher, FallbackFetcher |
| `Cargo.toml` (broker) | Dependency | Add hickory-dns for DNSSEC |
| `README.md` | Document | Note spec divergence |

### Current Architecture

```
SupportDocumentFetcher (trait)
    └── HttpFetcher (broker) - fetches /.well-known/browserid

verify_assertion()
    1. Parse assertion, extract issuer
    2. Check issuer authorization (trusted_broker | email_domain | delegation)
    3. Fetch issuer's public key via SupportDocumentFetcher
    4. Verify cryptographic signatures
```

### Proposed Architecture

```
SupportDocumentFetcher (trait)
    ├── HttpFetcher       - /.well-known/browserid (for broker)
    ├── DnsFetcher        - DNS TXT with DNSSEC (new)
    └── FallbackFetcher   - DNS first, fallback to broker (new)

verify_assertion()
    1. Parse assertion, extract issuer
    2. Check issuer authorization:
       a. If issuer == trusted_broker → accept (fallback case)
       b. If issuer == email_domain:
          - Query DNS with DNSSEC → if valid, accept (primary IdP)
          - If no DNS record or no DNSSEC → fallback to broker
       c. If email_domain delegates to issuer (via DNS) → accept
    3. Fetch issuer's public key via appropriate fetcher
    4. Verify cryptographic signatures
```

## DNS Record Format

### TXT Record Name
```
_browserid.<domain>
```

Example: `_browserid.example.com`

### TXT Record Value Format

Minimal key-value pairs separated by semicolons:

```
v=browserid1; public-key-algorithm=Ed25519; public-key=<base64url-encoded-public-key>
```

Fields:
| Field | Required | Description |
|-------|----------|-------------|
| `v` | Yes | Version identifier (browserid1) |
| `public-key-algorithm` | Yes | Algorithm for the public key (e.g., `Ed25519`) |
| `public-key` | Yes | Base64url-encoded public key |
| `host` | No | Host for `.well-known/browserid` lookup (defaults to email domain) |

The DNS record contains only the public key and optionally a host for further discovery. Authentication and provisioning endpoint paths are obtained via `.well-known/browserid` lookup on the specified host (or the email domain if no host is specified).

### Example Records

**Primary IdP (simple - same host for endpoints):**
```
_browserid.example.com TXT "v=browserid1; public-key-algorithm=Ed25519; public-key=KFaU7T5YCQ3F8IhaHd_80rKOAQFMwIKMrRAsJfZ6biI"
```
→ Auth/provision endpoints fetched from `https://example.com/.well-known/browserid`

**Primary IdP (separate IdP host):**
```
_browserid.example.com TXT "v=browserid1; public-key-algorithm=Ed25519; public-key=KFaU7T5YCQ3F8IhaHd_80rKOAQFMwIKMrRAsJfZ6biI; host=idp.example.com"
```
→ Auth/provision endpoints fetched from `https://idp.example.com/.well-known/browserid`

### Discovery Flow

1. Query `_browserid.<email-domain>` TXT record with DNSSEC
2. If DNSSEC-validated record found:
   - Extract `public-key` (required for certificate verification)
   - Extract `host` (optional, defaults to email domain)
   - Fetch `https://<host>/.well-known/browserid` for `authentication` and `provisioning` paths
3. If no DNSSEC or no record → fall back to broker

## DNSSEC Requirement

DNSSEC validation is **mandatory** for primary IdP mode:

1. **DNSSEC-validated response** → Domain operates as primary IdP
2. **No DNSSEC** → Fall back to broker as IdP
3. **DNS lookup fails** → Fall back to broker as IdP
4. **BOGUS DNSSEC** → Reject (security failure, don't fall back)

### DNSSEC States

| DNS Response | DNSSEC Status | Action |
|--------------|---------------|--------|
| Record found | AD flag set (authenticated) | Use as primary IdP |
| Record found | No AD flag (insecure) | Fall back to broker |
| NXDOMAIN | Authenticated | Fall back to broker |
| NXDOMAIN | Insecure | Fall back to broker |
| SERVFAIL | BOGUS | **Reject** (don't fall back) |

The BOGUS case (DNSSEC validation failure) is a security event and must not fall back silently.

## Implementation Plan

### Phase 1: Core DNS Types

**browserid-core/src/discovery.rs**

1. Add `DnsRecord` type for parsed TXT records:
```rust
pub struct DnsRecord {
    pub version: String,
    pub public_key_algorithm: String,  // e.g., "Ed25519"
    pub public_key: PublicKey,
    pub host: Option<String>,  // Host for .well-known lookup
}

impl DnsRecord {
    pub fn parse(txt: &str) -> Result<Self>;
}
```

2. Add `DnssecStatus` enum:
```rust
pub enum DnssecStatus {
    Secure,     // AD flag set, DNSSEC validated
    Insecure,   // No DNSSEC, or domain not signed
    Bogus,      // DNSSEC validation failed
}
```

3. Add `DnsDiscoveryResult`:
```rust
pub struct DnsDiscoveryResult {
    pub record: Option<DnsRecord>,
    pub dnssec_status: DnssecStatus,
}
```

### Phase 2: DNS Fetcher

**browserid-broker/src/dns_fetcher.rs** (new file)

```rust
use hickory_resolver::{TokioAsyncResolver, config::*};

pub struct DnsFetcher {
    resolver: TokioAsyncResolver,
}

impl DnsFetcher {
    pub fn new() -> Result<Self>;
    pub async fn fetch(&self, domain: &str) -> DnsDiscoveryResult;
}
```

Key implementation details:
- Use `hickory-dns` (formerly trust-dns) for DNSSEC support
- Configure resolver with DNSSEC validation enabled
- Check AD (Authenticated Data) flag in responses
- Parse TXT records into `DnsRecord`

### Phase 3: Fallback Fetcher

**browserid-broker/src/verifier.rs** (extend)

```rust
pub struct FallbackFetcher {
    dns_fetcher: DnsFetcher,
    http_fetcher: HttpFetcher,
    trusted_broker: String,
}

impl FallbackFetcher {
    /// Try DNS with DNSSEC first, fall back to broker if needed
    pub fn fetch(&self, domain: &str) -> Result<(SupportDocument, String)> {
        let dns_result = self.dns_fetcher.fetch(domain);

        match dns_result.dnssec_status {
            DnssecStatus::Secure => {
                // Primary IdP mode
                let record = dns_result.record.unwrap();
                let host = record.host.as_deref().unwrap_or(domain);

                // Fetch .well-known for auth/provision endpoints
                let mut doc = self.http_fetcher.fetch(host)?;
                // Override public key with DNSSEC-validated key
                doc.public_key = record.public_key;

                Ok((doc, domain.to_string()))
            }
            DnssecStatus::Insecure => {
                // No DNSSEC - fall back to broker
                Ok((self.http_fetcher.fetch(&self.trusted_broker)?, self.trusted_broker.clone()))
            }
            DnssecStatus::Bogus => {
                // DNSSEC validation failed - reject
                Err(Error::DnssecValidationFailed)
            }
        }
    }
}
```

### Phase 4: Verifier Integration

**browserid-broker/src/verifier.rs** (modify `verify_assertion`)

Current logic:
1. issuer == trusted_broker → accept
2. issuer == email_domain → accept
3. email_domain delegates to issuer → accept (via HTTP discovery)

New logic:
1. issuer == trusted_broker → accept (fallback case)
2. issuer == email_domain:
   - Query DNS for email_domain with DNSSEC
   - If DNSSEC secure and record found → verify with DNS public key (primary IdP)
   - If DNSSEC insecure or no record → issuer must be trusted_broker
3. email_domain delegates (via DNS) to issuer → accept

### Phase 5: Testing

**browserid-core/tests/dns_discovery_test.rs**

- TXT record parsing (valid records, malformed, missing fields)
- Version validation
- Public key extraction

**browserid-broker/tests/dns_fetcher_test.rs**

- Mock DNS responses with DNSSEC status
- Fallback behavior tests
- BOGUS rejection tests

## Dependencies

Add to `browserid-broker/Cargo.toml`:
```toml
hickory-resolver = { version = "0.24", features = ["dnssec-ring"] }
```

## README Update

Add section to README.md:

```markdown
## Differences from Original BrowserID Spec

### DNS-Based Key Discovery

BrowserID-NG diverges from the original BrowserID specification by using **DNS TXT records
with DNSSEC validation** for primary IdP key discovery, instead of the `.well-known/browserid`
HTTP approach.

| Aspect | Original Spec | BrowserID-NG |
|--------|---------------|--------------|
| Key Location | `https://<domain>/.well-known/browserid` | `_browserid.<domain>` TXT record |
| Trust Anchor | HTTPS/TLS certificate | DNSSEC |
| Fallback | None | Broker as fallback IdP |

**Why the change:**
- DNS is more fundamental infrastructure than HTTP endpoints
- DNSSEC provides cryptographic authentication independent of TLS PKI
- Simpler deployment for domain operators (DNS record vs. hosted file)
- Domains without DNSSEC automatically fall back to broker

**Fallback behavior:**
- If domain has DNSSEC-validated `_browserid` TXT record → Domain acts as primary IdP
- If domain has no DNSSEC or no record → Broker acts as fallback IdP
- If DNSSEC validation fails (BOGUS) → Verification rejected (security error)
```

## Security Considerations

1. **BOGUS DNSSEC must reject**: A failed DNSSEC validation indicates an attack and must not silently fall back to broker.

2. **Cache considerations**: DNS responses should be cached respecting TTL, but DNSSEC validation must be performed on each lookup.

3. **Resolver trust**: The local DNSSEC-validating resolver must be trusted. Consider running a local validating resolver rather than relying on upstream.

4. **Delegation chains**: DNS-based delegation follows the same chain rules as HTTP but via `authority` field in TXT record.

## Migration Path

Since BrowserID-NG is not yet deployed in production:
1. Implement DNS discovery with DNSSEC
2. Keep HTTP discovery for broker self-discovery (/.well-known/browserid)
3. Primary IdP mode only available via DNS+DNSSEC

Domains wishing to be primary IdPs must:
1. Enable DNSSEC for their domain
2. Add `_browserid.<domain>` TXT record with their public key
