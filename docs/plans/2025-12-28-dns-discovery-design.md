# DNS-Based Key Discovery with DNSSEC

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

Single-line key-value pairs separated by semicolons:

```
v=browserid1; public-key=<base64url-encoded-ed25519-public-key>; auth=/auth; prov=/provision
```

Fields:
| Field | Required | Description |
|-------|----------|-------------|
| `v` | Yes | Version identifier (browserid1) |
| `public-key` | Yes | Base64url-encoded Ed25519 public key (32 bytes) |
| `auth` | No | Authentication endpoint path |
| `prov` | No | Provisioning endpoint path |
| `disabled` | No | If present, domain has disabled BrowserID |
| `authority` | No | Delegation to another domain |

### Example Records

**Primary IdP (native support):**
```
_browserid.example.com TXT "v=browserid1; public-key=KFaU7T5YCQ3F8IhaHd_80rKOAQFMwIKMrRAsJfZ6biI"
```

**Delegation:**
```
_browserid.example.com TXT "v=browserid1; authority=idp.example.net"
```

**Disabled:**
```
_browserid.example.com TXT "v=browserid1; disabled"
```

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
    pub public_key: Option<PublicKey>,
    pub authentication: Option<String>,
    pub provisioning: Option<String>,
    pub authority: Option<String>,
    pub disabled: bool,
}

impl DnsRecord {
    pub fn parse(txt: &str) -> Result<Self>;
    pub fn to_support_document(&self) -> Result<SupportDocument>;
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
    trusted_broker: String,
}

impl FallbackFetcher {
    /// Try DNS with DNSSEC first, fall back to broker if needed
    pub fn fetch(&self, domain: &str) -> Result<(SupportDocument, String)> {
        let dns_result = self.dns_fetcher.fetch(domain);

        match dns_result.dnssec_status {
            DnssecStatus::Secure => {
                // Primary IdP mode - use DNS public key
                Ok((dns_result.record.to_support_document()?, domain))
            }
            DnssecStatus::Insecure => {
                // No DNSSEC - fall back to broker
                // Return broker's support document
                Ok((broker_document(), self.trusted_broker))
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
