<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# BrowserID-NG

A modern Rust implementation of the [BrowserID protocol][], derived from Mozilla's [Persona][].

BrowserID is a decentralized identity protocol that allows users to authenticate to websites using their email address, with cryptographic proof of ownership.

[BrowserID protocol]: https://github.com/mozilla/id-specs
[Persona]: https://github.com/mozilla/persona

## Repository Contents

This repository contains:

* **browserid-core**: Core cryptography and protocol primitives
  - Ed25519 keypair generation and signing
  - JWT/JWS creation and verification
  - Certificate and assertion handling
  - Identity provider discovery via `.well-known/browserid`

* **browserid-broker**: Fallback Identity Provider (IdP)
  - Full authentication flow (signup, signin, password reset)
  - Email verification with 6-digit codes
  - Certificate issuance for authenticated users
  - SQLite storage for users and sessions
  - Compatible `navigator.id` API via `include.js`

* **e2e-tests**: Playwright end-to-end tests
  - 50 tests covering all authentication flows

## Getting Started

### Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- Node.js 18+ (for E2E tests only)

### Running the Broker

```bash
# Clone and build
git clone https://github.com/nicksandmill/browserid-ng.git
cd browserid-ng
cargo build --release

# Run the broker (creates browserid.db for storage)
cargo run -p browserid-broker
```

The broker will start on `http://localhost:3000`. Verification codes are printed to the terminal (production would use a real email sender).

### Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `BROKER_PORT` | `3000` | HTTP port |
| `BROKER_DOMAIN` | `localhost:3000` | Public domain for certificates |
| `BROKER_KEY_FILE` | `broker-key.json` | Ed25519 keypair file |
| `DATABASE_PATH` | `browserid.db` | SQLite database file |

### Integrating with Your Site

Include the shim on your page:

```html
<script src="http://localhost:3000/include.js"></script>
```

Then use the `navigator.id` API:

```javascript
navigator.id.watch({
  loggedInUser: null,
  onlogin: function(assertion) {
    // Send assertion to your server for verification
    console.log('Got assertion:', assertion);
  },
  onlogout: function() {
    console.log('User logged out');
  }
});

// Trigger login popup
document.getElementById('login').addEventListener('click', function() {
  navigator.id.request();
});
```

## Testing

### Unit Tests

```bash
cargo test
```

### End-to-End Tests

```bash
cd e2e-tests
npm install
npx playwright test
```

## Architecture

### Protocol Flow

1. User clicks "Sign in with BrowserID" on a website
2. Dialog opens, user enters email and authenticates with broker
3. Broker issues a certificate binding user's email to a browser-generated public key
4. Browser signs an assertion for the target website
5. Website receives `certificate~assertion` and verifies:
   - Certificate is signed by the broker
   - Assertion is signed by the key in the certificate
   - Audience matches the website's origin

### Backed Identity Assertion Format

```
<certificate>~<assertion>
```

Where both are JWTs:
- **Certificate**: Signed by broker, contains `{principal: {email}, public-key, iat, exp}`
- **Assertion**: Signed by user's key, contains `{aud, exp}`

## Differences from Original Persona

- Written in Rust instead of Node.js
- Uses Ed25519 instead of RSA/DSA
- SQLite storage instead of MySQL
- Simplified codebase focused on core protocol
- DNS-based primary IdP discovery (see below)

### DNS-Based Key Discovery (Spec Divergence)

BrowserID-NG diverges from the original BrowserID specification by using **DNS TXT records with DNSSEC validation** for primary IdP key discovery, instead of the `.well-known/browserid` HTTP approach.

| Aspect | Original Spec | BrowserID-NG |
|--------|---------------|--------------|
| Key Location | `https://<domain>/.well-known/browserid` | `_browserid.<domain>` TXT record |
| Trust Anchor | HTTPS/TLS certificate | DNSSEC |
| Fallback | None | Broker as fallback IdP |

**DNS Record Format:**
```
_browserid.example.com TXT "v=browserid1; public-key-algorithm=Ed25519; public-key=<base64url>; host=idp.example.com"
```
- `v` - Version (required)
- `public-key-algorithm` - Algorithm for the public key, e.g., `Ed25519` (required)
- `public-key` - Public key, base64url-encoded (required)
- `host` - Host for `.well-known/browserid` lookup to get auth/provision endpoints (optional, defaults to email domain)

**Why the change:**
- DNS is more fundamental infrastructure than HTTP endpoints
- DNSSEC provides cryptographic authentication independent of TLS PKI
- Simpler deployment for domain operators (DNS record vs. hosted file)
- Domains without DNSSEC automatically fall back to broker

**Fallback behavior:**
- If domain has DNSSEC-validated `_browserid` TXT record → Domain acts as primary IdP
- If domain has no DNSSEC or no record → Broker acts as fallback IdP
- If DNSSEC validation fails (BOGUS) → Verification rejected (security error)

See `docs/plans/2025-12-28-dns-discovery-design.md` for full implementation details.

## LICENSE

All source code here is available under the [MPL 2.0][] license, unless otherwise indicated.

This project is derived from [Mozilla Persona][], which is also licensed under MPL 2.0.

[MPL 2.0]: https://mozilla.org/MPL/2.0/
[Mozilla Persona]: https://github.com/mozilla/persona
