# browserid-ng ↔ Mozilla BrowserID — Divergence Analysis

> **STATUS: DRAFT / WIP.** Phase 1–2 output of bean `browserid-ng-v9rz`
> (review Mozilla id-specs → document divergences → decide keep/reconcile →
> author canonical spec). Not yet human-reviewed. The keep/reconcile flags are
> *preliminary recommendations* to drive the Phase 3 decision, not conclusions.

## Phase 1 — The Mozilla baseline

Source: <https://github.com/mozilla/id-specs> — **archived, read-only since 2022-01-19.**

The `browserid/` directory contains a **single consolidated spec**:
`browserid/index.md` (plus repo-level `README`, `CODE_OF_CONDUCT.md`). There is
no longer a multi-document suite; `index.md` is the whole protocol. What it
defines:

| Area | Mozilla `index.md` |
|---|---|
| Discovery | Support document at `https://<domain>/.well-known/browserid` (HTTPS/WebPKI trust root only). No DNS discovery. |
| Support document | Fields `public-key`, `authentication`, `provisioning`; delegation via an `authority` pointer. |
| Crypto | **RSA** (RS256/RS128 examples); JWK-style public keys with algorithm + params (`n`, `e`). Spec notes keys "should eventually align with JWK." |
| Certificate | JWT: `iss` (issuer domain), `exp`, `iat`, `public-key`, `principal` (**email _or_ host**). |
| Assertion | JWT: `exp`, `aud`. |
| Backed assertion | `<cert-1>~…~<cert-n>~<assertion>` (tilde-joined cert chain + assertion). |
| Primary IdP | `authentication` + `provisioning` HTML pages driving the shimmed **`navigator.id`** browser API: `beginProvisioning()`, `genKeyPair()`, `registerCertificate()`, and RP-side `navigator.id.get()`. |
| Fallback IdP | **`login.persona.org`** for domains without BrowserID support. |
| Verification | Remote verifier API (historically `verifier.login.persona.org`) taking `{assertion, audience}`; local verification possible. |

## Phase 2 — Divergence catalog

Flag legend: **KEEP** (deliberate, sound) · **RECONCILE** (drift / needs a
decision) · **DECIDE** (open protocol question, tracked elsewhere).

### 1. Discovery / DNSSEC — *our biggest addition*
- **Mozilla:** `/.well-known/browserid` over HTTPS only; trust root = WebPKI (any CA).
- **Ours:** authenticated **`_browserid.<domain>` DNS TXT** record is the primary trust root — `browserid-core/src/dns.rs:1` parses `v=browserid1; public-key-algorithm=Ed25519; public-key=<b64url>; host=<opt>`; `browserid-broker/src/dns_fetcher.rs:1-16,126-208` fetches over **DNS-over-TLS**, sets the EDNS DO bit, trusts the resolver **AD** flag only because the channel is authenticated, treats **SERVFAIL as Bogus → hard reject**, and AD-unset as insecure → broker fallback. `.well-known` is still fetched by `browserid-core/src/discovery.rs`.
- **Flag: KEEP** (the DNSSEC root is the whole differentiator — offline-verifiable proofs, on-chain attribution). **But see #10 (dual-path) — DECIDE.**

### 2. Crypto / keys
- **Mozilla:** RSA (RS256), JWK params `n`/`e`.
- **Ours:** **Ed25519 / EdDSA everywhere** — `browserid-core/src/keys.rs:3`; public keys are raw 32-byte base64url, **not** JWK (`keys.rs:35`).
- **Flag: KEEP** (modern, compact, matches on-chain `ed25519:` keys). Note for spec: we deliberately drop JWK in favor of `ed25519:<hex>` / base64url forms.

### 3. Support document
- **Mozilla:** `public-key`, `authentication`, `provisioning`, `authority`.
- **Ours:** same four **plus `disabled`** (explicit opt-out) — `browserid-core/src/discovery.rs:13-33`. Broker emits `public-key` + `/auth` + `/provision` (`routes/well_known.rs:23-27`).
- **Flag: KEEP** `disabled` (useful explicit signal), but **RECONCILE the doc-comment drift** (`discovery.rs:3` still says discovery is "by fetching `/.well-known/browserid`", now false as the primary path).

### 4. Certificate format
- **Mozilla:** JWT `iss/exp/iat/public-key/principal`, principal = **email OR host**.
- **Ours:** JWT `iss/exp/iat/public-key/principal`, principal = **email only** — `browserid-core/src/certificate.rs:14-19,42-59`. Signed EdDSA.
- **Flag: RECONCILE / DECIDE.** Dropping the **host principal** is unremarked — see Flagged item A.

### 5. Backed assertion + assertion format
- **Mozilla:** `<cert>~…~<assertion>`; assertion `exp`+`aud`.
- **Ours:** **identical** tilde format (`assertion.rs:135-179`); assertion JWT `EdDSA`, claims `exp`+`aud` (`assertion.rs:12-19,91`).
- **Flag: KEEP** (faithful wire compat; only the signature alg differs).

### 6. Verification
- **Mozilla:** remote verifier API `{assertion, audience}`.
- **Ours:** `POST /verify` mirrors it (`routes/verify.rs`), but verification is **DNS/DNSSEC-aware** (`verifier.rs::verify_assertion_with_dns`) and can resolve the issuer's key from the authenticated DNS record rather than only `.well-known`.
- **Flag: KEEP.**

### 7. Primary IdP + browser API
- **Mozilla:** shimmed **`navigator.id`** (`beginProvisioning`/`genKeyPair`/`registerCertificate`/`get`), dialog-driven.
- **Ours:** **no `navigator.id`.** First-party `/auth` + `/provision` pages, `provisioning_api.js`/`authentication_api.js` shims, `wsapi/*` endpoints, a broker **signer popup** (`/sign`), and `include.js` + `communication_iframe` kept only for RP compat (`routes/mod.rs`).
- **Flag: KEEP** (navigator.id was never standardized; Persona is dead). Spec should describe our page/postMessage model as the replacement.

### 8. Fallback / broker
- **Mozilla:** `login.persona.org` central fallback.
- **Ours:** **`browserid.me`** broker — SMTP-verifies emails, issues certs as `iss=browserid.me`, **publishes its own `_browserid` DNSSEC key**, and is a pinned **broker trust anchor** for on-chain attribution (`/sys/trust/brokers`).
- **Flag: KEEP** (same role; DNSSEC-rooted + attribution-aware rather than a trusted central host).

### 9. Agent provisioning + on-chain attribution — *net-new, no Mozilla analog*
- Delegation-chain provisioning + grant API (`docs/specs/agent-provisioning-and-grant-api.md`); SBO on-chain attribution of an email identity to an `ed25519:` key via DNSSEC-proof objects.
- **Flag: KEEP**, spec as **layered/optional modules** on top of the core protocol so a plain RP need not know about them.

### 10. Dual discovery path (the open decision)
- Core still fetches `.well-known`; broker prefers DNSSEC. Accepting **either** means security = the weaker path (a mis-issued TLS cert forges `.well-known`). Tracked by **`browserid-ng-28uc`** (unify verifier) and the "make DNSSEC mandatory" question.
- **Flag: DECIDE** (Phase 3 / 28uc).

## Flagged — looks accidental or unjustified (needs a human decision)

- **A. Certificate `principal` narrowed to email-only** (`certificate.rs:14-19`). Mozilla allowed a **host** principal for delegated/primary cert chaining. We removed it *silently*. Possibly fine (our delegation runs through support-doc `authority` + the agent provisioning chain, not host-principal certs) — but confirm it's intentional, not an oversight, before the spec canonizes email-only.
- **B. Placeholder all-zero public key** in `SupportDocument::delegate()` and `::disabled()` (`discovery.rs:62,73` — `PublicKey::from_bytes(&[0u8;32])`). A real (if unusable) Ed25519 point standing in as a sentinel; a latent footgun if such a doc were ever verified against. Prefer `Option<PublicKey>`. Code smell, not protocol — but flag.
- **C. Stale doc-comment** (`discovery.rs:3`, and the module still framed as ".well-known first") now contradicts the DNSSEC-primary reality. Drift; fix when authoring.
- **D. `disabled` field** is un-specced (not in Mozilla). Deliberate-looking, but it needs to be *written down* with precedence rules (does `disabled:true` override a valid DNS key? which wins?).

## Open decisions for Phase 3
1. **Mandatory DNSSEC vs. dual-path** (#10 / 28uc) — the load-bearing one.
2. **Host principal**: drop for good (email-only) or restore (A)?
3. **`disabled` precedence** and whether DNS or `.well-known` wins on conflict (D).
4. Whether agent-provisioning + SBO attribution live in the core spec or as separate linked modules (recommend: modules).

## Suggested spec structure (Phase 4)
`docs/specs/browserid-ng-protocol.md` (core: discovery, support doc, cert, assertion, backed assertion, verification, primary + broker), with `agent-provisioning-and-grant-api.md` and a new `sbo-attribution.md` as linked modules. Each section notes *inherited from BrowserID* vs *deliberate departure*.
