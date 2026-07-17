# browserid-ng ↔ Mozilla BrowserID — Divergence Analysis

> **STATUS: DRAFT / WIP.** Phase 1–2 output of bean `browserid-ng-v9rz`
> (review Mozilla id-specs → document divergences → decide keep/reconcile →
> author canonical spec). The Phase 1–2 catalog below is the *review record*;
> the **Phase 3 decisions** section that follows supersedes the preliminary
> keep/reconcile flags wherever they differ.

## Phase 3 decisions (resolved 2026-07-10)

These are the decisions taken after the review; they drive the canonical spec
(`browserid-ng-protocol.md`).

1. **DNSSEC is the required, sole root of trust** (resolves #1/#10, bean
   `browserid-ng-28uc`). A primary issuer's identity key is obtained **only**
   from the authenticated `_browserid` DNSSEC record (RFC 9102 / DoT / AD flag;
   SERVFAIL → reject). `.well-known/browserid` is **no longer a key-trust
   source** — no dual path, no downgrade. `.well-known` is **retained for
   endpoint discovery** (auth/provision URLs) and optional host-cert delivery.
   Long tail unaffected: domains/users without DNSSEC go through the
   `browserid.me` broker, which itself publishes DNSSEC.
2. **Host principal / host certificates: reinstated** (resolves item A). Do
   *not* keep the email-only narrowing. Certificates may carry a **host**
   principal again, but a host cert MUST be **signed by the DNSSEC key**
   (`K_dns`), not self-signed-and-trusted-via-`.well-known`. This is an
   **optional** intermediate: `K_dns → (optional) host cert (K_host) → user
   cert`. It enables DNS-admin ≠ host/IdP-operator separation and operational
   key rotation without a DNS change. *(Implementation: Phase 2 of 28uc.)*
3. **`disabled` support-document field: removed** (resolves item D). A domain
   opts out simply by publishing no `_browserid` record / no endpoints; we do
   not need an explicit disabled signal. *(Done on branch
   `fix/discovery-cleanup`.)*
4. **Placeholder all-zero key: removed** (resolves item B) — the support
   document's key is now `Option<PublicKey>`; consumers fail closed on `None`.
   *(Done on branch `fix/discovery-cleanup`.)*
5. **Stale discovery doc-comment** (item C): fix folds into the 28uc
   implementation (discovery is DNSSEC-primary, not `.well-known`-first).
6. **Layering:** agent provisioning + SBO on-chain attribution remain
   **separate linked modules** on top of the core protocol, not core.

---

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
decision) · **DECIDE** (open protocol question, tracked elsewhere). *(See the
Phase 3 decisions above for final resolutions.)*

### 1. Discovery / DNSSEC — *our biggest addition*
- **Mozilla:** `/.well-known/browserid` over HTTPS only; trust root = WebPKI (any CA).
- **Ours:** authenticated **`_browserid.<domain>` DNS TXT** record is the primary trust root — `browserid-core/src/dns.rs:1` parses `v=browserid1; public-key-algorithm=Ed25519; public-key=<b64url>; host=<opt>`; `browserid-broker/src/dns_fetcher.rs:1-16,126-208` fetches over **DNS-over-TLS**, sets the EDNS DO bit, trusts the resolver **AD** flag only because the channel is authenticated, treats **SERVFAIL as Bogus → hard reject**, and AD-unset as insecure → broker fallback. `.well-known` is still fetched by `browserid-core/src/discovery.rs`.
- **Flag: KEEP** → **Phase 3 #1: DNSSEC required + sole root.**

### 2. Crypto / keys
- **Mozilla:** RSA (RS256), JWK params `n`/`e`.
- **Ours:** **Ed25519 / EdDSA everywhere** — `browserid-core/src/keys.rs:3`; public keys are raw 32-byte base64url, **not** JWK (`keys.rs:35`).
- **Flag: KEEP.** Spec: deliberately drop JWK in favor of `ed25519:<hex>` / base64url forms.

### 3. Support document
- **Mozilla:** `public-key`, `authentication`, `provisioning`, `authority`.
- **Ours:** same four **plus `disabled`** — `browserid-core/src/discovery.rs:13-33`. Broker emits `public-key` + `/auth` + `/provision` (`routes/well_known.rs:23-27`).
- **Flag: RECONCILE** → **Phase 3 #3: `disabled` removed.** Doc-comment drift → #C.

### 4. Certificate format
- **Mozilla:** JWT `iss/exp/iat/public-key/principal`, principal = **email OR host**.
- **Ours:** JWT `iss/exp/iat/public-key/principal`, principal = **email only** — `browserid-core/src/certificate.rs:14-19,42-59`. Signed EdDSA.
- **Flag: RECONCILE** → **Phase 3 #2: host principal reinstated (DNSSEC-signed host certs).**

### 5. Backed assertion + assertion format
- **Mozilla:** `<cert>~…~<assertion>`; assertion `exp`+`aud`.
- **Ours:** **identical** tilde format (`assertion.rs:135-179`); assertion JWT `EdDSA`, claims `exp`+`aud` (`assertion.rs:12-19,91`).
- **Flag: KEEP** (faithful wire compat; only the signature alg differs).

### 6. Verification
- **Mozilla:** remote verifier API `{assertion, audience}`.
- **Ours:** `POST /verify` mirrors it (`routes/verify.rs`), but verification is **DNS/DNSSEC-aware** (`verifier.rs::verify_assertion_with_dns`).
- **Flag: KEEP** → unified around the DNSSEC-rooted path (28uc).

### 7. Primary IdP + browser API
- **Mozilla:** shimmed **`navigator.id`**, dialog-driven.
- **Ours:** **no `navigator.id`.** The browser is the user's first agent: a one-time top-level `/auth` **bootstrap** yields a provisioning credential (`U_cert~P_cert`, `subjects` incl. `self`), then login certs are refreshed via the cookie-free `POST /provision/mint` (`subject: self`) — the same verb agents use. A first-party **signer popup** (`/sign`) MAY remain for typed signing.
- **Flag: navigator.id rejection KEPT; iframe transport RETIRED** (2026-07-18, Model A / epic `browserid-ng-oup3`). The `provisioning_api.js` + hidden `communication_iframe` silent-refresh path is removed — it was ITP-dead and is superseded by the mint verb. This reverses the earlier "keep the first-party iframe/postMessage provisioning" stance; the `navigator.id` rejection itself stands.

### 8. Fallback / broker
- **Mozilla:** `login.persona.org` central fallback.
- **Ours:** **`browserid.me`** broker — SMTP-verifies emails, issues certs as `iss=browserid.me`, **publishes its own `_browserid` DNSSEC key**, and is a pinned **broker trust anchor** for on-chain attribution (`/sys/trust/brokers`).
- **Flag: KEEP.**

### 9. Agent provisioning + on-chain attribution — *net-new, no Mozilla analog*
- Delegation-chain provisioning + grant API (`docs/specs/agent-provisioning-and-grant-api.md`); SBO on-chain attribution of an email identity to an `ed25519:` key via DNSSEC-proof objects.
- **Flag: KEEP** → **Phase 3 #6: layered modules.**

### 10. Dual discovery path (the open decision)
- **Flag: DECIDE** → **Phase 3 #1: resolved — DNSSEC required, sole root.**

## Flagged items — resolutions

- **A. Cert `principal` email-only** → **reinstate host principal** (DNSSEC-signed host certs). Phase 3 #2.
- **B. Placeholder all-zero key** → **fixed** (`Option<PublicKey>`). Phase 3 #4.
- **C. Stale doc-comment** → fix in 28uc implementation. Phase 3 #5.
- **D. `disabled` field** → **removed.** Phase 3 #3.

## Spec structure (Phase 4)
Suite: `browserid-ng-protocol.md` (core), with `agent-provisioning-and-grant-api.md`
as a linked module in this repo. The general **offline-verification** capability
(detached DNSSEC proofs) lives in the core (§6.3); the **SBO on-chain
attribution** application of it lives in the **sbo** repo
(`specs/SBO Attribution Specification.md`), since sbo depends on browserid-ng,
not the reverse. Each core section notes *inherited from BrowserID* vs
*deliberate departure*.
