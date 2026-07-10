<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# SBO On-Chain Attribution — browserid-ng module

> **STATUS: DRAFT.** A layered module on top of the
> [core protocol](./browserid-ng-protocol.md). It describes how a browserid-ng
> **email identity** is attributed to an on-chain **`ed25519:` key** in a
> trustless (offline-verifiable) setting — e.g. the SBO ledger. A plain
> relying party does not need this; it exists for contexts where verification
> happens without a live connection to the IdP.
>
> Reference implementation: `sbo-core/src/attribution.rs`,
> `sbo-daemon/src/validate.rs`.

## 1. Why

Core verification (protocol §6) resolves an IdP key over a live authenticated
DNS channel. On a ledger there is no live channel at replay time — a validator
must decide, deterministically and offline, *"did this signing key speak for
this email at this block?"* browserid-ng answers it with a **self-contained
proof**: a browserid certificate plus a **DNSSEC proof** (RFC 9102) for the
cert's issuer, both carried in (or referenced by) the write.

This is only possible because the core trust root is DNSSEC (protocol §3): a
DNSSEC proof is a portable artifact; a Web-PKI/`.well-known` fetch is not.

## 2. Identity rootings

An on-chain object's owner is one of:

- **Key-rooted** (`identity.v1`) — the owner *is* an `ed25519:` key
  (`Controller::Key`). Writes are authorized by signature alone. A key-rooted
  name is established once via a `/sys/names/<name>` claim.
- **Email-rooted** (`identity.email.v1`, or a bare email) — the owner is an
  email (`Controller::Email`). Each write must carry browserid **attribution**:
  an `Auth-Cert` and `Auth-Evidence` (below), proving the signing key spoke for
  that email at inclusion time.

## 3. The attribution proof

A write attributing signer key `K` to email `e` carries:

- **`Auth-Cert`** — a browserid certificate (protocol §4) with
  `principal.email = e`, `public-key = K`, issued by some `iss`.
- **`Auth-Evidence`** — a DNSSEC proof for `iss`'s `_browserid` record. It may
  be provided as `inline:<base64url>`, as `ref:<sbo-path>`, or resolved from the
  conventional **`/sys/dnssec/<iss>`** object (a `dnssec.v1` object holding the
  RFC 9102 proof bytes). The proof objects are **self-authorizing**: policy
  grants create/update on `/sys/dnssec/**` to anyone, because the proof attests
  its own domain — it needs no identity to post.

## 4. Verification algorithm

`verify_attribution(public_key, auth_cert, auth_evidence, inclusion_time, anchors)`:

1. **Parse** the cert; read its issuer `iss`.
2. **Extract the provider key + validity window** from the DNSSEC proof for
   `iss` (the `_browserid` record's published key, its RRSIG inception/expiration).
3. **Key match** — the certified `public-key` MUST equal the signer `K`.
4. **Window** — `inclusion_time` must fall inside both the proof window and the
   cert's `iat…exp`.
5. **Signature** — the cert must verify against the DNSSEC-proven provider key.
6. **Authority** — `domain(e) == iss` (the email's own domain is a primary), OR
   `iss` is a pinned **broker** (`anchors.is_broker(iss)`, from
   `/sys/trust/brokers`). This is what lets a broker-certified email
   (`iss = browserid.me`) attribute while its email domain is unrelated.

On success the signer is attributed to `e` for the intersection of the cert and
proof windows.

> **Note (host certs, protocol §4.2):** once DNSSEC-signed host certificates
> land, step 5 generalizes to verifying the cert chain up to `K_dns` (direct or
> via a host cert), rather than a single issuer-key check. To be specified when
> host certs are implemented (bean `browserid-ng-28uc` Phase 2).

## 5. Freshness & the `/sys/dnssec` objects

`/sys/dnssec/<domain>` holds the current proof; it is refreshed before its RRSIG
window lapses. Because the proof is what authorizes an email-rooted write, a
stale or wrong-key proof breaks attribution for that domain until refreshed —
so proof freshness (and correct key rotation, protocol §4.2) is operationally
load-bearing.

> **Known issue (bean `mingo-jyzt`):** `/sys/dnssec/<domain>` objects are keyed
> by *creator*, and evidence resolution currently takes the first creator's
> object rather than a *valid* one — so multiple writers can fork the slot and
> a stale fork can win. Resolution should select a proof that validates for the
> domain at inclusion time. Cross-reference when specifying this section.

## 6. Trust anchors

- **`/sys/trust/brokers`** — the pinned set of broker issuers whose
  broker-certified emails are honored (step 6). `browserid.me` is the default.
- The IANA DNSSEC root anchors the RFC 9102 chains.

---

*Draft notes:* §4 step 5 and §5 finalize alongside the host-cert work (28uc
Phase 2) and the resolution fix (`mingo-jyzt`).
