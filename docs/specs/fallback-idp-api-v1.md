# Fallback IdP v1: native-client issuance

Status: draft, 2026-08-28. Companion to `registry-api-v1.md`. Wire
examples follow the §6 resolution.

## 1. The model

Four parties. Each is chosen independently, and the APIs between them
are identical no matter who runs which — browserid.me runs all of
them by default, but any piece can be replaced.

- **RP** — requests a login (`navigator.id`, core §2). Decides which
  fallback IdPs it accepts (core §8.1); its verifier enforces that.
- **Wallet** — the user agent. Native app or the browserid.me web
  wallet. Holds the keys and drives every step below.
- **IdP** — issues device + config certs. The identity's domain
  determines it: the domain's own IdP if it has one, otherwise a
  **fallback IdP** the wallet is configured with. To be usable, the
  fallback must be one the user's RPs accept (§8.1).
- **Registry** (registry-api-v1) — records devices and warrants,
  hosts the approvals inbox. Wallet configuration; the web wallet
  hardcodes browserid.me, a native wallet may not.

The wallet connects the dots itself: it discovers the IdP, runs the
issuance ceremony there, then registers the result at its registry.
It MUST NOT assume the IdP and registry talk to each other — even
when they are the same host.

A fallback IdP presents itself to the wallet exactly as a primary
does: same discovery keys, same ceremony page. A conforming wallet
has one issuance flow and never needs to know which kind of issuer
it reached.

## 2. Discovery

1. Discover the identity's domain (core §3). If it publishes an IdP,
   that is the issuer.
2. Otherwise the issuer is the wallet's configured fallback IdP.

The issuer's support document (`/.well-known/browserid`) supplies:

| Key | Meaning |
|---|---|
| `device_authorization` | The ceremony page (§3). |
| `access_mint` | The access-cert mint (core §5). |

A fallback IdP MUST advertise both — the same keys as a primary.
(`/wsapi/address_info` is not part of this contract; it exists for
the web dialog, which cannot run discovery itself.)

## 3. The ceremony page

### 3.1 Contract

The wallet opens `device_authorization` with fragment parameters
`email`, `device_pubkey`, `config_pubkey`, `return_origin`,
`return_url`. Fragments are never sent to the server. The wallet
intercepts the navigation to `return_url`:

    return_url#device_cert=…&config_cert=…      success
    return_url#device_error=…                   refusal

The page may be rendered in an embedded window or the system
browser; the contract is the same. Embedded with a persistent
partition is RECOMMENDED: interception is simple and a live session
makes re-issuance ceremony-free. Tradeoff: no access to the system
browser's password manager.

### 3.2 Requirements on the issuer

Everything between invocation and return is the issuer's UX:
sign-in, account creation, password reset, re-verification, bridge
proof. No credential ever crosses a native API. The outcome MUST
satisfy:

- **The mint bar is the issuer's strongest session bar.** For the
  broker's fallback role: `authorize_mint` unchanged — a password
  session for SMTP-proofed addresses, a live bridge grant for
  bridge-proofed ones.
- **Verification freshness is issuer policy.** Verification does not
  last forever; when the issuer considers it stale (age, password
  reset), the page re-runs the mailbox ceremony before returning
  certs.
- **A fresh holder.** The certs bind the fragment's keys to a holder
  the issuer assigns fresh — never taken from the page's own browser
  session. The resulting device is the wallet, not the browser the
  ceremony ran in. Same rule as the primary lane.
- **Per-key status refs** on both certs (core §6.3).

## 4. Registration

Issuance yields certs. The wallet then registers them at its
configured registry:

1. `POST /api/v1/token` (registry-api-v1 §3.1) with a presentation
   of the new certs — this resolves or creates the account.
2. `POST /api/v1/devices/register { device_cert, config_cert }` —
   records the device. Idempotent (upsert on public key). To be
   added to registry-api-v1 §5.3; validation details there.

Rules:

- Registration is always the wallet's act. An issuer that also runs
  a registry MAY pre-record its own issuances, but wallets MUST NOT
  rely on that — the flow above is identical whether or not the
  issuer and registry are the same host, and re-registering an
  already-recorded device is a no-op.
- One registry per identity in v1.

## 5. Errors

`device_error` values (enumerated with wire examples): `cancelled`,
`email_mismatch`, `policy_refused`, `unsupported_key`. Discovery
errors are core §3; registration errors are registry-api-v1 §7.

## 6. Open questions

1. **Config-cert identity coverage.** Does the issued config cert
   cover only the exact address, or also its sub-addresses
   (`local+*@domain`, which lets one cert sign warrants for derived
   agent identities)? The broker's two legacy lanes disagree; pin
   one.

## 7. Decision log

Resolved (2026-08-28 review):

1. **No native credential lane.** Passwords, codes, and proofs stay
   inside the ceremony page. Password-over-API is scriptable attack
   surface; client-side digests defeat nothing against bcrypt
   storage; PAKE/passkeys are protocol-wide successors (bean n0ut).
2. **The fallback presents as a primary**; `address_info` is not
   part of the native contract.
3. **Issuance bar unchanged** (the session lane's bar). Verification
   max-age is issuer policy, not spec: browserid.me uses 90 days
   (bean uboq).
4. **Holder matches the primary lane** — issuer-assigned, fresh,
   never the ceremony page's session state.
5. **Registration is always wallet-driven** through the registry
   API; issuer-side recording is an internal convenience nothing may
   depend on. Requires `devices/register` in registry-api-v1 §5.3.
6. **Fallback choice is bounded by RP acceptance** (core §8.1),
   enforced at verification. Gap: the native wallet lane does not
   yet forward the RP's `acceptedFallbacks` (bean u6jq).
