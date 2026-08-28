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
does: same discovery keys, same ceremony page. The wallet has one
issuance flow that never needs to know which kind of issuer it
reached — the reference wallet runs a single ceremony lane for both
and holds no issuer cookies. (Its issuer *resolution* still leans on
the broker's `address_info` as a discovery convenience; client-side
core §3 DNSSEC discovery remains future work.)

## 2. Discovery

1. Discover the identity's domain (core §3). If it publishes an IdP,
   that is the issuer.
2. Otherwise the issuer is the wallet's configured fallback IdP.

The issuer's key comes solely from the domain's DNSSEC `_browserid`
record (core §3). The support document carries no key; a client MUST
ignore any key material served in it, and MUST treat a DNSSEC
failure as a hard reject rather than trusting a TLS-served answer.

The issuer's support document (`/.well-known/browserid`) supplies:

| Key | Meaning |
|---|---|
| `device-authorization` | The ceremony page (§3). |
| `access-cert` | The access-cert mint (core §5). |

A fallback IdP MUST advertise both — the same keys as a primary.
(`/wsapi/address_info` is not part of this contract; it exists for
the web dialog, which cannot run discovery itself.)

The reference fallback IdP advertises both: its ceremony page is
mounted at `/device-authorize` over the broker-session backend, and
its one issuance core also serves the web dialog (the legacy
`/auth/device_cert` batch lane is retired; bean 2jfh).

## 3. The ceremony page

### 3.1 Contract

The wallet opens `device-authorization` with fragment parameters
`email`, `device_pubkey`, `config_pubkey`, `return_origin`,
`return_url`. Fragments are never sent to the server. The wallet
intercepts the navigation to `return_url`:

    return_url#device_cert=…&config_cert=…      success
    return_url#device_error=…                   refusal

The page MUST validate `return_origin` (a well-formed http(s)
origin, or the wallet's registered loopback/custom-scheme origin)
and MUST reject unless `return_url` is same-origin with it, before
delivering anything. The certs bind the fragment's public keys, so a
page that navigates to an unvalidated `return_url` hands a
victim-identity config cert to whoever supplied the URL and the keys
— a warrant-signing takeover. (The current shared page validates
`return_origin` for its postMessage lane but not the `return_url`
lane; bean 9it0.)

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
  certs. (Not yet enforced by the broker: `verified_at` is currently
  write-only; bean uboq.)
- **A fresh holder.** The certs bind the fragment's keys to a holder
  the issuer assigns fresh — never taken from the page's own browser
  session. The resulting device is the wallet, not the browser the
  ceremony ran in. Same rule as the primary lane.
- **Config-cert coverage tracks the bar.** A config cert covering
  the address's sub-addresses (`local+*@domain`) grants authority
  over the holder's derived agent identities, so the wildcard is
  permitted ONLY when the ceremony reached the password / session
  bar above. A weaker bar (e.g. mailbox proof alone) MUST issue an
  exact-address config cert (the 7ww7 blast-radius rule).
- **Per-key status refs** on both certs (core §6.3).

## 4. Registration

Issuance yields certs. The wallet then registers them at its
configured registry:

1. `POST /api/v1/token` (registry-api-v1 §3.1) with a presentation
   built from the new certs — resolves or creates the account and
   binds the token to the config cert's key.
2. `POST /api/v1/devices/register { device_cert, config_cert }` —
   records the device.

`devices/register` is a new registry-api-v1 §5.3 endpoint (the token
exchange verifies only the presentation's config and access certs,
not the sibling authentication `device_cert`, so registration must
verify it explicitly). It MUST require, and reject otherwise:

- both certs verify against an issuer the registry accepts for their
  identity — the domain's own DNSSEC-published IdP (core §3/§6), or,
  for a domain without one, a fallback issuer in the registry
  operator's configured accepted-fallback set (the registry-side
  mirror of the RP rule, core §8.1; the reference registry's default
  set is its own domain) — and are unexpired and unrevoked;
- their identity is one the token's account owns (§3.1 resolution);
- both share one holder, and the config cert is the one the token is
  bound to.

Idempotent: re-registering an already-recorded device (matched on
public key) is a no-op success.

Rules:

- Registration is always the wallet's act. An issuer that also runs
  a registry MAY pre-record its own issuances, but wallets MUST NOT
  rely on that — the flow above is identical whether or not the
  issuer and registry are the same host.
- A registry is free to refuse issuers outside its accepted set;
  wallet configuration should pair a fallback IdP with a registry
  that accepts it (issuer == registry always composes).
- One registry per identity in v1.

## 5. The registry `browser` object

Registry-api-v1 §5.5 reserves a `browser` object in the registry's
discovery and delegates its keys here. One key in v1:

| Key | Opens |
|---|---|
| `account` | The registry's account-management page (devices, warrants, approvals). |

Clients MUST ignore unknown keys. Issuer-side ceremonies need no
keys here — they live behind `device_authorization` (§3).

## 6. Errors

`device_error` carries a short reason. Recognized values are
`cancelled`, `email_mismatch`, `policy_refused`, `unsupported_key`;
the set is open, and a wallet MUST treat any unrecognized value as a
generic refusal. Discovery errors are core §3; registration errors
are registry-api-v1 §7.

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
7. **Config-cert coverage tracks the authentication bar** (§3.2):
   the `local+*@domain` wildcard is allowed only when the ceremony
   reached the password/session bar; a weaker bar issues exact-only
   (the 7ww7 rule). Consolidation of the broker's three issuance
   lanes onto one core is bean 2jfh.
