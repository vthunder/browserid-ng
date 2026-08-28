# Fallback IdP v1: native-client issuance

Status: draft, 2026-08-28. Companion to `registry-api-v1.md` (same
family and conventions). Wire examples follow the §6 resolutions.

## 1. Overview

A **fallback IdP** issues device + config certs for identities whose
domain runs no IdP of its own. This spec defines how a native client
(a wallet) obtains those certs: **exactly as it would from a
primary** — a browser-page ceremony at the issuer, discovered from
the issuer's support document. The fallback IdP is the primary of
last resort, not a different kind of thing; a conforming client has
one issuance flow for every identity type.

No credential ever crosses a native API. All authentication —
password, account creation, reset, re-verification, bridge proof —
happens inside the issuer's own browser page, where password
managers, origin UI, and recovery links live. The native contract is
only: *open this URL carrying these public keys; receive certs on
the return navigation.* Headless secondary issuance is deliberately
not offered; scripted clients use the agent lane (core §7.5).

From the client's view two roles are involved, independently chosen:

- the **issuer** — determined by the identity's domain (its own IdP,
  or the client's configured fallback when the domain has none);
- the **registry** (registry-api-v1) — the client's configured home
  for devices, warrants, and approvals.

One host may serve both (the hosted broker does); nothing in this
spec assumes it.

## 2. Discovery

The client resolves the issuer itself, per core §3:

1. Discover the identity's domain. If it publishes an IdP, that IdP
   is the issuer.
2. Otherwise the issuer is the client's **configured fallback IdP** —
   client configuration, not a lookup: which fallback vouches for
   your unclaimed addresses is the user's choice.

Either way, the issuer's support document (`/.well-known/browserid`)
supplies the ceremony surface. A fallback IdP MUST advertise:

| Key | Meaning |
|---|---|
| `device_authorization` | The §3 ceremony page. |
| `access_mint` | The access-cert mint (core §5) for identities it issues. |

These are the same keys a primary advertises; a client MUST NOT need
to know which kind of issuer it is talking to. (The legacy
`/wsapi/address_info` endpoint remains for the web dialog, which
cannot run discovery itself; native clients do not use it.)

## 3. The ceremony page

### 3.1 Invocation

The client opens `device_authorization` with the standard fragment
parameters — `email`, `device_pubkey`, `config_pubkey`,
`return_origin`, `return_url`. Parameters ride the URL **fragment**
and are never sent to the server; delivery rides the return
navigation. The client intercepts navigation to `return_url`:

    return_url#device_cert=…&config_cert=…      on success
    return_url#device_error=…                   on refusal

A client MAY render the page in an embedded window (RECOMMENDED: a
persistent partition makes re-issuance ceremony-free) or hand off to
the system browser; the contract is identical. An embedded window
does not reach the user's system-browser password manager — clients
should weigh that against interception simplicity.

### 3.2 Behind the page

What the page does between invocation and return is the issuer's UX —
sign-in, account creation, password reset, re-verification, or a
bridge-proof ceremony as the account's state requires. Normative
requirements on the outcome:

- **The mint bar is the issuer's strongest session-lane bar.** For
  the broker's fallback role that is `authorize_mint` unchanged: a
  Full (password) session for SMTP-proofed addresses, a live bridge
  grant for bridge-proofed ones. The page is a front end to the
  chokepoint, never a bypass.
- **Verification freshness.** An address MUST NOT remain verified
  forever: past the issuer's maximum verification age (§6 Q1), and
  after any event that voids verification (e.g. a password reset
  un-verifying sibling addresses), the page re-runs the mailbox
  ceremony before returning certs.
- **A fresh holder, never the page's.** The issued certs bind the
  FRAGMENT's public keys to a holder the issuer assigns fresh for
  this client — never derived from, or shared with, any browser
  session state the page itself carries. The device row that results
  belongs to the native client, not to the browser the ceremony
  happened to run in; registry placement and labeling follow the
  registry's standard machinery (a client may label itself via
  registry-api-v1 §5.4). This is the same holder rule the primary
  lane follows.
- **Per-key status refs** on both certs, as core §6.3 requires of
  revocable issuance.

## 4. Registration: the client's registry

Issuance yields certs; **registration** makes them useful — devices
listed, warrants registrable, approvals routable. Registration is a
distinct step at the client's configured registry, not a property of
the issuer:

- The client registers by authenticating to its registry with a
  presentation of its new certs — the token exchange
  (registry-api-v1 §3.1) for API clients, or the session join
  (`auth_with_presentation`) where a browser session is wanted.
  Account resolution is registry-api-v1 §3.1's: existing owner of
  the identity, else a fresh account.
- **When the issuer IS the registry** (the hosted broker default),
  issuance itself records the device and registration is complete —
  the explicit step is redundant and a client skips it. (The session
  join's self-issued rejection makes the redundant case unreachable
  on that lane by construction; the token lane accepts self-issued
  presentations and simply finds the rows already present.)
- **When they differ** — a primary-issued identity registering at
  the hosted broker (today's default for primaries), or any identity
  registering at a self-hosted registry — the presentation is
  foreign-issued at that registry and follows the normal
  verification path. Nothing about issuance changes.

The registry is client **configuration surfaced at setup**, with a
sensible default — registration is a chosen relationship, not a side
effect of issuance. A conforming client uses one registry at a time
per identity; multi-registry membership is out of scope for v1.

## 5. Errors

Native surface: the `device_error` fragment values, to be enumerated
with the wire examples (expected set: `cancelled`,
`email_mismatch`, `policy_refused`, `unsupported_key`). Discovery
and registration errors are core §3 and registry-api-v1 §7
respectively. Page-side failures are page UX, not protocol.

## 6. Open questions

1. **Verification max-age** (§3.2): 90 or 180 days; and whether the
   window is spec-fixed or issuer policy with a spec ceiling.
2. **Config-cert identity set**: `[email]` exact vs
   `[email, local+*@domain]` — the broker's two legacy lanes
   disagree; the page must pin one.
3. **Page mount**: a new broker route implementing the contract, vs
   reusing the hosted-IdP page machinery with the broker as its own
   tenant.

## 7. Decision log

Resolved (2026-08-28 review):

1. **No native credential lane.** An earlier draft carried
   password/code endpoints (`stage`/`complete`/`issue` and an
   `email_proof` artifact); deleted. Password-over-API is parity
   with the browser lanes but scriptable; client-side digests are
   theater against server-side bcrypt; PAKE/passkeys are
   protocol-wide successors (bean n0ut). The ceremony page keeps
   the credential surface where its tooling lives.
2. **The fallback presents as a primary** — same support-document
   keys, same page contract, one client flow.
3. **No `address_info` in the native contract.** Native clients run
   discovery themselves and choose their own fallback; the endpoint
   exists for the web dialog, which can do neither.
4. **Issuance bar = the session lane's bar, unchanged** (password +
   verified address for SMTP proofs), plus the new time-bound on
   verification (broker implementation tracked in bean uboq).
5. **Holder handling matches the primary lane** — issuer-assigned,
   fresh, never derived from the page's browser state (no
   client-supplied holder parameter; bean kmvm stays independent).
6. **Registration is a client-configured relationship** with the
   registry, distinct from issuance; issuer==registry is the
   redundant special case, not the model.
