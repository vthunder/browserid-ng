# Fallback-IdP API v1 (draft skeleton)

Status: **draft**, 2026-08-28 — redrafted after review (§7): the
fallback IdP presents itself to native clients **as a primary**. Same
family as `registry-api-v1.md`; wire examples follow once §6 settles.

**What this is.** How a native wallet gets a secondary identity's
device + config certs from the broker (acting as fallback IdP). The
answer: the same way it gets them from any primary — a browser-page
ceremony at the issuer, discovered from `address_info`. No password,
code, or credential ever crosses a native API; the wallet has ONE
bootstrap flow for every identity type.

**The one rule.** All authentication — password, signup, reset,
re-verification, bridge proof — happens inside the issuer's own
browser page, where the password manager, origin UI, and recovery
links live. The native contract is only: *open this URL with these
public keys; receive certs on the return navigation*. The
mint-authorization chokepoint behind the page is unchanged.

## 1. The flows

### A. Wallet bootstrap — any secondary address

1. `GET address_info?email=` → for a secondary, NOW includes (new):

       "device_auth":  "https://broker.example/device-authorize",
       "access_mint":  "https://broker.example/access/mint"

   — the same two fields a primary advertises. The wallet no longer
   branches on `type`.

2. Wallet opens `device_auth` in a browser surface (embedded window
   or system browser — client's choice, §3.3) with the standard
   fragment: `#email=…&device_pubkey=…&config_pubkey=…&
   return_origin=…&return_url=…`.

3. The page does whatever this user needs — sign in, create the
   account, reset a forgotten password, re-verify a stale address
   (§3.4), or run a bridge-proof ceremony. All server-side UX; the
   wallet neither knows nor cares which happened.

4. On success the page navigates to
   `return_url#device_cert=…&config_cert=…` (or `#device_error=…`);
   the wallet intercepts the navigation and persists the certs.

5. If `issuer` ≠ the wallet's registry host, the wallet joins the
   registry silently (`auth_with_presentation`, gxi9). When the
   fallback IdP IS the registry host, issuance already recorded the
   device — the join is skipped. This one-line branch is all that
   remains of the old two-lane bootstrap.

### B. Primary address — unchanged, shown for symmetry

Identical steps; `device_auth` just points at the primary's own IdP.
That is the point: **the fallback IdP is the primary of last
resort**, not a different kind of thing.

### C. Re-issuance / new device

Flow A again. With a live browser session in the page's partition the
ceremony may complete without retyping anything; with a stale
verification (§3.4) the page demands a fresh mailbox code first.

## 2. What this deletes

The previous draft's native endpoints — `stage`, `complete`,
`email/send`, `email/verify`, `issue`, and the `email_proof`
artifact — are all gone (§7, decision 2). Headless secondary
issuance is deliberately not offered: scripted clients use the
agent-provision lane (core §7.5), and tests use test endpoints.
Passwords cannot be credential-stuffed through an API that never
accepts one.

## 3. The contract

### 3.1 `address_info` additions (normative)

For `type: "secondary"` addresses the issuer MUST advertise
`device_auth` and `access_mint` (today these appear only for
primaries). Existing anti-enumeration behavior is unchanged — the
fields are properties of the issuer, not of the account.

### 3.2 The device-authorize page

The fragment/return contract that today exists as implementation
(the hosted-IdP page; the wallet's `primaryHop`) becomes normative
here: REQUIRED fragment params (`email`, `device_pubkey`,
`config_pubkey`, `return_origin`, `return_url`), success return
(`device_cert`, `config_cert`), error return (`device_error` +
enumerated values), and the rule that params ride the **fragment**
(never sent to the server) while delivery rides the return
navigation. The broker mounts this page for its own secondaries;
behind it, issuance is the existing session-authed chokepoint
(`authorize_mint`) — Full session for E3, live bridge grant for E2,
holder assigned under the account's `browsers` namespace.

### 3.3 Client guidance: embedded vs system browser

The contract works in both. RECOMMENDED: an embedded window with a
persistent partition (the wallet's existing primary-hop shape) —
consistent UX, clean return interception, and the live session makes
re-issuance ceremony-free. Tradeoff to disclose: an embedded window
does not reach the user's system-browser password manager. A client
MAY use the system browser instead (loopback `return_url`).

### 3.4 Verification freshness (issuer policy, new)

An address MUST NOT stay verified forever. The issuer enforces a
maximum verification age (window: §6 Q2); an issuance attempt past
it re-runs the mailbox ceremony inside the page before certs are
returned. (Broker gap tracked in bean uboq: `verified_at` is
currently write-only and `EmailVerificationExpired` is never
raised; kgb9's reset-unverifies rule is today's only re-trigger.)

## 4. Browser handoff (fills registry-api-v1 §5.5's `browser` object)

The device-authorize page absorbed claim/recovery, so the object
shrinks to:

| Key | Opens | Used by |
|---|---|---|
| `account` | the account page | menu shortcut; email add/remove, cancel |

Clients MUST ignore unknown keys.

## 5. Errors

Native surface: only the `device_error` fragment values (to
enumerate: `cancelled`, `email_mismatch`, `policy_refused`, …) and
registry-api-v1 §7 for `address_info`. Everything else is page UX.

## 6. Open questions

1. **Client-supplied `holder`** — the page contract has no holder
   param today (primaries self-assign + join-side healing). For the
   fallback the broker assigns from the account's real namespace, so
   healing isn't needed — but wallet holder *continuity* across
   re-issuance may still want an optional fragment param validated
   like `/device/issue`'s (absorbing bean kmvm). Lean: add it,
   optional.
2. **Verification max-age window** (§3.4) — 90 days? 180?
3. **Config-cert identity set** — the page's issuance should pin one
   behavior for `[email]` vs `[email, local+*@domain]` (today's two
   lanes disagree).
4. **Page mount + naming** — new `/device-authorize` on the broker
   vs reusing the hosted-IdP page machinery with the broker as its
   own tenant. Implementation-leaning, but affects the URL the spec
   blesses.

## 7. Decision log

- **2026-08-28 (Dan): no credential ever crosses a native API**
  (option a). The earlier draft's native password lane
  (`stage`/`complete`/`issue`, password-over-TLS) is deleted, not
  rationalized: literal-password APIs are parity with the browser
  lanes but scriptable; digest schemes are theater against bcrypt
  storage; PAKE/passkeys are protocol-wide successors (bean n0ut).
  The browser page keeps the phishing/password surface where the
  tooling for it lives.
- **2026-08-28 (Dan): the fallback presents as a primary.**
  `address_info` advertises `device_auth`/`access_mint` for
  secondaries; the wallet's per-type bootstrap branch reduces to
  "skip the registry join when the issuer is the registry".
- **2026-08-28 (Dan): issuance bar = password + durable verified
  flag** — `/device/issue`'s bar, unchanged; now enforced inside the
  page. Freshness is issuer policy (§3.4), newly required to be
  time-bounded.
