# Warrant use cases — one page

**Date:** 2026-08-24 · living reference (update when a use case ships or changes)

Every warrant is one English sentence plus a standard envelope. The envelope
is identical on every record — `typ`, `iat`/`exp`, `status` (the revocation
ref) — and in self-grants `grantee` is forced (`== grantor`). The sentence
fills the remaining claims:

> **I authorize [who] to [do what] as/with [identity], at/for [where].**

The `binding` claim holds a set of authenticated-channel entries, all of
which must check out (a singular object is shorthand for a one-entry set —
the form all deployed records use; see the signing-grants note §3 for the
kind × operation table). Five use cases exist today (four live, one
proposed).

---

## 1. Login *(live — `dialog.js:489`, v1)*

Minted fresh at each sign-in by the dialog and presented to the RP; the user
being present at the dialog is the consent ceremony. Holder is the account
prefix's whole namespace so the login reuses across the user's browsers.

> "I sign in to **example-shop.com** as **dan@example.com**, from any of this
> account's devices."

```json
{ "typ": "browserid-warrant-v1", "iat": …, "exp": …,
  "grantor": "dan@example.com", "grantee": "dan@example.com",
  "holder": "<account-prefix>.*",
  "audience": "https://example-shop.com",
  "scopes": ["login"],
  "status": { "uri": "…/browserid-status", "idx": … } }
```

## 2. Agent grant *(live — `consent.html:674`, spec §7.5, v1)*

The user approves an agent's request at the consent page; the agent holds the
record and presents it with its own access certs. The only case where grantee
≠ grantor: attribution transfers to the grantor, within scopes.

> "I authorize **agent@sandmill.org** (its own devices only) to **post** to
> **my SBO database**, attributed to me."

```json
{ "typ": "browserid-warrant-v1", "iat": …, "exp": …,
  "grantor": "dan@example.com", "grantee": "agent@sandmill.org",
  "holder": "<the agent's holder>",
  "audience": "sbo+raw://avail:turing:506/",
  "scopes": ["post"],
  "status": { … } }
```

## 3. Connection record *(live — `consent.html:659`, rjmm design §3.5, v2)*

Signed at the consent card when an anonymous OAuth host (claude.ai) connects
to a warrant-gated resource. Held by the resource, admission-consumed: the
record is the row the authenticated connection is matched against. Never
presentable.

> "I connect **Claude (claude.ai)** to **gate.dan.dev/notes** — acting as me
> through that one connection, with these tools."

```json
{ "typ": "browserid-warrant-v2", "iat": …, "exp": …,
  "grantor": "dan@example.com", "grantee": "dan@example.com",
  "binding": { "kind": "connection", "protocol": "oauth", "id": "cn_8f3a…",
               "client_host": "claude.ai", "client_name": "Claude" },
  "audience": "https://gate.dan.dev/notes",
  "scopes": ["tool:read_file", "tool:search_files"],
  "status": { … } }
```

## 4. Policy record *(live — `consent.html:665`, rjmm design §3.4, v2)*

Authored in the grant-authoring ceremony: an admin admits another person to
their resource. Held by the resource; the subject logs in as themselves and
is matched against it (permission, never attribution — the actor's identity
comes from their own login).

> "I authorize **friend@gmail.com** to use **these tools** at **my resource
> gate.dan.dev/notes**, from any of their devices."

```json
{ "typ": "browserid-warrant-v2", "iat": …, "exp": …,
  "grantor": "dan@example.com", "grantee": "friend@gmail.com",
  "binding": { "kind": "holder", "matcher": "*" },
  "audience": "https://gate.dan.dev/notes",
  "scopes": ["tool:read_file"],
  "status": { … } }
```

## 5. Signing grant *(proposed — `2026-08-22-signing-grants-design.md`, v2)*

Stored at the user's wallet; the wallet refuses any signing request not
covered by a stored record. Presented per use with a fresh access cert. Its
binding is a two-entry channel set — the signing device (`holder`) and the
site allowed to ask (`requester`) — and scope entries carry parameters
(`mode`: silent vs prompted, per scope).

> "I authorize **mingo.example** to submit **SBO posts** (silently) and
> **deletes** (with a prompt) to be signed as **me**, for **database
> avail:turing:506**."

```json
{ "typ": "browserid-warrant-v2", "iat": …, "exp": …,
  "grantor": "dan@example.com", "grantee": "dan@example.com",
  "binding": [ { "kind": "holder",    "matcher": "<this device's holder>" },
               { "kind": "requester", "origin": "https://mingo.example" } ],
  "audience": "sbo+raw://avail:turing:506/",
  "scopes": ["sign:sbo:post", { "scope": "sign:sbo:delete", "mode": "prompt" }],
  "status": { … } }
```

---

At a glance:

| # | Use case | grantee | instance claims | consumed by |
|---|---|---|---|---|
| 1 | Login | self | `holder` (namespace) | RP verifies presentation |
| 2 | Agent grant | the agent | `holder` (agent's) | anyone verifies presentation |
| 3 | Connection | self | `binding: connection` | resource holds, admits |
| 4 | Policy | another person | `binding: holder *` | resource holds, admits |
| 5 | Signing grant | self | binding set {holder, requester}, scope params | wallet holds, then presents |

## Known limits (2026-08-24 review)

The five cases sit on a small matrix — operation (presented / admitted) ×
grantee (self / other) × what's conferred (attribution / permission):

| | presented | admitted |
|---|---|---|
| **self, via channel** | login (1), signing grant (5) | connection (3) |
| **other, attribution** | agent grant (2) | *deliberately unconstructible* (rjmm §3.1's "delegated connection" door) |
| **other, permission only** | policy record satisfied by op P | policy record (4) |

Two observations. The empty cell is a documented decision, not an oversight.
And login shares a cell with the signing grant because **a login is a
one-shot signing grant** — self-grant, holder-bound, presented to an
audience, with the consent ceremony (the dialog) performed per use instead
of once. When signing grants reach the spec, login should be defined as the
degenerate case rather than a parallel form.

Compared with other authorization languages, four things the format cannot
say — each with a disposition:

- **Grantee-side attenuation** (Macaroons, Biscuit, UCAN): a holder cannot
  narrow its own grant and hand the slice on (orchestrator agent →
  subagent). Holders narrow *which keys*, not which scopes. Future work:
  bean `browserid-ng-0ijs`.
- **Stateful conditions** (IAM condition keys, RAR payment authorization):
  "at most 20 posts/day", "up to €500". These render perfectly on a consent
  card; they are excluded because enforcement is stateful and verifiers are
  deliberately stateless. If wanted, they enter as wallet-enforced scope
  parameters. Future work: bean `browserid-ng-eodu`.
- **Deny rules** (IAM explicit Deny): "everyone at my domain except bob".
  Permanently out — deny semantics confuse most people; exceptions belong in
  the resource's role layer, compiled down to flat allow records (rjmm
  §3.4's grant-authoring ceremony already works this way).
- **Audience hierarchies / wildcards** (IAM ARNs, UCAN path scoping): one
  exact audience per record, deliberately — N records buy N independently
  revocable /account rows.

Growth path in one line: every viable extension above is an *attenuation*,
and it enters the language as a scope parameter (stricter-wins,
wallet-enforced) — never a new claim, never a policy language.
