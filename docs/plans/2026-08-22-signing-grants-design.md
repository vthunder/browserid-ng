# Signing grants — who may ask my keys to sign what

**Date:** 2026-08-22, revised 2026-08-24 (review rounds 1–4 folded) · **Status:** design proposal
**Beans:** `ttn3` (motivating bug, audit M9) · `rjmm` (companion: connection warrants)
**Companions:** `2026-08-13-connection-warrants-design.md` (warrant v2), `docs/security-audit-2026-07-29.md` (M9).

**One line:** a signing grant is a v2 self-grant warrant plus a signed
**requester** rule — "*this website* may submit objects of *this kind* to be
signed as me, for *this audience*" — stored at the user's **wallet**, which
checks every request against it and refuses anything not covered. SBO envelope
signing is the first instance, replacing the custom SBO consent screen and the
signer popup's per-request warrant fabrication with the standard consent card,
registry row, /account ledger, and revocation bit.

**Terminology.** The **wallet** is the party holding the user's keys and
signing on their behalf — concretely today the broker-origin signer popup
backed by the browser Keystore; also the hosted wallet and the CLI wallet.
(Distinct from rjmm's "custody channel," which is the *counterparty's* side —
claude.ai custodying a bearer.)

---

## 1. The motivating bug (audit M9)

The SBO signer popup is a confused deputy. Consent is stored as
`siteInfo[origin].sbo_sign_granted = true` — an origin-keyed boolean — and the
popup honors it as total authority: it takes the **opener-supplied** `email`
and `audience`, fabricates a fresh 90-day warrant client-side from that input
(`sbo-signer.js:147-151`), and signs. Its keystore holds device certs for
*every* local identity, so a granted origin (or XSS on one) signs as any
identity, for any SBO database, unlimited, silently. Nothing ever clears the
grant; the consent card's "take this back anytime" has no code path behind it.

The narrow fix (scope the boolean) would close the hole but add a third
bespoke consent system beside the agent-warrant and connection flows. This
note takes the question up a level.

## 2. What a signing grant is

The user's approval of a standing arrangement: **"this website may submit
objects of this kind and have them signed with my keys, for this
destination."** It is recorded as one signed, registrar-revocable warrant,
stored at the wallet; the wallet is the enforcement point — every incoming
request either matches a stored record or is refused. Consent, registry row,
/account rendering, and revocation reuse the standard machinery the
connection-warrant work added — one more consumer of the standard consent
card and ledger, not a new consent system. Only SBO signing is specced here;
other wallet-mediated signing flows (e.g. the hosted wallet's agent grants)
could adopt the same record shape later.

## 3. The record

An ordinary `browserid-warrant-v2` **self-grant with a holder binding** — the
presentable shape; every use produces a full four-object presentation — plus
one new claim, `requester`, and parameterized scope entries (claims ordered
to read as the grant's sentence):

```json
{
  "typ": "browserid-warrant-v2",
  "iat": …, "exp": …,
  "grantor": "dan@example.com",
  "grantee": "dan@example.com",
  "binding": { "kind": "holder", "matcher": "<this device's holder>" },
  "requester": { "kind": "origin", "origin": "https://mingo.example" },
  "audience": "sbo+raw://avail:turing:506/",
  "scopes": ["sign:sbo:post", { "scope": "sign:sbo:delete", "mode": "prompt" }],
  "status": { "uri": "https://browserid.me/.well-known/browserid-status", "idx": 168 }
}
```

One record per (requester, audience) pair. Expiry is wallet/broker
implementation policy; the suggested lifetime is 90 days and our
implementation uses it, with the status bit as the kill switch.

**`requester` and scope parameters are standing rules from the user to their
wallet.** `requester` says: only sign requests that arrive from this source.
The wallet must authenticate the source to its own satisfaction before
honoring a request — for a website, the browser-verified `event.origin` on
the message, which page JS cannot forge. `requester.kind` is a fail-closed
enumeration; `origin` is the only kind specced. Scope entries carry their own
parameters (below); `mode` is the first.

`binding` and `requester` are the same kind of condition: authenticated
channels that must all check out before the keys sign — the device channel
(authenticated by key possession) and the website channel (authenticated by
the browser's origin check). What separates them is who can check them: key
possession is proved inside the presentation, so network verifiers check the
binding; only the wallet witnesses the ask, so the wallet checks the
requester. Enforcement locus, stated per claim: `binding` — verifiers;
`requester` — the wallet, with a downstream audit via the stamped
`req_origin` (§5, invariant 13); scope parameters — the wallet alone. The rules live
in the signed record rather than wallet-local storage so a wallet bookkeeping
bug cannot cross grants — each record carries its own answer to "may this
site ask?" — and so the /account row shows exactly what was authorized.

**Scopes name what may be signed; parameters attenuate each entry.**
`sign:<kind>` is a new scope namespace, disjoint from resource scopes
(`tool:*`). The scope determines what the wallet will sign, the consent-card
verb, and the payload discipline (a typed SBO envelope destined for the
warrant's audience — never a bare hash or arbitrary blob). SBO envelopes are
typed, so scopes can be finer than "envelope" (`sign:sbo:post` vs
`sign:sbo:delete`). Phase 1 enumerates only `sign:sbo:*`; extending the
vocabulary is deferred until another instance is real.

A scopes entry is either a bare string `s` — shorthand for `{"scope": s}` —
or an object carrying the scope plus parameters. Three rules: **(1)**
everywhere the system treats scopes as identifiers (`scope_fingerprint`,
config-cert constraint checks, scope intersection) an entry's identity is its
scope *string*; parameters ride along. **(2)** Parameters are attenuations
with a defined stricter-wins order; a wallet MUST refuse an entry carrying a
parameter it does not implement. **(3)** `mode` is the first parameter:
`"prompt"` makes the wallet render the object in its own window and wait for
approval before signing; absent ⇒ `"auto"` — the grant's baseline is standing
silent authority, prompt is the explicit tightening (`prompt` > `auto`).
Wallet-local overrides may only tighten, never loosen. Future parameters
(counts, rate caps — stateful, wallet-enforced; bean `eodu`) enter as new
object keys, not new claims.

**Invariants** (spec-text candidates, continuing v2 §3.3):

9. A wallet MUST NOT sign for an external request except under a stored,
   valid, unrevoked record whose requester, `grantee`, `audience`, and
   `sign:` scope all cover the request, honoring the entry's parameters. No
   covering record, an unevaluable check, an unclassifiable object, or a
   prompt-mode scope on a wallet with no interactive surface ⇒ refuse.
10. A signing grant is a self-grant (`grantor == grantee`) with an exact
    grantee and a `holder` binding — presentable (op P) and nothing else.
    `requester` and scope parameters never appear on admission records.
11. Wallets MUST NOT author warrants without a **consent ceremony** — the
    grant card (standing) or a per-request approval (one-shot) are both
    ceremonies; signing on the say-so of a message alone is what M9 was.
    Requests can only match existing records or trigger a ceremony.
12. A `sign:`-scoped record is never reusable as any other grant type, and
    vice versa. (Also blocked mechanically: an SBO grant's audience is an
    `sbo+raw://` ref no login verifier accepts — but the rule is stated.)
13. A presentation under a record with a requester rule MUST carry the
    requesting channel in the assertion (`req_origin`); conforming verifiers
    MUST match it against the warrant's `requester`, fail-closed.
14. **Unknown claims fail closed.** A consumer of these records MUST reject
    a record carrying a claim it does not implement (and a wallet, a scope
    parameter it does not implement). Adding a claim or parameter is
    therefore a versioned change — a new `typ`, or a capability the consumer
    explicitly advertises — never a silent addition. Consequence: a
    restriction the signer believes in can never be ignored by deployed
    consumers. (This deliberately supersedes, for signing grants, the v2
    working assumption that verifiers ignore unknown claims.)

**What the user consents to, plainly.** Auto-mode scopes are standing
authority: the site authors and submits content of that kind silently and
repeatedly — that is the product. The card must say so in the verb; the
counterweights are the scope constraint, pinned audience, /account row,
revocation bit, and prompt mode for scopes that warrant it.

## 4. The SBO flow

**Consent.** The RP opens the dialog with `sboSign` plus — new — its
audience(s) and requested scopes. After sign-in, the standard consent card
(connection-card chassis, signing verb: "**{site}** will sign posts on the SBO
network as **{email}**, to `<database>`"). Approve ⇒ the client signs ONE
durable record per audience (shared module with `consent.html`'s
`signWarrantV2`), gets a status idx, registers it (→ /account row), stores it
in broker-origin storage. The record replaces `sbo_sign_granted`; no parallel
boolean survives. No migration for existing grants: pre-launch, single user —
wipe the old booleans and re-consent once *(decided 2026-08-24)*.

**Dispatch.** Per request the popup looks up a stored record covering
(`event.origin`, email, audience, scope), applies the mode, then mints the
fresh access cert + assertion — with `req_origin` stamped in — and assembles
the presentation with the **stored** warrant. The fabrication block is
deleted (invariant 11). Not covered ⇒ a distinct error: `not_granted`,
`scope_not_granted`, or `prompt_declined`.

**Introspection.** Opener → popup `sbo:grant-info` returns the grant's public
facts *for the asking origin only* — `{email, audience, scopes (with parameters), exp}` —
so the RP can render capabilities honestly (e.g. "delete will ask you").
Non-granted origins get a uniform empty reply (no oracle).

**Revocation.** /account: `mingo.example ↔ sbo+raw://avail:turing:506/ · sign
posts as you · Revoke`. The status bit is checked fail-closed by SBO verifiers
per the existing contract (`sbo-core/src/device_attribution.rs:82-84`) —
revocation is network-wide. Per-site, per-audience revocation falls out of
one record per (requester, audience). Sign-out can also revoke (v2nb posture)
— and the consent copy finally becomes true.

**Notes.** No §3.5 audience-proof ceremony: the request arrives through a
dialog the site itself opened, so the browser-verified origin authenticates
the requester, and the record is a self-grant; a forged request buys only
consent spam, the bound §3.5 accepts. Per-device: config keys are
device-resident, so each device signs its own record on first use — one card
per device, same posture holder bindings already impose.

## 5. Security analysis

**M9 closes structurally**: the popup loses the authority to author warrants
(invariant 11), rather than getting a stricter check. A granted origin's
remaining reach is exactly its consented scope.

| Compromise | Today | Proposed |
|---|---|---|
| Granted origin malicious / XSS | signs as ANY identity, ANY audience, forever | its identity, its audience, its scopes; prompt-mode scopes need a click; killable network-wide |
| Wallet dispatch bug | one boolean IS the whole check | grants can't cross: the record names its requester, and the stamped `req_origin` fails verification downstream even if the local gate fails |
| Broker-origin compromise | game over | identical — no new exposure |
| Revocation | none exists | status bit, fail-closed at verifiers |

**The origin stamp.** WebAuthn defeats phishing by having the *browser* — not
the page — write the requesting origin into the signed payload, so remote
verifiers see who asked even though the asker has no keys. Our popup sits in
the browser's position: it receives an unforgeable `event.origin` and mints a
fresh assertion per signature anyway, so stamping `req_origin` into it is
nearly free. Limits, stated plainly: the stamp is as honest as the stamper.
WebAuthn's stamper is the browser itself; ours is popup JS on the broker
origin — strong against page JS, but a compromised broker origin could lie.
No new trust is introduced (that origin already holds the keys); the gain is
that honest-but-buggy dispatch becomes downstream-detectable and every write
carries a signed audit trail of who asked. The same tier applies to an
optional `ceremony: "prompted"` assertion claim: it proves the wallet
*claimed* a prompt, not that one happened.

**Mode's threat model:** it constrains a bad **requester**, not a bad
**wallet**. A dishonest wallet holds the keys; no mode bit binds it — the
same position as WebAuthn's user-presence flag, where verifiers trust the
authenticator's word. Stronger wallet honesty is a certification /
hardware-attestation matter, open to a future hardware-backed wallet, out of
reach for a JS one — the spec should say so flatly.

## 6. Component impact

| Component | Change |
|---|---|
| Core spec | `requester` claim, `sign:sbo:*` namespace + scope parameters (`mode`), assertion `req_origin`, invariants 9–14. No change to ops P/A. |
| Broker dialog | sbo screen → standard card variant; approve = sign + register + store (shared module); RP declares audiences/scopes. |
| Signer popup | stored-record lookup + scope parameters; delete fabrication; `req_origin` stamp; `sbo:grant-info`; error vocabulary. |
| Registrar | nothing structural; registry row kind for rendering. |
| /account | signing-grant rows (requester ↔ audience · verb · Revoke). |
| include.js / mingo | pass audiences/scopes with `sboSign`; handle errors, use grant-info. |
| sbo-core / callers | add the `req_origin` ↔ `requester` match (invariant 13); audit that callers check the warrant status ref. |
| Wallet / mcp-auth / gate | untouched. |
