# Design note — Holder-based authorization (replacing `subject` + `as:`)

**Date:** 2026-07-20
**Status:** Design proposal (settled in discussion; no code yet)
**Supersedes:** the "re-add the `as:` / warrant-delegator" direction and the
per-agent sub-address idea. It is the foundation the mingo-poster (service /
agent posting, "D") should be built on.

## Problem

The device-cert model attributes a presentation to **one identity** (the access
cert's `identity` + `subject`), and its warrant is `(identifier, subject) →
audience [+ scopes]`. Two things fall out of that which we want to fix:

1. **Fungible warrants (a real isolation bug).** In the "give a service a device
   cert for `identity=you, subject=agent` + a warrant `(you, agent) → X`" model,
   the warrant binds to `(identity, subject, audience)` — *not to the specific
   agent*. If service&nbsp;1 and service&nbsp;2 each hold a device cert that
   mints `(you, agent)` access certs, then either can present the other's
   warrant: the join only checks identity/subject/audience, all of which match.
   The stated safety argument ("a leaked warrant is useless without a matching
   IdP-minted access cert") quietly fails, because *each* qualifying holder can
   mint the matching access cert. Warrants become bearer-ish tokens shared
   across all your agents.

2. **`subject: user|agent` is a false guarantee.** Whether a human or a program
   drives a key is unobservable from a signed cert — a human can sign "as an
   agent", and a human can build an agent that signs "as a user". Absent an
   independent attestation (proof-of-personhood, TEE), `subject` is a
   self-asserted *hint*, not a descriptive claim, so gating security on it (our
   "agents-only" guestbook; a hypothetical "humans-only" vote) is not sound.

A third constraint shapes the fix: **the fix must not let a relying party
gatekeep agents by brand.** If an RP can tell "OpenAI's agent" from "mingo's
agent" from "a competitor's agent", it can allow the ones it is paid for and
block the rest under a safety pretext. Distinguishability that enables *warrant
isolation* is the same distinguishability that enables *RP gatekeeping* — they
are one lever, so the design has to place it deliberately.

## Model

Replace both `subject` and any `as:`/delegator notion with an opaque **holder**.

### Holders

- Every device cert (and, copied at mint, every access cert) carries a
  **required, opaque, high-entropy `holder` id**.
- The id is **assigned by the user's broker** (browserid.me, the mediator that
  runs the dialog and owns the account), **not** by the party requesting the
  cert. The requesting device/agent supplies only its device pubkey. *(This is
  load-bearing: if an agent could name its own holder, it would request a
  colliding id and inherit another holder's warrants — the isolation bug in a
  new dress.)*
- The IdP that issues the device cert treats `holder` as **opaque passthrough**:
  it signs it verbatim and **copies it into the access cert at mint**. So even a
  primary IdP (e.g. mingo.place) learns nothing about your holder structure.
- browserid.me privately maps holders into user-organized **namespaces**
  (`browsers` / `agents` / `services` / …) with friendly labels ("Main Laptop").
  The namespace is encoded as a **randomized** dot-separated prefix in the id
  (e.g. `<rand-ns>.<rand-holder>`), so an id looks like `k3n9.q7f2x1` — the
  *structure* (which holders share a namespace) is visible for wildcard
  matching, but the *labels* and cross-user correlation are not.

Everything is attributed to **you** (the identity/email). The holder says *which
of your things* is acting, opaquely. There are no separate agent identities and
no cross-identity delegation — an agent is *you, through a holder you
authorized*.

### Warrants

A warrant grants `(holder-matcher) → (audience, scopes)`. The matcher has three
forms, spanning the reuse↔isolation axis:

| Matcher | Meaning | Use | Structure leak |
|---|---|---|---|
| `holder: *` | any of your holders | **logins** — device-agnostic reuse | none |
| `holder: <ns>.*` | any holder in a namespace | "all my browsers/agents" | the namespace prefix |
| `holder: <id>` | one specific holder | a single service you want isolated | none |

The RP verifies the presented access cert's `holder` against the warrant's
matcher (equality, prefix, or wildcard) — a trivial string check, no new crypto.

This is the whole point: **the user picks reuse vs isolation per grant.**

- **Logins use `*`.** A trusted device (one that holds a config cert) signs one
  `* → W, login` warrant and registers it. A **less-trusted device with only a
  user cert** (config cert withheld for least privilege) can then log into W by
  fetching that `*` warrant + the trusted device's config cert from the registry
  (both public), minting its own access cert, and presenting — the RP accepts
  because `*` matches any holder. Logging into a *new* site needs a *new*
  warrant → needs a config cert → the less-trusted device can't → blocked. That
  device-agnostic-reuse-but-not-new-audiences property is exactly the
  config-cert-withholding model, and it falls out for free.
- **A specific service uses `holder: <id>`.** Isolated: service 2 cannot present
  service 1's warrant (its access cert carries a different, unforgeable holder,
  since the mint copies the device cert's id and the agent cannot choose it).
- **A category uses `holder: <ns>.*`.** "All my browsers → W" or "all my agents
  → X" without enumerating them, and it keeps covering holders you add later.

### `subject` is removed

The human/agent distinction becomes **private account metadata** (the namespace)
and is never an RP-facing cryptographic claim. RPs that genuinely need
human-vs-agent must use a real independent attestation — orthogonal to this
protocol and out of scope here. (Our guestbook "agents-only" demo was always
relying on a self-asserted hint; it becomes advisory or drops the restriction.)

## Security properties

- **Isolation (fixes bug 1):** a `holder: <id>` or `<ns>.*` warrant cannot be
  used by a holder outside the id/namespace, because the holder id is
  IdP-attested inside the signed access cert and the requesting agent cannot
  forge or choose it. The two conformance rules that make this hold:
  1. the broker (not the requester) assigns the holder at issuance;
  2. the IdP signs it verbatim and copies device→access at mint.
  A buggy IdP that violates (2) breaks isolation *among your own agents* — a
  conformance failure, not a boundary against your (already fully trusted) IdP.
  browserid.me can monitor an IdP's minting and warn if it mints over-broad
  (holder-less / wildcarded) access certs.
- **No durable brand gatekeeping (the anti-competitive worry):** RPs see
  opaque, per-user-randomized holder ids, never brands. The most an RP can do is
  **guess-and-block** a namespace prefix ("these look like bots"); the user
  **re-categorizes** (new randomized namespace → re-issued device cert +
  warrants) and is out, forcing the RP to re-fingerprint. Gatekeeping is a
  cat-and-mouse the user can always escape, not a wall — the property that
  actually mattered.
- **Accepted leak:** a structured (namespaced) holder id reveals its namespace
  prefix on *every* action, so an RP can cluster your holders by namespace
  (not label). Accepted as manageable given the escape hatch above. A future
  opt-in reduction (browserid.me-signed "holder ∈ ns" revealed only on
  wildcard use, keeping the flat id opaque otherwise) is possible but not worth
  it now.
- **Per-audience holder derivation** (blinding the id per RP to stop cross-RP
  correlation of *which* holder) was considered and **dropped**: it forces the
  mint to be audience-aware, and the identity/email is already the dominant
  cross-RP linkage, so it buys little.

## Account UI (browserid.me/account)

- Default namespaces `browsers`, `agents`, `services`; new device certs create a
  new entry under one (auto-created for a browser at login), renameable to a
  friendly label — editing the DB row, never the opaque token.
- **Adopt-after-wipe:** a holder id is a *user-managed logical slot*, not a key.
  A device that lost its keystore can be re-issued a device cert bound to an
  *existing* slot ("this is Main Laptop again"), so its warrants survive the
  re-key. Re-keying is the user re-authorizing their own slot — fine, because
  the unforgeability we need is against third parties, not against you.
- **Re-categorize:** move a holder to a new namespace (new randomized prefix) to
  escape an over-broad RP block; re-issues the device cert + affected warrants.

## What this changes to build

- **`browserid-core`**: `DeviceCert` / `AccessCert` gain a required `holder`;
  `Warrant` claims gain the holder-matcher (`*` / `<ns>.*` / `<id>`); drop
  `Subject`; `AccessPresentation::verify` checks holder-match instead of
  subject-equality.
- **Broker**: `/device/issue` + the fallback + primary device-authorize accept a
  broker-assigned holder; `/access/mint` copies it; account holder-registry
  (namespaces, labels, adopt, re-categorize); consent/warrant issuance targets a
  matcher; login warrants default to `*`.
- **Registrar / warrant flow**: matcher in the warrant request + registry;
  wildcard/namespace grants; per-holder issuance where isolation is chosen.
- **sbo**: `authorize` keys off `owner == attributed identity` (unchanged —
  owner stays *you* for both A and D); `device_attribution` surfaces the holder
  if useful; no `subject`.
- **D (mingo-poster)** builds on this: the poster is a holder in your `services`
  (or per-service) namespace, warranted `(<its holder>) → sbo-db, [scopes]`;
  writes are owned by *you*, attributed to *you*, isolated per service.

## Deferred / out of scope

- Real human-vs-agent gating (independent attestation) — orthogonal.
- Merkle set-commitment warrants (compact hidden-set matcher) and ZK category
  credentials (auto-future-coverage without re-issue) — future options if the
  per-holder / prefix-wildcard approach ever proves insufficient.
- Per-audience holder blinding — dropped (see above).
