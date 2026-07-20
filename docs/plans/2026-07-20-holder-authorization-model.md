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

A third constraint shapes the fix. We want to issue warrants that apply to **one
specific holder** (an agent/service/browser) *or* to a **category**, while
keeping those categories **opaque to RPs** — so an RP cannot ban a whole
category it dislikes (e.g. agents competitive with it) under a safety pretext.
Distinguishability that enables *warrant isolation* is the same
distinguishability that enables *RP gatekeeping* — they are one lever, so the
design places it deliberately. Note the constraint is that the fix must not
*require* disclosure of a holder's category to RPs; a user who *wants* to
disclose ("this is my agent") is free to, but that is voluntary and out of scope
here.

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
- **The broker mediates *all* device-cert issuance — including the primary-IdP
  flow.** Even when a primary IdP (sandmill.org, mingo.place) is the one that
  signs the device cert for its own identity, the request routes through the
  broker so the broker assigns the holder. This is needed independently of this
  change: the broker must have a record of every device cert issued for a user
  so that **revocation is initiated from the broker's UI** (the CRL itself may
  live on the issuing IdP, but the user manages revocation centrally). Without
  broker mediation the primary flow would be a hole where the requester (or the
  primary IdP) picks the holder — reopening the isolation bug. *(This closes the
  seam the browser-signing §3 bug lives in: the deferred-handle provisioning
  must go through the broker.)*
- The IdP that issues the device cert treats `holder` as **opaque passthrough**:
  it signs it verbatim and **copies it into the access cert at mint**. So even a
  primary IdP (e.g. mingo.place) learns nothing about your holder structure
  beyond the opaque id the broker handed it.
- **Format:** `holder` is a single **opaque string**, spec-capped at a generous
  length (≈64–128 bytes) to leave room for other broker implementations. The
  reference broker structures it as `<rand-ns>.<rand-holder>` (≈4-byte namespace
  + 8-byte holder), expecting ~3–5 namespaces × ~1 holder each ≈ 30–100 holders
  per user — but that structure is a *broker convention*, not part of the wire
  spec. RPs and IdPs treat the whole string as opaque; only the `<ns>.*` matcher
  reads the dot-prefix.
- browserid.me privately maps holders into user-organized **namespaces**
  (`browsers` / `agents` / `services` / …) with friendly labels ("Main Laptop").
  The namespace is encoded as a **randomized** dot-separated prefix in the id
  (e.g. `<rand-ns>.<rand-holder>`), so an id looks like `k3n9.q7f2x1` — the
  *structure* (which holders share a namespace) is visible for wildcard
  matching, but the *labels* and cross-user correlation are not. The prefix is
  stable per-user-per-namespace under normal use; **re-categorizing** (§Account
  UI) rotates it to a fresh random value — a manual escape hatch a user can
  invoke if an RP starts prefix-banning. We don't build automatic rotation.

Everything is attributed to **you** (the identity/email). The holder says *which
of your things* is acting, opaquely. There are no separate agent identities and
no cross-identity delegation — an agent is *you, through a holder you
authorized*.

### Warrants

A warrant grants `(holder-matcher) → (audience, scopes)`. The matcher has three
forms, spanning the reuse↔isolation axis:

| Matcher | Meaning | Use | Structure leak |
|---|---|---|---|
| `holder: *` | any of your holders | reserved (spec-legal, broker-forbidden) | none |
| `holder: <ns>.*` | any holder in a namespace | logins ("all my browsers"), "all my agents" | the namespace prefix |
| `holder: <id>` | one specific holder | a single service/agent you want isolated | none |

The RP verifies the presented access cert's `holder` against the warrant's
matcher (equality, prefix, or wildcard) — a trivial string check, no new crypto.

**Bare `*` is spec-legal but the reference broker refuses to issue it.** A
warrant any holder can present is a bearer-ish token, and we don't have a use
for it today; the spec keeps it defined for a possible future need, but
browserid.me will only issue `<ns>.*` and `<id>` matchers.

This is the whole point: **the user picks reuse vs isolation per grant** — but
the *broker recommends* the matcher and the user approves or modifies it in the
consent UI; the RP never dictates it. First-pass broker defaults:

- **Website logins → `browsers.*`** (a namespace matcher over your browsers), so
  you can sign into an already-warranted site from another machine/browser
  without minting a new warrant.
- **Agents / services → `<id>`** (isolated per holder), so each one gets a narrow
  warrant only for itself.
- *(CLI tools sit between these — a user might authorize a whole service's CLI
  access, or one specific instance. Deferred; build with the two defaults above.)*

- **Logins use `browsers.*`.** A trusted device (one that holds a config cert)
  signs one `browsers.* → W, login` warrant and registers it. A **less-trusted
  device with only a user cert** (config cert withheld for least privilege) can
  then log into W by fetching that warrant + the trusted device's config cert
  from the registry (both public), minting its own access cert under a holder in
  `browsers.*`, and presenting — the RP accepts because the holder matches the
  prefix. Concretely: **browser 1 logs into site A and creates the warrant;
  later browser 2 (provisioned with only a login-capable user cert, no config
  cert) signs into site A with no new warrant**, because its holder is in
  `browsers.*`. Logging into a *new* site needs a *new* warrant → needs a config
  cert → the less-trusted device can't → blocked. That
  device-agnostic-reuse-but-not-new-audiences property is exactly the
  config-cert-withholding model, and it falls out for free.
- **A specific service uses `holder: <id>`.** Isolated: service 2 cannot present
  service 1's warrant (its access cert carries a different, unforgeable holder,
  since the mint copies the device cert's id and the agent cannot choose it).
- **A category uses `holder: <ns>.*`.** "All my browsers → W" or "all my agents
  → X" without enumerating them, and — deliberately — **it keeps covering
  holders you add later**: a browser/agent provisioned tomorrow is immediately
  covered by an existing category grant. That future-inheritance is the point,
  not a leak; it is what lets a freshly provisioned login-only device use grants
  made before it existed.

### `subject` becomes `holder`

We **replace the `subject` field with `holder`** rather than adding a new field
next to it: the old `subject: <user|agent>` meaning is removed completely, and
the slot's successor carries the opaque holder id (`<ns>.<id>`). The rename (not
just a repurpose) is deliberate — "subject" conventionally means "who the cert
is *about*", which in this model is the **identity/email**, so naming the holder
field `subject` would mis-signal to future readers. There is no backward-compat
to preserve (all serialization is our own), so the rename is free.

The human/agent distinction thus becomes **private account metadata** (the
namespace) and is never an RP-facing cryptographic claim. RPs that genuinely
need human-vs-agent must use a real independent attestation — orthogonal to this
protocol and out of scope here. (Our guestbook "agents-only" demo was always
relying on a self-asserted hint; it drops the restriction — see §Security /
Deferred.)

## Security properties

- **Isolation (fixes bug 1):** a `holder: <id>` or `<ns>.*` warrant cannot be
  used by a holder outside the id/namespace, because the holder id is
  IdP-attested inside the signed access cert and the requesting agent cannot
  forge or choose it. The two conformance rules that make this hold:
  1. the broker (not the requester) assigns the holder at issuance;
  2. the IdP signs it verbatim and copies device→access at mint.
  A buggy IdP that violates (2) breaks isolation *among your own agents* — a
  conformance failure, not a boundary against your (already fully trusted) IdP.
  *(Future, mechanism TBD: browserid.me could monitor an IdP's minting and warn
  if it mints over-broad (holder-less / wildcarded) access certs — but the mint
  happens at the IdP, so this needs a feedback path (IdP self-reports, or the
  broker audits registered certs) that isn't specced here. Not load-bearing for
  the isolation guarantee, which rests on the two conformance rules above.)*
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

This replaces much of the current `browserid.me/account` surface. Only the
*browser-vs-headless* axis is load-bearing (it sets the default matcher); the
`Agents`/`Services` split is cosmetic organization.

### Data model

- **Namespace** = (random prefix e.g. `k3n9`, friendly label "Browsers", set of
  holders). New accounts default to three: **Browsers**, **Agents**, **Services**.
- **Holder** = (opaque id `k3n9.q7f2`, friendly label "Main Laptop", device
  pubkey(s), certs). The id embeds the namespace prefix; the label is a plain DB
  row, never the opaque token.
- **Rename vs. re-categorize are different operations:** *rename* edits a label
  only (free; warrants keep matching). *Re-categorize* moves a holder to another
  namespace → rotates its prefix → new holder id → re-mints the device cert and
  re-issues affected warrants (heavy; a deliberate "escape an RP block" action,
  warned as key-rotating).

### Holder list

Grouped by namespace. Per device row: friendly label, **trust badge**
(`trusted` = holds a config cert, can authorize *new* sites; `login-only` = user
cert only, reuses existing warrants but can't create new-site logins — shown in
the first pass so "why can't my phone log into a new site?" is legible; the
grant/withhold *toggle* is deferred), last-used, warrant count.

- **No "add device" affordance** — users don't add devices; devices
  self-provision by signing in. The list only *reflects* devices.
- The current browser row is auto-annotated **"(this browser)"**.
- **Rename** available on every namespace *and* every device (inline).
- **Remove** available on namespaces (see edge cases: block if non-empty) and
  revoke on devices.
- **Clicking a device opens its warrants** (everything granted to that device) —
  this is the primary drill-down and replaces much of today's `/account` UI.

### New-device naming

An unknown device at login gets a default name (a couple of random words, e.g.
`quiet-otter-042`), renameable anytime. If it's actually an already-known
machine, the user uses the adopt flow to say "this is Main Laptop" instead.

### Provisioning / consent screen (new-holder gate)

Shown when a browser-external holder (agent/service/CLI) requests its first
device cert:

- **Name** (prefilled from the requester's hint, editable).
- **Category** — a `Agents`/`Services`/… dropdown prefilled from the requester's
  **untrusted hint**, user confirms/overrides. Cosmetic + correctable (see the
  agent/service reframe: nothing depends on getting it right).
- **Authorize** — the matcher control (labeled **"Authorize"**, *not* "Reuse"):
  defaults to isolated `<id>` ("only this service"), with `<ns>.*` available
  ("any of my Agents/Services"). For browser logins the equivalent defaults to
  `browsers.*` and is folded into the sign-in dialog.

### Warrant interface (two slices, as tabs)

Users reason in two directions, so the warrants view offers both:

1. **By device/holder** — "everything *this device* can do."
2. **By audience** — "everything that can act on *this site*" (all holders +
   matchers with a warrant for that audience).

Each warrant names its holder-or-namespace in friendly terms ("Browsers (any)"
for `<ns>.*`, the holder label for `<id>`), shows the raw matcher small, scopes,
created-at, and a revoke action; the holder label is inline-renameable here too
(this is where a badly-named holder gets noticed).

### Lifecycle / edge cases

- **Adopt-after-wipe:** a holder id is a *user-managed logical slot*, not a key.
  A device that lost its keystore can be re-issued a device cert bound to an
  *existing* slot ("this is Main Laptop again"), so its warrants survive the
  re-key — the unforgeability we need is against third parties, not against you.
  After a new login mints an orphan device, offer "actually this is an existing
  device →" to merge into the existing slot (else the list fills with dupes).
- **Re-categorize:** as above — move to a new namespace to escape an over-broad
  RP block; re-issues the device cert + affected warrants (heavy, warned).
- **Revoke a holder** cascades its warrants + device cert; confirm dialog lists
  what breaks.
- **Remove a namespace:** blocked while non-empty (revoke/move its holders
  first) — avoids a scary one-click cascade.
- **Dangling holder (0 warrants):** surfaced as "unused" so it's cleanable.
- **Lockout guard:** don't let a user revoke their only trusted (config-cert)
  device with no path back — see the open question below.

### Open: minting a config cert vs. a user cert

Today every login yields *both* a user cert and a config cert. The
config-cert-*withholding* model (trusted vs. login-only devices) needs a story
for **how a device gets a config cert**, and a **recovery path so a user can't
lock themselves out** of new-site authorization. Not yet designed. Sketch: if
granting a config cert is just an IdP-side checkbox, the user re-signs-in and
checks it; if it requires higher assurance (2FA), they satisfy that — but there
must *always* be a way to re-authenticate and obtain a config cert. Deferred
with the withhold *toggle*; the badge (read-only trust state) ships first.

## What this changes to build

- **`browserid-core`**: `DeviceCert` / `AccessCert` **rename `Subject` →
  `Holder`** (required, opaque string ≤128B); `Warrant` claims gain the
  holder-matcher (`*` / `<ns>.*` / `<id>`); `AccessPresentation::verify` checks
  holder-**match** (equality / prefix / wildcard) instead of subject-equality.
- **Broker**: mediates **all** device-cert issuance (`/device/issue`, the
  fallback, *and* the primary device-authorize path) so it assigns the
  broker-chosen holder and records the cert for revocation; `/access/mint`
  copies the holder verbatim; account holder-registry (namespaces, labels,
  adopt-after-wipe, re-categorize); consent/warrant issuance recommends a matcher
  the user approves/modifies; broker **refuses bare `*`**, defaults website
  logins to `browsers.*` and agents/services to `<id>`.
- **Registrar / warrant flow**: matcher in the warrant request + registry;
  wildcard/namespace grants; per-holder issuance where isolation is chosen.
- **sbo**: `authorize` keys off `owner == attributed identity` (unchanged —
  owner stays *you* for both A and D); `device_attribution` surfaces the holder
  if useful; no `subject`.
- **D (mingo-poster)** builds on this: the poster is a holder in your `services`
  (or per-service) namespace, warranted `(<its holder>) → sbo-db, [scopes]`;
  writes are owned by *you*, attributed to *you*, isolated per service.

### Build sequence

Each stage lands green (with the named checkpoint passing) before the next
starts — the dependency order is core → broker → registrar → sbo → D.

1. **core** — rename `Subject → Holder`, add the warrant matcher, flip
   `verify` to holder-match. *Checkpoint:* unit + conformance tests for
   holder-match (equality/prefix/wildcard) and a device→access **passthrough+copy**
   test (mint copies the holder verbatim); nothing downstream compiles against
   `Subject` anymore.
2. **broker** — broker-mediated issuance across all three paths (`/device/issue`,
   fallback, primary device-authorize) assigning the holder + recording the cert;
   `/access/mint` copies it; account holder-registry (namespaces, labels,
   adopt-after-wipe, re-categorize); consent recommends `browsers.*` / `<id>` and
   refuses bare `*`. *Checkpoint:* end-to-end broker test issuing a device cert
   with a broker-assigned holder, minting an access cert that carries it, and a
   login presentation verifying against a `browsers.*` warrant.
3. **registrar / warrant flow** — matcher in the warrant request + registry;
   wildcard/namespace grants; per-holder issuance where isolation is chosen.
   *Checkpoint:* register a `browsers.*` warrant and an isolated `<id>` warrant;
   verify service-2 cannot present service-1's `<id>` warrant.
4. **sbo** — `authorize` unchanged (`owner == attributed identity`);
   `device_attribution` on the holder, no `subject`. *Checkpoint:* device
   attribution verifies a holder-bearing presentation; guestbook agents-only
   restriction dropped.
5. **D (mingo-poster)** — poster as a warranted `<id>` holder in `services`.
   *Checkpoint:* live browser vs. server-side post both owned by + attributed to
   *you*, isolated per service.

## Deferred / out of scope

- Real human-vs-agent gating (independent attestation) — orthogonal.
- Merkle set-commitment warrants (compact hidden-set matcher) and ZK category
  credentials (auto-future-coverage without re-issue) — future options if the
  per-holder / prefix-wildcard approach ever proves insufficient.
- Per-audience holder blinding — dropped (see above).
