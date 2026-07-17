# +label Self-Delegation Agent Certificate — Design Spec & Change Inventory

Status: DESIGN (no production code). Author: agent for team-lead / dan.
Date: 2026-07-17.
Roadmap: item 4 of epic `browserid-ng-mr2n` (CLI-auth / agent identities for
external-primary IdP users). Bean `browserid-ng-u7t8`. Chosen by dan over item 3
(`browserid-ng-pv9b`, browserid.me-rooted agent).

This is a specification and a precise, file:function-level change inventory. It
does **not** implement anything. It builds directly on the two exploration
verdicts in `browserid-ng-u7t8` and `browserid-ng-pv9b`; where those already
located a line, this doc cites it and does not re-derive.

---

## 1. Motivation & the problem being solved

A user whose home IdP (`sandmill.org`) is a **classic primary** — it publishes
`_browserid.sandmill.org` and serves `/.well-known/browserid` with interactive
`provisioning`, but has **no agent-mint endpoint** (`/provision/mint` → 404, no
`/agents`, it is not a `browserid-broker`) — cannot today obtain a CLI agent
identity. `mingo login as danmills@sandmill.org` fails at the agent mint with
"IdP rejected the request (404)" (bug `browserid-ng-3nsg`). There is no
agent-mint endpoint anywhere for a `sandmill.org`-rooted delegator, because the
browser roots a primary's `U_cert` at the primary's own IdP, and browserid.me
cannot substitute (broker mint requires `verified.issuer == state.domain`).

Item 4 removes the dependency on any IdP mint: the user's **existing**
`danmills@sandmill.org` identity key self-issues a name-constrained agent
certificate for `danmills+<label>@sandmill.org`. No sandmill.org cooperation, no
browserid.me hosting of the identity. Generalizes to any primary.

### Why this needs real work (not a free cheat)

The `browserid-ng-u7t8` verdict established that the `+` convention **cannot**
cheat past the core requirement that the agent leaf cert be signed by the IdP's
DNSSEC domain key. That requirement is enforced **independently in two
security-critical verifiers**:

- browserid-core: `assertion.rs` (`verify` / `check_structure`) + `warrant.rs`
  (`verify_for`) — the chain roots at the domain key, and the warrant's embedded
  parent-cert must verify under that same domain-issuer key
  (`warrant.rs:189-196`).
- sbo-core `attribution.rs` (`verify_attribution_with_warrant` /
  `extract_provider_key`) — independently re-verifies the agent cert against the
  `_browserid.<iss>` DNSSEC key.

So making a self-issued `danmills+label@sandmill.org` cert verify requires
**adding a new, constrained trust path** in both codebases. This spec defines
that path so it is an *addition* alongside the existing domain-signed path,
never a weakening of it.

---

## 2. The new certificate chain shape

Today an agent presentation is a single agent leaf cert (domain-signed) plus a
warrant whose embedded `parent-cert` is domain-signed:

```
[ agent_cert(domain-signed) ] ~ warrant(parent-cert: U_cert domain-signed) ~ assertion
```

The self-delegation chain introduces one intermediate link — the base identity
cert — and shifts who signs the agent leaf:

```
domain key (sandmill.org, via _browserid DNSSEC)
  └─signs→  BASE identity cert   principal = danmills@sandmill.org       (domain-signed, SHORT-LIVED)
              └─signs→  AGENT cert   principal = danmills+mingo-cli@sandmill.org   (IDENTITY-signed)
                          typ = browserid-agent-cert-v1
                          agent.parent = danmills@sandmill.org
                          status = <browserid.me status ref>   ← per-agent revocation
```

Presentation is self-contained (the base cert travels inside the presentation,
exactly as a warrant embeds its `parent-cert`):

```
[ base_cert(domain-signed) , agent_cert(identity-signed) ] ~ warrant(parent-cert: base_cert) ~ assertion
```

The base cert is domain-signed and **fresh** (short-lived, refreshed by the
human re-authenticating to sandmill.org). Because verifiers check the whole
chain, the freshness of the base cert is the primary revocation lever (§6).

### 2.1 The +label name constraint (the security core)

An agent cert MAY be signed by an identity cert's key **instead of** the domain
key **iff**:

- the agent principal local-part is exactly `<base>+<label>` for some non-empty
  `<label>` with no further `@`; **and**
- `<base>@<domain>` equals the signing base identity cert's `principal.email`;
  **and**
- the agent principal `<domain>` equals the base cert `<domain>` (same domain);
  **and**
- the agent cert's `iss` equals the base cert's `iss` (same issuer domain).

This is X.509 name-constraint style: holding `danmills`'s key lets you mint
`danmills+anything@sandmill.org`, but **not** `bob@sandmill.org`, **not** a bare
second `danmills@sandmill.org`, and **not** `danmills+x@other.org`. The
existing (unconstrained, domain-signed) agent path is untouched: a domain can
still mint any agent name it likes; only the *identity-signed* path is
constrained to the `+label` subaddress of the signer.

### 2.2 The self-delegation verification algorithm (ordered checklist)

A verifier presented with an identity-signed agent leaf runs, in order:

1. **Parse** the presentation. Recognize the two-cert chain `[base, agent]`
   where `agent.is_agent()` and `base` is plain (email principal, non-agent).
2. **Distinguish the path.** The agent cert declares it is identity-signed (see
   §3.1, `sig` / `chain` marker). If absent → this is the classic domain-signed
   agent path; run the existing rules unchanged. If present → run steps 3–8.
3. **Base cert is domain-signed and fresh.** `base.iss` == `base` principal
   domain; `base.verify(domain_key)` under the DNSSEC domain key for that
   domain; `!base.is_expired()` (freshness — this is a *hard* expiry check for
   the base cert, unlike the warrant's signing-time-only parent-cert; see §6.1).
4. **Agent leaf signed by the base key.** `agent.verify(base.public_key())`.
5. **+label name constraint** (§2.1): parse `agent` principal as
   `<local>+<label>@<domain>`; require `<local>@<domain> == base.principal`;
   require non-empty `<label>` and exactly one `+` split point (first `+`);
   require `agent.iss == base.iss == <domain>`.
6. **agent.parent binding.** `agent.agent_parent()` == `base.principal.email`
   (`danmills@sandmill.org`). (The `+label` agent acts *as* its base.)
7. **Status ref present.** The identity-signed agent cert MUST carry a `status`
   ref whose origin is a recognized status authority (browserid.me by default,
   §6.2). Unlike the domain-signed path (which pins to `registrar`), the
   self-issued path pins revocation to the status authority the base identity
   chose at self-issuance.
8. **Warrant** (agent presentations only): run the existing warrant checks
   (§4) with the *base cert* as the parent-cert, verified under the domain key.

Only if all pass is the presentation accepted, attributed to the agent identity
with `agent.parent = danmills@sandmill.org`.

---

## 3. Certificate format additions

Extends the existing `Certificate` / `CertificateClaims` in
`browserid-core/src/certificate.rs`. Today an agent cert is `typ =
TYP_AGENT_CERT` (`"browserid-agent-cert-v1"`), an `agent: AgentClaims { parent }`
block, an optional `registrar`, and an optional `status` (§6.4 fast-revocation).
The certificate is always domain-signed; nothing in the claims records *who*
signed it — the verifier supplies the key.

Two things the self-issued cert must additionally declare:

### 3.1 (a) "I am identity-signed, not domain-signed"

The self-issued agent cert must be self-describing so a verifier picks the
constrained path (step 2 above) without guessing. Options, in preference order:

- **Preferred: a distinct `typ`.** Add
  `TYP_SELF_AGENT_CERT = "browserid-self-agent-cert-v1"` alongside
  `TYP_AGENT_CERT`. The existing fail-closed `Certificate::parse` matcher
  (`certificate.rs:223-241`) rejects unknown `typ`s — so old verifiers reject
  self-issued certs (correct: they can't check the constrained path). New
  verifiers accept both `typ`s and branch on which. This is the cleanest
  fail-closed signal and reuses the existing typ machinery.
- **Alternative: a claim on the existing agent typ** (e.g. `sig: "identity"`
  vs the implicit `"domain"`). Lighter, but a predating verifier would silently
  treat it as a normal (domain-signed) agent cert and try to verify the leaf
  against the domain key — which fails closed anyway, but less legibly. The
  distinct `typ` is safer.

A self-issued agent cert therefore carries: `typ = TYP_SELF_AGENT_CERT`,
`agent = { parent: <base email> }`, `status = <authority ref>` (required),
and **no** `registrar` (registrar is the domain-signed concept). The base cert
is a plain cert produced by the existing `Certificate::create` (unchanged).

### 3.2 (b) Its status / revocation URI

Reuse the existing `status: Option<StatusRef>` field (`certificate.rs:99-100`,
`StatusRef { uri, idx }`). For a self-issued cert `status` is **mandatory** and
its `uri` origin is the status authority (browserid.me) the base identity chose.
This is the per-agent revocation anchor that the `u7t8` verdict flagged as
missing for self-signed certs — §6 defines the service that honors it.

### 3.3 New constructor

`Certificate::create_self_agent(base_cert, agent_email, base_key, validity,
status_authority) -> Certificate`: asserts the `+label` constraint at creation
(`agent_email` == `<base_local>+<label>@<base_domain>`), sets `typ =
TYP_SELF_AGENT_CERT`, `agent.parent = base_cert.principal.email`, `status =
<ref at status_authority>`, signs with `base_key` (the base identity's key, not
a domain key). Mirrors `create_agent` / `create_agent_with_status`
(`certificate.rs:164-207`).

---

## 4. Composition with the existing warrant

The warrant model (`warrant.rs`) is **almost** unchanged: the warrant still
delegates authority to the agent identity, embeds the delegator's cert as
`parent-cert`, and is signed by the delegator's identity key. For self-delegation
the delegator *is* the base identity, so the warrant's `parent-cert` is the
**base cert** (domain-signed), and the warrant is signed by the base key — the
same key that signed the agent leaf.

What must change in `Warrant::verify_for` (`warrant.rs:178-278`):

- **Step 1 issuer match (`warrant.rs:189-195`)**: today it requires
  `parent.issuer() == agent_cert.issuer()`. This still holds for self-delegation
  (base and agent share the domain), so **no change** — but confirm the check is
  against the *base* cert now embedded, which it is.
- **Step 3 delegator consistency (`warrant.rs:214-233`)**: `warrant.iss ==
  parent_email == agent_cert.agent_parent()`. For self-delegation
  `agent.parent = danmills@sandmill.org = base principal = warrant.iss` — holds
  with **no change**.
- **Step 6 revocation authority (`warrant.rs:254-275`)**: today it requires the
  agent cert to name a `registrar` and pins the warrant's `status` origin to
  that registrar. A self-issued cert has **no** `registrar` — it has a `status`
  authority instead. This branch MUST be generalized: for a self-issued agent
  cert, pin the warrant's status origin to the **cert's status authority**
  (browserid.me) rather than to `registrar`. (Equivalently: "the revocation
  authority is `registrar` for domain-signed agents, `status.uri` origin for
  self-issued agents.")

The `Warrant::create` guard "an agent identity cannot be a delegator"
(`warrant.rs:114-116`, `186-188`) is unaffected: the base cert is a plain
identity cert, a valid delegator; the agent cert still cannot delegate onward.

Role/owner matching in SBO is **already solved** (per the `u7t8` verdict): the
daemon's `as:` path resolves the effective author to the base email
(`danmills@sandmill.org`) via `authorize.rs::warrant_effective_email`, so
`roles.admin = ["danmills@sandmill.org"]` matches a `+label` agent write with
**zero canonicalization changes**. This spec does not touch role matching.

---

## 5. Revocation design

Two mechanisms, matching dan's confirmed model. The primary (`sandmill.org`)
stays **dumb** — no revocation infrastructure is added there.

### 6.1 Chain revocation (expiry-driven, no CRL at the primary)

Verifiers check the whole chain, so **not renewing the base
`danmills@sandmill.org` cert instantly invalidates every `+label` agent** under
it. Because the base cert is **short-lived** and re-minted only when the human
re-authenticates to sandmill.org, this is expiry-driven: stop re-authing → the
base cert lapses → all self-issued agents die at the next base-cert expiry
window. This is why step 3 of the verification algorithm (§2.2) treats the base
cert with a **hard** `is_expired()` check (unlike the warrant's parent-cert,
which uses signing-time-only semantics for its 90-day lifetime). No CRL is
required at the primary. Blast radius of a base-key compromise is exactly "all
of that base's `+label` agents" — intended and bounded by the base cert's short
life.

Spec the base-cert validity short (e.g. hours, matching the existing 24h agent
cert / `U_cert` cadence in `warrant.rs` tests) and require the client to embed a
**fresh** base cert at presentation time (re-fetching by re-auth as needed).

### 6.2 Per-agent revocation (browserid.me status authority)

For revoking **one** `+label` agent without waiting for base-cert expiry, the
self-issued agent cert **bakes in** a `status` ref (§3.2) pointing at a status
authority the base identity chose — browserid.me by default. browserid.me:

- **Registers** a status subject for each self-issued cert (an index allocated
  under a status list the owner controls). See open question OQ-1 on how the
  base identity registers the subject before first use.
- **Publishes a signed status list** at a well-known URI (reuse the existing
  `/.well-known/browserid-status`-style list the registrar already publishes for
  warrants — same `StatusRef { uri, idx }` shape). Verifiers fetch it, honor a
  revoked bit after a cache/TTL window.
- **Exposes a revoke control at `/account`** (browserid-broker
  `static/account.html`). The authenticated owner (danmills, proven via a
  **normal browserid assertion to browserid.me as an RP** — no special auth)
  revokes a specific agent by flipping its status bit.

Cache/TTL: verifiers cache the signed status list for a bounded window (spec a
default, e.g. minutes-to-an-hour, matching how RPs treat warrant status today);
revocation takes effect after the window. This keeps verification offline-capable
between refreshes.

For **SBO specifically**, on-chain revocation is available as an alternative
anchor (the daemon can read a revocation record from the wire), but the
browserid.me-hosted status list is the chosen default.

---

## 6. Security analysis

- **The name constraint is sound.** The identity-signed path only ever certifies
  `<base>+<label>@<domain>` where `<base>@<domain>` is the signer's own verified
  principal and `<domain>` matches. Holding `danmills`'s key confers authority
  over `danmills`'s subaddress namespace and nothing else — it cannot mint
  `bob@`, cannot mint a second bare `danmills@`, cannot cross domains. This
  mirrors RFC 5233 plus-addressing, where `danmills+x@` already routes to
  `danmills@`, so treating the base as authoritative over its `+label` space
  matches deployed email semantics.
- **It ADDS a path, it does not weaken the domain path.** The domain-signed
  agent flow (`create_agent`, verified against the DNSSEC domain key) is
  untouched. A verifier reaches the constrained path **only** for the new
  `TYP_SELF_AGENT_CERT`; everything else still requires the domain key. Old
  verifiers fail closed on the new typ (§3.1).
- **Blast radius.** Base-key compromise = all of that base's `+label` agents
  (intended, §6.1); it does **not** extend to other users or to non-`+label`
  identities at the domain. Domain-key compromise is unchanged (still the root
  of trust; already catastrophic in the existing model).
- **Interaction with per-warrant status.** The existing warrant status
  (`warrant.rs:254-275`) still governs per-grant revocation and is pinned — now
  to the cert's status authority instead of `registrar` for self-issued certs
  (§4). So there are two independent revocation levers: per-agent (cert status,
  §6.2) and per-grant (warrant status). The per-agent lever is the new one this
  design adds; the per-grant lever is unchanged in mechanism, only re-pinned.
- **Two-verifier consistency.** Because attribution is re-verified independently
  in sbo-core, the constrained path must be implemented identically in both
  browserid-core and sbo-core, or an agent write could verify in one and not the
  other. This is the main correctness risk and the reason the change touches two
  repos (§7).

---

## 7. Change inventory (EXISTS vs NEW, file:function, size)

### browserid-core (`/Users/thunder/src/browserid-ng/browserid-core`)

- **`certificate.rs`** — MEDIUM.
  - NEW const `TYP_SELF_AGENT_CERT` (near `TYP_AGENT_CERT`, line 16).
  - EXISTS→EXTEND `Certificate::parse` matcher (`certificate.rs:223-241`): add
    the `(Some(TYP_SELF_AGENT_CERT), true)` accepting arm; keep fail-closed on
    everything else.
  - NEW `Certificate::create_self_agent[_with_status]` (mirrors `create_agent`,
    `certificate.rs:164-207`), enforcing the `+label` constraint at creation and
    signing with the base key.
  - NEW accessors: `is_self_agent()`, and a helper to parse
    `<base>+<label>@<domain>` (base email + label). Small.
- **`assertion.rs`** — MEDIUM/LARGE (security-critical).
  - EXISTS→EXTEND `verify` (`assertion.rs:295-392`) and the multi-cert chain
    branch (`assertion.rs:349-371`, which already verifies each cert against the
    previous cert's key — the hook the `u7t8` verdict flagged). Add: recognize
    the `[base, self_agent]` chain; run the §2.2 checklist (base domain-signed &
    fresh, agent signed by base key, `+label` constraint, parent binding, status
    presence). Route the warrant verification (`assertion.rs:376-386`) to use the
    base cert as parent and the domain key as issuer key.
  - EXISTS→EXTEND `check_structure` (`assertion.rs:250-271`): allow a
    self-issued agent leaf preceded by exactly one plain base cert; keep the
    "agent cert must be the leaf" and "warrant required for agent leaf" rules.
- **`warrant.rs`** — SMALL.
  - EXISTS→EXTEND `verify_for` step 6 (`warrant.rs:254-275`): generalize the
    revocation-authority pin — `registrar` for domain-signed agents, `status`
    origin (the cert's status authority) for self-issued agents. Steps 1/3
    (`warrant.rs:189-195`, `214-233`) confirmed to need **no** change.

### sbo-core (`/Users/thunder/src/sbo/crates/sbo-core`)

- **`attribution.rs`** — MEDIUM/LARGE (security-critical, mirrors browserid-core).
  - EXISTS→EXTEND `verify_attribution_with_warrant` (`attribution.rs:~355-424`)
    and `verify_attribution_with_provider_key` (`attribution.rs:520+`): today it
    verifies the agent cert against the DNSSEC domain key via
    `extract_provider_key`. Add the identity-signed branch: when the leaf is
    `TYP_SELF_AGENT_CERT`, verify the **base cert** against the domain key (via
    the existing `extract_provider_key` path) and the **agent leaf** against the
    base cert's key, then apply the `+label` constraint + parent binding. The
    cross-issuer plumbing already present (`warrant_delegator_issuer`,
    `delegator_evidence`) is reused for the base-cert domain proof.
  - EXISTS→EXTEND `verify_warrant_with_provider_key` (`attribution.rs:248-337`):
    the warrant's `parent-cert` is now the base cert; the existing bindings
    (`warrant.agent() == agent_email`, `warrant.delegator() ==
    agent.parent == parent-cert principal`) already hold. Confirm the
    signing-time window checks (`attribution.rs:~322-333`) apply against the
    base cert. The self-issued cert carries no `registrar`, so if any
    registrar-pin logic exists here it needs the same generalization as
    browserid-core §4.
  - NOTE: the daemon's `as:`/effective-author resolution
    (`authorize.rs::warrant_effective_email`, `validate.rs::resolve_creator`)
    needs **no change** — it already collapses `+label`/agent to the base email
    and matches `roles.admin` (per `u7t8` verdict).

### browserid-broker / registrar — MEDIUM (the browserid.me status-authority service)

- **NEW service: status authority for self-issued certs** (browserid-broker
  routes + registrar store). Register a self-issued cert's status subject,
  publish the signed status list (reuse the existing warrant status-list
  publisher — same `StatusRef` shape and `/.well-known/browserid-status` URI),
  and add a `/account` revoke control.
- **`browserid-broker/static/account.html`** — SMALL/MEDIUM: the revoke control
  UI for self-issued agents (list the owner's self-issued agents + a revoke
  button). NOTE: editing broker inline scripts requires updating
  `INLINE_SCRIPT_HASHES` in `routes/mod.rs` (see repo memory `csp-inline-script-hashes`).
- **Owner auth for revoke**: no new auth — a normal browserid assertion to
  browserid.me as an RP proves the owner; the revoke endpoint checks the asserted
  email owns the status subject.

### browserid-agent SDK + mingo — MEDIUM

- **`browserid-agent/src/lib.rs`** (`AgentIdentity` / provisioning path,
  around the `provision` / cert-refresh flow): NEW self-issue path — instead of
  POSTing `{idp}/provision/mint` (the call that 404s for sandmill.org), the
  client takes the human-approved base credential, self-issues the `+label`
  agent cert with the base key (`create_self_agent`), registers the status
  subject at browserid.me, embeds the **fresh** base cert, and persists the
  bundle. `mingo login --idp` (the mint) becomes unnecessary for this path.
- **`sdk/agent`** (TS SDK, README documents `provision` / cert refresh at
  `{idp}/provision/mint`): mirror the self-issue path for JS clients if parity
  is wanted (can defer).
- **mingo `mingo-app/src/login.rs`** (`/Users/thunder/src/mingo/mingo-app`):
  replace the failed-mint fail-fast (commit c88d23e, from `browserid-ng-3nsg`)
  with the self-issue flow when the home IdP lacks agent provisioning; pass the
  CLI label hint (roadmap item 7) as `<label>`.

### Size summary

| Piece | Size | Risk |
|---|---|---|
| browserid-core `certificate.rs` | Medium | Low |
| browserid-core `assertion.rs` | Medium/Large | High (security-critical) |
| browserid-core `warrant.rs` | Small | Medium |
| sbo-core `attribution.rs` | Medium/Large | High (must mirror core exactly) |
| broker/registrar status authority | Medium | Medium |
| `account.html` revoke UI | Small/Medium | Low (CSP hash gotcha) |
| agent SDK + mingo self-issue | Medium | Medium |

---

## 8. Open questions

- **OQ-1 (status-subject registration).** How does the base identity register a
  self-issued cert's status subject at browserid.me *before* first use, without
  browserid.me having minted anything? Likely: the owner authenticates to
  browserid.me as an RP (normal assertion) and pre-allocates a status index /
  list that the client then embeds in `create_self_agent`. Defines whether
  self-issuance can be fully offline or needs one online registration step.
- **OQ-2 (status-URI trust / pinning).** Must a verifier *trust* the status
  authority named in a self-issued cert, or accept any origin? Proposal: pin to
  a small allowlist (browserid.me by default; on-chain for SBO), so a compromised
  base key cannot point revocation at an attacker-controlled always-"valid"
  status list. Needs a decision on how the allowlist is configured per verifier.
- **OQ-3 (base-cert refresh cadence at presentation).** Exact base-cert
  validity and how aggressively the client must re-fetch a fresh base cert. Too
  short → constant re-auth friction; too long → slow chain revocation. Suggest
  matching the existing 24h agent/U_cert cadence but confirm against the CLI UX.
- **OQ-4 (self-describing marker choice).** Distinct `typ`
  (`TYP_SELF_AGENT_CERT`, preferred, §3.1) vs a `sig` claim on the existing agent
  typ. Distinct typ is fail-closed-legible; confirm no downstream consumer
  enumerates agent certs solely by `TYP_AGENT_CERT` in a way the new typ would
  silently skip.
- **OQ-5 (two-verifier drift).** How to keep the browserid-core and sbo-core
  implementations of the constrained path provably in sync (shared test vectors?
  a shared verification helper in browserid-core that sbo-core calls?). This is
  the top correctness risk (§6).
- **OQ-6 (RPs that treat `x+label@d` as distinct).** A web RP that keys accounts
  on the full email would see `danmills+mingo-cli@sandmill.org` as a different
  principal than `danmills@sandmill.org`. For SBO this is resolved by the `as:`
  path; for generic web RPs, note it as a caveat (the `+label` agent is a
  distinct principal unless the RP canonicalizes).
```
