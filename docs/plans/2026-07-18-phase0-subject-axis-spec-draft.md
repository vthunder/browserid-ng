# Phase 0 draft — the `subject` axis + self-mode mint (spec deltas)

**Bean:** browserid-ng-i32c · **Epic:** oup3 · **Status:** draft for review before editing normative specs.

Vocabulary locked: **`subject: self | agent`**. `subjects` (allowed set) on the `Constraint`; `subject` (selected) on the request `R`; mint refuses `subject: self` unless the signed constraint grants the `self` subject.

This draft gives the concrete spec text for the *new primitive*. Once approved, it's applied to `docs/specs/agent-provisioning-and-grant-api.md` (§4.1, §4.3, §6.4) and `docs/specs/browserid-ng-protocol.md` (§7, §4.1, §9, §3.1).

---

## 1. `Constraint` becomes a typed capability descriptor (agent §4.1)

Today the constraint has `names` + `patterns` (which agent handles). We add a **`subjects`** axis (which *kinds* of identity the credential may mint) and a fail-closed rule.

**Proposed `P_cert` shape:**
```json
{
  "typ": "browserid-provisioning-cert-v1",
  "iss": "alice@domain.com",
  "iat": 1783600000,
  "exp": 1791376000,
  "public-key": { "algorithm": "Ed25519", "publicKey": "<P_pub>" },
  "constraint": {
    "subjects": ["agent"],           // NEW axis: which identity kinds
    "names": ["worker", "attestor2"],
    "patterns": ["dan+*"]
  }
}
```

**Proposed normative text (replaces the "Constraint (REQUIRED)" block, agent §4.1 lines 228-243):**

> **Constraint (REQUIRED).** A `P_cert` MUST carry a `constraint` — a typed
> capability descriptor bounding what the provisioning key may mint. An empty
> constraint (granting nothing) MUST be rejected. Axes:
>
> - **`subjects`** (REQUIRED, non-empty; a `P_cert` lacking `subjects` MUST be
>   rejected — there is no legacy default): the identity kinds the key may mint.
>   - `agent` — derived agent identities `<name>@<delegator-domain>` (§5.1),
>     scoped by `names`/`patterns` below.
>   - `self` — the delegator's **own** identity (`principal = iss`). Strictly
>     more powerful than `agent`: a `self` credential can act as the human
>     directly. It MUST NOT be granted implicitly; it is present only when the
>     delegator explicitly consented at credential creation (§4.x bootstrap).
> - `names`, `patterns` — as today; **apply only to the `agent` subject.** A
>   `self`-only credential MAY omit both (the `self` subject *is* its
>   authorization); a credential MUST still be non-empty overall.
>
> **Fail closed on unknown axes.** A verifier (registrar or IdP) that
> encounters a `constraint` axis, or a `subjects` value, it does not recognize
> MUST reject the credential — never ignore the field. This keeps the
> descriptor safely extensible: an older verifier refuses a newer capability
> rather than over-granting it.

## 2. Request `R` carries the selected `subject` (agent §4.1)

**Proposed `R` shape (self-mode):**
```json
{
  "typ": "browserid-provisioning-request-v1",
  "iat": 1783600000,
  "exp": 1783600600,
  "action": "mint",
  "subject": "self",               // NEW, REQUIRED: agent | self
  "domain": "domain.com",
  "agent-key": { "algorithm": "Ed25519", "publicKey": "<browser key>" },
  "ephemeral": false,
  "jti": "<128-bit nonce>"          // NEW for subject:self (OQ1)
}
```

**Proposed text (extends agent §4.1 request bullet, lines 260-266):**

> - **`subject`** (REQUIRED) ∈ `agent` | `self` — no default; a `mint` request
>   without `subject` MUST be rejected. For `subject:
>   agent`, `name` is REQUIRED (the handle to mint) and MUST be authorized by
>   the constraint's `names`/`patterns`. For `subject: self`, `name` MUST be
>   **absent** — the minted principal is the delegator's own `iss`; the request
>   MUST carry a `jti` (a fresh 128-bit nonce) and the IdP MUST reject a
>   replayed `jti` within the request's validity window (OQ1).
> - A mint request's `subject` MUST be a member of the `P_cert`
>   `constraint.subjects`, else the IdP/registrar MUST reject (`403`).

## 3. Self-mode mint semantics (agent §4.3)

**Proposed text (replaces "The minted certificate is an agent certificate…", §4.3 lines 353-357):**

> The minted certificate's shape depends on `R.subject`:
>
> - **`subject: agent`** (as today) — an **agent certificate** per §5.1
>   (distinct `typ`, `agent` block naming the delegator, `registrar` claim
>   copied from `E`). Counts against the delegator's agent quota.
> - **`subject: self`** — a **plain user certificate**: `typ` absent, no
>   `agent` block, no `registrar` claim, `principal.email = U_cert.principal`
>   (the delegator's real email), certified key = `R.agent-key` (the browser's
>   stable key). It is byte-indistinguishable from a cert issued by the
>   interactive login path, so every existing RP verifies it unchanged
>   (protocol §6). It does **not** consume the agent quota and does **not**
>   create an agent identity row.
>
> Before minting `subject: self`, the IdP MUST additionally verify: the
> `constraint.subjects` includes `self`; the `U_cert` is the IdP's own current
> issuance for `principal.email`; and the delegator email is verified and owned
> by the account (the same ownership guarantee the interactive path enforces).
> A credential lacking the `self` subject MUST NOT be able to mint a self cert
> under any request (`403`).

**Why this is safe (design note, not spec text):** the `self` subject is signed
into `P_cert` by the user's own key `U` at bootstrap. The IdP certifies
*identity* (`U_cert`); the user's key authorizes *scope* (`constraint`). So the
capability cannot be widened after the fact without re-signing with `U`, and an
agent-only credential is cryptographically incapable of self-minting.

## 4. Revocation = logout-everywhere (agent §4.6 + protocol §6.4)

> Revoking a provisioning credential (`P_cert`) at the registrar MUST (a) stop
> future endorsements for that `P_cert`, and (b) be reflected in a
> provisioning-credential status reference the IdP consults at mint time, so a
> stolen-but-revoked credential cannot continue minting fresh certs until
> `P_cert` expiry. For a `self` credential this is the durable "log out
> everywhere" control; already-issued certs are additionally killed within the
> cache window by the per-identity status list (protocol §6.4).

## 5. Protocol §7 rewrite (outline — full text next)

Recast §7 from "first-party `/auth` + `/provision` pages + `provisioning_api.js`
shims + `communication_iframe`" to:

> The browser is the user's **first agent.** A one-time interactive bootstrap
> (top-level, first-party — no hidden cross-origin iframe) authenticates the
> user and yields a **provisioning credential**: a `U_cert~P_cert` delegation
> to the browser's stable non-extractable key, with `constraint.subjects`
> including `self` (and optionally `agent`), held client-side. Thereafter the
> browser obtains and refreshes login certs by the same cookie-free,
> signature-authed `POST /provision/mint` (agent §4.3) that agents use, with
> `subject: self`. The hidden-iframe + `postMessage` silent-refresh path and
> the `provisioning_api.js` shim are retired.

Discovery (§3.1) advertises the mint endpoint + capability block; conformance
(§9) states an IdP that serves login MUST serve the mint verb, cookie-free and
iframe-free.

---

## 6. Open questions — recommended resolutions

- **OQ1 (replay for self-mode) — RESOLVE: add `jti`.** `subject: self` mints a
  cert that speaks as the human; the stakes justify a per-request nonce +
  single-use check within the validity window. Agent-mode keeps today's
  idempotent behavior (no `jti` required).
- **OQ2 (bootstrap handoff) — RESOLVE: browser self-signs `P_cert`.** The
  interactive auth mints a short-lived bootstrap `U_cert` for a freshly
  generated stable browser key; the browser self-signs a `P_cert` delegating
  that same key with `subjects` per the consent (`self`, and `agent` if the
  user also opted into browser-provisioned agents); only the `U_cert~P_cert`
  delegation is persisted client-side (`P_priv` non-extractable, never on the
  wire). Mirrors the existing `account.html:670-719` driver.
- **OQ3 (lifetime/rotation) — RESOLVE: 90-day `P_cert`, re-bootstrap on
  expiry.** Reuse `PROVISIONING_CERT_VALIDITY_DAYS = 90`. When the credential
  expires (or is revoked), the browser silently attempts a fresh bootstrap;
  if the IdP session is gone, it falls back to the interactive ceremony. Minted
  self-certs stay short-lived (IdP's call; ~24h reference).
- **OQ4 (SBO signing's new home) — TRACKED in bean 3b8m.** Relocate
  `signSboEnvelope` to the same-tab typed-signing surface (coordinate with
  `2026-06-24-typed-signing-extension-design.md`); it gates Phase 4.

## 7. Back-compat / migration notes

- **DECIDED (2026-07-18): `subjects`/`subject` are REQUIRED — no deprecation
  window, no missing-field default.** A `P_cert` without `subjects`, or a `mint`
  request without `subject`, MUST be rejected. Clean spec, acceptable pre-GA.
- **Consequence — existing agent credentials must re-provision.** Live
  `P_cert`s that predate the axis (the mingo CLI holds some) stop working the
  moment this ships. Migration action: coordinate a mingo CLI re-bootstrap
  (the CLI already re-mints on demand; it needs a fresh `P_cert` carrying
  `subjects: ["agent"]`), and bump `browserid-agent` so new provisions emit the
  axis. Track under Phase 5 (consumers) / the `browserid-agent` bump.
- No cert-struct change: self-certs use the existing plain-cert path; the
  fail-closed `typ` table (`certificate.rs:221`) is untouched.
</content>
