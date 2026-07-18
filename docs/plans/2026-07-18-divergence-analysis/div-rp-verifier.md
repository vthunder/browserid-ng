# Divergence: RP library (include.js), verifier(s), demo RPs

Target design: `docs/design/browserid-end-to-end-flow.md` (device-cert model).
Scope: RP-facing shim, hosted verifier, RP libs, demo RPs.

## TL;DR

- The **primary/fallback conformance rule the brief flags as CRITICAL is ALREADY
  implemented** in the hosted verifier (`browserid-broker/src/verifier.rs:223-233`):
  a fallback-issued cert for a domain that has a primary already **fails**. This
  is the smallest gap, not the biggest.
- The real divergence is the **credential shape**: the RP path today is a
  1-or-2-part **backed assertion** (`cert~assertion`, or agent
  `agent_cert~warrant~assertion`). The design wants **4 named objects**
  (`access_cert + assertion + warrant + config_cert`), with the **warrant ALWAYS
  present** (today it's agent-only) and **signed by a config cert** (today it's
  signed by the user's own cert, embedded inside the warrant as `parent-cert`).
- Certs need a **purpose × subject** taxonomy (authentication/authorization ×
  user/agent/any). Today there is only a boolean `is_agent()` + `agent_parent`.
- The join key gains **subject**: design joins access_cert/assertion/warrant/
  config_cert by **(identity, subject, audience)**; today the join is
  (parent-identity, agent-identity, audience) with no subject axis.

---

## 1. include.js (`browserid-broker/static/include.js`) — the RP shim

**What it is:** the Persona `navigator.id` shim — `watch/request/logout/get`.
Opens the dialog via WinChan popup (`internalRequest`, :1428) or FedCM silent
path, and hands the RP an opaque **`assertion` string** through
`observers.login(r.assertion)` (:1466). Also `communication_iframe` for state.

- **KEEPS:** the entire `navigator.id` surface + WinChan popup channel is exactly
  the "existing WinChan popup" the design names (design :59). The RP contract is
  "receive one opaque string, POST it to /verify" — that does **not change**; the
  shim is agnostic to whether the string is `cert~assertion` or the new 4-object
  bundle. FedCM silent path (:1489-1571) is orthogonal and keeps.
- **CHANGES:** nothing structural in include.js itself — the opaque token it
  passes back just carries more segments. The `acceptedFallbacks` display/routing
  hint (:1285-1287, :1353) stays. **Note:** include.js already looks stale vs the
  same-tab handle-provisioning work in recent commits (mingo-ytrs); the hidden
  `communication_iframe` (:1171) is ITP-dead per the design's premise, but that's
  the consent/provisioning surface's concern, not the RP-return contract.
- **ADDS:** none required for the RP contract. (Optional: none.)
- **REMOVES:** none required.

**Verdict:** include.js is the *least* divergent surface — the RP-return contract
is opaque-token pass-through and survives the model change untouched.

---

## 2. Hosted verifier — `POST /verify` + `verify_assertion_with_dns`

Files: `browserid-broker/src/routes/verify.rs`, `browserid-broker/src/verifier.rs`,
`browserid-core/src/discovery.rs`, `browserid-core/src/assertion.rs`
(`BackedAssertion`), `browserid-core/src/warrant.rs` (`verify_for`).

### KEEPS
- DNSSEC-rooted key resolution (`verifier.rs:184` docstring, discovery is
  DNSSEC-first, `.well-known` for endpoints only — matches design :133-134).
- **Primary/fallback conformance is ALREADY enforced** (`verifier.rs:223-233`):
  `if email_disc.is_primary { if issuer != email_domain { fail } }`. A
  fallback-issued cert for a primary domain already fails verification — this is
  design §Conformance (:143-149) and the brief's CRITICAL ask, **already done**.
- Accepted-fallbacks policy for no-primary domains (`verify.rs:27-28,57-61`;
  `verifier.rs:236-258`) — matches design §8.1 fallback set.
- Audience / expiry / signature-chain checks (`verifier.rs:264-309`).
- Agent warrant enforcement is fail-closed (`verifier.rs:315-332`;
  `warrant.rs:178`) — parse rejects an agent cert without a warrant.
- Own-list revocation status check (`verify.rs:76-105`).

### CHANGES (the substantive work)
- **Credential model: 1-2 part → 4 objects.** `BackedAssertion` today is
  `certificates()` + optional `warrant()` + `assertion()` (`assertion.rs:167,
  187, 395, 400`). Design wants a first-class **access_cert + assertion +
  warrant + config_cert** bundle. Needs a new wire/parse shape OR a re-mapping of
  the 4 objects onto the existing chain.
- **Warrant ALWAYS present** (design :102, :166 "uniform RP path"). Today the
  non-agent path returns success with **no warrant** (`verifier.rs:334`); a human
  login carries no warrant at all. Making warrants unconditional means the
  human-login branch must also fetch/verify a warrant, and `verify.rs` /
  `VerificationResult` must reflect it.
- **Warrant signer: user cert → config cert.** Today `verify_for`
  (`warrant.rs:178-223`) verifies the warrant under the **parent cert's own
  subject key** — i.e. the warrant is signed by the *user cert*, which it embeds
  as `parent-cert`. The design says the warrant is signed by a **config cert**
  (an `authorization`-purpose cert) that is **presented separately to the RP**
  and that the RP **sees** — whereas the user cert is **never seen** (design
  :49, :32-34). This inverts what's embedded vs presented and changes the signing
  key semantics. Significant `warrant.rs` change.
- **purpose × subject taxonomy on certs.** Design certs carry `purpose`
  (authentication/authorization) and `subject` (user/agent/any) and verifiers
  **reject unknown values** (design :36-37). Today `Certificate` has only
  `is_agent()` / `agent_parent()` (used at `verifier.rs:315`, `warrant.rs:186`).
  The verifier must (a) require the access cert be `authentication`, (b) require
  the config cert be `authorization`, (c) enforce subject matching in the join.
- **Join key gains `subject`.** Design joins the 4 objects by **(identity,
  subject, audience)** (:132-134). Today `verify_for` joins by parent-email ==
  warrant-iss == agent_cert.agent_parent + agent==cert-email + aud
  (`warrant.rs:214-229`) — no `subject` axis. Add subject to the join.
- **Access-cert tier.** Design: access cert certifies a **fresh** key, minted
  online via the IdP mint API, short-lived (design §2). The verifier just checks
  one issuer-signed cert today; it does not distinguish a device cert from an
  access cert. If the two-tier chain reaches the RP, the verifier's single-cert
  assumption (`certificates().first()`, `verifier.rs:197`) may need chain-walk.
- **Two revocation authorities.** Design: RP checks revocation for **access cert
  (→ IdP)** AND **warrant (→ hosted broker)** — two different status authorities
  (:133-134). Today `verify.rs:76-105` only checks refs whose `uri` == **our own**
  status list (`r.uri == own_uri`), explicitly skipping foreign issuers
  (`verify.rs:72-75` comment "no federated IdP issues status claims today"). The
  access cert's IdP-hosted list would be a **foreign** list → needs the
  HTTP-fetch+cache path that's currently unimplemented.

### ADDS
- Config-cert object type + its `authorization` purpose validation.
- Foreign status-list fetch/cache in the hosted `/verify` (the RP-lib
  `StatusCache` in `browserid-rp` already does fetch+verify; the hosted verifier
  does not).
- Warrant lookup for human logins (warrants stored in the broker registry, design
  §3 — the always-present warrant for a user login must be located/attached).

### REMOVES
- The "agent-only warrant" special-casing (`verifier.rs:315` `if cert.is_agent()`)
  collapses once warrants are uniform.
- The embedded-`parent-cert`-as-signer model in `warrant.rs` if the config cert
  becomes the separately-presented signer.

---

## 3. RP libraries

### `browserid-rp/src/lib.rs` (Rust self-verify)
Same divergences as the hosted verifier but on the **pinned-key** path
(`Verifier::trust_issuer` / `trust_issuer_from_well_known`, :162-195). Notable:
- `verify()` (:206) calls `backed.verify(audience, key_resolver)` — the 1-2 part
  model; needs the 4-object bundle + always-warrant + config-cert signer.
- `VerifiedIdentity` (:100-111) has `agent: Option<AgentAttribution>` — with
  warrants always present, the human/agent distinction moves to **subject**, not
  presence-of-warrant.
- `StatusCache` (:456-521) already does foreign-list fetch+verify+cache — this is
  the piece the **hosted** verifier still lacks; the RP lib is *ahead* here.
- Scope intersection (`grant_scopes`, :407) keeps.
- **Does NOT enforce primary/fallback conformance** — this path trusts explicitly
  pinned issuer keys (`issuer_keys` map), so there is no DNSSEC primary/fallback
  discrimination at all. If a self-verifying RP must honor the conformance rule,
  this path needs the DNSSEC discovery logic that only `verifier.rs` has today.
  (Gap: pinned-key RPs can't tell primary from fallback.)

### `sdk/js/index.mjs` (`@browserid-ng/verify`)
- Thin FAIL-CLOSED HTTP client to a hosted `/verify` (:19, :50-110). Contract is
  `{assertion, audience, accepted_fallbacks}` → `{ok,email,issuer,agent}`.
- **KEEPS:** the whole shape; it delegates all model logic to the hosted verifier.
- **CHANGES:** only the response typedef if `subject`/config-cert attribution is
  surfaced; `allowAgent` gate (:58, :103-108) may key off `subject` instead of
  presence-of-`.agent`.
- No Python/Go verifier libs exist (`sdk/` has only `js`, `agent`, `wallet`) —
  the brief's "Python/Go verifier libs" are **not present** (ADD if wanted).

---

## 4. Demo RPs

- `examples/rp-quickstart/server.mjs` — canonical RP: `createVerifier({verifierUrl})`
  then `verifier.verify(assertion, RP_ORIGIN)` (:22, :92), agents rejected by
  default. **KEEPS** wholesale (delegates to hosted verifier). No change unless it
  wants to accept agents/subjects.
- `browserid-broker/static/broker-demo.html` — `navigator.id.watch/request`, POST
  to `/verify` with default (browserid.me) fallback (:37-53). KEEPS.
- `browserid-broker/static/fallback-demo.html` — same but passes
  `acceptedFallbacks: ["fallback.sandmill.org"]` (:22, :55) to exercise the §8.1
  path. KEEPS — this demo is exactly the conformance/fallback story and stays
  valid.
- `marketing/*` (`fedcm-demo.html`, `guestbook.html`) and other static demos
  consume the opaque-assertion/verify contract → KEEP; cosmetic only.

**Verdict:** demo RPs need **no structural change** — they all treat the assertion
as opaque and delegate verification. They keep working as the bundle grows,
provided `/verify`'s request/response contract stays compatible.

---

## Bottom line for the CRITICAL question

"How much must the verifier change to enforce the primary/fallback conformance
rule?" — **Almost nothing: it is already enforced** in the hosted verifier
(`verifier.rs:223-233`). The exception is the **pinned-key `browserid-rp` path**,
which has no primary/fallback discrimination at all (it trusts explicit keys), and
would need DNSSEC discovery bolted on to honor the rule.

The verifier's *large* work is elsewhere: 4-object bundle, always-present
warrants, config-cert-as-signer (vs today's user-cert-embedded-signer),
purpose×subject cert taxonomy with a subject-inclusive join key, and the
two-authority (IdP + broker) foreign status-list revocation checks.
</content>
</invoke>
