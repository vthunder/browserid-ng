---
# browserid-ng-rjmm
title: 'Consent-card + warrant semantics for OAuth-lane connections: name the CONNECTION (host/client), not the gateway'
status: completed
type: feature
priority: normal
created_at: 2026-08-13T18:10:47Z
updated_at: 2026-08-25T19:17:11Z
---

From the Lane B design review with Dan (2026-08-13, after the mcp-demo connector E2E):

**The problem.** In the auth-code lane, the warrant's grantee is the resource's own service credential (gateway-as-agent), so the consent card reads "danmills+mcp-demo2 wants permission" — infrastructure presented as an agent. Dan's critique: user→gateway consent is incoherent (the gateway already has the data); with an anonymous host there is no agent to consent to; "they should only need to log in."

**The resolution reached.** The flow's real product is a durable bearer+refresh capability held by the HOST (claude.ai) — a third party. The meaningful consent object is that connection/custody, mirroring classic OAuth (cards name the CLIENT, never the resource). Login covers identity; the warrant is the revocable record of the CONNECTION. What you revoke at /account is the connection, not "the gateway's permission".

**Design directions:**
- Warrant carries/records the OAuth client metadata (client_name, redirect-URI domain) as the named counterparty; the service credential stays as custodial plumbing, not the displayed grantee
- Broker consent card gets a connection variant: "You're connecting <host> to <service label>. It can use: <tools>. Attributed to you. Revocable here." — no "X wants permission", no personal-looking subaddress
- /account Authorized Sites renders these as host↔service connections
- Service-class identities so infra credentials stop looking like personal agents (no danmills+foo)
- Explicit bridge framing: when hosts carry real agent identities, the grantee slot is filled honestly and this presentation-layer costume drops away

Touches: broker consent flow, mcp-auth authcode lane (pass client metadata into the warrant request), /account rendering, maybe warrant spec metadata fields.

**Slice 1 shipped (2026-08-13, commit 665794e):** mcp-auth 0.2.1 — auth-code-lane bearers carry {name, host} of the OAuth client; authenticate() exposes ctx.client (null on Lane A); mcp-demo attributes 'via Claude (claude.ai) — authorized by <human>'. Remaining: broker consent-card connection variant, /account rendering as host↔service connections, service-class identities, spec-level connection-grantee kind.

**Design note written (2026-08-13):** docs/plans/2026-08-13-connection-warrants-design.md — v2 warrant + descriptor grantee, two-object bundle + four invariants, §7.5 audience-proof, theft matrix, rollout phases. Awaiting Dan's review; spec PR is phase 1.

## Handoff (2026-08-14) — design review COMPLETE, ready for phase 1

Eight review rounds with Dan converged; the design note is the single source of truth:
**docs/plans/2026-08-13-connection-warrants-design.md** (final at commit 1d1fcbd).

Final shape: one record format (browserid-warrant-v2), grantee always a scalar email (matchers `*`/`*@domain` admission-only), single `binding` slot (kind: holder | connection; connection has `protocol` subtype, both fail-closed), connection records are self-grants (derived invariant), binding.id 1:1 with its record, two operations (presentation / admission), two-record composition joined on email (deliberately not hash-tied), record lifecycle §3.4 (grant-authoring ceremony; resource is custodian), audience-proof request flow §3.5, eight invariants, theft matrix, rollout phases.

**Phase 1 work items (next session):**
1. Spec PR: core spec §5 (v2 format + bindings table + scalar-grantee + matchers + privacy sentence), §6 (operation A + invariants), §7.5 (connection grant request + audience proof + grant-authoring ceremony)
2. Verifier (crate + hosted /verify-access): v2 parsing, record-validation call (warrant~config_cert)
3. Broker: consent-card connection variant, binding.id mint + registry pairing, /account rendering, request endpoint + challenge fetch — all behind a support-advertisement flag

Phase 0 already shipped: mcp-auth 0.2.1 ctx.client (commit 665794e). mcp-demo runs Lane B live with a provisioned service credential ($BROWSERID_CREDENTIAL on dokku) — that credential becomes unnecessary once phases 1–2 land.

Suggested kickoff: read the design note top to bottom, then draft the §5/§6/§7.5 spec diffs against docs/specs/browserid-ng-protocol.md before touching code.

## Phase 1 progress (2026-08-14)

Spec diff drafted (uncommitted, working tree): docs/specs/browserid-ng-protocol.md — §5 rewritten around browserid-warrant-v2 (bindings table, matchers, status REQUIRED, self-grant rule, v1 compat, privacy sentence); §6 intro names the two operations; §6.1 v2-aware (parse + join steps); new §6.4 admission, §6.5 composition, §6.6 eight invariants; §7.5 gains connection grant requests (audience proof) + grant-authoring ceremony. Awaiting Dan review before commit/implementation.

## Adversarial review of spec draft (2026-08-14, 27-agent workflow)

5 lenses (coherence/consistency/security/implementability/fidelity) → 21 deduped findings, each adversarially verified. Verdicts: 7 confirmed (3 high: §6.4-1d drops the §4.7 aud constraint on the admission path; the acquisition/per-use split exempts expiry so held records never age out; §7.5 connection flow missing poll contract + consent URL + config-cert delivery), 5 downgraded (grant-authoring wire contract, v1-status wording in 1e, SSRF address-class guard on proof fetch, proof-document body format, email/matcher comparison rules), 9 refuted (incl. binding.id-enforcement and custody-vs-dual-use "contradictions" — both misreadings). Full results: task output wdadyqnlq/whqweud86. Fixes not yet applied — awaiting Dan triage.

Review triage round 1 (Dan): fixed the 3 highs + client_host + §1.2 grantee definition (spec working tree; §6.4-1d aud fix also mirrored into the design note). Still open for discussion: §4.7 mint-policy uniformity claim, then the downgraded batch (grant-authoring wire contract, 1e wording, proof-fetch address guard, proof body format, email comparison rules) and the confirmed-low step-2 reference.

Freshness-backed minting decided + drafted (2026-08-14): spec §6.4 gains the rule (bearers ≤1h reference; mint/refresh MUST be backed by status-list snapshots no older than the bearer + validity windows; AS SHOULD retain snapshot per mint for audit); §4.7 mint-policy paragraph rewritten per-operation with the config-cert-rotation short loop for connections. Design note §3.6 records the decision + rejected alternatives (broker-minted bearers, per-record voucher/OCSP, push revocation, short-exp records); impact table rows updated. Still open: downgraded batch + confirmed-low step-2 reference.

Review triage round 2 (2026-08-14, all six approved + applied): grant-authoring ceremony got the full wire contract (typed request, shared-origin rule, audience proof, per-row grantee rendering MUST, request_id poll, warrant~config_cert delivery) — subsumes the step-2 reference fix; §5 identity-comparison rule (domain lowercase+A-label, local byte-exact; *@domain covers subaddresses not subdomains) with cross-refs at both joins; audience-proof document format sentence (verbatim nonce, trailing-whitespace strip, retention) + public-unicast fetch guard + WebPKI origin-scope rationale; §6.4-1e reworded conditional. Design note Q1 annotated, Q6 marked decided. Spec-review findings now fully dispositioned: 12 fixed, 9 refuted-no-change. All uncommitted, pending Dan final read + commit.

## Handoff (2026-08-14 EOD) — spec draft COMMITTED, ready for phase 1 build

Spec text for warrant v2 is done and reviewed: §5 (v2 format, bindings, matchers, identity comparison, status REQUIRED, v1 compat), §6.1 (v2-aware P), §6.4 (admission + freshness-backed minting), §6.5 (composition), §6.6 (eight invariants), §7.5 (connection grant requests + audience proof + grant-authoring ceremony, both with full wire contracts), §4.7 (per-operation mint policy, config-cert rotation loop), §1.2 (v2 role definitions). Survived a 27-agent adversarial review (5 lenses; 12 findings fixed, 9 refuted); freshness-backed minting was designed in response to the review and is recorded in the design note §3.6 with rejected alternatives.

**Build order (fresh session; read the committed spec sections first, the design note only for rationale):**
1. Verifier crate: v2 parsing (binding slot, fail-closed kinds/protocols), operation P updates (§6.1 steps 1+6), operation A record validation (§6.4 steps 1a–1e incl. full §4.7 constraints + live expiry), identity comparison (§5). Hosted /verify-access unchanged; NEW two-object record-validation endpoint (warrant~config_cert, no caller auth).
2. Broker: connection request endpoint + audience-proof fetch (public-unicast guard, verbatim-nonce compare), consent-card connection variant, binding.id mint + id↔record registry pairing, authoring ceremony endpoint, /account connection rendering — all behind support advertisement (discovery flag).
3. mcp-auth lane: credential-less mode w/ capability detection + fallback; bearer/refresh bound to (binding.id, record); short bearers (≤1h ref) + freshness-backed mint/refresh.

Gotchas from memory: cargo runs via `ssh localtest`; new crates need Dockerfile edits before dokku deploy; broker inline-script CSP hashes if consent card touches static pages; e2e wants a warm broker on :3000.

## Phase 1 item 1 DONE (2026-08-14, bean 1g9j)

Verifier v2 support landed: core §5 identity comparison (identity.rs), Binding enum + dual-version WarrantClaims + parse shape matrix + create_v2 (device.rs, v1 wire byte-frozen), operation P step-1/step-6 updates, operation A record validation (admission.rs: RecordBundle validate/recheck_live/matches_login), broker validate_record_with_dns + POST /validate-record (no caller auth; /verify-access untouched). Full workspace green. Next: item 3 (broker consent-card connection variant, binding.id mint + registry pairing, request endpoint + audience-proof fetch, /account rendering, behind support advertisement), then mcp-auth credential-less lane.

## Phase 1 items 2+3 DONE (2026-08-14, beans qmvw/h2m1)

Item 2 (commit ea6475e): broker record-request surface per §7.5 — /warrant/record-request (connection + authoring), audience-proof gate (BrokerProofFetcher, SSRF-guarded, verbatim-nonce), deep-linked claim with per-axis status idx allocation, respond validation pinning binding.id/client descriptor/status refs, consent-card connection + authoring variants (v2 client-side signing), /account host↔service connection rendering, record-grants support advertisement, sqlite v28, per-origin rate limit. 5 new integration tests.

Item 3 (commit cb935aa): mcp-auth 0.3.0 — credential-less connection mode with capability detection + agent fallback; validateRecord/mintFromValidatedRecord; bearers ≤1h capped by record exp, bound to (binding.id, record); freshness-backed mint/refresh (every mint backed by fresh /validate-record, fail-closed); rotate-on-use refresh tokens with family burn; client_host binding enforced at return + every exchange; mcp-demo credential-less + proof route.

Deferred follow-ups: per-mint status-snapshot retention (§6.4 SHOULD, needs /validate-record to return snapshot tokens); service-class identities (from the original design directions); npm publish of mcp-auth still not done. Note: guestbook + paired-provisioning e2e specs fail on main pre-existing (stale spec vs authorize-page flow) — unrelated, worth its own bean.

## Post-test design round (2026-08-15, gate 0.7.1→0.9.0)

From Dan's live testing: signing banner bugs fixed (stale cache; banner only on Roles tab while sharing happens on People tab → moved into the header sync pill/popover); connect flow made identity-visible (interstitial 'Continue as X / switch' — a live gate session never silently bounces; switch clears the member session). Trust discussion outcome: signed policy records do NOT constrain a hostile enforcement point (irreducible for hosted resources) — their value is provenance integrity, honest-but-sloppy containment, unilateral owner revocation, and the door to verification moving down the stack. Decision: enforcement source is a deployment property — LOCAL roles default for self-hosted, --signed-grants sticky opt-in (gate 0.9.0). Two-tier future direction captured in its own draft bean. npm: mcp-auth 0.5.0 published; gate 0.9.0 awaiting Dan's OTP publish.

## Sibling design (2026-08-22)

The SBO signer fix (bean ttn3, audit M9) generalized into **signing grants** —
docs/plans/2026-08-22-signing-grants-design.md — the presentation-side mirror
of connection records: same consent card / registry / ledger / status-bit
machinery, record parked at the user's key custodian instead of the resource.
Adds a `requester` sibling claim to the v2 record (custodian-enforced, like
the client binding's PKCE-enforced precedent) and a `sign:` scope namespace.
No change to operations P/A. If the v2 spec PR (phase 1 here) lands first,
the signing-grant spec text should ride as a small addition to it.

## Sibling-design update (2026-08-25)

The signing-grants note now AMENDS this design's 'exactly one binding is
structural' invariant: `binding` holds a set of channel entries, singular
object remains valid shorthand (deployed connection/authoring records are
byte-unchanged; pre-amendment verifiers reject the array shape, fail-closed).
Entries are conjunctive with a kind × operation evaluation table; the
signing grant's set is {holder, requester}. Multi-entry sets are
self-grant-only — the delegated combinations (requester-on-agent-grant,
connection-on-policy-record / §3.4 host constraints) stay labeled doors.
When the v2 spec PR lands, fold this amendment in. Source of truth:
docs/plans/2026-08-22-signing-grants-design.md §3.

## Note (2026-08-25): the binding-set amendment landed via ttn3

The 'binding set amendment' this bean was carrying for the v2 spec is now IN the spec: docs/specs/browserid-ng-protocol.md §5 holds the channel-entry set (kind × operation table incl. requester), scope-entry parameters, assertion req_origin, and invariants 9-14 (commit c8e8964, implementation 73d4625/73831d8). Nothing remains to fold in from this side.

## Closed (2026-08-25) — verification pass + Dan's sign-off

Everything substantive shipped and verified: warrant-v2 spec text (adversarially reviewed, later amended to binding channel sets via ttn3); verifier v2 + /validate-record (re-exercised by the 2026-08-25 binding-set refactor, all green); broker record-request surface, audience proof, connection + authoring consent cards, binding.id↔record pairing, /account host↔service rendering (connection-sharing e2e passing); mcp-auth credential-less lane with freshness-backed minting — mcp-auth 0.5.1 and gate 0.10.1 live on npm (the 'awaiting OTP publish' note was stale). The 'pre-existing failing guestbook/paired-provisioning e2e' note is also stale — both pass on current main. The two deferred items (per-mint snapshot retention §6.4 SHOULD; service-class identities, whose motivating UX connection records eliminated) moved to browserid-ng-vwju.
