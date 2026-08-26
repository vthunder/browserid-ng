---
# browserid-ng-oup3
title: 'Browser-as-first-agent: login via the agent mint (A direction)'
status: todo
type: epic
priority: normal
created_at: 2026-07-17T22:08:36Z
updated_at: 2026-08-26T23:10:23Z
---

Reframe human login as provisioning the browser's stable non-extractable key as an agent. Interactive bootstrap (top-level first-party, reusing mingo-ytrs consent.html handshake) yields a provisioning credential (U_cert~P_cert delegation to the browser key, ~90d, client-held). Cert issuance + refresh = cookie-free signature-authed POST to the SAME /provision/mint endpoint agents use (login-mode vs agent-mode a single param). Replaces the ITP-dead hidden-iframe+postMessage silent refresh. Chosen from a 3-way PoC spike (A=popup/same-tab, B=redirect, C=minimal-iframe-relies); A/B share the architecture, C rejected (entangles at URL but keeps cookie-auth => zero ITP fix). Guardrails: login is an explicit consented capability (typed login:bool + distinct consent); 'logout everywhere' = revoke provisioning cert. Spike A branch: worktree-agent-a050bf44400d2fe0d. This epic = produce a very thorough migration plan across spec, implementation, README, website, and consumer apps (sbo, mingo).

## Migration plan (2026-07-18)

Full plan: docs/plans/2026-07-18-model-a-browser-first-agent-migration-plan.md (synthesis of 5 parallel audits).

**Two spine decisions:**
- D1 — login cert MUST be a plain untyped user cert (typ:None, agent:None, principal=real email). RP-compat CONFIRMED across browserid-core/rp, SBO attribution.rs, mingo-idp verify.rs. login:bool is a mint-REQUEST param, never a cert claim; no @self in principal.
- D2 — login must be an explicit SIGNED capability on Constraint, enforced at mint. The #1 security gap: today any provisioning credential could mint => account takeover.

**Other required controls:** plain-cert-for-self issuance branch; P_cert revocation at mint = logout-everywhere; quota/EmailType separation; keep mint cookie-free (CSRF structurally gone); login-mode replay hardening (open).

**Hard prereq:** relocate SBO signSboEnvelope (communication_iframe/start.js:156-241) BEFORE deleting the iframe, or SBO signing breaks.

**Consumers:** SBO unaffected (verifier only); mingo CLI already embodies Model A; mingo-idp/mingo-web is a PARALLEL migration (its own iframe/postMessage/SameSite=None/FedCM stack).

**Phases:** 0 spec/design · 1 core types · 2 broker issuance security · 3 browser client · 4 iframe retirement (gated on SBO) · 5 consumers (+mingo parallel) · 6 docs/website · 7 conformance+live validation.

## Status (2026-07-18 overnight): vertical slice LIVE
Phases 0-3 done: spec (i32c), core subject axis (54jz), broker self-mode mint + D2 (wid3), hosted demo (8fq2). Deployed to browserid.me and proven end-to-end in prod via smoke.mjs. Try it: https://browserid.me/demo-self-login. Remaining (deferred, follow-ups): Phase 4 iframe retirement (blocked by SBO relocation 3b8m), Phase 5 mingo parallel migration + browserid-agent subjects bump, Phase 6 docs/website, Phase 7 conformance hardening (jti replay cache, <=10min endorsement window, discovery advertisement).

## Device-cert build progress (2026-07-18 overnight, part 2)
Implemented DC Phases 1-6 (vertical slice) + hosted RP demo:
- Phase 1 (ru87 done): browserid-core::device — DeviceCert(purpose x subject), AccessRequest, AccessCert, Warrant over (identifier,subject), AccessPresentation verify. 3 core tests.
- Phases 2-4 (thzq/xboy/qo3j done): routes/device.rs — /device/issue, /access/mint, /warrant/issue, /verify-access. 2 integration tests.
- Phases 5-6 (1ep4/umme done): /demo-device-login hosted RP demo (in-browser full flow).
No regressions (core 65, broker agent 17 + device 2 green). Deploying to browserid.me.
REMAINING: Phase 7 (retire old subject-axis/self-mint/iframe path + rebuild-cleanup + mingo/sbo consumers), Phase 8 (docs/website/conformance suite/full live validation). Warrant registry/storage/revocation (Phase 4 full) is demo-stubbed (fresh config cert per issue). Q5/Q8 open.

## Build progress (2026-07-19): P1+P2+P6 done, additive+tested
- P1 (ru87): browserid-core::device — DeviceCert/AccessRequest/AccessCert/Warrant/AccessPresentation with the adversarial fixes (config-cert issuer binding, per-device status, subject-in-join, fail-closed). Golden vectors test-vectors/device-cert-v1.json (frozen). 7 tests.
- P2 (thzq): routes/device.rs — /device/issue (batch), /access/mint (per-device status root). HTTP tests.
- P6 (umme, partial): verify_access_with_dns — REAL primary/fallback conformance; reject-fallback-for-primary + reject-rogue-config-issuer proven. TODO: fail-closed foreign status fetch (with P4 registry), jti replay cache.
All ADDITIVE (legacy routes untouched; baseline builds; prod on baseline). No regression (core 32, broker lib 41, verifier 18, device 2).
REMAINING for a clickable cold-start login: P5 browser client (device keygen -> /device/issue -> /access/mint -> config-cert-signed warrant -> assertion -> /verify-access), P3 DB persistence, P4 warrant registry+status, P10 sandmill primary.

## Full build wave (2026-07-19) — merged to main, additive
DONE+MERGED: P1 core+vectors, P2 issuance/mint, P5 client/demo, P6 verifier, P3 device_certs persistence (migrate_v12), P4 warrant registry + /warrant/register + fail-closed 3-authority status, P0/P9 spec+docs. P10 sandmill PHP (byte-compat proven, deploying). Broker + sandmill deploying.
IN FLIGHT: P7 headless agent SDK (worktree), P8 device-cert management UI (worktree).
REMAINING: consumer migration (mingo full IdP+web+CLI+poster, sbo verifier), cleanup phase (retire legacy chain, gated 3b8m). All additive so consumers still compile until cleanup.
No regressions: core 68, broker lib 41, verifier 18 (incl fail-closed status), registrar 8.

## Cleanup done (2026-07-19) — delegation chain retired
Pushed to origin (0efbd1c) + deploying. Removed: provisioning.rs delegation types (jws helpers extracted to jws.rs first), /provision/* routes, provisioning-cert registry + endorse, legacy AgentCredential/AgentIdentity SDK, migrate_v13 DROP provisioning_certs+api_keys. Device model + browser warrant consent kept. Full workspace build + tests GREEN (delegation tests + the consent_flow flake removed with the chain).
DONE: entire device-cert migration P0-P10 built, tested, pushed, deployed (browserid.me + sandmill.org). Live device-cert login verified.
REMAINING (follow-ups): (1) finish consumer migration mingo/sbo onto the device model + bump their pin to 0efbd1c (partial WIP in those repos); (2) hidden-iframe deletion gated by SBO-signing relocation 3b8m; (3) account.html legacy Agents-create card removal (tracked, degrades gracefully); (4) a device-shaped /warrant/request path (browser consent respond/registry/status kept, but the agent-facing request entry was removed with the chain).

**Audit note 2026-08-27:** the core of this epic shipped long ago and the protocol has since evolved past its framing — device-cert model live in prod (browserid.me well-known advertises device-cert/access-cert/record-grants), provisioning.rs/delegation chain retired, Model A + DC phase children completed, then superseded further by the holder model (129z) and warrant v2 + signing grants. Moved to todo as a stale container: remaining open children (zj2w, bwi4, ga3w, 7wj3, 10n1, kmvm, lq56, p5i0, 4d80, drafts jgta/850o) all stand on their own. Candidate for closure-with-respawn: the subject-axis/as: framing in the body no longer describes the shipped architecture.
