---
# browserid-ng-v9rz
title: 'Write a canonical browserid-ng spec: review Mozilla id-specs, document our divergences, decide keep/revert, author our own'
status: in-progress
type: feature
priority: high
created_at: 2026-07-10T08:50:20Z
updated_at: 2026-07-10T10:03:57Z
---

## Motivation

The public landing page (browserid.me) links "Spec" at `docs/specs/agent-provisioning-and-grant-api.md` — but that's only the **agent provisioning slice**. There is no canonical spec for the browserid-ng protocol as we actually implement it. The base protocol is Mozilla's BrowserID/Persona (https://github.com/mozilla/id-specs), which we **derive from but have deliberately diverged from** in significant ways (DNSSEC-rooted discovery, Ed25519, a primary-IdP + sovereignty model, agent-native delegation, on-chain SBO attribution). We need our own spec that matches the implementation, grounded in an explicit, reviewed diff from the originals — and to confirm which divergences were intentional vs. accidental drift.

## Goal

A canonical **browserid-ng protocol spec** (in `docs/specs/`) that accurately describes what we implement, preceded by a documented divergence analysis against Mozilla id-specs and a keep/revert decision for each difference. Then repoint the landing page "Spec"/"Docs" links at it.

## Phase 1 — Review the Mozilla originals

- [ ] Enumerate the documents in https://github.com/mozilla/id-specs (BrowserID protocol overview, the `.well-known/browserid` support-document format, certificate + backed-assertion formats, the Primary IdP provisioning/authentication API, the fallback IdP / Persona model, verification). Catalog each with a one-line summary.
- [ ] Note their status/vintage (JWT/JWS crypto choices, RSA/DSA, the `login.persona.org` fallback, the shimmed browser API) so we compare against the right baseline.

## Phase 2 — Document how our implementation diverges

For each protocol surface, compare Mozilla spec ↔ our code and record the delta. Known divergences to seed the analysis (verify + expand against the code):

- [ ] **Discovery.** We authenticate discovery via a DNSSEC `_browserid` DNS TXT record (RFC 9102) in addition to / preferring `/.well-known/browserid`; Mozilla used well-known only. (See `browserid-core/src/dns.rs`, `browserid-broker/src/dns_fetcher.rs`; beans browserid-ng-28uc, l7q1.)
- [ ] **Crypto.** Ed25519 keys throughout (Mozilla: RSA/DSA). JWK/JWT shapes, `public-key` TXT format.
- [ ] **Support document.** Our `.well-known/browserid` fields (`public-key`, `authentication`, `provisioning`) vs Mozilla's `{public-key, authentication, provisioning}` — confirm parity/changes.
- [ ] **Certificate & assertion formats.** Cert issuer semantics, backed-assertion structure, audience/expiry, our verification path (`browserid-broker/src/verify*`, `verifier.rs`).
- [ ] **Primary IdP model + sovereignty.** Our primary-IdP support and identity/sovereignty records (mingo-sux8 family) — new relative to Mozilla's primary API.
- [ ] **Fallback / broker.** browserid.me as SMTP-verifying broker vs Mozilla's `login.persona.org` fallback; the `_browserid` broker-key + broker trust model.
- [ ] **Agent-native provisioning.** The delegation-chain provisioning + grant API — entirely new; fold the existing `agent-provisioning-and-grant-api.md` in as a component.
- [ ] **On-chain attribution (SBO).** Attribution of a browserid identity to an on-chain key (email-rooted / broker-path, DNSSEC proof objects) — new; keep coherent but clearly layered/optional.
- [ ] **Browser/JS surface.** What we kept for compat (`include.js`, `communication_iframe`, wsapi endpoints) vs dropped (the shimmed navigator.id API, dialog flows).

## Phase 3 — Decide keep vs. reconcile

- [ ] For each divergence: mark **deliberate (keep)** with rationale, or **accidental drift** to reconcile. Flag anything that diverged without a clear reason for a decision.

## Phase 4 — Author the browserid-ng spec

- [ ] Write `docs/specs/browserid-ng-protocol.md` (+ split docs as needed) describing the protocol as implemented, noting inheritance from and intentional departures from Mozilla BrowserID. Reference the agent-provisioning spec as a module.
- [ ] Repoint the landing page "Spec" (and possibly "Docs") links from the agent-provisioning slice to the new canonical spec.

## Deliverables

- A divergence analysis doc (Phase 2/3 output).
- `docs/specs/browserid-ng-protocol.md` (canonical spec).
- Updated landing-page links (browserid-broker/static/index.html + the shared source).

## Related

- Base: https://github.com/mozilla/id-specs (BrowserID/Persona).
- Existing partial spec: docs/specs/agent-provisioning-and-grant-api.md.
- Divergence-relevant beans: browserid-ng-28uc (unify verifier paths / DNSSEC-required vs well-known), browserid-ng-l7q1 (authenticated DNSSEC discovery), browserid-ng-5zdh (agent capability constraints), browserid-ng-egr7 (revocation). Identity model: mingo-sux8.

## Phase 1-2 draft done (agent, 2026-07-10)

DRAFT written (uncommitted): docs/specs/browserid-ng-divergence-analysis.md

Key finding: mozilla/id-specs is archived (read-only since 2022); browserid/ is now a SINGLE consolidated doc browserid/index.md (support doc fields public-key/authentication/provisioning/authority; RSA/JWK certs with principal = email OR host; ~-joined backed assertions; navigator.id primary API; login.persona.org fallback; remote {assertion,audience} verifier).

Deliberate divergences (keep): DNSSEC _browserid discovery, Ed25519, browserid.me broker, no navigator.id (first-party /auth+/provision + wsapi, include.js/communication_iframe kept for RP compat), agent provisioning + SBO attribution as layered modules. Backed-assertion ~ wire format kept IDENTICAL (only sig alg differs).

Flagged for Phase 3 human decision (possible accidental drift):
- A. cert principal narrowed to email-only, dropping Mozilla's host principal — silent (certificate.rs:14-19). Confirm intentional.
- B. SupportDocument delegate()/disabled() stuff an all-zero Ed25519 placeholder key as a sentinel (discovery.rs:62,73) — prefer Option<PublicKey>.
- C. stale doc-comment discovery.rs:3 still says discovery is via /.well-known/browserid only.
- D. added 'disabled' support-doc field is un-specced; needs precedence rules (DNS vs well-known vs disabled).
- Biggest: dual discovery path (well-known OR DNSSEC → security = weaker) = the mandatory-DNSSEC decision (browserid-ng-28uc).

## Divergence 'A' RESOLVED (2026-07-10)
Do NOT keep the email-only cert narrowing. REINSTATE host certificates, but require them to be signed by the DNSSEC key (K_dns) rather than self-signed + well-known-trusted. Optional intermediate: DNSSEC key → (optional) host cert → user cert. Canonize this chain in the spec. Rationale + full model on browserid-ng-28uc (FINAL decision).

## Divergences B + D addressed (2026-07-10) — branch fix/discovery-cleanup (a6e9573, unmerged)
- B (all-zero placeholder key): SupportDocument.public_key is now Option<PublicKey>; delegate()=None; verifier/fallback_fetcher/browserid-rp updated to fail closed ('published no public key') on None.
- D (un-specced disabled): removed the support-document disabled field/constructor/is_disabled + discover() branch + tests. (Note: routes/email.rs AddressInfoResponse.disabled is a SEPARATE address-info API field — left untouched.)
- C (stale discovery.rs doc-comment) still pending → folds into the 28uc DNSSEC-only implementation.
Build clean; browserid-core 30 pass, broker suites green. Awaiting review/merge (deploy alongside 28uc verifier work).

## Phase 4 drafting started (2026-07-10) — branch docs/spec-suite (25202e8, unmerged)

Suite committed: docs/specs/browserid-ng-divergence-analysis.md (now with a Phase 3 decisions section), browserid-ng-protocol.md (core), sbo-attribution.md (module). agent-provisioning-and-grant-api.md referenced as the third module.

SETTLED sections written: crypto/keys (Ed25519, no JWK), support-document endpoints, assertions + backed assertions (tilde format kept faithful), verifier API shape, primary-IdP overview (no navigator.id), broker/fallback.

PENDING (decided model stated, wording finalizes when feat/dnssec-required lands): discovery/trust-root (DNSSEC required + sole root), verification algorithm (unified path), certificates section incl. optional DNSSEC-signed host cert (28uc Phase 2).

Next: finalize the PENDING core sections against the shipped verifier once 28uc Phase 1 merges; add host-cert section after Phase 2.

## SBO attribution split out (2026-07-10)
Per dependency boundary (sbo depends on browserid-ng, not the reverse): removed sbo-attribution.md from this repo; added the general 'offline verification with detached DNSSEC proofs' capability to the core (browserid-ng-protocol.md section 6.3) as the rationale for the DNSSEC trust root. The ledger-specific attribution spec now lives in the sbo repo: specs/SBO Attribution Specification.md (branch docs/attribution-spec, 0c4f1f2). browserid-ng branch docs/spec-suite now at 38e33ce.

## Spec §3/§6.2 finalized (2026-07-10)
Confirmed all active primaries DNSSEC-validate (AD=true via Google + Cloudflare/1.1.1.1): sandmill.org, mingo.place, browserid.me. So no production breakage from the DNSSEC-required change. Flipped browserid-ng-protocol.md §3 (discovery/trust-root) and §6.2 (verification algorithm) from PENDING to SETTLED against shipped verifier 85021d2; folded in broker-key-also-DNSSEC. §4.2 host certs remain the only PENDING section (28uc Phase 2). docs/spec-suite now has the finalized core.

## Spec suite merged + pushed (2026-07-10)
browserid-ng spec suite (divergence analysis + core protocol with settled sections) merged to main, pushed to origin (cdb13c4). SBO Attribution Specification merged to sbo main and pushed (vthunder/sbo 0c4f1f2). Worktrees/branches cleaned up. Remaining: protocol section 4.2 (host certs) finalizes with 28uc Phase 2.
