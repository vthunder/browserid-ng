# Adversarial sequencing / feasibility review — device-cert migration plan

Plan: `docs/plans/2026-07-18-device-cert-model-migration-plan.md`
Claimed sequence: **P0 → P1 → {P2, P3} → P4 → {P5, P6, P7} → P8 → P9 → P10 → P11**

Verified against workspace crate graph:
- `browserid-core` — no deps (foundation)
- `browserid-registrar` → core
- `browserid-broker` → core, registrar
- `browserid-rp` → core
- `browserid-agent` → core, **broker, rp**

Key discovered facts:
- Existing `browserid-core/tests/conformance_test.rs` is **Rust-only, self-generated** ("we create our own test vectors" — line 707-712). There are **no language-agnostic golden vectors** (exported JSON/JWS fixtures) that PHP + JS + Rust all consume. `e2e-tests/fixtures` holds only `test-helpers.ts`.
- sandmill PHP (`BrowserIdController`) today serves `/.well-known/browserid`, `POST /api/browserid/cert_key`, `/browserid/{provision,auth}` iframe pages — exactly the legacy model P10 must replace.
- `browserid-agent` (mint/endorse SDK, used by mingo CLI per prod) still hard-depends on the endorse→mint chain (`lib.rs:519`) and on the broker+rp crates.

---

## RANKED FINDINGS

### 1. [CRITICAL] No frozen wire format / shared cross-language test vectors — and the conformance suite is placed LAST (P11). This is the central sequencing defect.
**Problem.** The plan's whole value proposition is byte-compatible JWS across Rust (core/broker/rp), JS (dialog/keystore/sdk), and PHP (sandmill P10). The plan explicitly flags "Cross-language risk: the PHP cert/JWS output must match `browserid-core`'s shapes exactly" (risks section) — yet the artifact that would *pin* that agreement (golden test vectors: canonical JSON claim shapes + expected signed JWS + verify-accept/reject cases for device/access/config cert + warrant-v2) is not a phase output until **P11**, the last phase. P1 "freezes types" only in Rust; the existing conformance test generates its own vectors in-process, so nothing external can be checked against it.
**Evidence.** `conformance_test.rs:707-712` (self-generated, Rust-only). P10 sits at position 9 of 11 and P11 (conformance suite) after it. No `*vector*`/`*golden*` fixtures exist in-repo.
**Consequence.** P2, P5, P6, P7, and especially P10 (PHP) all code against a *moving* Rust target with no external oracle. Every party discovers disagreement at P11 — the classic integration cliff, on the highest-risk (cross-language) surface, with zero schedule slack.
**Severity:** Critical.
**Fix.** Insert **P0.5 — "Freeze wire format + publish golden vectors"**, produced as the *deliverable* of P1 (it's the natural home: `browserid-core` has no deps and unit-tests in isolation). Emit versioned JSON fixtures under a shared `test-vectors/` dir: for each new typ, the canonical claim object, the exact base64url header/payload, a signed JWS with a fixed test key, and labelled accept/reject cases (unknown purpose/subject → reject). Make P2/P5/P6/P7/P10 each consume these vectors as their red tests. Nothing downstream starts until the vectors exist.

### 2. [CRITICAL] Retiring the delegation chain (P1 type-removal, P2 endpoint-removal) breaks prod while the old flow must keep serving for the entire migration.
**Problem.** P1 says "Deprecate/retire `provisioning.rs` chain types"; P2 says "Remove `/provision/endorse`, the provisioning-cert registry, `/provision/reserve`." But the OLD flow (hidden iframe, `cert_key` 24h identity certs, `U_cert~P_cert~R` chain, endorse→mint) must keep working in prod until P5/P6/P7/P10 flip the clients — and mingo CLI auth rides `browserid-agent`'s endorse→mint (`lib.rs:519`) today. The plan itself gates hidden-iframe deletion on SBO relocation (`3b8m`) at **P11** — directly contradicting removing the mint/endorse endpoints those same clients still call back at **P2**.
**Evidence.** Plan lines 57-59 (P1 retire), 84-85 (P2 remove endpoints), 153/180 (P11: "SBO signing relocation before deleting the hidden iframe"). `browserid-agent/src/lib.rs:519` still calls `endorse()`.
**Consequence.** From P2 landing until the last client flips, the whole endorse/mint path is red in prod — a multi-phase outage window for mingo and any agent using the SDK.
**Severity:** Critical.
**Fix.** Make the new model **strictly additive** through the middle of the migration: add device-cert types *alongside* `provisioning.rs` (don't retire in P1), add new issuance/mint routes *alongside* `/provision/*` (don't remove in P2). Keep both live. Flip clients (P5/P7/P10). Then a **dedicated final cleanup phase** (fold into/after P11, gated by `3b8m`) removes `provisioning.rs`, `/provision/endorse|reserve`, `provisioning_certs`, and the old iframe — once nothing calls them. Removal timing must be one coherent late step, not split between P1/P2.

### 3. [HIGH] {P5, P6, P7} is not a valid parallel brace — P7 (agent) sits ON TOP of P2(broker)+P6(rp) in the crate graph, and P6 can't be end-to-end-validated until P5/P7 emit real bundles.
**Problem.** The brace implies P5, P6, P7 are independent. Two hard couplings say otherwise: (a) `browserid-agent` depends on `browserid-broker` AND `browserid-rp`, so P7 literally cannot compile until P2's mint API and P6's rp verify changes land — P7 is downstream of both, not parallel. (b) P6 (verifier) *consumes* the 4-object bundle that P5 (dialog) and P7 (agent) *produce*; P6 can be unit-tested against synthetic bundles but the real "does a live client bundle verify?" check serializes after P5/P7.
**Evidence.** `browserid-agent/Cargo.toml` depends on `browserid-broker` + `browserid-rp`. Bundle shape shared via `AccessPresentation`/`BackedAssertion` in core.
**Consequence.** Treating them as parallel underestimates critical-path length and hides an integration step (client bundle × verifier) that has no owner in the plan.
**Severity:** High.
**Fix.** Order within the brace: **P6 (verifier + rp) → P5 (dialog client) and P7 (agent) in parallel**, with the golden vectors (Finding 1) as the shared contract so P5/P7/P6 can develop against fixtures before live integration. Add an explicit **"live bundle × verifier integration"** checkpoint after the first client (P5) lands. Note P7's compile-dependency on P2+P6 explicitly.

### 4. [HIGH] {P2, P3} is not independent — P2's issuance/mint endpoints write to the `device_certs` table and warrant `subject` column that P3 creates, and both mutate the same store trait.
**Problem.** P2 evolves `issue_certificate`/`mint` to issue+persist device certs and remove the provisioning-cert registry; P3 adds the `device_certs` table + warrant `subject`/config-cert ref and removes `provisioning_certs` + the trait methods. You cannot mint/persist a device cert without the table, and both phases edit `store/sqlite.rs`, `store.rs` (`RegistrarStore`), and `registrar_glue::BrokerRegistrarStore`. They share files and a schema→code dependency.
**Evidence.** Plan P2 (lines 80-85) + P3 (lines 86-91) both touch `RegistrarStore`/`registrar_glue`; div-agents-db.md §"Migration note" (store.rs:17-45 trait methods).
**Consequence.** Parallel P2/P3 will collide on the store trait and sqlite migrations; P2 has nothing to write to until P3 lands.
**Severity:** High.
**Fix.** Serialize: **P3 (schema + store trait) → P2 (endpoints)**, or merge them into one "IdP issuance/mint + its storage" unit. Do the ADDs (device_certs table, subject column) in P3-first; defer the REMOVEs (`provisioning_certs`, trait method deletion) to the late cleanup phase (Finding 2) so the old path keeps its storage.

### 5. [HIGH] No thin vertical slice — the plan is big-bang; no working end-to-end login exists until P4 + most of {P5,P6}.
**Problem.** The first real login only works once P1→P3→P4→P5→P6 all land (types, schema, config-cert-signed warrants incl. self-login auto-warrant, dialog bundle assembly, verifier). Because "warrant always present" is on the critical path of even the simplest human login, a large chunk of P4 (self-login auto-warrant, config-cert registry) is pulled into the minimum viable path. Nothing is demoable until very late.
**Evidence.** Design lines 102/166 (warrant always present); plan P4 line 96 (self-login auto-warrant); P11 is the first "faithful demo."
**Consequence.** Long dark period with no runnable checkpoint; risk accumulates undetected.
**Severity:** High.
**Fix.** Define a **thin vertical slice** as an explicit early milestone: *user-cert only, fallback-IdP only (browserid.me, SMTP), no agents, config cert held server-side at the hosted broker so the browser needn't hold one.* That threads P1→P3→P2(mint)→P4(self-login warrant only)→P5(user path)→P6 for ONE working cold-start fallback login. Land that green, then layer **agents (P7)** and **primary/PHP (P10)** as additive slices. Turns the big-bang into two-plus incremental, verifiable slices.

### 6. [MEDIUM] P10 (sandmill PHP) is serialized to position 9, but it only depends on the frozen wire format — sequencing the riskiest cross-language work last removes all slack.
**Problem.** P10 is placed after P0–P9, and P11's primary demo depends on P10. But PHP conformance depends on the *wire format/vectors* (Finding 1), not on Rust client/verifier internals. Deferring it to the end means the single most uncertain integration (PHP byte-compat, deployed via dokku) lands right before the finish with no recovery room.
**Evidence.** Plan line 155-156 sequence; line 130-147 P10 depends only on issuance+mint format; risks note the cross-language byte-compat hazard.
**Severity:** Medium (becomes High if Finding 1 is not adopted).
**Fix.** Once golden vectors are frozen (P0.5), **pull P10 forward to run in parallel with {P5,P6,P7}**, validated continuously against the Rust verifier via the shared vectors. Its only true predecessor is the vectors, not P8/P9 (docs/UI).

### 7. [MEDIUM] P4 depends on P2 (config-cert issuance), not only P3 — the "P4 after {P2,P3}" edge is right but under-stated, and P4 is itself two separable pieces.
**Problem.** P4 (config-cert-signed warrant validation + config-cert registry + self-login auto-warrant) needs P2 to actually *issue* config certs and P1's config-cert type — not just P3's schema. The plan orders P4 after the brace so this is satisfied, but the dependency on P2's issuance (not just P3's DB) should be explicit, and P4's "config-cert registry" ADD vs "warrant validation flip" CHANGE can be split (registry can precede, validation-flip rides the slice).
**Severity:** Medium.
**Fix.** State P4→P2 issuance dependency explicitly; split P4 into P4a (config-cert registry + issuance wiring) and P4b (warrant validation flip + self-login auto-warrant) so P4a can land inside the vertical slice and P4b with it.

### 8. [LOW] P1's fail-closed and type work is genuinely isolatable and testable — this is the plan's strongest ordering choice; lean on it.
**Observation (not a defect).** `browserid-core` has no deps and already unit-tests in isolation, so P1 (types, purpose/subject enums, fail-closed-on-unknown, warrant-v2 shape) can be fully red/green tested alone. This makes P1 the correct place to also *own the golden vectors* (Finding 1). No change needed except to load more of the contract-defining work into P1.
**Severity:** Low / affirmation.

---

## PROPOSED IMPROVED SEQUENCE

**P0** Spec rewrite (as planned).
**P1** Core types + **fail-closed** + **golden test-vectors artifact** (`test-vectors/`) — the frozen wire contract. *Additive: keep `provisioning.rs` chain types alongside; do NOT retire yet.*
**P3** DB schema **ADDs** (device_certs table, warrant subject + config-cert ref) + store-trait extension. *No REMOVEs yet.*
**P2** IdP issuance + access-cert mint + config-cert issuance, as **new routes alongside** `/provision/*`. Consumes P1 vectors as red tests.
**P4a** Config-cert registry + issuance wiring.
--- **THIN VERTICAL SLICE MILESTONE**: user-cert, fallback-IdP, hosted-broker-held config cert, one cold-start login ---
**P4b** Warrant validation flip + self-login auto-warrant.
**P6** Verifier + rp (config-cert signer, always-warrant, subject join, two-authority status). Against vectors.
**P5** Dialog + keystore client (user path first). → **live bundle × verifier integration checkpoint**.
Parallel from here (all gated only on vectors + P6):
**P7** Agent SDK + headless (depends P2+P6). | **P10** sandmill PHP conformance (depends only on vectors).
**P8** Management + warrant UI. **P9** Docs + landing.
**P11** Faithful demo + **cross-language conformance suite run** + **CLEANUP**: remove `provisioning.rs`, `/provision/endorse|reserve`, `provisioning_certs`/`api_keys`, hidden iframe — gated by SBO relocation (`3b8m`), once no client calls them.

Net changes vs original: vectors pulled to P1 (was P11); removals deferred to a single P11 cleanup (was split into P1/P2); {P2,P3} serialized as P3→P2; a thin slice milestone inserted; P10 pulled forward to run parallel with P5/P6/P7; P6 ordered before P5/P7 within its group; P4 split.
