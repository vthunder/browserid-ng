---
# browserid-ng-8g49
title: Spec + codebase + cross-repo drift/security audit (2026-08-07)
status: completed
type: epic
priority: high
created_at: 2026-08-07T15:44:14Z
updated_at: 2026-08-08T12:54:26Z
---

Thorough multi-angle audit across browserid-ng, mingo, sbo, sandmill, browserid-bsky, sandmill-infra. Angles: (A) spec<->core-code conformance, (B) cross-repo API/version drift, (C) security delta since 2026-07-29, (D) broken/confusing. Deliverable: docs/spec-code-audit-2026-08-07.md + one bean per confirmed finding. Method: adversarial fan-out with skeptic verification. Builds on epic browserid-ng-wre6 (July 29 security audit).

## Summary of Changes

Audit complete. Report: docs/spec-code-audit-2026-08-07.md. Tests: cargo test --workspace green (exit 0, 0 failures).

Method: 4-angle adversarial fan-out (spec-conformance, cross-repo drift, security-delta, broken/confusing) + first-hand re-verification of every high/medium finding.

Result: implementation is sound and ahead of the spec; the dominant issue is documentation drift on security-critical semantics (subject/identifier -> holder/grantor-grantee rename never propagated to the spec). 4 High, 10 Medium, ~12 Low filed as child beans (25kf, kh0j, jvcl, rsh1, mmnp, o68b, 97jn, 16i2, lnas, c6wi, bmi0, oawf, yc4r, fpcc, ya11).

Headline: H1 spec mandates a config.iss==access.iss binding the reference verifier deliberately removed; H2 browserid-rp trusts Web-PKI .well-known keys (the downgrade spec forbids); H3 whole e2e flows quarantined incl a skipped cert-leak regression test.

Verified NON-issues / already fixed: prod fail-closed hatches unreachable, holder isolation holds, set_parent safe, test endpoints gated, jti replay present, cookie flags (0eud) fixed, no secrets committed, cross-repo wire format actually conforms.

Builds on epic browserid-ng-wre6 (July 29 security audit).

## Documentation reconciliation complete (2026-08-08)

All human-facing docs are now on the holder/grantor/grantee model:
- docs/specs/browserid-ng-protocol.md (core) — rewritten over three review passes; standalone (no code/bean refs), holder + grantor/grantee, per-identity issuer authority (config.iss==access.iss removed), auth cert, subaddressing authorization-only, /verify endpoint moved out, BrowserID lineage → appendix.
- docs/specs/agent-provisioning-and-grant-api.md (module) — rewritten to the model; version-history preamble + code/bean refs stripped (615→498 lines).
- docs/specs/README.md — module row + status section de-referenced.
- docs/design/browserid-end-to-end-flow.md — actors/artifacts/ceremonies added, model reconciled (H1/rpsv).
- README.md (repo root) — "three properties" agent bullet, verify example (r.subject → r.grantee), the "agent model in one picture" diagram + explanation, human-login note, and Protocol-notes section all updated.

Code deltas surfaced during the doc work (filed as beans):
- browserid-ng-bls2 — mint must require exact identity match (subaddressing is authorization-only).
- browserid-ng-zexp — remove advisory public-key from the .well-known support document.
- browserid-ng-pl41 — rename hosted /verify-access → /verify.
- browserid-ng-6q3u (pre-existing, epic wre6) — JS SDK still reads a `subject` field the broker no longer sends; allowAgent gate is dead. The README now documents the correct {email, grantee, scopes, issuer} shape.
