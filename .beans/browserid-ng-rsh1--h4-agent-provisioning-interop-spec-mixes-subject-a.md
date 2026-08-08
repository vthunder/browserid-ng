---
# browserid-ng-rsh1
title: '[H4] Agent-provisioning interop spec mixes subject and holder models'
status: completed
type: bug
priority: high
created_at: 2026-08-07T16:03:17Z
updated_at: 2026-08-08T11:19:09Z
parent: browserid-ng-8g49
---

docs/specs/agent-provisioning-and-grant-api.md uses 'agent-subject device cert' + (identifier,subject) tuples through most of its body (lines 13,24,50,61,96,124,139,159,173) while tail+impl use holder/grantor/grantee; README.md:28 repeats stale term. An implementer following the first half builds the removed model. Reconcile with holder model. See audit H4.

## Done (2026-08-08)

Rewrote docs/specs/agent-provisioning-and-grant-api.md to the holder/grantor/grantee model, matching the core-spec style:
- Stripped the entire v0.2–v0.6 version-history/changelog preamble → a clean 'draft, module of core spec' status line.
- subject:agent removed everywhere; agents are holders (agents/services namespace); attribution is grantor (attributed) vs grantee (actor). JSON examples updated (device cert / access request / access cert carry holder not subject; warrant is grantor/grantee/holder-matcher).
- Removed the config_cert.iss == access_cert.iss binding → per-identity issuer authority throughout (§3, §5.3, §7.3, §8).
- Aligned with core §4.6: mint verifies identity EXACTLY (subaddressing is authorization-only).
- Renamed to 'auth cert'; grant-exchange token response now {email=grantor, grantee, scopes}; status refs point to core §6.3.
- Removed all code-path refs, bean refs (s75b/t1jp/eywc), the reference-implementations table, and the design-rationale/migration/superseded footer. Kept the consent flow (RFC 8628), grant exchange (RFC 7521), two-stage provisioning, and security considerations.
- 615 → 498 lines.
Also updated docs/specs/README.md (module row + status section) off code/bean refs.

Remaining in the H1/H4 arc: README.md (repo root) agent model + verify example still old-model.
