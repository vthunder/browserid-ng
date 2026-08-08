---
# browserid-ng-rpsv
title: 'Docs: README/spec conceptual overview — actors, artifacts, ceremonies'
status: completed
type: task
priority: normal
created_at: 2026-08-08T08:20:37Z
updated_at: 2026-08-08T08:29:18Z
parent: browserid-ng-8g49
---

Add a succinct protocol-overview section (repo README and/or spec preamble) so a reader comes away understanding the building blocks and how they combine to achieve outcomes. Built around three short lists; each entry one short paragraph; cross-link to detailed spec sections. Must stay succinct (gist-level), not a full spec.

## Actors
- IdP — domain authoritative for its identities; issues device certs (authentication: mint access certs; authorization/config: sign warrants) + runs mint API.
- Grantor — identity holder with a config cert; authorizes new permissions for that identity by signing warrants (grantor is pinned to what the config cert is authoritative for).
- Grantee — identity holder who accesses a resource / takes an action; proven live by the assertion signed by its access cert's fresh key.

## Artifacts
- Device cert (durable, IdP-signed, never presented). Subtypes by purpose: authentication (mints access certs) — user cert / agent cert; authorization = config cert (signs warrants).
- Access cert (short-lived, RP-facing, one identity, certifies a fresh key).
- Warrant (config-cert-signed delegation grantor->grantee over holder-matcher + audience + [scopes]; long-lived, reusable, device-agnostic).
- Assertion (fresh-access-key-signed; audience + exp) and the presentation bundle access_cert~assertion~warrant~config_cert.

## Ceremonies
1. Obtaining a device cert — sub-scenarios: interactive login (device generates keypair; IdP batch-issues user cert + config cert); agent device-grant (user authorizes; IdP issues agent device cert directly); fallback IdP for no-primary domains (verify email control via SMTP challenge -> issue device certs under the fallback's iss).
2. Obtaining an access cert — device signs an access request with its authentication device key -> POST mint API -> IdP returns a short-lived access cert on a fresh key (cookie-free, headless-capable).
3. Obtaining a warrant — grantor signs with the config cert, delegating to a chosen grantee over (holder-matcher, audience, scopes); grant-exchange/consent surface for the grantee to request + grantor to approve; stored in the broker warrant registry; reused device-agnostically.
4. Presenting + verifying — assemble the 4-object bundle; RP verifies two DNSSEC-rooted issuer paths (grantee's access cert, grantor's config cert), the join (grantee==access identity, holder-matcher covers holder, audiences match), and three fail-closed status checks.

## Acceptance
Succinct enough that a newcomer grasps the gist; each actor/artifact/ceremony ~1 short paragraph; links out to protocol spec sections for detail. Related: H1 (browserid-ng-25kf) spec-rewrite and H4 (browserid-ng-rsh1) agent-provisioning module reconciliation.

## Summary of Changes

Done by modifying the existing overview `docs/design/browserid-end-to-end-flow.md` in place (rather than a new page), per review preference.

Added:
- **## Actors** section (IdP / grantor / grantee) with the signing-time-vs-presentation-time grantee asymmetry.
- **## Artifacts** section: one-glance table (device cert, config cert, access cert, assertion, warrant) + the presentation bundle; folded the former "Two senses of broker" and "Holders" under it.

Reconciled (the doc was itself stale — it had holders but NOT the grantor/grantee split, and still asserted the removed `config.iss == access.iss` binding):
- Warrant now described as grantor→grantee over holder-matcher (was "identifier, holder-matcher") in the Artifacts table, Stage 3, Stage 4, and Properties.
- Replaced the old `config_cert.iss == domain(identity)` "privilege-escalation hole" text with the per-identity authority rule (each issuer authoritative for its own identity; cross-issuer delegation allowed), plus an implementer note that core verify() does not enforce the binding (links H1 25kf / H2 kh0j).
- Added the "why config cert not a grantor access cert" (longevity) rationale to Stage 3.

Corrected the audit report's earlier claim that the design doc "already reflects the new model" — it only reflected holders.
