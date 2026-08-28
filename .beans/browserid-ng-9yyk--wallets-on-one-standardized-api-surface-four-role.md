---
# browserid-ng-9yyk
title: 'Wallets on one standardized API surface: four-role separation (RP / wallet / IdP / registry)'
status: in-progress
type: epic
priority: normal
created_at: 2026-08-28T21:18:17Z
updated_at: 2026-08-28T21:26:27Z
---

Umbrella for the design worked out 2026-08-27/28. Goal: RP, wallet, IdP (primary or fallback), and registry are cleanly separated and independently operable, with identical spec'd APIs regardless of operator (browserid.me runs all four by default; any can be replaced). A conforming wallet — native or the browserid.me web dialog — uses ONLY standard surfaces: /api/v1 (registry-api-v1) + the device-authorization ceremony contract (fallback-idp-api-v1) for issuance. Broker-private endpoints belong to the issuer's ceremony-page role, never the wallet role.

## Specs (drafted + reviewed this session)
- docs/specs/registry-api-v1.md — §5.3 devices, §5.4 holders/namespaces landed (bw9q, completed); needs devices/register added (d0xb §4).
- docs/specs/fallback-idp-api-v1.md — fallback presents as a primary; issuance via the ceremony page; wallet-driven registration. Adversarially reviewed + impact-mapped.

## Children (see each bean)
- d0xb — fallback-IdP spec finalize + native-wallet convergence + devices/register impl. The spine.
- 2jfh — consolidate the broker's 3 device-cert issuance lanes onto one core (blocked by d0xb).
- 71vt — migrate the web dialog off cookie /wsapi onto /api/v1 + the ceremony contract; retire duplicated routes (blocked by d0xb).
- rjge — reword core spec: stop welding the registry to 'the hosted broker' (blocked by d0xb).
- 9it0 — SECURITY: device-authorize page delivers certs to an unvalidated return_url (ship now, independent; hardens the live tenant lane).
- uboq — time-expire SMTP verification (verified_at write-only; independent).
- u6jq — native wallet lane drops the RP's acceptedFallbacks (independent).
- fl6r — native wallet device-management UI over the registry API (low).

## Kickoff / re-analysis pointers
Read this epic, then d0xb (work plan + impact analysis + sequencing), then the two specs. Prior analyses were run as fresh-eyes agents; re-run against docs/specs/*.md + the cited code. Sequencing lives in d0xb's body.
