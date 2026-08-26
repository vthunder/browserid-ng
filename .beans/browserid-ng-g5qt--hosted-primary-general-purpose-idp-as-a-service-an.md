---
# browserid-ng-g5qt
title: 'Hosted primary: general-purpose IdP-as-a-service any domain can delegate to'
status: completed
type: epic
priority: normal
created_at: 2026-08-08T17:08:08Z
updated_at: 2026-08-26T23:09:58Z
---

browserid.me operates the full primary-IdP surface for a customer domain: all §3.1 endpoints (authentication, provisioning, device-cert, access-cert, device-authorization, revocation), the tenant's user DB, status lists, and admin console. The domain opts in via its own DNS; RPs need no new config.

Captures the plan discussed ~2026-08-08 (earlier discussion was not written down; reconstructed from the roadmap's Theme 1 line "self-serve primaries … hosted primary kit" + existing protocol machinery).

## What already exists (leverage)

- Protocol: `_browserid` DNSSEC TXT carries the key + optional `host=`; `.well-known/browserid` carries endpoints + optional `authority` delegation pointer; core discovery follows delegation chains (max 5 hops, cycle-checked).
- The broker already implements every required IdP surface (it IS the fallback IdP) + the extracted browserid-registrar crate.
- Precedents: mingo.place uses browserid.me as external registrar (1pnf); sandmill.org is a hand-rolled primary whose DNS record is its sole root of trust (key-rotation runbook exists).
- Dedicated identity host just stood up (gzq7) — natural place to run this.

## Open decisions (settle before build)

- [x] Key model: DECIDED — per-tenant custodial key in the tenant's own DNSSEC record, iss=tenant, off-ramp = DNS flip.
- [x] User-DB authority: DECIDED — hybrid, with the admin always able to maintain an email-independent roster (create user + set password even when the user can receive no mail); roster entries authoritative for their local part.
- [x] Placement: DECIDED — the broker grows tenancy; the self-hostable kit is a later extraction (registrar-crate pattern).
- [x] Onboarding UX: record generator + DNSSEC checker + domain-control verification ceremony (the /domains stepped add-domain wizard with live DNSSEC checking; claim ceremony incl. OIDC Google claim, 5a07031)
- [x] Guardrails: resolved in practice — per-tenant custodial keys, the DNS-flip off-ramp (a tenant leaves by repointing host=), and tenant delete/start-over (0bd01f5) keep this an escape-hatched default rather than an SSO lock-in; issuance transparency remains a future mitigation (see the transparency-log direction).

## Related

o92d (fallback abuse vectors), dff5 (DNSSEC host certs), 7sew (auth-only issuance), n0ut (passkey graduation), 5bic (anti-squatting), roadmap: docs/plans/2026-08-02-roadmap-directions.md

## Design doc

Authoritative plan (decisions, tenant model, roster semantics, onboarding ceremony, phases 0–4, open questions): docs/plans/2026-08-08-hosted-primary-idp-as-a-service.md

Verified in code: `host=` is implemented end to end (browserid-core/src/dns.rs well_known_host) — a tenant opts in with one DNSSEC TXT record and zero web hosting.

Remaining open (non-blocking): surface origin (apex vs idp. subdomain), password bootstrap UX, tenant branding, roster-vs-self-claimed collision rule.

## Admin claim (settled 2026-08-08)

First admin = the signed-in identity whose onboarding attempt's generated key gets published in DNS (the record doubles as a per-attempt challenge nonce). DNS control alone confers admin; recovery/transfer = re-run the ceremony (rotates tenant key, hold-down + notify + clean-roster-with-export guardrails). Hand-authored keys are self-hosting, never an admin claim. Details in the design doc's 'Admin claim' section.

## UX inventory (2026-08-08)

Four audiences mapped in the design doc's 'UX inventory' section: www landing (trails); add-domain wizard + live DNSSEC checker on apex (/account entry + /domains/add — the product's front door, = roadmap's record generator/checker); tenant admin console at /domains/<domain> (overview w/ DNS-health banner, roster table + display-once password modal, admins, settings); dialog tenant-rostered password lane + forced-change screen (needed at Phase 1/2 boundary, before the console). Email-less users' password reset is admin-only — dialog must route to 'contact your domain admin'.

## Correction (2026-08-08): no dialog changes — hosted-primary is a new §7 surface

Dan's decision: the existing dialog is NOT modified. Tenant users are reached purely via the primary-IdP mechanism — discovery + host= → a NEW page set implementing the §7 primary contract (authentication w/ password + forced-change, provisioning, device-authorization, device-revoke), same contract sandmill/mingo satisfy externally. No address_info lane, no dialog tenant-awareness; the claim-time hierarchy already flips the domain to primary handoff when the record validates. This surface + registrar crate = the substance of the future self-host 'primary kit'. Surface-origin open question now leans strongly to a dedicated origin (e.g. idp.browserid.me). Supersedes the 'dialog tenant-rostered lane' item in the earlier UX note.

## Summary of Changes

browserid.me now operates a full multi-tenant primary-IdP surface at idp.browserid.me — authentication, provisioning, device-cert, access-cert, device-authorization, and revocation — with per-tenant custodial keys, tenant rosters, and a /domains onboarding wizard plus per-domain admin console (Users / Administrators / Managed identities / Settings). A domain opts in with a single DNSSEC _browserid TXT record carrying host=idp.browserid.me; iss stays the tenant domain, so RPs need no new configuration. sandmill.org is live as tenant #1, with managed identities minting agent certs through the hosted surface in production (danmills+claude-gh@sandmill.org, 2026-08-12). All verifiers were made DNSSEC-conformant along the way (browserid-dnssec extraction, 0p5f). SMTP self-claim, directory sync, and SBO-verifier test coverage continue in their own beans (j91f, mhvi, k3rg). (Closed by audit 2026-08-27.)
