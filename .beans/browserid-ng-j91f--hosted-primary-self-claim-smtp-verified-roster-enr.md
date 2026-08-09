---
# browserid-ng-j91f
title: 'Hosted-primary self-claim: SMTP-verified roster enrollment for tenant domains'
status: todo
type: feature
created_at: 2026-08-09T14:29:21Z
updated_at: 2026-08-09T14:29:21Z
parent: browserid-ng-g5qt
---

Let a user who controls the mailbox for user@<tenant-domain> — but has no roster entry — verify via SMTP and set a password, then use the hosted primary IdP going forward. This is the "hybrid roster" half of g5qt that was deferred at MVP: the self_claim policy flag exists on the tenant record but is currently inert.

## Current state (confirmed 2026-08-09)

- `tenant.self_claim` is stored (models.rs, default 0) but READ NOWHERE — it gates nothing.
- The §7 tenant surface has no SMTP path: `idp_login` only looks up a roster entry and rejects if absent.
- Once a domain is a verified primary, the broker's own fallback SMTP loop (`/auth/send`) does NOT apply to it (the claim-time authority hierarchy refuses fallback issuance for a domain with a validated `_browserid` record; discovery routes it to the primary).
- Net: today only admin-provisioned roster users can sign in; an inbox-only user is locked out.

## What to build

- [ ] Console: a per-tenant "Allow self-service sign-up by email" toggle wired to `tenant.self_claim` (default off). Store method to flip it (`set_tenant_self_claim`).
- [ ] Tenant device-authorize page (`/idp/device-authorize`): when the roster has no entry for the typed local part AND `self_claim` is on, offer "Email me a code" instead of a dead-end password prompt.
- [ ] Endpoints: `/idp/claim/send` (send a code to user@<tenant-domain> via the broker's existing SMTP sender) and `/idp/claim/verify` (check code → create a self-claimed roster entry → prompt to set a password). Reuse the broker's pending-verification + email machinery; rate-limit like the fallback loop.
- [ ] On successful claim: create roster entry (mark provenance = self-claimed), set password (must_change=false since the user chose it), then proceed to cert issuance exactly like a password login.
- [ ] Precedence: if an admin roster entry already exists for that local part, self-claim is REFUSED — the admin's statement of who owns the address wins (see g5qt design doc "Roster semantics").
- [ ] Deliverability guard: only offer/allow self-claim when the tenant domain actually accepts mail (MX present); otherwise the code can't be delivered. Consider surfacing this in the console toggle ("this domain has no MX — codes can't be delivered").
- [ ] Tests: self-claim creates a usable login; blocked when self_claim off; blocked when an admin entry exists (precedence); wrong/expired code rejected.

## Design references

- docs/plans/2026-08-08-hosted-primary-idp-as-a-service.md — "Hybrid roster" decision + "Roster semantics" (roster entry authoritative for its local part).
- Reuse patterns: routes/fallback_idp.rs (auth_send/auth_verify SMTP loop, rate limiting), the pending-verification store methods.
- Parent epic g5qt; sibling build bean browserid-ng-0j6l (MVP) lists this under deferred follow-ups.
