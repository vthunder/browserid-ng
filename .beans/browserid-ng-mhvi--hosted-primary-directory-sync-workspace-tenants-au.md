---
# browserid-ng-mhvi
title: 'Hosted-primary directory sync: Workspace tenants auto-provision via OIDC (avoid self-claim UX)'
status: draft
type: feature
created_at: 2026-08-10T06:01:23Z
updated_at: 2026-08-10T06:01:23Z
parent: browserid-ng-g5qt
---

Connect a hosted-primary tenant to its directory so provisioning is automatic + tighter, instead of self-claim (whose UX resembles the fallback). If the tenant is a Google Workspace: its roster IS the Workspace — users sign in with Google, accounts provision just-in-time, no passwords, no roster management.

Design exploration: docs/plans/2026-08-10-tenant-directory-sync-design.md.

Depth 1 (tightest, least config, recommended first): per-tenant auth_method incl. oidc; a tenant-side OIDC login lane on the §7 surface that JIT-provisions the roster entry (provenance directory-oidc, no password) then issues the cert. Reuses the OIDC core (qer8): Workspace MX detection, RS256 verify, email_verified, and the hd==domain guard (already built). Deprovisioning rides Google (suspended user can't get a token).
Depth 2 (enterprise follow-up): Admin SDK Directory / SCIM sync for admin-visible roster + proactive offboarding (service account + read-only scope; reconcile loop).

Decisions pending (in doc): auth_method {password,oidc,both} (both default recommended); JIT policy (auto-create any valid @domain Google login recommended); whether Depth-1 deprovisioning (next-login-blocked + certs age out) is sufficient before calling it done.
