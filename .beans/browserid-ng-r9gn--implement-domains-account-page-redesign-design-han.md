---
# browserid-ng-r9gn
title: Implement domains + account page redesign (design handoff bundle)
status: completed
type: feature
priority: normal
created_at: 2026-08-11T21:33:35Z
updated_at: 2026-08-26T23:07:14Z
---

Recreate the high-fidelity design handoff (scratchpad: account-design/design_handoff_domains_integration/) in the broker's static pages: shared navbar, /domains list + stepped add-domain wizard + per-domain console (Users/Administrators/Managed identities/Settings tabs), account-page managed-identity indicators + Try-it-out card. Backend gaps to close: remove-admin endpoint; split max_ttl into device_cert_ttl + access_cert_ttl; standalone revoke-all endpoint; per-address managed flag in the account API. Spec = README.md in the bundle; copy strings verbatim. Delegated to a worktree agent.


Progress (worktree agent):
- Backend done, suite green (260 passed / 0 failed; baseline 254):
  - POST /wsapi/tenant/admins/remove {csrf, domain, identity} — refuses self-removal (any verified own identity) and the last admin; store gains remove_tenant_admin (memory + sqlite + Arc forwarding).
  - ManagementPolicy gains device_cert_ttl / access_cert_ttl (seconds; stored in the management JSON blob, no schema migration). /wsapi/tenant/management round-trips them; /idp/device_cert honors device_cert_ttl (default 90d); /idp/access_cert honors access_cert_ttl, falling back to legacy max_ttl, else 24h. Constraint stamping (max_ttl as warrant bound) unchanged.
  - POST /wsapi/tenant/revoke_all {csrf, domain} — standalone revoke-everything, returns {revoked}; policy-save revoke_now kept working.
  - /wsapi/list_emails now returns managed: [{email, domain}]; /wsapi/tenant/list gained a users count (list-view meta line).
  - 6 new tests in hosted_primary_test.rs covering all four gaps.
- Frontend: domains.html + common/js/domains.js fully rewritten to the redesign (shared navbar, list + pending cards with Copy buttons, 3-step wizard, 4-tab console, inline reset-password row, two-click confirms — no prompt()/confirm() anywhere new). account.html: navbar with Domains link, managed pills/footnote/notes, Try-it-out card; INLINE_SCRIPT_HASHES updated; node --check clean on both scripts.
- Next: local render sanity check, commit.


## Summary of Changes

Backend (browserid-broker, all admin endpoints session+CSRF gated via session_admin_identity):
- **POST /wsapi/tenant/admins/remove** {csrf, domain, identity} → {success}. Refuses removing any verified identity on your own account ('you cannot remove yourself…') and the last admin ('a domain must keep at least one administrator'); refuses non-admin identities. New store method remove_tenant_admin (trait + memory + sqlite + Arc<SqliteStore>).
- **Split cert lifetimes**: ManagementPolicy gains device_cert_ttl and access_cert_ttl (seconds, serde-defaulted — management is a JSON blob column, no migration). POST /wsapi/tenant/management accepts them (>0 filtered), GET surfaces them. /idp/device_cert: validity = policy.device_cert_ttl when management enabled, else 90d default. /idp/access_cert: validity = access_cert_ttl, else legacy max_ttl, else 24h. max_ttl keeps its warrant-constraint stamping role unchanged.
- **POST /wsapi/tenant/revoke_all** {csrf, domain} → {success, revoked}. tenant_status_revoke_all + revoke_domain_device_certs, independent of management state; policy-save revoke_now untouched.
- **Per-address managed flag**: /wsapi/list_emails response gains managed: [{email, domain}] (active tenant + management.enabled, one lookup per distinct domain). Also: /wsapi/tenant/list rows gain a users roster count for the list-view meta line.
- Tests: 6 new in hosted_primary_test.rs (admin floor/self-removal, TTL bounds + max_ttl fallback, policy round-trip, revoke-all + mint refusal, managed flag). Suite: 254 → 260 passed, 0 failed.

Frontend:
- **static/domains.html + static/common/js/domains.js**: full redesign per handoff. Shared navbar (Account link, Domains current, tooltip'd Sign out; no signed-in email). List view with status pills, users/since meta, pending-domain inline DNS records with Copy(→Copied) buttons and Check DNS; empty state. Stepped 3-part wizard (Domain → Administrator → Publish record) replacing the single form — verbatim copy, radio option cards, Generate password (existing charset), dnsMessage() strings kept. Per-domain console with four tabs: Users (add-user card w/ require_password_change checkbox; roster grid; INLINE reset-password row replacing prompt()), Administrators ('you' pill, Remove via the new endpoint, add-admin card), Managed identities (master checkbox, per-site creds, allowed sites/scopes, Certificate lifetimes days/hours; two-click confirm on enable), Settings (Sign everyone out via /wsapi/tenant/revoke_all with two-click confirm + revoked count; typed-domain delete). URL scheme unchanged (/domains vs /domains/{domain}).
- **static/account.html**: navbar with Domains link + Sign out tooltip; managed pills on Your addresses (+footnote), roster blanket lines ('where {domain} allows' caveat), actor detail ('managed by {domain}' filled pill + amber managed note); 'Try it out' card (→ https://www.browserid.me/demos) replacing 'Goes well with'. INLINE_SCRIPT_HASHES updated in routes/mod.rs (csp guard test green).

Deliberately deferred: account.html's pre-existing confirm()/alert() calls in cutoff / sign-out-everywhere / perm-forget flows (predate this handoff, out of its scope).

**Closure addendum (audit 2026-08-27):** committed to main as a897b49 and verified live in production — the redesigned /domains stepped wizard and the /account Try-it-out card are both serving. See the Summary of Changes above for the full scope.
