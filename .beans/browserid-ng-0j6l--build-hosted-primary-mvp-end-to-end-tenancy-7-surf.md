---
# browserid-ng-0j6l
title: 'Build: hosted-primary MVP end-to-end (tenancy + §7 surface + onboarding + deploy)'
status: completed
type: feature
priority: normal
created_at: 2026-08-08T17:42:39Z
updated_at: 2026-08-09T06:56:57Z
parent: browserid-ng-g5qt
---

Overnight build of the g5qt plan, MVP scoped to make the sandmill.org cutover test possible. Design: docs/plans/2026-08-08-hosted-primary-idp-as-a-service.md

- [x] Recon: dialog primary-handoff wire contract — device-authorization popup + CORS mint are the whole contract; both certs required; hold/reissue choreography; mock-IdP test hook exists
- [x] Recon: sandmill reference §7 implementation — fragment/postMessage contracts captured; cutover = fresh key, old certs die at DNS flip (acceptable)
- [x] Recon: infra — *.browserid.me wildcard → id-host exists; idp.browserid.me = domains:add + LE SAN re-issue; deploy = CI image + manual git:from-image (mini-ops key)
- [x] Tenant substrate: migration v23, store trait+sqlite+memory+Arc impls, XChaCha20-Poly1305 sealed tenant keys (TENANT_KEYSTORE_KEY env, AAD=domain), AppState.tenant_keystore/idp_host — compiles clean
- [x] (partial) Discovery/verifier host= fixes: FallbackResult.serving_host, address_info + issuer_revoke_url base URLs honor host=, status-list authority accepts DNSSEC-declared serving host. Issuance routing lands with the /idp routes.
- [x] §7 hosted-primary surface: routes/hosted_idp.rs (idp_login/whoami/password/device_cert/access_cert + tenant_status_list) + static/idp/device-authorize.html + common/js/idp-device-authorize.js. Dialog untouched — the page speaks the exact device_certs/reissue postMessage contract. Mint is fail-closed on tenant revocation + roster state.
- [x] Support doc: well_known.rs is Host-aware — idp host serves tenant_support_document() (no key, /idp/* paths); apex serves broker doc
- [x] Onboarding: /domains + wizard (static/domains.html + common/js/domains.js): tenant_create generates attempt-bound sealed keypair + record text; tenant_check runs the DNSSEC checker and activates + seats first admin on a matching validated record
- [x] Roster admin: /domains/<domain> console — create user w/ set password, disable/enable, reset password, add admin; roster_* + tenant_admin_add endpoints (session+CSRF+admin gated)
- [x] Integration tests green: hosted_primary_test.rs (3) + tenant_keys unit (4); full broker suite green, no regressions
- [x] Committed (4272f38)+pushed; CI built+pushed GHCR image; released via manual git:from-image (mini-ops; CI ssh step still fails per o7ip); idp.browserid.me vhost+SAN cert; production verified
- [x] Cutover instructions in Summary below

## Build log

- Protocol finding: verifier's uri_matches_issuer locks status-list URIs to the cert iss host; hosted tenants serve no web content at their domain → extend authority rule to accept the iss's DNSSEC-declared host= as status-list host (broker verifier + browserid-rp + spec §6.3 note). Tenant lists: signed by tenant key, iss=tenant, served at https://<host>/status/<tenant-domain>.
- Substrate design: migration v23 — tenants (custodial keypair, private key AEAD-sealed w/ env key; status pending_dns→active→suspended; self_claim policy), tenant_admins (identity-keyed), tenant_roster (local_part, admin-set bcrypt hash, must_change_password, state). Tenant-scoped status entries via tenant_id column.

## Summary of Changes

Hosted-primary IdP-as-a-service shipped end to end and live in production on idp.browserid.me. Commit 4272f38; design docs/plans/2026-08-08-hosted-primary-idp-as-a-service.md.

### Live deployment
- App `id` now serves browserid.me + idp.browserid.me (same app, SAN cert). Env on `id`: IDP_HOST=idp.browserid.me, TENANT_KEYSTORE_KEY=<64hex in dokku config>. sandmill-infra/apps/id.conf DOMAINS updated + committed.
- ACTION NEEDED (durability): add IDP_HOST + TENANT_KEYSTORE_KEY to sandmill-infra/secrets/id.env.age so they survive an app destroy/recreate (they persist across normal git:from-image redeploys).

### sandmill.org cutover test (for Dan)
1. Sign in at https://browserid.me/account with any account holding a verified identity you own (e.g. vthunder@gmail.com).
2. https://browserid.me/domains -> Add a domain -> enter sandmill.org, pick admin identity -> Generate DNS record. Copy the TXT record.
3. At Namecheap, REPLACE _browserid.sandmill.org TXT with the generated one (new tenant key + host=idp.browserid.me). Existing sandmill-issued certs die at the flip (new key) — expected.
4. On /domains, Check DNS until it validates. Tenant activates; you become first admin.
5. Domain console -> add user danmills with a password (forced change on first sign-in).
6. Sign in as danmills@sandmill.org at an RP (e.g. https://browserid.me/guestbook): dialog discovers sandmill.org primary -> host=idp.browserid.me -> /idp/device-authorize password login -> certs signed by the tenant key, iss=sandmill.org. Roll back anytime by restoring the old DNS record.

### Deferred follow-ups
Recovery/transfer guardrails (hold-down, notify, clean-roster); admin recent-strong-auth gate; tenant branding; roster-vs-selfclaimed collision rule; e2e Playwright for the tenant lane; self-claim policy wiring.

## Post-testing UX fixes (2026-08-09, commit 89041b0, deployed)

From Dan's initial testing:
1. Onboarding now collects the first user's username + password (with Generate) up front and creates that roster entry the instant DNS validates — no separate step.
2. Forced password-change is now a parameter, not always-on. The onboarding first-user is created with require_password_change=false (the admin chose the password, so no confusing change prompt on their own first sign-in). Console Add-user exposes it as a checkbox (default on = provisioning others). Change-screen copy reframed to be about the user's own password.

Store create_roster_entry gained a must_change param; API RosterCreateRequest.require_password_change (default true). Test: roster_user_without_forced_change_issues_directly.

## Delete tenant (2026-08-09, commit 0bd01f5, deployed)

Added tenant deletion for start-over testing: store delete_tenant (cascades admins/roster/status), POST /wsapi/tenant/delete (admin-gated + typed domain confirmation), console 'Danger zone' section. Test: delete_tenant_clears_rows_and_frees_the_domain.

## Admin-flow redesign + revoke-on-verify (2026-08-09, commit 4e83b36, deployed)

Per Dan's feedback:
- Onboarding is now ONE admin question ("Who administers this domain?"): existing identity (dropdown filtered to exclude emails at the domain being configured; no password; sign in with browserid) OR an email at the domain (set password; that email is admin + login). Helper copy reframed to "how you'll sign in". No separate first-user step.
- Tenants gain owner_user_id (migration v24): the onboarding account always retains console access even when the admin-of-record is a fresh domain-local email. Local admin login is pre-created at tenant_create (hashed, must_change=false, usable once active).
- On activation, revoke_domain_device_certs retires broker/fallback-issued certs for identities at the domain (fail-closed). External-IdP certs die via the DNS key change.

Tests: create_local_admin_preseeds_login_no_forced_change, activation_revokes_prior_broker_certs_for_the_domain. Suite green. Verified live: new wizard copy serving, tenant/create gated, migration applied.
