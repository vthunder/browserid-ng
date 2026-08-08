---
# browserid-ng-0j6l
title: 'Build: hosted-primary MVP end-to-end (tenancy + §7 surface + onboarding + deploy)'
status: in-progress
type: feature
priority: normal
created_at: 2026-08-08T17:42:39Z
updated_at: 2026-08-08T18:10:38Z
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
- [ ] Integration tests green (ssh localtest)
- [ ] Commit(s) with beans; push; CI image; release to id-host; verify production
- [ ] Write sandmill.org cutover test instructions for Dan

## Build log

- Protocol finding: verifier's uri_matches_issuer locks status-list URIs to the cert iss host; hosted tenants serve no web content at their domain → extend authority rule to accept the iss's DNSSEC-declared host= as status-list host (broker verifier + browserid-rp + spec §6.3 note). Tenant lists: signed by tenant key, iss=tenant, served at https://<host>/status/<tenant-domain>.
- Substrate design: migration v23 — tenants (custodial keypair, private key AEAD-sealed w/ env key; status pending_dns→active→suspended; self_claim policy), tenant_admins (identity-keyed), tenant_roster (local_part, admin-set bcrypt hash, must_change_password, state). Tenant-scoped status entries via tenant_id column.
