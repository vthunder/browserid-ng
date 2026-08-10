# Hosted-primary ⇄ directory services — design exploration

**Date:** 2026-08-10
**Status:** exploration, per the 2026-08-10 discussion. Connects the
hosted-primary tenant model (epic g5qt) to a tenant's existing directory so
provisioning is automatic and tighter — avoiding the self-claim path (bean
j91f), whose UX risks resembling the fallback flow for users and admins.

**One line:** if a tenant domain is a Google Workspace, its browserid roster
*is* the Workspace — users just "sign in with Google," accounts provision
just-in-time, no passwords and no roster management.

## The problem with the two roster options we have

- **Admin-managed roster** (shipped): the admin hand-creates every user + sets
  a password. Tight, but high friction; doesn't mirror the org's real
  directory; passwords to manage.
- **Self-claim** (specced, j91f): a user proves the mailbox (SMTP) and sets a
  password. Low admin friction, but the *experience* is basically the fallback
  ceremony (emailed code, self-set password) — the very thing hosted-primary
  was meant to feel better than, and it gives the admin little control.

A directory connection is the third door: the org already maintains its users
in Google Workspace / Microsoft Entra / Okta. Mirror that, and there is nothing
to self-claim and nothing to hand-manage.

## Two integration depths (ship in this order)

### Depth 1 — JIT provisioning via OIDC (tightest, least config)

The Workspace is both the **directory** and the **authenticator**. No
directory API, no service account.

- The tenant is configured with **auth method = OIDC (Google)** instead of (or
  alongside) tenant passwords. Reuses the OIDC core already built
  (`browserid-broker/src/oidc/`, bean qer8): Workspace-domain detection via MX,
  RS256 ID-token verification, `email_verified`, and the `hd` (hosted-domain)
  guard that ties the token to *this* Workspace domain.
- **First sign-in provisions the roster entry just-in-time**: a Google login
  whose verified `email` is at the tenant domain and whose `hd` == the domain
  creates the roster entry (provenance = `directory-oidc`, no password),
  then issues the tenant cert exactly as a password login would.
- **Deprovisioning rides Google**: a suspended/removed Workspace user cannot
  obtain an ID token, so they cannot sign in — access ends without any
  browserid action. (Outstanding certs age out; for immediate cutoff, the
  admin disables the roster entry, or Depth 2 syncs the suspension.)
- **Admin experience**: nothing to manage. The roster auto-populates as people
  sign in; the console shows who's active. Optionally the admin sets a policy
  "only allow @domain Google identities" (the default) vs. also allowing
  admin-created password users (mixed mode).

This is small and almost entirely reuse: the OIDC verifier exists; the new work
is (a) a per-tenant `auth_method` = `oidc`/`password`/`both`, (b) a tenant-side
OIDC login lane on the §7 surface that provisions-then-issues, and (c) the
`hd`-must-equal-domain gate (already in the OIDC core).

### Depth 2 — Directory API sync (admin roster + proactive offboarding)

For orgs that want the browserid roster to reflect the directory *without*
waiting for each user's first login, and to **proactively** deprovision.

- The tenant admin connects the directory: for Google, a service account with
  **domain-wide delegation** and the read-only Admin SDK Directory scope
  (`admin.directory.user.readonly`); for Entra/Okta, SCIM.
- The broker periodically pulls the user list + suspension state and reconciles
  the roster: add new users (state `active`, provenance `directory-sync`),
  mark suspended/removed users `disabled` (which the mint already fail-closes
  on). A webhook/push channel makes it near-real-time; a poll is the fallback.
- Heavier: a service-account credential per tenant (custody), the directory
  scopes, and the reconcile loop. Worth it for enterprise; not for the first
  Workspace tenant.

## Why this is the right "tighter" answer

- **No passwords, no self-claim.** Auth is the org's own Google sign-in;
  provisioning is implicit. The user never sees a browserid-specific ceremony.
- **The org keeps its source of truth.** Offboarding in Workspace offboards
  here (immediately with Depth 2, next-login with Depth 1).
- **It composes with everything shipped.** The tenant is still a normal
  browserid primary — RPs need no change; the warrant/agent story is unchanged;
  the difference is purely *how the roster is populated and how users auth*.

## Security notes

- **`hd` binding is load-bearing.** A Google login only provisions/authorizes a
  tenant-domain address when the token's `hd` equals the domain (already
  enforced in the OIDC core) — otherwise any Google account could mint a
  Workspace address. Consumer-Gmail tokens (no `hd`) never provision a
  Workspace tenant.
- **Domain control still roots in DNS.** The tenant is a hosted primary because
  it published the `_browserid` record; the directory connection only governs
  *which humans* are users, not the domain's authority.
- **Service-account custody (Depth 2)** is a real secret per tenant — same
  sealing story as the custodial tenant key (`tenant_keys`), or keep it
  broker-side with least-privilege read-only scope.

## Decisions to confirm (before a Depth-1 build)

1. **Auth-method model** — per-tenant `auth_method ∈ {password, oidc, both}`
   (recommended `both` default so a Workspace can also have password users like
   service/shared accounts), or OIDC-only for Workspace tenants?
2. **JIT provisioning policy** — auto-create on any valid @domain Google login
   (recommended), or only for pre-approved local-parts / require one admin
   click the first time?
3. **Deprovisioning for Depth 1** — accept "next-login is blocked + certs age
   out", or require Depth 2 for immediate cutoff before we call it done?

## Deferred (follow-ups)
Microsoft Entra + Okta SCIM (Depth 2); Google groups → scopes/roles; a
tenant "connect your directory" onboarding step; near-real-time push channels.
