# Hosted primary — IdP-as-a-service for any domain

**Date:** 2026-08-08
**Status:** design plan; decisions below settled with Dan 2026-08-08. Epic:
browserid-ng-g5qt. Realizes the roadmap's Theme 1 counterweight
("self-serve primaries … hosted primary kit",
`2026-08-02-roadmap-directions.md`).

**One line:** browserid.me runs the entire primary-IdP surface for your
domain — auth pages, cert issuance, revocation, the user roster — and you
opt in by publishing **one DNSSEC-signed TXT record**. RPs need no new
config; they see your domain as a first-class primary.

## Settled decisions

1. **Per-tenant custodial key.** browserid.me generates and holds an
   Ed25519 keypair per tenant. The *tenant's own* `_browserid` record
   carries the public key plus `host=<broker host>`. Certs are issued with
   `iss = tenant domain`, signed by the tenant key. The off-ramp is a DNS
   flip to a self-hosted key — the exact runbook sandmill.org already
   exercises. This keeps the DNSSEC-sole-root model intact, isolates
   compromise blast radius per tenant, and answers the Persona
   centralization critique with an exit that needs no one's permission.
2. **Hybrid roster, admin always sovereign.** Where the domain has working
   mail, users may self-claim via the existing ceremonies (SMTP loop, OIDC
   bridge later). Independently of email, the tenant admin can maintain a
   roster directly: **create a user and set a password for them even if
   that user can receive no email**. Roster entries are authoritative for
   their local part (see §Roster).
3. **The broker grows tenancy.** No new deployable. Tenant tables,
   per-tenant keys, and tenant-scoped issuance land in browserid-broker on
   the identity host (gzq7). The self-hostable "primary kit" remains a
   later extraction, the way browserid-registrar was extracted (1pnf).

## Why this is mostly wiring, not protocol

Verified in code 2026-08-08:

- `browserid-core/src/dns.rs` parses `host=` and `well_known_host()`
  redirects the `.well-known/browserid` fetch to it; the record's key
  remains the sole trust root (the support doc never carries a key).
- Discovery follows `authority` delegation chains (bounded, cycle-checked)
  — not needed for the chosen shape, but available.
- The broker already implements the backend machinery — device/access-cert
  issuance, status lists, the registrar component, password auth for
  fallback accounts. The browser-facing **§7 primary pages**
  (authentication/provisioning/device-authorization) are new UI, but they
  implement a contract two external primaries (sandmill, mingo) already
  satisfy, and the dialog's primary-handoff machinery that drives them is
  untouched.

The RP-side story is therefore **zero config**: resolve
`_browserid.tenant.com` → tenant key → fetch support doc from
`host=` → verify `iss = tenant.com` certs against the DNS key. Nothing in
browserid-rp changes.

## Tenant model

New broker tables (names indicative):

- `tenants` — domain (unique), custodial keypair (private key encrypted at
  rest with the host age key), status (`pending_dns` → `active` →
  `suspended`), created_by, policy flags.
- `tenant_admins` — tenant ↔ browserid identity of each admin (the
  onboarder's identity seeds it; admins can add admins).
- `tenant_roster` — tenant ↔ local part, auth material (password hash,
  later passkeys), state (`invited`/`active`/`disabled`), created_by,
  email_reachable flag.

Policy flags (per tenant): `self_claim` (allow mailbox-proof claims for
unrostered local parts; default on iff the domain has MX), auth methods
allowed, maybe issuance quotas.

### Issuance routing

At every issuance point (device-cert batch API, access-cert mint, agent
provisioning), key selection becomes: identity domain ∈ active tenants →
sign with that tenant's key, `iss = tenant domain`; else the existing
fallback path. Status refs point at broker-served, **tenant-scoped**
signed status lists (`status.uri` is an absolute URL, so
`https://<broker>/status/<tenant>` needs no tenant web presence). All
existing revocation semantics carry over unchanged.

### Roster semantics

- A roster entry is **authoritative for its local part**: while one
  exists, mailbox self-claim for that address is refused — the admin's
  statement of "who is user@domain" outranks mailbox possession.
- Self-claimed identities at a tenant domain (where policy allows) behave
  like today's fallback accounts, but issue under the tenant key.
- Admin-created, email-less users authenticate at the broker's auth page
  with the admin-set password (forced change on first login), and should
  graduate to passkeys (relates n0ut).
- Admins can disable a roster entry and revoke its outstanding certs
  (tenant-scoped status list flip) — the "kill it from a web page" story,
  now for whole-domain operators.

## Onboarding ceremony

Proof of domain control **is** publishing the record — no separate
verification step needed:

1. Signed-in user starts "add your domain" on /account; broker generates
   the tenant keypair and shows the exact TXT record to publish
   (`v=browserid1; …; public-key=<tenant pub>; host=<broker host>`).
2. A DNSSEC checker polls (DoT, AD-required — same channel as the
   verifier) until the record validates; tenant flips to `active`, the
   onboarder becomes first admin.
3. Failure diagnostics (no DNSSEC on the zone, bogus chain, malformed
   record) surface in the checker UI — this is the roadmap's "record
   generator + DNSSEC checker," delivered as the onboarding funnel.

Domains without DNSSEC cannot be primaries (protocol-wide rule); the
funnel should say so early and leave them on the fallback lane.

### Admin claim — how the first admin is determined

The generated record doubles as the challenge that binds DNS control to a
specific identity:

1. Onboarding requires being signed in as *some* browserid identity —
   necessarily external to the tenant (pre-activation the domain has no
   users). Starting "add your domain" creates an **onboarding attempt**
   recording `(domain, generated keypair, requesting identity)`.
2. The shown TXT record contains that attempt's public key, so it is an
   unguessable per-attempt nonce: only the record from your attempt
   validates against your attempt. When the poller sees exactly that key
   DNSSEC-validated, the attempt's identity becomes **first admin** and
   the tenant activates. Admins add further admins by identity.

Properties:

- **DNS control alone confers admin — by design.** DNS is already the
  protocol's sole trust root; a weaker gate (e.g. a mailbox at the
  domain) would only add a spoofable side channel.
- **Concurrent claims cannot race**: different attempts → different
  keys; the actual DNS controller picks the winner by publishing.
- **Recovery = transfer = the same ceremony re-run.** A fresh attempt +
  newly published record rotates the tenant key (old certs die within
  DNS TTL) and reseats admin. Guardrails needed: notify existing admins,
  hold-down window before a re-claim over an *active* tenant activates,
  and re-claim starts with a **clean roster** (export available to the
  outgoing admins) — inheriting it would leak the old owner's user list
  to a new domain owner.
- **A hand-authored key is not an admin claim** — that's self-hosting
  (the off-ramp). The hosted service only recognizes keys it generated.

Residual risk: between DNS ceremonies, tenant admin is exactly as strong
as the admin's own identity. Recommend passkey-backed identities for
admins and recent-strong-auth gating on destructive admin actions.

### Interaction with existing fallback identities

The claim-time hierarchy already refuses fallback issuance for any domain
with a validated `_browserid` record, so activation cleanly stops the
fallback lane for the domain. Existing fallback-issued certs for
user@domain simply age out (short-lived); on next sign-in the user goes
through the tenant primary. Roster precedence then applies.

## UX inventory — what gets designed and built, and where

Four audiences. Privileged pages live on the auth origin (sessions +
CSP inline-hash regime); marketing on www. The apex-vs-`idp.` open
question concerns only the tenant IdP endpoints named by `host=`, not
these pages.

**A. Prospect (www, static):** "BrowserID for your domain" landing +
docs. Trails the build.

**B. Domain-owner onboarding (apex, signed-in) — the front door:**

- "Your domains" section on /account: domains you admin + "Add a domain".
- Add-domain wizard (`/domains/add`), three steps:
  1. domain entry + preflight (zone DNSSEC? already primary/tenant? MX?)
     so expectations are set before any key is generated;
  2. record screen: generated TXT, copy button, per-registrar
     instructions, and the explicit "publishing this record makes this
     account the admin" sentence;
  3. live checker with distinct states — not seen / seen-but-insecure /
     bogus chain / wrong key (another attempt or self-hosted) /
     validated→activated — each with a diagnostic. Attempts persist
     across sessions (DNS takes hours); notify by email/account on
     validation.
- This wizard IS the roadmap's record generator + DNSSEC checker.

**C. Tenant admin console (apex, `/domains/<domain>`, admin-gated)** —
first real table-and-CRUD admin UI in the product:

- Overview: status, continuous DNS-health monitor (broken record ⇒ RPs
  are rejecting now ⇒ red banner + admin notification), key info +
  rotation, counts.
- Users (roster): table (local part, state, auth method,
  email-reachable, last sign-in); create-user modal (admin types or
  generates a password, shown once); per-user reset / disable / revoke /
  device+agent view (reuse account-page list patterns).
- Admins: add/remove by identity; recent-strong-auth gate on
  destructive actions.
- Settings: self-claim toggle, auth methods, branding later.

**D. Tenant end user — a NEW hosted-primary surface; the existing
dialog is not touched (decided 2026-08-08):**

The dialog already hands off to primaries (sandmill.org, mingo.place);
a hosted tenant must be indistinguishable from them. So tenant users
are served by a **new page set implementing the §7 primary contract**,
declared in the tenant support doc and reached only via discovery +
`host=` — never by dialog special-casing:

- `authentication` page: password login for rostered users, email-loop
  ceremony where policy allows; forced password-change on first
  sign-in; passkey enrollment later.
- `provisioning` + `device-authorization` pages per §7 (backend
  device-cert/mint APIs reused; the browser-facing pages are new).
- `device-revoke` page (tenant-scoped).
- "Forgot password" for an email-less rostered user is admin-only by
  construction — the page must say "contact your domain admin", never
  dead-end.
- No `address_info` changes, no dialog lanes, no fallback-surface CSP
  churn. The claim-time hierarchy already stops fallback issuance the
  moment the tenant record validates; the dialog then simply sees a
  primary.

This surface + the registrar crate is the substance of the future
self-hostable "primary kit" — building it standalone advances the
extraction story.

/account works for tenant users as-is (devices, agents, revocation).

Design-brief order (approval-dialog-brief style): wizard + checker
states first, hosted-primary authentication page second (needed by the
first rostered sign-in, Phase 1/2 boundary), console users-table +
display-once password modal third, marketing last.

## Guardrails

- **Non-goal guard:** this is BrowserID-primary hosting, not an
  OAuth/SAML SSO product — no OIDC provider surface, no enterprise
  directory sync. The roadmap's non-goals stand.
- **Centralization mitigations:** per-tenant keys + DNS off-ramp
  (settled), issuance transparency log covers tenant issuance too
  (Theme 3), and the eventual kit extraction is the self-host story.
- **Abuse:** tenant onboarding inherits the fallback abuse audit (o92d);
  quotas per tenant; the identifiers-changing-hands policy (Theme 3)
  gains a concrete instance — domain expiry/transfer with a live tenant —
  and should be written before GA.
- **Custody:** custodial private keys are the crown jewels; encrypted at
  rest, rotation runbook per tenant from day one (generate → tenant
  updates TXT → old key retired after DNS TTL).

## Phases

- **Phase 0 — spike (prove the spine):** hand-inserted tenant for a test
  domain we control; per-tenant key wired into device-cert + mint;
  verify with browserid-rp that `iss = tenant` validates zero-config over
  the real DoT path, including `host=` redirect of the support-doc fetch
  and tenant-scoped status. Exit: a guestbook sign-in as
  someone@testdomain with the tenant as issuer.
- **Phase 1 — tenancy substrate:** tenant/admin/roster tables, encrypted
  custodial keys, issuance routing, roster CRUD + password auth +
  precedence rules, tenant-scoped status lists. API-first; no console UI.
- **Phase 2 — onboarding funnel:** record generator, DNSSEC
  checker/poller with diagnostics, activation + first-admin seeding, all
  on /account.
- **Phase 3 — admin console:** roster UI (create user / set password /
  disable), device+agent visibility per user, revocation, policy toggles,
  admin management.
- **Phase 4 — hardening & product:** quotas, domain-transfer policy,
  transparency-log coverage, key-rotation self-serve, docs + pricing.

## Open questions (not blocking Phase 0)

- **Surface origin:** does `host=` point at the apex broker origin or a
  dedicated `idp.` subdomain on the identity host? Now leaning strongly
  **dedicated**: the tenant-user §7 pages are a new surface by decision
  (no dialog changes), so a separate origin keeps the fallback dialog's
  CSP/cookie regime untouched and makes the primary-kit extraction
  boundary physical.
- **Password bootstrap UX:** admin reads a temp password out-of-band vs
  an invite link (link requires *some* reachable channel; the email-less
  requirement means out-of-band must always work).
- **Tenant-scoped branding** of auth pages (logo/name), and whether the
  dialog should show "via browserid.me" for custodial tenants.
- **Roster ↔ pre-existing self-claimed identity collision:** admin
  creates a roster entry for a local part that already self-claimed —
  adopt, or block until the admin confirms takeover? (Security-sensitive;
  decide in Phase 1.)
