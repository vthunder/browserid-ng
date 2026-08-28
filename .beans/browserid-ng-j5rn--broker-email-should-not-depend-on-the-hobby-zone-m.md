---
# browserid-ng-j5rn
title: Broker email should not depend on the hobby zone — move sender to a browserid.me domain
status: todo
type: task
priority: medium
created_at: 2026-08-27T16:38:38Z
updated_at: 2026-08-27T16:38:38Z
parent: browserid-ng-gzq7
---

The broker (`id` on the identity host) sends login emails via Resend SMTP as
`SMTP_FROM_EMAIL=id@id.sandmill.org`. The Resend domain verification for
`id.sandmill.org` lives as DNS records in the SANDMILL.ORG zone:
`send.id.sandmill.org` (SPF TXT + MX -> amazonses.com, Resend fronts SES) and
`resend._domainkey.id.sandmill.org` (DKIM). Discovered 2026-08-27 during the
hobby-host cutover prep, when these records were nearly deleted as "old SES
leftovers" — deleting them would have silently broken every browserid.me
login email.

That is a quiet violation of the sandmill-infra rule that the domain is the
trust boundary: the identity system's core login flow depends on records in
the hobby zone, where they look like cruft and have no obvious owner.

Fix:
- [ ] Verify a browserid.me sender domain in the Resend dashboard (e.g. plain
      `browserid.me` or a `mail.browserid.me` subdomain) — adds SPF/MX +
      `resend._domainkey` records to the browserid.me zone (Namecheap, manual)
- [ ] Update the id app config: `SMTP_FROM_EMAIL=login@browserid.me` (or
      similar); refresh sandmill-infra `secrets/id.env.age` (seed-secrets or
      hand-edit) so the declared config matches
- [ ] Send a test login email and check it lands (SPF+DKIM pass headers)
- [ ] Check whether rolodexterity's `RESEND_API_KEY` also sends from
      `id.sandmill.org` before retiring anything
- [ ] THEN retire the `id.sandmill.org` Resend domain + its DNS records
      (`send.id` TXT+MX, `resend._domainkey.id` TXT) — and only then is the
      `id` A record deletable (mind RFC 4592: while `send.id` exists, `id` is
      an empty non-terminal and the `*.sandmill.org` wildcard will NOT answer
      for it)
