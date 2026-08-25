# BrowserID for domains — be your own identity provider, with one DNS record

> browserid.me issues certificates as your domain — your users sign in as
> you@yourdomain.com everywhere, you govern every identity and agent from one
> console, and you can leave anytime.

Onboard at [browserid.me/domains](https://www.browserid.me/domains).

## Managed identities

Offboard anyone — and every agent they ever authorized — with one click. A
managed identity answers to its domain: you set the roster, the sites, and
what agents may be granted. When someone leaves, one revocation stops their
sign-ins and kills every agent grant they ever signed — everywhere.

- Roster: only identities you created (or approved) exist.
- Constraints ride in the certificates and are enforced by verifiers — not by
  trust in us.
- Users see plainly that a managed identity answers to its domain; their
  personal identities are untouched.
- Per-tenant keys, sealed and exportable — a compromise is isolated to one
  domain, and the key is yours to take self-hosted.

## How it works

Publish one record — that's the onboarding:

1. **Add one DNS record.** Add a signed `_browserid` record to your
   DNSSEC-secured zone; browserid.me operates the full identity surface as
   your domain. The issuer is *you*, not us.
2. **Your users just sign in.** Every identity is issued as @yourdomain.com —
   relying parties resolve your key straight from DNS; no one calls our
   servers to trust your users.
3. **Leave whenever you want.** Flip that same record to a key you hold and
   you're self-hosted — no migration, no permission needed, no lock-in.

## Coming soon (roadmap)

- **Directory sync** — point at your Google Workspace and your directory is
  the roster; users auto-provision on first sign-in and deprovision when you
  remove them.
- **Self-host the primary kit** — run the whole primary surface yourself, on
  your own key, from day one.

## More

- [Just need sign-in in your app? → Developers](/developers)
- [See it all working → Demos](/demos)
- [llms.txt (agent index)](/llms.txt) · [GitHub](https://github.com/vthunder/browserid-ng) · [Spec](https://github.com/vthunder/browserid-ng/tree/main/docs/specs)
