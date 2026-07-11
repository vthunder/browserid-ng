---
# browserid-ng-0efn
title: Polyfill-selectable broker endpoint — user-chosen broker for the login path
status: draft
type: feature
priority: low
created_at: 2026-07-11T08:51:20Z
updated_at: 2026-07-11T08:51:20Z
---

Decentralization idea for the **login (user-present) path**, sibling to the cert-baked registrar endpoint (which decentralizes the headless *agent* path). From vthunder (2026-07-11) — explore later.

## Framing

When you visit an RP and click login, *something* opens to mediate. If the browser natively supports the broker APIs, it takes over (the ideal end state). If not, the RP falls back to a broker service — today, hardcoded to browserid.me. This is "RP acceptance" only in the UX sense (which service opens), not a cryptographic trust choice. A hypothetical competitor.me broker could be opened instead; there's just strong gravity toward one standard fallback.

## The idea

Let the **user** choose their broker via a polyfill, instead of browserid.me being the hardcoded fallback for everyone:

- User logs into browserid.me/account and, under an advanced setting, types a custom **broker endpoint**.
- When they later visit an RP and click login, if the browser lacks native broker APIs, the polyfill **briefly contacts browserid.me to resolve the user's broker endpoint**, then hands off to that broker for the actual flow.
- browserid.me stays only minimally in the loop (an endpoint-resolution redirect), not the full mediator.

## Open questions

- **Interaction with the fallback-IdP role.** browserid.me is also the SMTP-verifying fallback IdP for secondary emails. If the user's chosen broker is elsewhere, how does the fallback-IdP responsibility split from the mediator responsibility? (Probably: the chosen broker mediates; the fallback-IdP cert-issuance for secondaries is a separate trust the RP accepts — needs working out.)
- How does the polyfill discover the user's browserid.me session to resolve their endpoint (third-party cookie / redirect dance) without reintroducing the coupling we're trying to reduce?
- Bootstrapping: what if the user has never set an endpoint (default to browserid.me) — and how to make the resolution step fast/invisible.
- End state: native browser broker APIs make the polyfill unnecessary; this is the intermediate decentralization step.

## Related

Sibling of the corrected-role-decomposition bean (cert-baked registrar endpoint, agent path). Both are decentralization axes: this one for user-present logins, that one for headless agents.
