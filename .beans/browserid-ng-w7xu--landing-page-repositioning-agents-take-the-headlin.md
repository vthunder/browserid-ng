---
# browserid-ng-w7xu
title: Landing page repositioning — agents take the headline
status: todo
type: task
created_at: 2026-07-10T15:24:35Z
updated_at: 2026-07-10T15:24:35Z
---

GTM decision (2026-07-10): lead with **delegated agent identity**, demote passwordless human sign-in to a supporting feature. Full rationale: `docs/plans/2026-07-10-agent-identity-v3-and-gtm-plan.md` (§1, §7). Current page (`browserid-broker/static/index.html`) hedges across both audiences ("humans and agents").

- Hero: agents-first ("the identity layer for agents acting on behalf of people — passwordless human sign-in included").
- RP pitch: attribution/compliance angle — know which agent, for whom, with what permissions; per-agent rate limits; revocable by the principal.
- **Honest claims**: hero card currently shows `post · read` scope badges + "revocable" — only true once warrants (5zdh) and the revocation stack (egr7) ship. Mark aspirational claims as coming, or flip copy on as features land.
- Lead with the capability, not the protocol name ("BrowserID" is an awkward flag for headless identity; no protocol rename).
- Defuse Persona history explicitly if referenced: different market, not a retry.

### Todo
- [ ] Rewrite hero + section order (agents → apps/attribution → humans → why → start)
- [ ] Audit every claim against shipped features; gate scope/revocation copy
- [ ] Keep the for-apps zero-registration pitch prominent (it's the adoption asymmetry)
