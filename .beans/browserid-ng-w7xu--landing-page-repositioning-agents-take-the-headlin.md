---
# browserid-ng-w7xu
title: Landing page repositioning — agents take the headline
status: completed
type: task
priority: normal
created_at: 2026-07-10T15:24:35Z
updated_at: 2026-07-10T17:39:44Z
---

GTM decision (2026-07-10): lead with **delegated agent identity**, demote passwordless human sign-in to a supporting feature. Full rationale: `docs/plans/2026-07-10-agent-identity-v3-and-gtm-plan.md` (§1, §7). Current page (`browserid-broker/static/index.html`) hedges across both audiences ("humans and agents").

- Hero: agents-first ("the identity layer for agents acting on behalf of people — passwordless human sign-in included").
- RP pitch: attribution/compliance angle — know which agent, for whom, with what permissions; per-agent rate limits; revocable by the principal.
- **Honest claims**: hero card currently shows `post · read` scope badges + "revocable" — only true once warrants (5zdh) and the revocation stack (egr7) ship. Mark aspirational claims as coming, or flip copy on as features land.
- Lead with the capability, not the protocol name ("BrowserID" is an awkward flag for headless identity; no protocol rename).
- Defuse Persona history explicitly if referenced: different market, not a retry.

### Todo
- [x] Rewrite hero + section order (apps/attribution → agents → humans → why → start)
- [x] Audit every claim against shipped features — scope/warrant/revocation claims now factual (warrants shipped + prod-verified 2026-07-10)
- [x] Keep the for-apps zero-registration pitch prominent (chips + get-started card)

## Summary of Changes

Hero: "Identity for agents, answerable to humans"; problem section reframed to the agent-credential mess (no identity / no boundaries / no kill switch); for-apps leads with attribution + user-signed scopes and the code sample shows who.agent.parent/scopes; for-agents shows the obtainWarrant consent flow; humans demoted to third section with approve/cut-off framing; Sign in link added to top nav (→ /account), Account removed from footer.
