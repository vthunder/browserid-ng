---
# browserid-ng-mr2n
title: 'Roadmap: CLI-auth / agent identities for external-primary IdP users'
status: todo
type: epic
priority: high
created_at: 2026-07-17T14:30:49Z
updated_at: 2026-07-17T14:30:49Z
---

Roadmap from dan (2026-07-17) after `mingo login` as danmills@sandmill.org hit the primary-IdP agent-provisioning gap (browserid-ng-3nsg). Goal: let a user whose home IdP (sandmill.org) is a classic primary WITHOUT agent-provisioning still get a CLI agent that acts as: their primary identity. Parent epic for browserid-ng-wmgb (CLI-auth) + the items below.

## 0. Shorten the mingo CLI error (quick)
The fail-fast (mingo c88d23e) is far too verbose for this case. Collapse to one line, e.g. "sandmill.org does not support provisioning agent identities". Keep the actionable hint minimal.

## 1. Fail even faster: warrant UI hides non-agent-capable parents
On browserid.me/account, when authorizing a warrant, do NOT let the user select a parent identity whose IdP doesn't support agents. browserid.me checks capability (probe the primary's /.well-known/browserid for the provisioning/mint capability) and shows the identity but disables it, labeled "does not support agents" (present-but-disabled, so it's not a confusing absence).

## 2. Personal namespace on browserid.me
Reserve a personal name -> (a) a `handle@browserid.me` identity, and (b) `handle+<label>@browserid.me` sub-identities. Foundation for (3). Relates to browserid-ng-fnr1 (reservation-only flow).

## 3. EXPLORE: browserid.me-rooted agent for an external primary
When authorizing a warrant, allow choosing a `handle+<label>@browserid.me` AGENT identity whose PARENT is an external primary, e.g. `dan+mingo-cli@browserid.me` acting as: `danmills@sandmill.org`. browserid.me CAN mint its own `+label` identity; the warrant delegates the external primary's authority to it (cross-issuer — browserid-ng-yhcx). Only surface this option when the primary itself doesn't support agents. If it works -> design UI. (Own bean.)

## 4. EXPLORE (the elegant one): +label self-authoritative agent under the primary
Can we mint `danmills+<label>@sandmill.org` WITHOUT sandmill.org's cooperation, by leaning on the '+' subaddress convention? Proposal: make it an official spec rule that `inbox@domain` is authoritative for any `inbox+label@domain` suffix. Then the EXISTING `danmills@sandmill.org` cert/key can self-authorize a `danmills+mingo-cli@sandmill.org` agent (base identity self-issues the +label agent cert / directly warrants the agent key), no IdP mint, no browserid.me hosting. Needs: (a) the +label-authoritative rule in the browserid/SBO spec, (b) cert verification + sbo attribution honoring it (attributed_email canonicalizes `x+label@d` -> `x@d` for role matching, OR roles match the +label form). If feasible this is the cleanest — generalizes to ANY primary. (Own bean.)

## 5. Build browserid.me UI for whichever of (3)/(4) wins.

## 6. BUG: "(will activate)" identity doesn't trigger IdP login/refresh
When the user is not signed into a primary, the warrant UI labels it "(will activate)" but actually using it fails "not authenticated". It should trigger a login to that IdP + a certificate refresh. Current workaround: go to an RP (mingo), log out, log in as the primary. (Own bean.)

## 7. UX: label-forward
The client (CLI) can pass a hint that becomes the label — use it in mingo cli, and refine the browserid.me UI to emphasize the LABEL (e.g. "mingo-cli") over the email. Depends on (3)/(4).

## Assessment (team-lead)
- (4) is the most elegant if it holds: no broker hosting, no IdP cooperation, universal across primaries. Explore FIRST; (3) is the reliable fallback (it definitely works — it's the mingo-poster shape with an external parent + cross-issuer warrant). The crux risk in (4) is whether cert verification + sbo attribution can honor +label-authoritative cleanly.
- (0), (1), (6) are independent of the (3)/(4) outcome and can proceed now.
- Sequence: 0 (now) -> explore 4 (+label) & 3 (broker-agent) in parallel -> pick -> 2/5/7 build; 1 & 6 as standalone UX/bug fixes.
