
## Refined analysis (2026-07-11)

Discussion sharpened this to the *login* path's broker-choice half (the fallback-IdP half split out to browserid-ng-8t8h, which is higher-leverage and needs no platform bet — do that first).

**The bootstrap is the whole difficulty, and it's narrower than first thought.** When the RP opens browserid.me as a *popup*, browserid.me is top-level/first-party there, so its localStorage is accessible and (on Chrome/Firefox) unpartitioned — the third-party-cookie objection only applied to the silent *iframe* path. So the interactive bootstrap is plausible today.

**Proposed flow (feasible pending the spike):**
1. RP opens the browserid.me popup (first-party there).
2. The popup reads localStorage for the user's broker preference — or shows a "configure broker" button *before login*.
3. **The popup redirects itself to the chosen broker** (`location = broker_url`) — the broker is now first-party in that same popup, runs the dialog, and posts the assertion back to the RP opener directly. browserid.me is fully out after the redirect (the goal), and there's no second popup / popup-blocker problem. (Preferred over "return broker to RP, RP opens it," which needs a fresh user gesture for the second popup.)

**The one load-bearing risk → spike browserid-ng-dcgm:** Safari ITP engagement-based eviction of browserid.me's localStorage when it's only ever a popup. If the preference doesn't survive, either keep it warm with periodic top-level visits or concede to FedCM.

**North star:** this is FedCM. The end state ("browser steps in natively") is literally FedCM; design the polyfill to be a swappable stopgap.

Blocked on the spike before committing to build.
