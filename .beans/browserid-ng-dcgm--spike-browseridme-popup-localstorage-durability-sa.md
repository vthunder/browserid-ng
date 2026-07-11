---
# browserid-ng-dcgm
title: 'Spike: browserid.me popup localStorage durability (Safari eviction) for broker-choice'
status: todo
type: task
priority: normal
created_at: 2026-07-11T13:00:50Z
updated_at: 2026-07-11T13:00:50Z
---

De-risks the broker-choice bean (0efn) with one measurement. ~1 day. Its binary result decides "build broker-choice now vs defer to FedCM," so it's cheap information resolving a roadmap fork — worth running before committing to build broker-choice.

## The one question

When browserid.me is opened as an **RP-opened popup** (top-level, first-party — NOT the silent iframe), does a broker preference written to its localStorage **persist and read back** across: (a) a different RP opening the popup, (b) a browser restart, (c) 7+ days — **in Safari specifically**?

Why this is the crux: the popup makes browserid.me first-party, so its localStorage is normally accessible and unpartitioned (Chrome/Firefox partition embedded *iframe* storage, not top-level popups). The real risk is **Safari ITP's engagement-based eviction**: Safari may evict localStorage for an origin it only ever sees as a popup (low top-level engagement) after ~7 days, silently reverting the user to the default broker.

## Method

- Minimal test RP page that opens a browserid.me-origin popup; the popup writes `broker_pref` to localStorage and reads it back.
- Measure read-back across: same RP re-open; a *second* RP origin opening the popup (opener-partitioning check); after browser restart; after 7+ days idle.
- Matrix: Safari (default ITP), Chrome, Firefox — default privacy settings.
- Also validate the **redirect-chain transport**: popup navigates browserid.me → broker origin → posts the assertion back to the RP opener through the existing winchan relay (confirm the relay tolerates the sender origin changing mid-flow; the assertion is self-verifying so origin isn't a trust boundary, but the handshake code may need to allow it).

## Outcomes

- **Survives** (incl. Safari) → broker-choice is buildable today; unblock 0efn.
- **Safari evicts** → either require a periodic top-level visit to browserid.me to keep the preference warm (workable but ugly), or concede this case to FedCM. Either way, decision made on data.

## Related

Blocks [[polyfill-selectable-broker-endpoint-user-chosen-broker-for-the-login-path]] (0efn). Independent of the replaceable-fallback-IdP work (browserid-ng-8t8h), which needs no spike.
