---
# browserid-ng-vy1a
title: 'Client/UA: managed disclosure + per-audience cert selection'
status: todo
type: task
created_at: 2026-08-11T12:29:56Z
updated_at: 2026-08-11T12:29:56Z
parent: browserid-ng-4vu7
blocked_by:
    - browserid-ng-790g
---

Broker dialog + wallet: managed-identity disclosure at add time (categorical: 'answers to its domain, no expectation of privacy from issuer' + terms link), distinct visual treatment, unmanaged→managed transition re-disclosure, mismatch rule (constraints/audience-demand on unmarked identity → treat as managed, disclose, surface inconsistency). Cert selection: cache multiple concurrent access certs keyed by audience, mint-on-miss sending audience only when marked (dialog + browserid-agent SDK). Mint-refusal UX at login ('your organization doesn't permit this identity at this site').
