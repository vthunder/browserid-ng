---
# browserid-ng-fpcc
title: '[M10] Audience matched by raw string equality; no canonicalizer in core'
status: todo
type: task
priority: normal
created_at: 2026-08-07T16:03:44Z
updated_at: 2026-08-07T16:03:44Z
parent: browserid-ng-8g49
---

browserid-core compares audiences with != (device.rs:645,675); the sbo+raw:// rule lives only in sbo-core/src/authorize.rs:180; literal sbo+raw://avail:turing:506/ hardcoded 5+ places across mingo/sbo. Fail-closed (mismatch rejects) so no takeover, but an availability foot-gun and cross-repo skew risk. Provide a canonicalization helper in core; centralize the audience constant. See audit M10.
