---
# browserid-ng-16i2
title: '[M4] Golden-vector freeze test silently passes when vector file absent'
status: todo
type: bug
priority: normal
created_at: 2026-08-07T16:03:17Z
updated_at: 2026-08-07T16:03:17Z
parent: browserid-ng-8g49
---

browserid-core/src/device/tests.rs:315 guards the drift assertion with 'else if let Ok(committed)=read_to_string' — if test-vectors/device-cert-v1.json is unreadable (the case in git-dep consumers mingo/sbo where ../test-vectors doesn't exist) the freeze check silently skips. Make missing file a hard error; keep REGEN_VECTORS=1 as the only regen path. See audit M4.
