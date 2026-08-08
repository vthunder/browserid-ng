---
# browserid-ng-bmi0
title: '[M7] Protocol logic forked across repos with only convention keeping sync'
status: todo
type: task
priority: normal
created_at: 2026-08-07T16:03:44Z
updated_at: 2026-08-07T16:03:44Z
parent: browserid-ng-8g49
---

StoredKeypair {secret_key} format parsed in 5 places (broker config.rs:62, mingo-idp config.rs:97, mingo mingo.rs:308, bsky idp/mod.rs:214, sandmill GenerateBrowserIdKey.php:32); 3 full IdP impls; mingo-idp/src/poster.rs:344-420 hand-rolls /agent-provision wire with string-indexed response parsing (silent mis-parse on shape change) despite depending on browserid-agent. Add cross-impl conformance vectors. See audit M7.
