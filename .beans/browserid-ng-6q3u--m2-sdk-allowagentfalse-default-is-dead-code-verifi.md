---
# browserid-ng-6q3u
title: '[M2] SDK allowAgent:false default is dead code (verifier dropped subject)'
status: todo
type: bug
priority: normal
created_at: 2026-07-28T23:54:23Z
updated_at: 2026-07-28T23:54:23Z
parent: browserid-ng-wre6
---

docs/security-audit-2026-07-29.md (M2). sdk/js/index.mjs:100 reads json.subject||'user' but AccessVerificationResult has no subject field → agent-rejection branch unreachable; RPs relying on the human-only default silently accept agents.
- [ ] Derive agent-ness from grantee !== email, or remove allowAgent API + doc promise
