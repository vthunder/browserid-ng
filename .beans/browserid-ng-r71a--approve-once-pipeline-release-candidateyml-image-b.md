---
# browserid-ng-r71a
title: 'Approve-once pipeline: release-candidate.yml (image build, smoke, e2e in CI) gating submissions and merges'
status: in-progress
type: task
priority: high
created_at: 2026-11-07T14:23:20Z
updated_at: 2026-11-07T15:34:30Z
---

Step 1-2 of sandmill-infra/ip-approval/PLAN.md (approved by Dan 2026-11-07).

- [x] deploy/publish workflows guarded to the canonical repo (mirror must never deploy)
- [x] release-candidate.yml: existing test/sdk/supply-chain jobs via workflow_call, toolchain pinned
- [x] build every production image (no push)
- [x] smoke: start each image, require health
- [x] Playwright e2e against the broker image in CI
- [x] green on the staging mirror
- [x] ip-submit.sh requires all mirror check runs green for the sha, names = required set
- [x] ip-merge.sh opens + merges from the approved sha
- [x] branch protection on main requires every release-candidate job

## Progress 2026-11-07

Branch `release-candidate` (mirror run 42386130467 at 85f56e04: all 9 rc jobs green, e2e 131 passed / 0 failed / 15 skipped, no retries). Branch protection on main now requires ip-approval-gate + the 9 rc jobs. Fixed on the way: offline DNS switch for tests (live DoT flake ~1/36), python-mcp-auth 0.2.1 (0.2.0 sdist had an extra file), e2e second broker from the image binary, iframe-failure test race.

- [ ] ip-merge.sh exercised end to end on the next approved batch
- [ ] same pipeline for sbo, mingo, browserid-pay, browserid-bsky (PLAN step 4)
- [ ] Dan sends the build-config clarification email (sandmill-infra/ip-approval/avail-build-config-email.md)
