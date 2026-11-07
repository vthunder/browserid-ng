---
# browserid-ng-r71a
title: 'Approve-once pipeline: release-candidate.yml (image build, smoke, e2e in CI) gating submissions and merges'
status: in-progress
type: task
priority: high
created_at: 2026-11-07T14:23:20Z
updated_at: 2026-11-07T14:23:20Z
---

Step 1-2 of sandmill-infra/ip-approval/PLAN.md (approved by Dan 2026-11-07).

- [ ] deploy/publish workflows guarded to the canonical repo (mirror must never deploy)
- [ ] release-candidate.yml: existing test/sdk/supply-chain jobs via workflow_call, toolchain pinned
- [ ] build every production image (no push)
- [ ] smoke: start each image, require health
- [ ] Playwright e2e against the broker image in CI
- [ ] green on the staging mirror
- [ ] ip-submit.sh requires all mirror check runs green for the sha, names = required set
- [ ] ip-merge.sh opens + merges from the approved sha
- [ ] branch protection on main requires every release-candidate job
