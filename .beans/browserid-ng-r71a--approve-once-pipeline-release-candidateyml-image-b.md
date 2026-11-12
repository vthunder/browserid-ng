---
# browserid-ng-r71a
title: 'Approve-once pipeline: release-candidate.yml (image build, smoke, e2e in CI) gating submissions and merges'
status: in-progress
type: task
priority: high
created_at: 2026-11-07T14:23:20Z
updated_at: 2026-11-08T11:03:38Z
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
- [x] same pipeline for sbo, mingo, browserid-pay, browserid-bsky (PLAN step 4)
- [ ] Dan sends the build-config clarification email (sandmill-infra/ip-approval/avail-build-config-email.md)

## Rollout 2026-11-08

All five repos: main protected by ip-approval-gate + every rc job, enforce_admins on. Each release-candidate branch is green on its mirror (staging only, unapproved):

- browserid-ng eb8a0038: rust, sdk, audit, image {wallet,guestbook-mcp,mcp-demo,python-mcp-demo,www}, broker image + e2e
- browserid-pay af32cc4b: rust, e2e, sdk, audit, image {pay,judge,index,relay}
- browserid-bsky 1a1d2f32: rust, js, audit, image pds-bridge
- mingo 65b39a1d: rust, audit, image mingo, image sbo-daemon
- sbo 718b96b7 (MINGO_DEPLOY_REV a465b6d; same Dockerfile as 65b39a1): rust, supply-chain, fuzz, image sbo-daemon

Merge order: mingo before sbo (sbo-daemon image needs mingo's vendor/ fix). Until each repo's next batch lands, no PR can merge there without carrying release-candidate.yml.

Gap: the process is not discoverable from other repos' agent sessions (no CLAUDE.md mentions it); proposed a global ~/.claude/CLAUDE.md section, awaiting Dan.
