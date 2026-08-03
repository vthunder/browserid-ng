---
# browserid-ng-dk6d
title: 'e2e local environment broken: 34 pre-existing failures + dead second-broker path + untrustworthy summaries'
status: todo
type: bug
priority: high
created_at: 2026-08-03T14:32:39Z
updated_at: 2026-08-03T14:32:39Z
---

Found 2026-08-03 while shipping ft55; conclusively NOT a code regression — the same 34 failures reproduce against the session-start commit 77c68cf (isolated worktree build, own binary confirmed serving via a 404 on complete_handle_claim).

Three distinct problems:

1. marketing-split.spec.ts brokerBin = join(__dirname,'..','..','target','debug','browserid-broker') — dead since the 2026-07-22 shared-target-dir move (~/.cache/cargo-target). Its 3 tests can NEVER pass locally ('second broker did not start', 30s hook timeout). Fix: resolve the binary via CARGO_TARGET_DIR / cargo metadata, or an env var with the shared-dir default.

2. 34 failures concentrated in cross-origin/iframe/popup-sensitive specs: primary-idp (mock-IdP popup postMessage origin assertions, legacy GET /browserid/provision expectations), silent-assertion (communication_iframe), cross-origin-rp (iframe diag says brokerReachable: 'Failed to fetch'), include-api (watch() iframe). Playwright pinned ^1.57.0 since Dec 2025 (lockfile), but chromium_headless_shell-1234 was downloaded 2026-07-29 — suspect newer-Chromium third-party storage partitioning / cookie behavior breaking these flows in HEADLESS runs. Diagnose properly: run one failing spec headed vs headless; try launch flags (--disable-features=ThirdPartyStoragePartitioning) or config tweaks; check whether specs assume aux servers that no longer start.

3. Result-reading hygiene + count discrepancy: historical 'green' baselines summed to ~82 of the 118 listed tests, and several of this week's runs were read via tail/grep (the handoff explicitly warns the 'N failed' header scrolls off — it still bit). Fix: add a JSON reporter output (playwright --reporter=json or blob) and a tiny summary script; make the warm-broker env (DISABLE_SMTP=1 AGENT_PROVISIONING=1) impossible to forget (a just script/Makefile target).

Until fixed, the Rust suites are the merge gate; e2e is advisory.
