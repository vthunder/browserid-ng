---
# browserid-ng-dk6d
title: 'e2e local environment broken: 34 pre-existing failures + dead second-broker path + untrustworthy summaries'
status: todo
type: bug
priority: high
created_at: 2026-08-03T14:32:39Z
updated_at: 2026-08-03T14:56:01Z
---

Found 2026-08-03 while shipping ft55; conclusively NOT a code regression — the same 34 failures reproduce against the session-start commit 77c68cf (isolated worktree build, own binary confirmed serving via a 404 on complete_handle_claim).

Three distinct problems:

1. marketing-split.spec.ts brokerBin = join(__dirname,'..','..','target','debug','browserid-broker') — dead since the 2026-07-22 shared-target-dir move (~/.cache/cargo-target). Its 3 tests can NEVER pass locally ('second broker did not start', 30s hook timeout). Fix: resolve the binary via CARGO_TARGET_DIR / cargo metadata, or an env var with the shared-dir default.

2. 34 failures concentrated in cross-origin/iframe/popup-sensitive specs: primary-idp (mock-IdP popup postMessage origin assertions, legacy GET /browserid/provision expectations), silent-assertion (communication_iframe), cross-origin-rp (iframe diag says brokerReachable: 'Failed to fetch'), include-api (watch() iframe). Playwright pinned ^1.57.0 since Dec 2025 (lockfile), but chromium_headless_shell-1234 was downloaded 2026-07-29 — suspect newer-Chromium third-party storage partitioning / cookie behavior breaking these flows in HEADLESS runs. Diagnose properly: run one failing spec headed vs headless; try launch flags (--disable-features=ThirdPartyStoragePartitioning) or config tweaks; check whether specs assume aux servers that no longer start.

3. Result-reading hygiene + count discrepancy: historical 'green' baselines summed to ~82 of the 118 listed tests, and several of this week's runs were read via tail/grep (the handoff explicitly warns the 'N failed' header scrolls off — it still bit). Fix: add a JSON reporter output (playwright --reporter=json or blob) and a tiny summary script; make the warm-broker env (DISABLE_SMTP=1 AGENT_PROVISIONING=1) impossible to forget (a just script/Makefile target).

Until fixed, the Rust suites are the merge gate; e2e is advisory.

## ROOT CAUSE FOUND (2026-08-03): stale tests, not environment

The ~34 failures assert the hidden communication_iframe / classic Persona JS stack that was DELIBERATELY DELETED on 2026-07-20 (d9a6baf, refactor!, bean 3b8m). include.js contains no communication_iframe at all; watch() was ported to presentations (8xvi). Every one of these tests has been failing by design since Jul 20 — invisible because results were read through tails/greps (the very trap the handoff warns about; historical 'green' baselines counting ~82 of 118 were misreadings).

Ruled out empirically: chromium version drift, storage partitioning, Local Network Access (flag experiments + headed run all still fail 7/7 on silent-assertion), and any commit since session start (77c68cf reproduces).

Remaining scope of this bean:
1. Rewrite or delete the stale specs for the device-model/FedCM reality: silent-assertion (silent = FedCM route now), include-api iframe assertions, cross-origin-rp communication-iframe paths, primary-idp classic GET /browserid/provision expectations, transition/paired stragglers. Judge each: does an equivalent modern behavior deserve the test, or is the behavior simply gone?
2. DONE: marketing-split brokerBin resolves via BROKER_BIN / CARGO_TARGET_DIR / shared-dir default / legacy path.
3. Still wanted: JSON reporter + summary script so results can never be tail-misread again; a run script that bakes DISABLE_SMTP=1 AGENT_PROVISIONING=1.
