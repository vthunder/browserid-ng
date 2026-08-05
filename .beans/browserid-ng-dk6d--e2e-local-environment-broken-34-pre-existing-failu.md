---
# browserid-ng-dk6d
title: 'e2e local environment broken: 34 pre-existing failures + dead second-broker path + untrustworthy summaries'
status: todo
type: bug
priority: high
created_at: 2026-08-03T14:32:39Z
updated_at: 2026-08-05T01:00:38Z
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

## Triage complete (2026-08-05) — suite is signal-bearing again: 86 passed / 0 unexplained failures

FIXED (product bugs found by the 'stale' tests — the user's skepticism was right):
- dialog: typed emails now lowercased at entry — an UPPERCASE email minted a cert for the lowercase identity and the access mint refused ('device cert not authorized for this identity'); sign-in case-insensitivity restored.
- dialog: the acceptedFallbacks refusal now NAMES the fallbacks that would work (8t8h's intended copy).
- gg5s tests updated to the current contract (set-password screen removed by the redesign; both paths land on the code-based reset screen; direct set lives at /account).
- marketing-split: binary path fixed earlier (passes).

MARKED (visible, not deleted):
- 12x test.fixme -> browserid-ng-6u70 (silent session sync v2 acceptance spec).
- 2x test.fixme cross-origin-rp (popup flow, logout): harness cannot fetch the broker cross-origin ('Failed to fetch' from the RP page) — the CAPABILITY is verified live daily (mingo.place is a cross-origin RP); rewrite the harness.
- 11x test.skip bucket B (classic provisioning-iframe lane, deleted d9a6baf/8xvi; modern coverage: device-auth-resume + bridge server tests). Final deletion pending a last port review.
- 1x test.skip keystore migration (migrateFromLocalStorage removed from keystore.js — migration era over; confirm then delete).

REMAINING REWRITES (real flows, outdated harnesses):
- guestbook agent flow: waits on the pre-redesign approval selectors; approval moved to /authorize (b5095ec) — pv-identity now lives there behind sign-in; rewrite the walk.
- paired-provisioning (74u1): drives the pre-device credential shape (secret_key/delegation/broker/idp); rewrite against the DeviceCredential flow.
