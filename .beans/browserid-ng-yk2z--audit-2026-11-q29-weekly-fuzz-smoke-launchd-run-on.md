---
# browserid-ng-yk2z
title: '[Audit 2026-11] Q29: weekly fuzz-smoke launchd run on the dev box'
status: completed
type: task
priority: low
created_at: 2026-11-02T22:43:21Z
updated_at: 2026-11-03T09:25:26Z
parent: browserid-ng-ag1l
---

Findings: Q29 (fuzzing cadence; Info). Decision: Q29 settled 2026-11-02: (a) weekly launchd run of make fuzz-smoke on the dev box, like the org.sandmill.cargo-sweep agent, failures written to a log Dan checks or mailed.

What: WS3 landed seven cargo-fuzz targets in the standalone fuzz/ workspace (scripts/fuzz-smoke.sh, make fuzz-smoke, nightly + cargo-fuzz 0.13 installed on the dev box), 90 s each, 0 crashes. CI is deliberately untouched (nightly toolchain, ASAN).

Change under (a): a launchd agent (~/Library/LaunchAgents/org.sandmill.fuzz-smoke.plist) running FUZZ_SECS=900 scripts/fuzz-smoke.sh weekly, log to /tmp/fuzz-smoke.log, non-zero exit surfaced. Remove the W3-1 / W3-2 guards in the targets when the clock-rule bean lands.

Reports: ws3 §2 and §4. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Q29 (a) landed: the fuzz smoke run is scheduled weekly on the dev box.

- `scripts/launchd/org.sandmill.fuzz-smoke.plist` (in the repo, modelled on `org.sandmill.cargo-sweep`): Sundays 13:00, an hour after the sweep. The job is inline in the plist (`/bin/bash -o pipefail -c …`) so it depends on nothing but the checkout's Makefile: it runs `ssh -o BatchMode=yes localtest 'cd ~/src/browserid-ng && FUZZ_SECS=60 make fuzz-smoke'` (Gatekeeper rule), strips ANSI, and ends the run with a `fuzz-smoke: OK <ts>` or `fuzz-smoke: FAILED (exit N) <ts> — see fuzz/artifacts/` verdict line; exits non-zero on failure so `launchctl print` shows `last exit code` too. stdout+stderr append to `/tmp/fuzz-smoke.log`. Not mailed (no MTA on the box); Dan's check is `tail -1 /tmp/fuzz-smoke.log` / `grep FAILED`.
- Budget: FUZZ_SECS=60 per target (the bean draft said 900; the brief fixed 60 — seven targets ≈ 8 min wall clock incl. the nightly build check), not 900.
- `make fuzz-smoke-install`: copies the plist to `~/Library/LaunchAgents/`, `launchctl bootout` (ignored if absent) + `bootstrap gui/$(id -u)`, then `launchctl print gui/$(id -u)/org.sandmill.fuzz-smoke | head -3` as the check (works from any shell; `launchctl list` only lists the gui domain from a login/ssh shell).
- `fuzz/README.md`: new "Weekly run on the dev box" section (install, check, kickstart, log).
- Installed and verified 2026-11-03: `ssh localtest 'launchctl list | grep fuzz'` → `-	0	org.sandmill.fuzz-smoke`; one manual `launchctl kickstart gui/501/org.sandmill.fuzz-smoke` ran all seven targets (10:17:13 → 10:24:56; e.g. dns_txt 2.18M runs, request_kind_json 2.04M runs, status_list 144k runs in 61 s each), 0 crashes, log ends `fuzz-smoke: OK 2026-11-03 10:24:56`, `last exit code = 0`.
- The W3-1 / W3-2 guards in the targets were already removed by bean gdo0 (the targets' comments now say "fixed, bean gdo0"); nothing to do there.
