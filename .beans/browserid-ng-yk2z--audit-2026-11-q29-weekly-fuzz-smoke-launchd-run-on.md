---
# browserid-ng-yk2z
title: '[Audit 2026-11] Q29: weekly fuzz-smoke launchd run on the dev box'
status: todo
type: task
priority: low
created_at: 2026-11-02T22:43:21Z
updated_at: 2026-11-02T22:43:21Z
parent: browserid-ng-ag1l
---

Findings: Q29 (fuzzing cadence; Info). Decision: Q29 settled 2026-11-02: (a) weekly launchd run of make fuzz-smoke on the dev box, like the org.sandmill.cargo-sweep agent, failures written to a log Dan checks or mailed.

What: WS3 landed seven cargo-fuzz targets in the standalone fuzz/ workspace (scripts/fuzz-smoke.sh, make fuzz-smoke, nightly + cargo-fuzz 0.13 installed on the dev box), 90 s each, 0 crashes. CI is deliberately untouched (nightly toolchain, ASAN).

Change under (a): a launchd agent (~/Library/LaunchAgents/org.sandmill.fuzz-smoke.plist) running FUZZ_SECS=900 scripts/fuzz-smoke.sh weekly, log to /tmp/fuzz-smoke.log, non-zero exit surfaced. Remove the W3-1 / W3-2 guards in the targets when the clock-rule bean lands.

Reports: ws3 §2 and §4. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
