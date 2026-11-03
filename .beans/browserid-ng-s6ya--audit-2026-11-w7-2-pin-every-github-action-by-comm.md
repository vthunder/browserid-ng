---
# browserid-ng-s6ya
title: '[Audit 2026-11] W7-2: pin every GitHub Action by commit SHA (plus Dependabot for actions)'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T09:14:10Z
parent: browserid-ng-ag1l
---

Findings: W7-2. Severity: Medium. Decision: Q11 settled 2026-11-02: (a) apply the SHA pins now and add Dependabot limited to github-actions.

Where: all nine workflows in .github/workflows/ pin third-party actions by mutable tag (actions/checkout@v7, docker/build-push-action@v6, pypa/gh-action-pypi-publish@release/v1, ...). A tag move runs arbitrary code with packages: write and the dokku deploy key in the deploy workflows, and with id-token: write in publish.yml (npm + PyPI trusted publishing).

Change: pin every action by full commit SHA with the tag in a trailing comment. WS7 resolved the SHAs (listed in .github/workflows/supply-chain.yml: checkout 3d3c42e5..., setup-node 949feb24..., setup-python 6d4fd22b..., setup-buildx 8d2750c6..., login-action c94ce9fb..., build-push 10e90e36..., rust-cache d1527c8f..., setup-uv 20cfd1bf..., rust-toolchain 1.85.0 cfcaf53b...); pypa/gh-action-pypi-publish needs its own lookup. Under (a) add .github/dependabot.yml with the github-actions ecosystem only. Deploy workflows cannot be test-run from a branch; verify on the first main push after merge (make deploy watches CI).

Acceptance: no test; grep for "@v" in .github/workflows returns nothing but comments.

Reports: ws7 §2. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Done 2026-11-03 on the audit-2026-11 branch.

- Every `uses:` in all ten workflow files (the nine from WS7 plus
  supply-chain.yml, whose comments now name the exact release too) is pinned
  by full commit SHA with the release in a trailing comment. SHAs were
  resolved on 2026-11-03 and cross-checked against the release tag that
  points at the same commit: checkout v7.0.1 3d3c42e5, setup-node v7.1.0
  949feb24, setup-python v7.1.0 6d4fd22b, setup-buildx v3.12.0 8d2750c6,
  login-action v3.7.0 c94ce9fb, build-push v6.19.2 10e90e36, rust-cache
  v2.9.3 d1527c8f, setup-uv v10.0.1 20cfd1bf, rust-toolchain 1.85.0
  cfcaf53b, install-action v2.89.1 682ce6c3, gitleaks-action v2.3.9
  ff98106e, and pypa/gh-action-pypi-publish 7245906f (= v1.14.3, the head of
  release/v1 today).
- `.github/dependabot.yml` added for the github-actions ecosystem only
  (weekly, grouped into one PR); cargo/npm/pip stay deliberately excluded.
- Acceptance: `grep '@v' .github/workflows` returns nothing; every `uses:`
  matches `@<40-hex> # <release>`.
- Deploy workflows cannot be exercised from the branch; verify on the first
  main push after merge (`make deploy` watches CI).
