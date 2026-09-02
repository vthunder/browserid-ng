---
# browserid-ng-qorh
title: 'Core spec: drop browserid-warrant-v1 compatibility'
status: todo
type: task
created_at: 2026-09-02T07:35:32Z
updated_at: 2026-09-02T07:35:32Z
---

Dan 2026-09-02 (registry-api-v1 review): v1 warrants are no longer in circulation, so the v1-compat paragraph in docs/specs/browserid-ng-protocol.md §5 (browserid-warrant-v1 interpreted as v2 with binding.kind=holder, status OPTIONAL) is dead spec weight. Remove it (and the 'verifiers accept both' allowance), keep the downgrade-protection note only if it still says something. registry-api-v1 §3.1 already dropped its v1-warrant allowance in the same review. Check the broker verifier for a v1 typ branch and remove it in the same change if tests allow.
