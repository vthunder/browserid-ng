---
# browserid-ng-hg9r
title: Scope parameter min_reputation (indexer + score) end to end
status: completed
type: feature
priority: normal
created_at: 2026-09-16T13:10:07Z
updated_at: 2026-09-16T13:38:20Z
---

For browserid-pay's reputation design (~/src/browserid-pay/docs/plans/2026-09-16-reputation-design-draft.md): a contract:agreement grant may say 'with any agent rated >= N at <indexer>'. Shape { indexer: https origin, score: 0..100 }. Audience-enforced (custodian/SDK query the named indexer); stricter = higher score, same indexer. Touch points mirror cap/counterparties/max_duration (ac6167c..a310de7).

- [x] core ScopeParams + MinReputation + strictness + tests
- [x] registrar validate_scope_params
- [x] scope-labels.js valid + label
- [x] wallet/src/request.js, sdk/agent, sdk/wallet, warrant.json, protocol §5
- [x] e2e request-kinds
- [x] deploy + publish (f7df6bb; broker live, agent 0.6.1 / wallet 0.5.1 on npm)

## Summary of Changes

min_reputation { indexer: https origin, score: 0..100 } on scope entries end to end: core MinReputation + strictness (same indexer, higher score), registrar shape check, consent label 'with any agent rated N or better at <host>' (parenthetical when counterparties present), wallet/agent/wallet-MCP shape checks and types, warrant.json, protocol §5 row, e2e. Deployed; SDKs published.
