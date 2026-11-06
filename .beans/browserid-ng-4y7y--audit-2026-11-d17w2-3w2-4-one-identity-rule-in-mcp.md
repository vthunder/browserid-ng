---
# browserid-ng-4y7y
title: '[Audit 2026-11] D17/W2-3/W2-4: one identity rule in mcp-auth and gate (exactly one @, domain-only folding)'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T08:19:05Z
parent: browserid-ng-ag1l
---

Findings: D17 = W2-3 (mcp-auth) + W2-4 (gate): the JS verifiers do not apply the one identity rule (core §5 / S2: domain folded, local part byte-exact, exactly one @). Severity: Low (needs an IdP in the admin's own domain that issues case-variant local parts to different people; malformed subjects need a non-hosted login path). Refuted in wallet-service, sdk/js, hosted_idp and python. Decision: Q26 settled 2026-11-02: (a) byte-exact comparison per spec (domain lowercased only); (b) would normalize allowlists at config time with a warning.

Where: sdk/mcp-auth/index.mjs:71 (splitEmail splits on the last @, so a@b@c.com is an identity with local part a@b), :87 (granteeCovers("*", s) is s.includes("@"), admitting "@", "@x", "nobody@"); sdk/gate/src/gateway.mjs:687, :779 (admin check lowercases the whole email), src/mount.mjs:61, :318 (allowlist and verified grantor lowercased), config.mjs normEmail, connectauth.mjs userFor.

Change: one parseIdentity / identityEq / granteeCovers in mcp-auth (exactly one @, non-empty parts, domain-only folding, mirroring core identity::email_parts) used by every comparison in mcp-auth and gate; under (b) additionally normalize gate allowlists at configuration time with a warning and compare exactly at admission.

Acceptance:
- un-skip sdk/mcp-auth/test/audit_2026_11_ws4.test.mjs: "D17: a string with two '@' is not an identity", "D17: granteeCovers('*') must not admit a malformed subject"
- un-skip sdk/gate/test/audit_2026_11_ws4.test.mjs: "D17: the admin gate must not fold the local part", "D17: the grantor gate must not fold the local part"
- delete the D17 rows from EXPECTED_FAIL in sdk/mcp-auth/test/conformance-vectors.test.mjs (A-REJ-07..10) and sdk/gate/test/conformance-vectors.test.mjs (P-OK-nn/case probes, A-REJ-07..10 in policy mode)

Reports: ws4 §1.6, ws2 §2 (W2-3, W2-4). Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Decision Q26 (a): one identity rule (spec §5 / core `identity::email_parts`) in mcp-auth and the gate — exactly one `@`, non-empty parts, domain case-folded, local part byte-exact.

- sdk/mcp-auth/index.mjs: new exported `parseIdentity(s)` (`{local, domain}` or null) and `canonicalIdentity(s)` (canonical spelling or null); `identityEq` and `granteeCovers` are built on them. `granteeCovers("*", s)` now covers only a well-formed identity (`@`, `@x`, `nobody@`, `a@b@c` are refused); `*@domain` rejects an empty or `@`-bearing domain. The old last-`@` `splitEmail` is gone. Types and README updated.
- sdk/gate: every comparison goes through `identityEq` / `canonicalIdentity`; no whole-email lowercasing remains. `gateway.mjs`: `adminEmail` is the canonical spelling (throws if `--admin` is not an identity); admin login, session checks, `requireSession`, the root route, `accessFor`, role-member and address-book normalization, the signed-row filter in `grantsDiff` all use `identityEq`. `mount.mjs`: the allowlist is stored canonically and the verified grantor is canonicalized (not lowercased) before the allowlist / roles / entitlement lookups; a malformed grantor is refused. `connectauth.mjs`: the member session email is used verbatim. `config.mjs`: `normEmail` folds the domain only and rejects non-identities. README note on the admin comparison.

Tests: un-skipped "D17: a string with two '@' is not an identity" and "D17: granteeCovers('*') must not admit a malformed subject" (mcp-auth) and the admin-gate / grantor-gate D17 tests (gate); the two "today … folded" pins were deleted. roles.test.mjs's legacy-allowlist migration now expects `Friend@example.com` (local part preserved). Conformance: A-REJ-07..09 un-listed in mcp-auth; A-REJ-07..10 and all eleven `P-OK-nn/case` probes un-listed in the gate.
