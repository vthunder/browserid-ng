---
# browserid-ng-jxhb
title: '[Audit 2026-11] Q13: salt the PostHog distinct id with a deployment secret'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:21Z
updated_at: 2026-11-03T09:20:52Z
parent: browserid-ng-ag1l
---

Findings: WS7 §5 PostHog observation (no finding id in the report). Severity: Low. Decision: Q13 settled 2026-11-02: (a) salt with a server secret; closes the rainbow-table argument.

Where: browserid-broker/src/analytics.rs:114: distinct_id = u_<sha256(email)[:12]>, unsalted, so anyone with PostHog access and an email guess can confirm membership. Everything else about the analytics wiring was verified PII-safe (no raw email, code, IP or RP origin; client side pinned bundle, first-party proxy, redactor).

Change: derive the id with HMAC-SHA256 under a per-deployment secret (new env var, add to id.env.age); accept that historical ids do not join. If W7-10/W7-11 adopts the hashed id for logs, use the same salted function.

Acceptance: unit test that the id changes with the secret and is stable for one secret.

Reports: ws7 §5. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Done 2026-11-03 on the audit-2026-11 branch (not deployed).

- `browserid-broker/src/analytics.rs`: the distinct id is now
  `u_<HMAC-SHA256(POSTHOG_ID_SALT, normalized email)[:12]>` when the new
  env var `POSTHOG_ID_SALT` is set. `Analytics` carries the salt and every
  capture site (oidc, guestbook, hosted_idp x2, handle_claim, email) calls
  `state.analytics.distinct_id(email)`; the free function is now
  `distinct_id_for_email(email, salt: Option<&[u8]>)`. Added `hmac = "0.12"`
  (RustCrypto, same family as sha2) to the workspace and broker.
- Default when unset: the historical unsalted `u_<sha256(email)[:12]>`, so
  existing dashboards keep joining until the secret is turned on (then older
  ids no longer join, as decided). `main.rs` logs the salted flag with the
  "analytics enabled" line and, on a non-loopback BROKER_DOMAIN
  (`email::is_production_domain`, the same predicate as the SMTP refusal),
  warns at startup that the id is unsalted.
- Tests (acceptance): `distinct_id_changes_with_the_salt_and_is_stable_for_one_salt`
  (id changes with the secret, stable for one secret, unset == legacy
  sha256 form), `analytics_distinct_id_uses_its_salt`, and the existing
  stability test now runs salted and unsalted. Broker suite: 434 passed,
  0 failed, 51 suites. `cargo audit` still clean (329 crates).
- README configuration table documents `POSTHOG_TOKEN`/`POSTHOG_HOST` and
  `POSTHOG_ID_SALT`.
- The www client (`marketing/analytics.js`) hashes nothing: visitors are
  anonymous posthog-js ids, so there is nothing to salt there.
- Infra follow-up (not done here; sandmill-infra is out of scope for this
  branch): generate a random secret (e.g. `openssl rand -base64 32`) and add
  `POSTHOG_ID_SALT` to `secrets/id.env.age`, then `apply-apps.sh`. If W7-10/
  W7-11 adopt a hashed id for logs, reuse `Analytics::distinct_id`.
