---
# browserid-ng-e85i
title: 'Grant identity = (audience, scopes): batch-dedup + warrant registry keying'
status: todo
type: task
created_at: 2026-07-10T22:23:05Z
updated_at: 2026-07-10T22:23:05Z
---

Refinement surfaced by the SBO on-behalf design (sbo-8t4b, 2026-07-11). Two warrants may legitimately target the **same audience** and differ only in scopes — e.g. at one ledger, an agent-as-itself grant (`path:/shared/*`) and an on-behalf grant (`as:you, path:/u/you/drafts/*`). So a grant's identity is **(audience, scopes)**, not audience alone. Two spots assume audience-alone and must be updated:

- **g0ba (batch consent)**: `/warrant/request` currently rejects duplicate grant audiences in a batch. Change the dedup to key on (audience, scope-fingerprint) so same-audience/different-scope grants coexist in one consent.
- **jipx (warrant registry)**: `upsert_warrant` keys on (user_id, agent_email, audience) — a second same-audience warrant overwrites the first. Add a scope fingerprint to the key: (user, agent, audience, sha(scopes)). Reissue-with-identical-scopes still replaces (upsert's purpose); a genuinely different grant coexists.

Respects scope opacity: the broker **hashes** the opaque scope list for keying, never interprets it. Sqlite: the `warrants` UNIQUE(user_id, agent_email, audience) constraint (migration v8) becomes UNIQUE(user_id, agent_email, audience, scope_hash); pending-request grant dedup in warrant.rs likewise.

Not urgent — only bites when a user wants both delegation modes at one audience. Blocks nothing in the base sbo agent-write work.
