---
# browserid-ng-e85i
title: 'Grant identity = (audience, scopes): batch-dedup + warrant registry keying'
status: completed
type: task
priority: normal
created_at: 2026-07-10T22:23:05Z
updated_at: 2026-07-11T00:14:07Z
---

Refinement surfaced by the SBO on-behalf design (sbo-8t4b, 2026-07-11). Two warrants may legitimately target the **same audience** and differ only in scopes — e.g. at one ledger, an agent-as-itself grant (`path:/shared/*`) and an on-behalf grant (`as:you, path:/u/you/drafts/*`). So a grant's identity is **(audience, scopes)**, not audience alone. Two spots assume audience-alone and must be updated:

- **g0ba (batch consent)**: `/warrant/request` currently rejects duplicate grant audiences in a batch. Change the dedup to key on (audience, scope-fingerprint) so same-audience/different-scope grants coexist in one consent.
- **jipx (warrant registry)**: `upsert_warrant` keys on (user_id, agent_email, audience) — a second same-audience warrant overwrites the first. Add a scope fingerprint to the key: (user, agent, audience, sha(scopes)). Reissue-with-identical-scopes still replaces (upsert's purpose); a genuinely different grant coexists.

Respects scope opacity: the broker **hashes** the opaque scope list for keying, never interprets it. Sqlite: the `warrants` UNIQUE(user_id, agent_email, audience) constraint (migration v8) becomes UNIQUE(user_id, agent_email, audience, scope_hash); pending-request grant dedup in warrant.rs likewise.

Not urgent — only bites when a user wants both delegation modes at one audience. Blocks nothing in the base sbo agent-write work.

## Summary of Changes (2026-07-11)

Grant identity is now (audience, scopes) everywhere it's keyed, via an order-insensitive opaque scope fingerprint (sha256 over the sorted scope list with separators, exported as browserid_registrar::scope_fingerprint — the registrar hashes scopes, never interprets them):

- Batch consent (/warrant/request): dedup keys on (audience, fingerprint); same-audience/different-scope grants coexist in one consent, exact duplicates rejected.
- Warrant registry: sqlite migration v10 rebuilds warrants with UNIQUE(user_id, agent_email, audience, scope_hash) and backfills the hash for existing rows; memory store matches. Same-scope reissue replaces; different scopes coexist.
- Status subjects (consistent extension beyond the two spots the bean named): warrant_status_subject carries the fingerprint too — per-grant revocation stays per-grant when two grants share an audience. /wsapi/allocate_warrant_status takes the grant's scopes; account.html reissue + manual-sign pass them. Note: pre-existing prod grants keep their old (hash-less) status subjects/indices — already-issued warrants stay revocable by embedded idx; only a reissue allocates under the new subject.

Tests: fingerprint properties (registrar), coexist/replace at the store (broker), consent_flow_test updated to the new upsert semantics; 363 workspace tests green.
