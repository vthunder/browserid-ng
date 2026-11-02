---
# browserid-ng-uphh
title: '[Audit 2026-11] D11: attaching a key active on another account refuses or moves the whole row; stores agree'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: D11. Severity: Low (reaching the handler needs the cert's private key). Decision: none needed.

Where: browserid-broker/src/store/sqlite.rs:2836-2850: ON CONFLICT(pubkey) DO UPDATE rewrites identities, holder, login_key_id but not user_id; browserid-registrar/src/account.rs:88-96 refuses only an inactive existing row. An active key on account A attached from account B leaves user_id=A with B's holder and identities. The memory store (store/memory.rs:935-946) moves the whole row to B instead: a different wrong answer invisible to memory-store tests (memory: sqlite-only constraints need a SqliteStore test).

Change: in carried_certs refuse when existing.user_id != caller (cert_recorded_elsewhere) unless the identity is being transferred, in which case record moves the row (user_id = excluded.user_id) in the same transaction. Make the two stores agree.

Acceptance (un-ignore): browserid-broker/tests/authz_matrix_test.rs: sqlite_upsert_of_a_key_active_on_another_account_keeps_the_row_coherent (SqliteStore).

Reports: ws5 §1. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
