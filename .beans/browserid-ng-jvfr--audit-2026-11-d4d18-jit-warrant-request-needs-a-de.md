---
# browserid-ng-jvfr
title: '[Audit 2026-11] D4/D18: JIT warrant_request needs a device-key signature; cap 8 grants, reject duplicate audiences, check foreign cert status'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-02T22:43:19Z
parent: browserid-ng-ag1l
---

Findings: D4 (Medium) and D18 (Low), both in the JIT warrant lane. Decision: none needed.

Where: browserid-registrar/src/consent.rs:1337-1470 (warrant_request): the body carries device_cert, identity, grants and nothing is verified against the agent's private key, so anyone who has seen an agent's public cert files consent requests in its name (consent phishing with a real agent identity on the card; spec §7.5 step 1). consent.rs:1386-1388: 1-10 grants accepted (spec: 1-8); no duplicate-audience check; a primary-issued device cert's status is never fetched (:1380-1385 checks the registrar's own list only); the /access/mint jti replay set is in-memory (browserid-broker/src/routes/device.rs:29-43), so a restart reopens the window.

Change:
- D4: require a request_proof JWS over the body hash signed by the device key (reuse the registry-api Proof shape in browserid-registrar/src/session.rs), jti single-use, iat window. /warrant/poll (code is a bearer) and record_request (audience proof) are fine.
- D18: cap grants at 8; HashSet on audiences; status check through the presentation verifier for a foreign iss; persist the mint jti cache (or document the restart window).

Acceptance (un-ignore) in browserid-broker/tests/authz_matrix_test.rs: warrant_request_needs_a_signature_by_the_agent_key, warrant_request_caps_grants_at_eight_and_rejects_duplicate_audiences. sdk/agent and the wallet must send the proof; update their tests.

Reports: ws5 §1 (D4, D18). Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
