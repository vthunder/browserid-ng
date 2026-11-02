---
# browserid-ng-vpdi
title: '[Audit 2026-11] D19: FedCM throwaway objects: document the exception or allocate status refs'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-02T22:43:20Z
parent: browserid-ng-ag1l
---

Findings: D19. Severity: Low (every object in the FedCM presentation expires in 5 min, pinned). Decision: Q20 settled 2026-11-02: (a) accept as the documented FedCM exception and say so in core §6.3 and fb §3.2; (b) would allocate broker-list refs for both throwaway keys (two allocate_status calls per mint).

Where: browserid-broker/src/routes/fedcm.rs:296-312 (config cert + warrant with None status), :325 (status_idx: None). "Forget this site" cannot revoke the registered warrant and the per-key refs of fb §3.2 / core §6.3 do not hold.

Change under (a): spec edit only (core §6.3, fb §3.2 FedCM-exception sentence) and convert the ignored test into a documented pin. Under (b): allocate refs for both keys and keep the test.

Acceptance: under (b) un-ignore browserid-broker/tests/audit_2026_11_ws4.rs: d19_fedcm_config_cert_and_warrant_carry_status_refs; under (a) delete it and keep d19_pin_fedcm_presentation_is_bounded_to_five_minutes.

Reports: ws4 §1.7. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
