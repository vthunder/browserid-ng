---
# browserid-ng-o1zy
title: '[Audit 2026-11] W5-7: agent-provision/complete goes through authorize_mint; bridged parents redeem a bridge grant'
status: todo
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-02T22:43:19Z
parent: browserid-ng-ag1l
---

Findings: W5-7. Severity: Medium. Decision: Q6 settled 2026-11-02: (b) route through authorize_mint under the approving session, and as-you agents for bridged (E2) parents must keep working via the existing bridge-grant mechanism.

Where: browserid-registrar/src/agent_provision.rs:885-892, :1391: /agent-provision/complete signs a 90-day auth cert with owns_verified_email only; it is not one of the documented exemptions in browserid-broker/src/mint.rs:25-31 and the mint_chokepoint_test source guard does not cover it. With identity_mode "self" a Lightweight or unadmitted session gets a broker-signed cert for the account's own E2/E3 address.

Change (from Q6):
- New host-trait method implemented in browserid-broker/src/registrar_glue.rs that runs authorize_mint with the approving session's level and the minted identity as input. For a handle/standalone agent the Agent email row does not exist until after signing, so the glue applies the Agent rule from the parent's record.
- Outcomes: Full session -> sign; NeedPassword / Reverify -> refuse with the same reasons /device/issue uses; Delegate(Primary) is already handled by the primary hop; Delegate(bridge) (E2 parent, self mode): the approval page runs /oidc/claim (or the Bluesky attestation), the ceremony records a bridge grant, complete redeems it like /device/issue does, cert TTL is the bridge's.
- Add agent_provision to the mint_chokepoint_test source guard.

Acceptance: no encoded test exists (the flow is long); write one in browserid-broker/tests using the mint_chokepoint_test harness covering: unadmitted session refused in self mode; E3 parent with a stale SMTP proof -> Reverify; E2-self lane requires and redeems a bridge grant; handle agent needs a Full session. Related: W4-34 (bridge grant per session, Q18 open) matters once provisioning redeems grants.

Reports: ws5 §2 and §6; decisions Q6 table. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
