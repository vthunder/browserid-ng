---
# browserid-ng-o1zy
title: '[Audit 2026-11] W5-7: agent-provision/complete goes through authorize_mint; bridged parents redeem a bridge grant'
status: completed
type: bug
priority: high
created_at: 2026-11-02T22:43:19Z
updated_at: 2026-11-03T08:52:45Z
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


## Summary of Changes

- Host trait (`browserid-registrar/src/host.rs`): `AuthedUser` gains `password_proven`, `admitted`, `proved_emails` (+ `proved()`); new `MintVerdict` (`Allow{ttl}` / `NotAdmitted` / `NeedPassword` / `Reverify` / `DelegatePrimary` / `NeedBridgeProof`) and `RegistrarHost::authorize_agent_mint(&AuthedUser, parent, agent) -> MintVerdict` (default refuses).
- Glue (`browserid-broker/src/registrar_glue.rs`): `resolve_session` fills the new fields from the broker session; `authorize_agent_mint` applies the `/device/issue` bar — unadmitted sessions must have proved the parent (160l), suspended parents refuse, then `crate::mint::authorize_mint` on the parent's record under the session level (for a named agent, the record re-typed as `EmailType::Agent`, since the agent row does not exist until after signing); `Delegate(bridge)` redeems the live bridge grant through a new `bridge_grant` closure field (wired in `routes/mod.rs` to `AppState::take_bridge_grant` — a one-line edit outside registrar_glue, flagged) and returns the bridge's TTL; `Delegate(Primary)` → `DelegatePrimary`.
- Registrar (`agent_provision.rs complete_device_cert`): when the registrar would sign (no page-supplied primary cert), the verdict is taken BEFORE any side effect; refusals map to new `RegistrarError` variants with `/device/issue`'s wire shapes: 401 `password required`, 403 `Email verification expired (re-verification required)`, 403 `not_admitted`, 403 `a live bridge proof is required to mint this address`; the cert TTL is the verdict's (bridge TTL for E2).
- `mint_chokepoint_test::issuance_call_sites_are_registered` now also scans `browserid-registrar/src`: `agent_provision.rs` is the one minting file and must call `authorize_agent_mint`; the glue must call `authorize_mint`.
- Tests: new `browserid-broker/tests/audit_2026_11_w5_7_agent_provision_mint.rs` (unadmitted identity session → not_admitted; E3 parent on a Lightweight session → password required for self and handle; stale SMTP proof → re-verification; E2 parent → bridge proof required, then a recorded bridge grant redeems once for a 7-day cert, and is consumed). `TestContext` exposes `state`.
- Not done here (flagged): the approval page hop — `authorize.html` should run `/oidc/claim` / the Bluesky attestation when `complete` answers the bridge-proof refusal and retry; the server side is in place and the refusal reason is stable. Q18 (grant bound to the proving session) is its own bean.
- Also in this commit: `merged_provision_test` primary/tenant agent certs now name the agent identity exactly (core D1 drift, agreed with fix-broker).
