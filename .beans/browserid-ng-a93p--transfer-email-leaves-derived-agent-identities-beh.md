---
# browserid-ng-a93p
title: transfer_email leaves derived agent identities behind — the losing account keeps operating +tag agents of a departed parent
status: completed
type: bug
priority: high
created_at: 2026-08-29T23:50:20Z
updated_at: 2026-09-08T07:40:24Z
parent: browserid-ng-9yyk
blocked_by:
    - browserid-ng-0c49
---

Found answering 1sb3's Q5 (2026-08-30). store::transfer_email moves exactly one email row; no caller (oidc.rs, handle_claim.rs, primary.rs) touches parent_email children. After dan@gmail.com transfers from account B to account A: B retains the dan+cal@gmail.com agent rows (dangling parent pointer), their certs and warrants stay live, and — because authorize_mint for EmailType::Agent only requires a Full session on the account owning the AGENT row — B can keep minting fresh certs for sub-addresses of a mailbox it no longer controls. hg2j's revocation is scoped to the parent (user, email) pair only, so nothing cleans the children. Applies to the shipped cookie transfers today AND, unfixed, to the new §5.6 transfer. Direction (pending Dan on 1sb3 Q5): on transfer-out, revoke the loser's derived children of the departed parent (they are sub-addresses of an identity the loser no longer owns) — mirroring hg2j per child; alternatively transfer them with the parent, but that grants the new account agent identities it never provisioned. Revoke-and-drop looks right.

## Summary of Changes

Closed by the hold model (0c49 step 1, 2026-09-08). On transfer, takeover or detach the parent identity's derived agent rows stay on the old account but are marked suspended: their warrant and cert status bits are set (stamped, so a return within the hold clears them), `/device/issue` refuses to mint for a suspended agent row, and the sweeper drops the agents and their records when the hold ends. Direction changed from revoke-and-drop to suspend-then-drop so a mistaken transfer can be undone within 30 days. Tests: `membership_test.rs` (both stores) and `suspended_agent_cannot_mint_on_the_old_account` in `device_cert_test.rs`.
