---
# browserid-ng-a93p
title: transfer_email leaves derived agent identities behind — the losing account keeps operating +tag agents of a departed parent
status: todo
type: bug
priority: high
created_at: 2026-08-29T23:50:20Z
updated_at: 2026-08-30T18:02:09Z
parent: browserid-ng-9yyk
blocked_by:
    - browserid-ng-0c49
---

Found answering 1sb3's Q5 (2026-08-30). store::transfer_email moves exactly one email row; no caller (oidc.rs, handle_claim.rs, primary.rs) touches parent_email children. After dan@gmail.com transfers from account B to account A: B retains the dan+cal@gmail.com agent rows (dangling parent pointer), their certs and warrants stay live, and — because authorize_mint for EmailType::Agent only requires a Full session on the account owning the AGENT row — B can keep minting fresh certs for sub-addresses of a mailbox it no longer controls. hg2j's revocation is scoped to the parent (user, email) pair only, so nothing cleans the children. Applies to the shipped cookie transfers today AND, unfixed, to the new §5.6 transfer. Direction (pending Dan on 1sb3 Q5): on transfer-out, revoke the loser's derived children of the departed parent (they are sub-addresses of an identity the loser no longer owns) — mirroring hg2j per child; alternatively transfer them with the parent, but that grants the new account agent identities it never provisioned. Revoke-and-drop looks right.
