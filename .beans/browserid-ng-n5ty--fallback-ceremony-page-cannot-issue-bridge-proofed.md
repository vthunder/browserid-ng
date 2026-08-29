---
# browserid-ng-n5ty
title: Fallback ceremony page cannot issue bridge-proofed (E2) identities — wallet bootstrap regression
status: todo
type: bug
priority: high
created_at: 2026-08-29T10:43:40Z
updated_at: 2026-08-29T10:43:46Z
parent: browserid-ng-9yyk
---

Found by Dan smoke-testing 2026-08-29 (mac mini, native wallet, 'set up a different identity' → vthunder@gmail.com). Symptoms: page asks for the browserid password (login SUCCEEDS), then a brief red error and the window closes; wallet keeps the old identity; second attempt shows the consent screen (session persisted in the partition) and fails the same way; account page never shows the wallet.

ROOT CAUSE: /device-authorize issues via /device/issue → authorize_mint. For an E2 address (Secondary+Oidc/Atproto) the decision is Delegate(bridge): issuance requires a LIVE bridge grant (take_bridge_grant), which only the dialog's claim flow (OIDC/atproto hop) can establish. The new page only implements password auth, so E2 issuance 403s (policy_refused) after a successful password login. The OLD wallet secondary lane worked because interactiveIssuerLogin loaded /account, whose dialog popup could run the bridge claim before /device/issue. So this is a capability regression introduced by the 2jfh/d0xb convergence for E2 identities; E3 (password/SMTP) and primaries work.

FIX DIRECTION (needs a call): the ceremony page should read the identity's proof class (address_info is same-origin/allowed for the page role) and route: password bar for E3, bridge hop for E2 — either embed the dialog's claim start (popup to the bridge, needs setWindowOpenHandler in the wallet's primaryHop window, which the old interactiveIssuerLogin had and the new window does NOT) or show 'Continue with Google/Bluesky' driving the same /oidc claim endpoints the dialog uses, then /device/issue consumes the grant.

ALSO in scope (error UX): on a policy refusal the page calls fatal() then fail() which navigates away INSTANTLY — the red error is an unreadable flash. Show the error with a Close/Back action that then returns device_error; and the wallet needs a visible failure surface (macOS notification from a spawned Electron app is unreliable; menu still claims the old identity as signed in).
