---
# browserid-ng-lbla
title: Friendly device labels for non-browser wallets (native apps show as bare holder ids)
status: todo
type: task
created_at: 2026-08-27T07:32:13Z
updated_at: 2026-08-27T07:32:13Z
---

Observed during the menubar-wallet prototype bootstrap (2026-08-28): the wallet's device registered on /account identified only by its holder id ("holder-t5da" style), because maybe_label_holder_from_ua only recognizes browser User-Agents — a native wallet's UA (BrowserID-Menubar-Wallet/0.1) produces no friendly label.

Options to consider:
- Teach the UA labeler a product-token convention (Name/Version → "Name" as the label) so any native client gets a sane default.
- Or accept a client-supplied label on /device/issue (validated/truncated), like /agent-provision/request already does for agent labels.
- Either way, the account page could distinguish wallet-class devices from browsers (icon/category) once they are identifiable.

Small, UX-only; no protocol change.
