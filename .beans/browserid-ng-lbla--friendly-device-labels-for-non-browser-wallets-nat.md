---
# browserid-ng-lbla
title: Friendly device labels for non-browser wallets (native apps show as bare holder ids)
status: completed
type: task
priority: normal
created_at: 2026-08-27T07:32:13Z
updated_at: 2026-08-27T18:22:13Z
---

Observed during the menubar-wallet prototype bootstrap (2026-08-28): the wallet's device registered on /account identified only by its holder id ("holder-t5da" style), because maybe_label_holder_from_ua only recognizes browser User-Agents — a native wallet's UA (BrowserID-Menubar-Wallet/0.1) produces no friendly label.

Options to consider:
- Teach the UA labeler a product-token convention (Name/Version → "Name" as the label) so any native client gets a sane default.
- Or accept a client-supplied label on /device/issue (validated/truncated), like /agent-provision/request already does for agent labels.
- Either way, the account page could distinguish wallet-class devices from browsers (icon/category) once they are identifiable.

Small, UX-only; no protocol change.

## Summary of Changes

Implemented 2026-08-27 as the UA product-token convention (the zero-protocol-change option): `ua_label` in broker routes/holders.rs falls through to `product_token_label` when the UA is not a browser — `Name/Version …` yields `Name` (charset-validated, ≤64 chars, 'Mozilla' excluded), so a native wallet sending `BrowserID-Wallet/0.1` registers with that friendly label instead of a bare holder id. Applies automatically wherever `maybe_label_holder_from_ua` runs (auth_with_presentation join, record_device_cert). Unit tests in the same file. The client-supplied-label and device-class-icon options were not needed for this; a wallet-class icon on the account page can ride a future account-UI pass.
