---
# browserid-ng-rrve
title: Second-browser-cold browsers-prefix reconciliation
status: completed
type: task
priority: low
created_at: 2026-07-21T21:02:32Z
updated_at: 2026-08-26T23:08:06Z
parent: browserid-ng-oup3
---

A SECOND browser signing in cold (account exists, browsers namespace in use) gets an IdP-self-assigned holder whose prefix cannot be adopted (adopt_namespace_prefix refuses while in use) -> lands Uncategorized until re-issue. Design + build the reconciliation (e.g. warm re-key on next login). Documented edge in the deep-dive note.

## Fix built (2026-07-22, per Dan's ruling): re-issue under the canonical prefix, one popup
Dan confirmed the bug shape: device 2 cold login self-assigns a fresh prefix, adoption fails (browsers taken), holder orphans into a duplicate namespace. Settled fix = re-issue after join (password-first rejected on UX).

Implementation (popup lane):
- dialog.js primaryPopupFlow gains hold mode (`&hold=1`, only when no cached browser holder = cold): the IdP page posts certs but STAYS OPEN; the resolved object carries reissue(holder)/done().
- After ensureBrokerSession, reconcileBrowserHolder() fetches /wsapi/browser_holder (session now exists); on prefix mismatch it asks the held popup to re-sign the SAME pubkeys under the canonical `<browsers-prefix>.<rand>` holder, replaces the stored pair, drops the orphan localStorage cache, and re-joins so the broker upserts the corrected config-cert row. First-ever device (adoption succeeded) just releases the popup. All failures non-fatal (keeps the working, mislabeled pair) — incl. IdPs that ignore hold (popup closed -> immediate reject).
- mingo device-authorize: hold mode implemented (postMessage certs, await browserid:reissue/done from return_origin, one re-issue, close; 60s auto-close).

Remaining:
- [x] lazy-IdP robustness (Dan's ask): reissue falls back to RE-OPENING the authorize popup with the canonical holder as an explicit param — plain passthrough all IdPs already implement, so sandmill cold logins reconcile WITHOUT sandmill changes; hold mode is now just an optimization (no second popup flash). Popup-blocked re-open degrades to today's behavior. sandmill hold support = optional nice-to-have.
- [x] redirect-mode lane (primaryRedirectHop resume) + FedCM lane reconciliation — redirect lane done via reissueViaRedirectHop (62f794a, i8a2); FedCM investigated and needs no reconciliation (never writes device-cert rows)
- [x] cleanup: existing orphaned namespaces from pre-fix cold logins — resolved by design: server backstop register_orphan_browser_move self-heals orphans on next sign-in (i8a2); residual re-categorize UI tracked in 10n1 (re-categorize UI bean 10n1 overlaps)

## Summary of Changes

Cold second-browser logins no longer orphan their holder. The popup lane got a held-popup re-issue with a lazy-IdP fallback (d3e8e14, 47b29cb); i8a2s 62f794a closed the two remaining lanes — the redirect lane repairs via a second same-tab hop (reissueViaRedirectHop, at most once per sign-in), and a server-side backstop (register_orphan_browser_move) guarantees correct categorization immediately and re-issue on next sign-in even if every client lane fails. FedCM needs no reconciliation. Pre-fix orphans self-heal on their next sign-in; the re-categorize account-UI work is tracked in bean 10n1. (Closed by audit 2026-08-27; work landed under sibling bean i8a2.)
