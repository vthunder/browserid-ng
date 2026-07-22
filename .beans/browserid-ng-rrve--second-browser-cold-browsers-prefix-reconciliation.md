---
# browserid-ng-rrve
title: Second-browser-cold browsers-prefix reconciliation
status: in-progress
type: task
priority: low
created_at: 2026-07-21T21:02:32Z
updated_at: 2026-07-22T13:45:30Z
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
- [ ] sandmill PHP device-authorize: hold support (until then sandmill cold logins keep today's orphan behavior, gracefully)
- [ ] redirect-mode lane (primaryRedirectHop resume) + FedCM lane reconciliation
- [ ] cleanup: existing orphaned namespaces from pre-fix cold logins (re-categorize UI bean 10n1 overlaps)
