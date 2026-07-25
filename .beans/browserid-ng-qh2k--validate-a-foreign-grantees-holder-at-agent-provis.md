---
# browserid-ng-qh2k
title: Validate a foreign grantee's holder at /agent-provision/request time
status: todo
type: task
created_at: 2026-07-25T22:18:04Z
updated_at: 2026-07-25T22:18:04Z
---

Follow-up from k0s9/8v6c. The human side no longer gets burned: info now exposes grantee_holder and the page shows the generic invalid screen (A6, 'a foreign grantee must supply its holder') before anyone approves. But the REQUESTER still only learns at that point. True foreignness is approver-relative, so full validation at request time is impossible — but the cheap shape check is not: when 'grantee' is a concrete identity and 'grantee_holder' is absent, the request is only satisfiable if the eventual approver owns the grantee; a requester that KNOWS its grantee is a foreign service (it usually does — it is the service) should be told at /agent-provision/request. Options: (a) reject concrete-grantee + missing-holder outright unless a flag says 'grantee is owned by the approver'; (b) add a warning field to RequestResponse. Also validate holder shape (Holder::new) at request time when supplied.
