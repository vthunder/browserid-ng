---
# browserid-ng-77mw
title: 'Broker: accept handle attestation, issue as fallback'
status: todo
type: feature
priority: normal
created_at: 2026-07-30T20:35:08Z
updated_at: 2026-07-30T20:35:08Z
parent: browserid-ng-tsqk
blocked_by:
    - browserid-ng-031k
---

- [ ] New route: verify the bridge's attestation signature, attach me@<handle> to the session's account as a verified identity
- [ ] Record the PROOF METHOD on the identity (stored, not re-derived per request)
- [ ] Enforce the scope asymmetry from stored state: SMTP-proven identity issues only for the proven local part; handle-proven domain issues for any label
- [ ] Device certs issue from the existing fallback IdP path with iss=browserid.me
- [ ] Verifier: confirm NO change is needed
