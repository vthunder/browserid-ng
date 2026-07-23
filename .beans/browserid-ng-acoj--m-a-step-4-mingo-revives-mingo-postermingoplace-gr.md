---
# browserid-ng-acoj
title: 'M-A step 4: mingo revives mingo-poster@mingo.place grantee + delegated submit'
status: completed
type: task
priority: high
created_at: 2026-07-23T14:02:51Z
updated_at: 2026-07-23T17:42:40Z
parent: browserid-ng-atge
blocked_by:
    - browserid-ng-s7gp
    - browserid-ng-nrwd
---

Revive dedicated mingo-poster@mingo.place (stable holder) from stale poster_key/create_agent_identity. Enable: request a warrant grantee=mingo-poster, grantor=user. Submit: present G's access cert + D's warrant, owner=grantor. Keep both issuers' /sys/dnssec fresh.

## DONE + deploying (2026-07-23, mingo c7a9169). Poster rebuilt as delegated mingo-poster@mingo.place service identity; 67 tests green. Deploying mingo.place + sbo-daemon (SBO_REV ae1a998 via CI).
