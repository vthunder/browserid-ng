---
# browserid-ng-u7t8
title: 'Explore: +label self-authoritative agent identity (inbox@domain authoritative for inbox+label@domain)'
status: todo
type: task
priority: high
created_at: 2026-07-17T14:30:49Z
updated_at: 2026-07-17T14:31:14Z
parent: browserid-ng-mr2n
---

Roadmap item 4 (see the CLI-auth epic). The elegant path to an agent identity for an external primary that doesn't self-host agent provisioning.

## Idea
Make it an official spec rule that `inbox@domain` is authoritative for any `inbox+label@domain` subaddress (RFC5233-style plus-addressing, already an inbox=inbox+label convention). Then `danmills@sandmill.org`'s existing classic cert + key can self-authorize a `danmills+mingo-cli@sandmill.org` AGENT identity: the base identity directly warrants the agent key as the +label subaddress, no sandmill.org IdP mint and no browserid.me hosting.

## What to determine
- Crypto/chain: does the standard agent presentation require an IdP-signed agent_cert (assertion.rs enforces agent cert leaf), or can the base identity self-issue a +label agent cert (base key signs it), spec'd as valid? Trace assertion.rs / certificate.rs / warrant verification.
- browserid verification: would a `danmills+mingo-cli@sandmill.org` agent cert, self-signed by the danmills@sandmill.org key, be accepted under a +label-authoritative rule? What changes in verify?
- sbo attribution: does the daemon's attributed_email / resolve_creator need to canonicalize `x+label@d` -> `x@d` for `roles.admin` matching (so a +label agent write matches admin = danmills@sandmill.org)? OR do we match the +label form directly? Trace validate.rs resolve_creator + evaluate.rs canonical_name_ref.
- Security: the +label-authoritative rule means anyone holding the base cert controls all +label variants (intended). Any downside (e.g. an RP that treats x+label@d as a distinct principal)? Note it.

Deliverable: is (4) feasible, what exact spec + code changes it needs (browserid cert verify + sbo attribution), and whether it beats (3). Read-only exploration first.
