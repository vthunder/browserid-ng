---
# browserid-ng-u7t8
title: 'Explore: +label self-authoritative agent identity (inbox@domain authoritative for inbox+label@domain)'
status: todo
type: task
priority: high
created_at: 2026-07-17T14:30:49Z
updated_at: 2026-07-17T15:03:51Z
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

## VERDICT (2026-07-17): feasible but NOT a free cheat — needs trust-root changes in TWO verifiers

The '+' rule cannot cheat past the core requirement that the agent LEAF cert be signed by the IdP's DNSSEC domain key. That requirement is enforced INDEPENDENTLY in:
- browserid-core assertion.rs (verify: leaf issuer must == domain, verified against get_domain_key; check_structure: agent leaf + warrant mandatory) and warrant.rs (parent-cert verified under the domain key; warrant binds the agent by EMAIL, never a raw key — so no "warrant delegates to a raw agent key" path exists).
- sbo-core/attribution.rs (verify_attribution_with_warrant independently re-verifies the agent cert against the _browserid.<iss> DNSSEC key via extract_provider_key).

So a `danmills+mingo-cli@sandmill.org` cert self-signed by the danmills@sandmill.org USER key fails in BOTH cores. Making it work requires a NEW self-issued 2-link chain (domain→identity→+label-agent, verified against the identity key not the domain key) + a +label principal-relationship rule, added to browserid-core (certificate.rs + assertion.rs + warrant.rs) AND sbo-core/attribution.rs — security-critical, in two codebases. It also LOSES the per-agent revocation anchor (self-signed certs have no registrar/status, which warrant.rs verify_for currently requires) — you'd have to invent a self-hosted status scheme.

Role-matching (the part I worried about) is ALREADY solved: the daemon's `as:` path (authorize.rs warrant_effective_email) resolves the effective author to the base email (danmills@sandmill.org) when the warrant carries as:<delegator> + a path: scope — so a +label agent acting as: danmills@sandmill.org already matches roles.admin with ZERO canonicalization changes. BUT this still needs the agent cert to exist+verify (the mint) — exactly what item 4 tries to remove.

CONCLUSION: item 4 is NOT cleaner than item 3. It trades item 3's "browser.me UI + hosting" for "loosen the cert-chain trust root in two independent security-critical verifiers + invent self-hosted revocation." Recommend item 3.


## DESIGN SPEC (2026-07-17) — chosen direction per dan, over item 3

Full spec + change inventory committed at docs/plans/2026-07-17-label-self-delegation-agent-cert-design.md.

Design: name-constrained self-delegation. Chain becomes domain key -> BASE danmills@sandmill.org cert (domain-signed, short-lived) -> danmills+mingo-cli@sandmill.org AGENT cert signed by danmills' OWN identity key. NEW constrained trust path (an addition, not a weakening of the domain-signed path): an agent cert MAY be signed by an identity cert's key iff agent local-part == <base>+<label> AND <base>@<domain> == signing base cert principal AND same domain/issuer. Base cert embedded fresh at presentation (self-contained, offline-verifiable). New typ TYP_SELF_AGENT_CERT distinguishes it (fail-closed for old verifiers).

Revocation: (1) CHAIN = short-lived base cert; not renewing it kills all +label agents (expiry-driven, no CRL at the dumb primary). (2) PER-AGENT = self-issued cert bakes in a status ref pointing at browserid.me; browserid.me publishes a signed status list + /account revoke control, owner authenticated by a normal browserid assertion as RP.

Change inventory (EXISTS vs NEW, security-critical in TWO cores — must mirror):
- browserid-core certificate.rs (new typ+constructor, Medium), assertion.rs verify/check_structure (Medium/Large, high risk), warrant.rs verify_for step-6 revocation pin generalization (Small).
- sbo-core attribution.rs verify_attribution_with_warrant/_with_provider_key (Medium/Large, must mirror core exactly). Daemon as:/role-matching needs NO change (already collapses +label -> base).
- broker/registrar: new browserid.me status-authority service + account.html revoke UI (Medium; CSP hash gotcha).
- browserid-agent lib.rs + mingo login.rs: self-issue path replacing the failed /provision/mint; `mingo login --idp` becomes unnecessary.

Open questions: status-subject pre-registration at browserid.me; status-URI trust/pinning (allowlist); base-cert refresh cadence; typ-vs-claim marker; keeping the two verifiers in sync; web RPs treating x+label@d as a distinct principal.
