# Design note — handle identities (`<label>@<handle>`) and the authority hierarchy

**Date:** 2026-07-30
**Status:** Design settled in discussion; no code yet
**Supersedes:** the identity shape in
`browserid-bsky/docs/plans/2026-07-27-bigtent-bsky-idp-design.md`
(`<handle>@bsky.browserid.me`, with the bridge as a *primary* IdP for a
bridge-owned domain D). D-shaped identities are not withdrawn — see
[Migration](#migration).

## Problem

An atproto handle identity minted as `<handle>@bsky.browserid.me` is anchored to
a domain we own. It works at every RP with no RP configuration, because D is a
primary on a DNSSEC-signed zone — but it can never be handed over. If the
handle's own host later spoke BrowserID, the user's identity string would have
to change, which is a migration, not a transition. Email does not have this
problem: `dan@example.com` names its own authority, so the day example.com
publishes, the fallback stops being accepted and the *same string* keeps
working.

## The shape

**An atproto handle is a domain name.** So invert the composition:

- identity = `<label>@<handle>`, e.g. `me@dan.bsky.social`
- `me` is the default label for a user's own identity
- any label works — the handle owner owns the whole domain — so agent
  sub-identities are `claude@dan.bsky.social` rather than `+tag`
  sub-addressing under a shared domain

This puts the handle in the **domain** position, where BrowserID's per-domain
discovery already looks. No spec extension is required, and the fallback →
primary hinge falls out of the existing rule: an unsigned / no-`_browserid`
handle domain reads as "no primary", so an accepted fallback may issue; the day
that domain publishes a DNSSEC-validated `_browserid` record, `is_primary` flips
and the fallback stops being accepted for it. Same string throughout.

It also removes the escalation hazard of the other direction
(`dan.bsky.social` → `dan@bsky.social`): the authority is exactly the name the
user proved control of for the handle, never its parent, and it cannot collide
with a real mailbox at the parent domain.

## The authority hierarchy

For a domain with no primary, the fallback must decide **which proof it will
demand** before it issues. The rule, in precedence order:

1. **A DNSSEC-validated `_browserid` record** → the domain is a primary. We do
   not issue for it at all; its own IdP does.
2. **A valid atproto handle binding** → prove ownership via atproto OAuth.
3. **An MX record** → prove ownership via the SMTP verification loop.
4. Otherwise: no proof method, refuse the claim.

Three things this rule is not:

- **Step 2 is not "an `_atproto` TXT record exists."** atproto resolution has two
  methods and hosted handles commonly use the HTTPS one
  (`https://<handle>/.well-known/atproto-did`, which a stock PDS serves
  per-`Host`). Step 2 means a *binding that resolves*, via the both-methods,
  DNS-wins-on-conflict logic in `pds-bridge/src/idp/resolve.rs`, **including the
  mandatory bidirectional `alsoKnownAs` check**. A forward-only binding is
  `handle.invalid` and falls through to step 3.
- **Step 1 means DNSSEC-*validated*.** `fallback_fetcher.rs` takes the identity
  key only from a secure record; an unsigned `_browserid` record is ignored and
  the domain still reads as no-primary. A domain that wants step 1 must sign its
  zone. That is a choice available to any domain, and it is the documented
  answer to the conflation risk below.
- **This is a claim-routing rule, not a verification rule.** RPs do not evaluate
  it. See the next section — that is the point of the whole design.

**No pinning.** The hierarchy is re-derived on every issuance. If `_atproto` is
published for a name that previously verified by SMTP, the next certificate
requires an atproto sign-in. Whoever can publish that record can already
redirect MX for the same name, so pinning would buy detection rather than
prevention, while blocking legitimate migrations. BrowserID asserts *current*
ownership; identifier transfer is part of the model.

## What does not change: verification

An RP verifying `me@dan.bsky.social` runs exactly the rule it runs today:
discover `dan.bsky.social`, find no primary, require `iss` to be an accepted
fallback. With browserid.me as the issuer, **every RP that already trusts
browserid.me for email accepts handle identities with no new configuration**,
and no verifier ever touches DoH, plc.directory, or PDS metadata.

This is the central property of the design and the reason to prefer it over a
per-identity discovery extension: the atproto indirection is paid once, by us,
at claim time — never by every verifier on every request.

## One fallback, two proof methods

browserid.me is the issuer for both `foo@example.com` (SMTP) and
`me@dan.bsky.social` (atproto). We are one entity; RPs decide whether to trust
us, not which of our proof methods ran. The hierarchy is what keeps that honest:
without a precedence rule, "try whichever works" would make an identifier's
security the *weaker* of the two methods rather than the stronger.

### Known risk: the A/B conflation

A domain may deliberately route `foo@example.com` to user A's mailbox while
`example.com` is user B's atproto handle. Under the hierarchy, atproto wins, and
B can claim `foo@example.com`.

This is unlikely but real, and it is **documented, not mitigated in code**. The
advice to such a domain is: *use BrowserID.* Sign the zone, publish `_browserid`,
become a primary, and you can express both users however you like — a
distinction the atproto path cannot represent, because it proves the whole
domain by construction. A domain that declines that gets the atproto owner as
the authority for the name.

Note the scope asymmetry underneath this: SMTP proves a **local part** (one
mailbox), atproto proves the **whole domain**. The issuance rule must follow the
method — an SMTP-proven identity may only issue for the proven address, a
handle-proven domain may issue for any label. Getting that backwards is either a
broken agent story or a domain-wide escalation from one verified mailbox.

## Architecture: who runs the atproto proof

**Recommendation: the bridge stays the atproto specialist; the broker is the
issuer.** The alternative — teaching browserid-ng's broker to be an atproto
OAuth client — would duplicate `oauth.rs`, `resolve.rs`, `net.rs` (SSRF guards)
and `pins.rs`, and drag atproto dependencies and registered client metadata into
the broker.

Flow for claiming `me@<handle>`:

1. Dialog asks the broker for `address_info`; the broker runs the hierarchy and
   answers "this domain is proven by atproto, here is where to go".
2. The dialog sends the user to the bridge's authorize page, which runs the
   existing atproto OAuth hop and the bidirectional resolution.
3. The bridge returns a **signed attestation** to the broker: this DID holds this
   handle, verified at this time. It signs with its existing IdP key
   (`bsky.browserid.me` is DNSSEC-signed and already publishes one), so the
   broker verifies it with machinery it already has.
4. The broker attaches `me@<handle>` to the account as a verified identity and
   issues device certs from its own fallback IdP, `iss = browserid.me`.

The bridge is a trusted internal component of the fallback here, not a third
party — worth stating explicitly, because the attestation is a bearer claim about
identity ownership and its trust boundary should be deliberate.

The broker also needs step 2's *presence* check during `address_info`, which is
resolution without OAuth. Delegate that to a small bridge endpoint and cache it;
do not put an uncached bridge call on the critical path of every `address_info`
for a no-primary domain.

## Changes by component

**browserid-ng / broker**

- `routes/email.rs` `address_info`: run the hierarchy; add a state that tells the
  dialog to take the atproto path. Today's response shape is primary-vs-secondary;
  handle identities are a *secondary/fallback* identity with a non-SMTP proof.
- `routes/email.rs` `stage_email`: gate the SMTP loop on step 3 — refuse to mail
  a domain whose authority is atproto (or that has no MX at all).
- New route: accept the bridge's attestation, verify its signature, attach the
  identity to the session's account.
- Issuance scope: record the proof method on the identity so the local-part rule
  above is enforced from stored state rather than re-derived per request.
- `routes/fallback_idp.rs`: unchanged in shape — it already issues device +
  config certs for a verified identity on the session.
- Verifier: **no change.**

**browserid-bsky / bridge**

- New endpoint: resolve-only (is this domain a valid handle binding?), cached.
- New endpoint: attestation issuance after the OAuth hop.
- Keep the existing D-shaped primary IdP for already-issued identities.
- `pins.rs` still carries handle↔DID pinning and suspension; that machinery is
  unchanged and still bounds handle moves and takedowns.

**Dialog**

- A third sign-in lane beside "secondary password" and "primary popup": the
  atproto hop. Mechanically it is the redirect/popup shape already built for
  primary IdPs, so most of `primaryPopupFlow` / `primaryRedirectHop` applies.

## Migration

Existing `<handle>@bsky.browserid.me` identities keep working — D remains a
primary and its certs are valid. New claims use `me@<handle>`. No automatic
migration: the strings are different identities and existing warrants, holder
labels and guestbook entries reference the old ones. Users who want the new shape
claim it and re-authorize.

Pre-flight check before shipping the MX gate: confirm no currently-verified
production email sits at a domain that also resolves as a handle, which would
change its proof method on the next issuance.

## Open questions

1. **Revoke outstanding certs when a domain's authority flips?** Re-deriving the
   hierarchy does not invalidate certs already issued, so after a flip the
   previous owner keeps a working cert until expiry (90 days) while the new owner
   holds a fresh one. Flipping the status bits on authority change closes that
   window and is cheap with existing machinery. Sounds correct but possibly
   harsh; **decide before implementing**, and treat it as one instance of the
   larger deferred question of how BrowserID should handle identifiers changing
   hands in general.
2. **Label conventions beyond `me`.** Reserved labels? Any interaction with the
   existing `local+tag@domain` agent sub-addressing when both are available on
   the same identity?
3. **Hosted handles becoming primaries.** `_browserid.<handle>` under a provider
   zone likely needs a record per handle, since wildcard matching does not extend
   beneath a name that already exists. Not urgent — no provider is close to this
   — and if one ever wants it, that is the moment to consider a protocol
   extension for provider-scoped delegation.

## Why accept the adoption trade

Making the atproto fallback this good reduces the pressure on hosts to become
primaries — the BigTent lesson, where a good-enough shim meant Yahoo and Google
never adopted BrowserID. The trade is still right: a protocol nobody can use
generates no adoption pressure at all, and unlike BigTent's targets, most handle
owners are custom-domain individuals who *are* the domain owner, for whom
publishing `_browserid` is a self-serve upgrade rather than a strategic
concession. The lever is making the primary's benefits legible — multiple
distinct identities at one domain, own keys, no dependency on browserid.me —
not making the fallback worse.
