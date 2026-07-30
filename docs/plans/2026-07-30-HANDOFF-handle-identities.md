# HANDOFF — handle identities (`<label>@<handle>`) + the authority hierarchy

Read this, then the design note:
**`docs/plans/2026-07-30-handle-identities-and-the-authority-hierarchy.md`** —
that doc is authoritative for the design; this one is for getting productive
fast and for the things that are easy to get wrong.

**Status: design settled, nothing implemented.** No code has been written for
this. Epic **`browserid-ng-tsqk`** with five children (`beans show
browserid-ng-tsqk`).

## 1. What we're building, in one paragraph

An atproto handle is a domain name, so a Bluesky user's browserid identity
becomes `<label>@<handle>` — default `me@dan.bsky.social` — putting the handle in
the **domain** position where browserid's per-domain discovery already looks.
That gets us the email fallback→primary hinge for free: an unsigned handle domain
reads as "no primary", so browserid.me may vouch for it; the day that domain
publishes a DNSSEC-validated `_browserid` record it becomes a primary and the
fallback stops being accepted — same identity string throughout. This replaces
the current `<handle>@bsky.browserid.me` shape, which is anchored to a domain we
own and can therefore never be handed over.

## 2. The five things that are easy to get wrong

These were each established by reading the code this session. Getting any of them
wrong produces something that looks right and isn't.

1. **`iss` must be `browserid.me`.** The tempting shortcut — have `address_info`
   present the handle domain as a *primary* with `device_auth` pointing at the
   bridge, so the existing primary lane runs verbatim — **does not work**. It
   fails twice: `dialog.js` `finishPrimaryCerts` rejects certs unless
   `dc.iss === domain`, and the broker's `resolve_conformant_key`
   (`browserid-broker/src/verifier.rs:366`) requires `iss` to be an accepted
   fallback for a no-primary domain. Certs cannot claim `dan.bsky.social`.
2. **Verification does not change. Do not touch the verifier.** An RP verifying
   `me@dan.bsky.social` runs today's rule unmodified: no primary → `iss` must be
   an accepted fallback → browserid.me. This is the central property of the
   design — every RP that already trusts browserid.me for email gets handle
   identities with no new configuration, and no verifier ever touches DoH,
   plc.directory, or PDS metadata. If a change starts requiring verifier edits,
   stop and re-read the design note.
3. **Hierarchy step 2 is "a binding that RESOLVES", not "an `_atproto` TXT
   exists".** atproto has two resolution methods and hosted handles commonly use
   the HTTPS one (`https://<handle>/.well-known/atproto-did`, served per-`Host`
   by a stock PDS). Use the both-methods, DNS-wins-on-conflict logic in
   `browserid-bsky/pds-bridge/src/idp/resolve.rs`, **including the mandatory
   bidirectional `alsoKnownAs` check**. A forward-only binding is
   `handle.invalid` and must fall through to MX.
4. **Hierarchy step 1 means DNSSEC-*validated*.**
   `browserid-broker/src/fallback_fetcher.rs` takes the identity key only from a
   secure record; an *insecure* (unsigned) `_browserid` record is ignored and the
   domain still reads as no-primary. That branch is also what makes this whole
   design work — unsigned handle domains fall to the fallback rather than erroring.
5. **Scope asymmetry.** SMTP proves a **local part** (one mailbox); atproto proves
   the **whole domain**. So an SMTP-proven identity may only issue for the proven
   address, while a handle-proven domain may issue for any label. Enforce this
   from the **stored** proof method on the identity, not re-derived per request.
   Backwards in one direction breaks agents; backwards in the other is a
   domain-wide escalation from one verified mailbox.

## 3. The hierarchy (claim-time routing, NOT a verification rule)

For a domain with no primary, decide which proof to demand:

1. DNSSEC-validated `_browserid` record → it's a primary; we don't issue at all
2. A resolved atproto handle binding → atproto OAuth
3. An MX record → the SMTP verification loop
4. Otherwise → refuse the claim

**No pinning** — re-derived on every issuance. Whoever can publish `_atproto` for
a name can already redirect its MX, so pinning would buy detection rather than
prevention while blocking legitimate migrations.

## 4. Build order

`beans show browserid-ng-tsqk` for the tree. Two roots, nothing else blocked:

- **`browserid-ng-5kf3`** — hierarchy in `address_info` + the `stage_email` MX
  gate. Files: `browserid-broker/src/routes/email.rs` (`address_info` at :500,
  `stage_email` at :270, `AddressInfoResponse` at :436).
- **`browserid-ng-031k`** — bridge endpoints (resolve-only, cached; and the
  signed attestation after the OAuth hop). Repo: **`~/src/browserid-bsky`**,
  `pds-bridge/src/idp/`. Signs with the existing `bsky.browserid.me` IdP key.

Then:

- **`browserid-ng-77mw`** (blocked by `031k`) — broker accepts the attestation,
  attaches `me@<handle>` to the session's account, records the proof method,
  issues via the existing fallback path (`routes/fallback_idp.rs`, unchanged in
  shape).
- **`browserid-ng-xcy6`** (blocked by `5kf3`) — dialog. **No atproto-specific
  UI**: the identity is just an address typed into the ordinary email field. Once
  it's verified on the session, `completeSignIn` → `issueDevicePair` →
  `/device/issue` runs unchanged; the only new step is one navigation out to the
  bridge and one return, reusing the redirect/popup + resume machinery. Plus the
  copy: "Bluesky user? Try `me@<your handle>`", and treat a bare handle-shaped
  input with no `@` as a suggestion rather than an error.

**`browserid-ng-jaa1` is an open DECISION, not a work item** — whether to revoke
outstanding certs when a domain's authority flips. Don't silently implement it;
it's deliberately `draft` and belongs to a larger deferred conversation about
identifiers changing hands.

## 5. Architecture: the bridge stays the atproto specialist

The broker is the **issuer**; the bridge does the atproto work and returns a
**signed attestation** ("DID X holds handle H, verified at T"). This avoids
duplicating `oauth.rs` / `resolve.rs` / `net.rs` (SSRF guards) / `pins.rs` into
the broker, and keeps atproto deps and registered OAuth client metadata out of
it. The bridge is a trusted internal component of the fallback here, not a third
party — that trust boundary is deliberate and should stay documented.

Cache the resolve-only check. Do not put an uncached cross-service call on the
critical path of every `address_info` for a no-primary domain.

## 6. Known risk, decided: the A/B conflation

A domain could route `foo@example.com` to user A's mailbox while `example.com` is
user B's handle. Atproto wins under the hierarchy, so B can claim
`foo@example.com`. **This is documented, not mitigated in code.** The advice to
such a domain is: sign your zone, publish `_browserid`, become a primary — then
you can express both users, which the atproto path cannot do because it proves
the whole domain by construction. Decision made; don't relitigate it in the
implementation.

## 7. Pre-flight before shipping the MX gate

Adding the gate changes the proof method for any existing verified address whose
domain also resolves as a handle. That's a **lockout** risk, not a security one,
and a delayed one — certs last 90 days, so it surfaces weeks after deploy as
"I can't sign in anymore".

Run 2026-07-30: **clear** — none of the five prod domains
(`bsky.browserid.me`, `mingo.place`, `sandmill.org`, `example.com`, `gmail.com`)
resolves as a handle. Zero identities would change lane. The realistic collision
class is *apex-domain* handles (people set their Bluesky handle to their bare
domain, and bare domains have MX) — it just happens to be empty for us.

**Re-run it immediately before shipping**, it's a snapshot. If it ever hits, the
fix is a one-time backfill of the proof method onto pre-existing identities — a
grandfather clause, not general pinning, so it doesn't reopen §3.

Query used:
```
ssh sandmill.org "sudo sqlite3 /var/lib/dokku/data/storage/id/browserid.db \
  \"SELECT DISTINCT substr(email, instr(email,'@')+1) FROM emails WHERE verified=1;\""
```
then for each domain check `_atproto.<d>` TXT, `https://<d>/.well-known/atproto-did`,
MX, and `_browserid.<d>`.

## 8. Migration of existing `<handle>@bsky.browserid.me` identities

They keep working — `bsky.browserid.me` publishes `_browserid` and has no MX, so
it lands on hierarchy step 1 (primary) and is untouched. No automatic migration:
the strings are different identities, and existing warrants, holder labels and
guestbook entries point at the old ones. Users who want the new shape claim it
and re-authorize.

## 9. Workflow gotchas (each cost time this session)

- **e2e needs a warm broker.** Playwright's `webServer` uses
  `reuseExistingServer`; if nothing is on :3000 it runs `cargo run` and tests
  race the compile, producing ~34 failures across unrelated specs that look
  exactly like real regressions. Build and start it first — and note the binary
  is in the **shared target dir**, `~/.cache/cargo-target/debug/browserid-broker`,
  not `./target/`. Warm baseline: 0 failed / 76 passed / 2 skipped / 3 did not
  run ("did not run" is normal). Never read e2e results from a `tail`ed log —
  the `N failed` header scrolls off.
- **Deploy = `git push origin main`**, then GitHub Actions builds the image and
  runs `dokku git:from-image`. `git push dokku main` is wrong and will be
  rejected; the `dokku` remote's HEAD is a generated one-line Dockerfile with the
  source deleted. Verify with `git show dokku/main:Dockerfile`.
- **CSP:** editing an *inline* script in broker static HTML requires updating
  `INLINE_SCRIPT_HASHES` in `browserid-broker/src/routes/mod.rs`. `dialog.js` is
  external, so it's unaffected.
- Cross-repo: bridge work lives in **`~/src/browserid-bsky`** (read its
  `docs/plans/2026-07-28-HANDOFF.md` first).

## 10. Context you may want

- The strategic trade is written down at the end of the design note: making the
  atproto fallback this good reduces pressure on hosts to become primaries (the
  BigTent lesson). Accepted deliberately; the lever is making the *primary's*
  benefits legible, not making the fallback worse.
- Superseded: the identity shape in
  `~/src/browserid-bsky/docs/plans/2026-07-27-bigtent-bsky-idp-design.md`. The
  rest of that document (resolution, pins, scopes, SSRF posture) still stands.
