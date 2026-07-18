# Adversarial correctness review — device-cert migration

Design: `docs/design/browserid-end-to-end-flow.md`. Plan:
`docs/plans/2026-07-18-device-cert-model-migration-plan.md`. All code cites verified.

## PART 1 — Flow traces

### (a) COLD primary login — danmills@sandmill.org
Design Stage 1→4. Plan homes: discovery=survives (P-none, already built,
`email.rs:403`/`discovery.rs`); primary device-cert issuance via popup=P5+P10;
access-cert mint=P2; warrant (self-login auto)=P4; presentation bundle=P1/P5;
RP verify=P6. **No orphan step**, BUT two under-specified spots:

- **G-1 (open, flagged as Q8).** The popup's *authenticate-then-issue* two-step
  on the primary is under-specified: how the device pubkey reaches the primary
  and the device cert returns via the same-tab handshake. Design Stage 1.3 and
  plan P5/P10 name the popup + mingo-ytrs handshake but don't nail the return
  leg. Plan already lists this as open (Q8). Acceptable, but it is on the cold
  primary critical path, so it must close before P11.
- **Sequencing note (not a gap).** P5 (client HTTP issuance) is scheduled before
  P10 (sandmill.org conformance). So the primary path exists client-side before
  any real primary implements it. Plan explicitly makes faithful primary demo
  fallback-only until P10 and says `@sandmill.org` MUST be rejected until then —
  internally consistent.

### (b) HEADLESS agent
Design Stage 1 agent variant + Stage 2. Plan homes: device-grant pairing yields
IdP-signed agent device cert=P7 (`agent_provision.rs complete()` today returns a
delegation — confirmed, `CompleteResponse{success}` + delegation-derived meta,
agent_provision.rs:382); headless mint=P2/P7; warrant request/poll=survives
(consent.rs); assertion_for emits 4-object bundle=P7. **No gap.** The
agent-needs-a-warrant invariant already holds (`browserid-agent/lib.rs:478`).

### (c) REVOKE EVERYWHERE — the weak flow
- **Warrant revoke:** clean. Broker registry status list, `consent.rs
  revoke_warrant`/`allocate_warrant_status`, RP checks warrant `status` ref →
  broker list. Homed (P4 + existing).
- **Device cert revoke:** UNDER-SPECIFIED (see G-3).
- **Config cert revoke:** NOT HOMED AT THE RP (see G-2, highest severity).

---

## PART 2 — Findings ranked by severity

### G-2 [HIGH] Config-cert revocation has no RP-checked authority
Design Stage 4 (L133-134) enumerates exactly **two** revocation authorities the
RP consults: access cert→IdP, warrant→broker. The **config cert is presented to
the RP** (L48-49) and is the warrant's signer, but the design specifies **no
status authority for it**. If a config cert is compromised, there is no
RP-visible revocation path except revoking every warrant it signed one-by-one.
The plan inherits this: P6 lists "two-authority revocation" (access→IdP,
warrant→broker) and P8 adds a "revoke config certs" UI action — but nothing
wires a config-cert status ref into the verify join. **Design gap the plan does
not close.** Either the config cert needs its own status ref (third authority)
or the doc must state that config-cert revocation == cascade-revoke its
warrants. Currently unstated.

### G-1b [HIGH] "Reuse the existing conformance check (verifier.rs:223-233)" is half-true for the 4-object bundle
Verified: `verifier.rs:223-233` does enforce primary/fallback conformance — but
it runs **once**, against `backed.certificates().first()` (verifier.rs:197), on
a **single** DNSSEC-discovered path (one `discover(email_domain)` call, :217).
The new bundle has **two independent DNSSEC-rooted paths** (access cert AND
config cert, per div-spec-core E/L102). A fallback-issued **config cert** for a
primary domain must fail the same way a fallback access cert does — that
requires running the conformance check a **second time** on the config-cert
issuer, with its **own** discovery. The plan's phrasing ("Reuse the existing
conformance check", P6 + div-rp-verifier TL;DR "already done, smallest gap")
undersells this: the *logic* is reusable, but it must be **applied twice over
two discoveries**, which is new work, not a reuse. The "CRITICAL ask already
done" framing hides the config-cert conformance leg.

### G-3 [MEDIUM] Device-cert revocation granularity vs. access-cert identity-rooted status
Plan P3 + div-agents-db: the device-cert table gets its **own** `status_idx`,
but the access cert's revocation root stays the **per-identity** index
(`cert.rs:99 get_or_allocate_status("identity", email)`). Consequence: with
several device certs for one identity, revoking **one** device cert (its
status_idx) does not, through the shared identity index, invalidate **that
device's** outstanding access certs. And because access certs are short-lived +
IdP-gated at mint, the RP-visible effect of a device-cert revocation is **nil
until the access cert expires** (enforcement is "IdP refuses next mint"). The
design never states this — L72 says "revoke one to log that device/agent out"
implying immediacy, but the mechanism gives eventual (expiry-bounded)
revocation, not immediate. Under-specified; should be made explicit (per-device
access-cert status index, or an accepted staleness bound).

### G-4 [LOW] Hosted verifier foreign-status fetch is genuinely absent (claim is honest, work is real)
Verified `verify.rs:76-105`: only refs where `r.uri == own_uri` are checked;
comment explicitly skips foreign lists. So the access cert's **IdP-hosted**
status list (a foreign list at the RP) is currently NOT checked by the hosted
`/verify`. Plan P6 correctly calls for porting `browserid-rp`'s `StatusCache`
(confirmed real + capable, `lib.rs:456-521`, does fetch+verify+cache). This
claim is accurate and the work is scoped — flagging only because it is
load-bearing for the two-authority revocation story and easy to under-budget.

---

## PART 3 — "What survives" claim audit (all verified against code)

| Claim | Verdict | Evidence |
|---|---|---|
| conformance already enforced, verifier.rs:223-233 | TRUE but insufficient for 4-obj (G-1b) | verifier.rs:223-233 runs once/one path |
| include.js opaque-token passthrough holds | TRUE | `observers.login(r.assertion)` include.js:1466; shim is segment-agnostic |
| demo RPs unchanged | TRUE | rp-quickstart delegates to `/verify`; broker/fallback-demo POST opaque string |
| device-grant pairing = agent-issuance hand-off | TRUE | agent_provision.rs `complete()` today returns delegation (must flip to cert) |
| warrant registry/status survive | TRUE | consent.rs upsert/revoke/allocate + `/.well-known/browserid-status` |
| browserid-rp StatusCache portable; hosted lacks it | TRUE both halves | rp lib.rs:456-521 vs verify.rs own_uri-only :91 |
| warrant identity-key-signed, rejects agent delegator | TRUE | warrant.rs:51 WarrantClaims, :114 guard, :136 `jws_sign(identity_key)` |

No **wrong** claims found. The two shaky ones are (1) conformance "already done"
(true for the access-cert leg, silent on the config-cert leg — G-1b) and (2) the
implicit "revoke one to log device out" immediacy (G-3). One genuine **design
gap** unaddressed by the plan: config-cert revocation authority (G-2).
