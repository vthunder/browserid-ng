<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS8: red-team PoCs

**Status:** complete, 2026-11-02. Epic `browserid-ng-ag1l`, bean
`browserid-ng-tx5r`. Scope: build a working proof of concept for every High+
candidate the earlier workstreams confirmed, plus the WS1 ordering list
(D1, D2, D3, D5, D8, W4-22, W6-3/W5-8), and walk the S1 login-page-token
phishing shape. Every PoC runs against a **local broker on :3000 or an
in-process harness**. No request touched a production host; the only
identities used are `@example.com`.

**Method.** Each PoC drives the live code along the real path a caller would
take and asserts the *vulnerable* outcome succeeds today (the mirror of the
`#[ignore]`d acceptance tests the other workstreams wrote, which assert the
fixed outcome and fail today). Rust PoCs reuse the WS6 core fixture and the
WS4 broker/wallet/mcp-auth/gate harnesses. The three new PoC test files are
`#[ignore]`d with an `// AUDIT-2026-11 <id>: PoC` comment; the JS findings
(D5, W4-22) are demonstrated by un-skipping the existing encoded tests, which
were restored unchanged afterwards. No production code was changed.

## 1. Results

| Target | Outcome | Severity | PoC location | Run |
|---|---|---|---|---|
| **D1** base identity speaks as `+tag` subaddress | **Reproduced** | Medium (holder-pinned warrants unaffected) | `browserid-core/tests/audit_2026_11_ws8_d1.rs` | `cargo test -p browserid-core --test audit_2026_11_ws8_d1 -- --include-ignored --nocapture` |
| **D2** `respond` accepts a non-IdP-signed config cert | **Reproduced** | High | `browserid-broker/tests/audit_2026_11_ws8_d2.rs` | `cargo test -p browserid-broker --test audit_2026_11_ws8_d2 -- --include-ignored --nocapture` |
| **D3** caller-chosen holder on hosted IdP | **Reproduced** | Medium | existing `d3_tenant_device_cert_does_not_take_a_caller_chosen_holder`, `browserid-broker/tests/audit_2026_11_ws4.rs` | `cargo test -p browserid-broker --test audit_2026_11_ws4 d3_ -- --include-ignored` |
| **W4-22** hosted wallet admits a delegated presentation as the human | **Reproduced** | Medium | existing skipped test, `wallet-service/test/audit_2026_11_ws4.test.mjs` | un-skip, then `node --test test/audit_2026_11_ws4.test.mjs` |
| **D5** narrowed policy row admits any holder (mcp-auth + gate) | **Reproduced** | Medium | existing skipped tests, `sdk/mcp-auth/test/audit_2026_11_ws4.test.mjs`, `sdk/gate/test/audit_2026_11_ws4.test.mjs` | un-skip, then `node --test` in each package |
| **D8** approval-code brute force | **Takeover refuted; no-limiter exposure quantified** | Medium | §2 below (measurement, no committed PoC) | — |
| **W6-3 / W5-8** zlib bomb via the status-list decoder | **Reproduced** | High | `browserid-core/tests/audit_2026_11_ws8_w6_3.rs` | `cargo test -p browserid-core --test audit_2026_11_ws8_w6_3 -- --include-ignored --nocapture` |
| **S1** login-page token to an attacker return URL | **Design finding, walkthrough in §3** | High (spec) | — | — |

All runs go through `ssh localtest` on this machine (Gatekeeper workaround);
cargo output is ANSI-stripped.

### 1.1 D1 — a base identity speaks as its subaddress

A base `user@example.com` **Authentication** cert (the browser/login key)
reports `authorizes_identity("user+agent@example.com") == true`, which is the
whole identity check `/access/mint` (`routes/device.rs`) and
`/idp/access_cert` (`routes/hosted_idp.rs`) apply, so the mint would issue an
access cert for the subaddress. A full presentation then verifies: access cert
identity `user+agent@example.com`, a config cert for the base identity signing
a warrant whose grantor and grantee are `user+agent@example.com` with a bare
`*` holder matcher, and the verifier returns `grantee =
user+agent@example.com`. This breaks attribution, the per-agent revocation
axis, and widens a browser-key compromise, as decided in Q1. The fix moves
`identity_matches` (`browserid-core/src/device.rs`); the PoC pins the current
wide behaviour.

### 1.2 D2 — `respond` accepts a config cert the broker never signed

Full HTTP flow against an in-process broker: file a self-grant with
`POST /warrant/request`, then `POST /api/v1/requests/respond` with a config
cert signed by a freshly generated **attacker** key (asserted in the PoC *not*
to verify under the broker's IdP key) and a warrant signed by that same key.
`respond` returns `200 {}` and `/warrant/poll` returns `approved`:
the forged-config grant is delivered verbatim. `validate_grant_warrants`
(`browserid-registrar/src/consent.rs:678`) checks only the config cert's
purpose, `authorizes_identity(grantor)`, and that the warrant is signed by
that cert's key; it never verifies the cert under the account's IdP key, never
confirms it is an enrolled cert on the account, and never checks its status.
The self-minted variant is the strongest demonstration; the retired/revoked
variant follows from the same missing status check.

### 1.3 D3 — the hosted IdP copies a caller-chosen holder

Run `d3_tenant_device_cert_does_not_take_a_caller_chosen_holder` (WS4's
encoded test) with `--include-ignored`: `/idp/device_cert` returns 200 and
the issued device cert's holder equals the caller-supplied
`zzzzzzzzzz.attacker` verbatim. `hosted_idp.rs:396-403` passes the body's
`holder` through with no namespace check, so a tenant user (or whoever holds
the roster password) can stamp any well-formed holder on its certs, including
the holder of another already-approved device, and satisfy holder-pinned
warrant matchers.

### 1.4 W4-22 — the hosted wallet opens the human's tenant for an agent

With the WS4 wallet-service test un-skipped (stubbed verifier, in-memory DB),
`POST /oauth/login` with a delegated presentation whose `grantee`
(`dan+agent@example.com`) differs from `email` (`dan@example.com`) returns
**200**, not 401: the agent gets full OAuth control of the human's custodied
key. A presentation without the `login` scope is also admitted (200).
`wallet-service/src/server.mjs:33-35,116-120` keys the tenant on `email` and
never compares `grantee`, after `@browserid-ng/verify` dropped `allowAgent`
(July M2) and moved that comparison to the RP.

### 1.5 D5 — a narrowed policy row admits any holder

With the WS4 mcp-auth and gate tests un-skipped: a policy row narrowed to one
holder (`binding: {kind: holder, matcher: "agents.one-specific-holder"}`)
admits a holder-less connection subject (mcp-auth: "Missing expected
rejection"), a policy row carrying a `requester` entry — unsatisfiable in
operation A — also admits, and at the gate a jwt-bearer login with a
different holder is admitted. The holder matcher is never evaluated:
`conjoinPolicy` filters by `granteeCovers` only (`sdk/mcp-auth/index.mjs:1040,
1051`), and the gate's entitlement lookup does the same while storing no
binding (`sdk/gate/src/gateway.mjs:121`, `mount.mjs:82`).

## 2. D8 — approval-code brute force (takeover refuted, exposure quantified)

The 30-bit approval-code takeover is **refuted**, consistent with WS5:
`approvals.rs:179-234` requires an enrolled session on the same account to
type the code, so only someone already inside can guess it. What the PoC
measured against the local broker is the live consequence of there being **no
429 anywhere on `/api/v1`** (`browserid-registrar/src/lib.rs:205-237`):

| Probe | Result |
|---|---|
| 600 sequential `POST /api/v1/accounts/lookup` | 600 × 401, **zero 429** |
| 3200 requests over 8 keep-alive connections, one machine | ~20,000 req/s, **zero 429** |
| Hypothetical 30-bit sweep at that rate | ~15 h full / ~7.5 h expected |

So the finding stands as a missing limiter (enumeration, approval-open floods
to `MAX_PENDING`, proof-replay-window pressure, cost), not a code-guess
takeover. Remediation is Q5's blanket per-source and per-account limiter.

## 3. W6-3 / W5-8 — status-list decompression bomb

`StatusList::decode` (`browserid-core/src/status.rs:96-106`) runs
`ZlibDecoder::read_to_end` into a `Vec` and only *then* checks the 4 MiB cap,
so the whole inflated stream is allocated before rejection. The PoC crafts a
~1 MB `base64url(zlib(...))` payload that inflates to 768 MiB of zeros, calls
`decode`, and samples the process RSS during the call:

```
crafted payload: 1042920 bytes compressed inflates to 768 MiB (4 MiB cap)
decode returned Err("status list too large"); RSS 9 MiB -> peak 845 MiB
```

An ~1 MB request drives 836 MiB of transient allocation. The same decoder is
reached **unauthenticated** through `GET /status/proxy?uri=…`
(`routes/status.rs:46`), which fetches a foreign status-list token and parses
it; WS5 confirmed that reachability. The fix caps the output during inflate
(a bounded `take`), not after.

## 4. S1 — login-page token to an attacker return URL (phishing shape)

S1 is a **design finding** (confirmed, decided), not a memory-safety or
authz bug, so it needs a walkthrough rather than a PoC.

`/wsapi/registry_login` (`routes/registry_login.rs:34-78`, code side W5-10)
mints the login-page token with **no `return_url` or origin binding**. Which
origin the minted token is delivered back to is left entirely to the page
script (`static/common/js/registry-login.js`). This conforms to reg §4.2 as
originally written; the accepted S1 spec change is what closes it.

The phishing shape:

1. An attacker stands up `evil.example` and embeds, or links to, the real
   broker's login surface so that a victim who is already signed in to the
   broker completes a login-page flow that `evil.example` initiated.
2. The broker mints a login-page token bound to the victim's session but
   **not** to any approved return origin, because the minting handler never
   receives or checks one.
3. The delivery step hands the token back to the caller-chosen location.
   Because the handler imposed no origin constraint, a return target the
   attacker controls can receive a token minted under the victim's
   authenticated session.
4. With that token the attacker drives the registry-login completion as the
   victim.

The exposure is the **missing server-side origin binding**, independent of
any single page's behaviour: hardening only the page leaves the handler
issuing "blind". Two accepted remediations: bind the token to the opener's
login-key public key passed in the URL fragment (so a token delivered
elsewhere is useless without that key), or apply fb §3.1's accepted-origins
check inside the minting handler. Either moves the decision from the page to
the broker.

Related confirmed items the same change touches: W5-10 (the handler takes no
return origin), and the W5-6 `X-Forwarded-For` caveat for any per-origin
limiter added alongside it.

## 5. Artifacts

Three new `#[ignore]`d PoC tests (un-ignore to run):

- `browserid-core/tests/audit_2026_11_ws8_d1.rs` — D1.
- `browserid-core/tests/audit_2026_11_ws8_w6_3.rs` — W6-3/W5-8.
- `browserid-broker/tests/audit_2026_11_ws8_d2.rs` — D2.

D3, W4-22, and D5 are demonstrated against the existing WS4 encoded tests and
need no new file. D8 is a measurement (§2). S1 is a walkthrough (§4).
