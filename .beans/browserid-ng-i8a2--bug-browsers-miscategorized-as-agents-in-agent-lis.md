---
# browserid-ng-i8a2
title: 'Bug: browsers miscategorized as agents in agent list (Safari on iOS, Chrome on macOS)'
status: completed
type: bug
priority: normal
created_at: 2026-07-30T13:18:06Z
updated_at: 2026-07-30T16:11:58Z
---

Two devices in the production agent list are actually browsers: 'Safari on iOS' and 'Chrome on macOS'. Chrome one likely from FedCM login creating a cert with a holder id with wrong category. Safari one unknown (probably not FedCM). Track down both root causes.

- [x] Inspect production DB records for the two holders
- [x] Root-cause the Chrome/FedCM path
- [x] Root-cause the Safari on iOS path

## Findings (2026-07-30)

Both entries are the SAME root cause: cold primary-IdP (bsky.browserid.me) logins in browsers with no broker session, whose self-assigned holder prefix could not be adopted and whose reconciliation lane silently skipped. Neither was created by FedCM.

**Prod data (user 1):**
- Canonical browser holder: `br56f9eb.1cd6e6ef98` (Arc on macOS) — browsers ns prefix `br56f9eb`.
- `brok3vo1.aadgxbrxzn` (Chrome on macOS) — authorization cert iss=bsky.browserid.me, 2026-07-27 20:49; new broker session created 20:49:29 → cold login.
- `brkunmmi.j2gzckmlmy` (Safari on iOS) — authorization cert iss=bsky.browserid.me, 2026-07-27 21:22; new session 21:22:16 → cold login.
- Prefixes match the bridge's `holder_for_device()` fallback (`br` + 6 chars of device pubkey) — i.e. dialog.js sent NO holder (`browserHolder()` returns null without a broker session).

**Failure chain:**
1. Cold login → `browserHolder()` null → bsky IdP self-assigns `br<pubkey>.<pubkey>` (pds-bridge idp/certs.rs `holder_for_device`).
2. Broker `auth_with_presentation` (primary.rs:195-203) tries `adopt_namespace_prefix(user, "browsers", prefix)` — refused because `br56f9eb` already has certs → holder orphans (no namespace row).
3. rrve reconciliation skipped: (a) popup mode — the atproto OAuth top-level redirect severs window.opener, certs return via the BroadcastChannel resume handoff, which resolves WITHOUT `reissue`, so `if (certs.reissue)` (dialog.js:971) never fires; (b) redirect mode — `resumeDeviceAuth()` (dialog.js:1120) has no reconcile call at all. So EVERY cold login through an OAuth-redirecting primary IdP orphans; the hold lane only works when the IdP session is warm (no redirect).
4. account.html `buildActors()` (:594) classifies: browsers-ns → browser, services-ns → service, ANYTHING ELSE (incl. orphans) → 'agent'. So orphaned browser holders render under "Your agents" with their UA label.

**FedCM ruled out:** fedcm.rs mints throwaway holders under the CORRECT browsers prefix and records only a WarrantRecord — never a device-cert row or holder label. Chrome was likely just session-less (daily browser is Arc, which holds the canonical holder; Chrome presumably opened for FedCM testing, then a bsky-handle dialog login there went cold).

Also: two stale `Chrome on macOS` holder_labels rows (`br746fb0.*`, `brb5e395.*`) have no cert rows — invisible in UI, harmless cruft.

**Fix candidates (follow-up):**
- Make orphan repair durable server-side: on failed adoption, register a pending holder-move (orphan → canonical browsers holder) so the existing move machinery re-issues on the next warm dialog visit.
- Add reconciliation to `resumeDeviceAuth()` and/or the BroadcastChannel handoff path (needs a gesture-safe re-issue).
- UI: stop defaulting unknown-namespace holders to 'agent' — render them distinctly (or infer 'browser' from UA-shaped labels).

## Implementation plan (approved 2026-07-30)

- [x] Server backstop: on failed prefix adoption in auth_with_presentation, register a pending holder-move (orphan → fresh canonical browsers holder); orphans-only guard so agent/service holders are never touched
- [x] Redirect lane: resumeDeviceAuth completes a pending move via a second same-tab hop (no popup)
- [x] Popup lane: extend the BroadcastChannel handoff so the resume popup self-navigates for the re-issue (no new window.open)
- [x] Tests for all three lanes
- [x] Deploy (CI image 62f794a → dokku git:from-image, verified live). Registering moves for the two existing orphans turned out to be unnecessary: the backstop schedules them on those browsers' next sign-in.

## Summary of Changes

Root cause was ONE bug reachable by two lanes, not two bugs — and not FedCM.

**Server backstop** (`routes/holders.rs`, `routes/primary.rs`): `auth_with_presentation`
now calls `register_orphan_browser_move()` when `adopt_namespace_prefix` is refused.
That records a pending move `orphan → fresh browsers holder`, which (a) categorizes the
browser correctly *immediately* (the holders view buckets a moving holder under its
TARGET) and (b) lets the existing move machinery re-issue the certs on the next
sign-in — with no dependence on any window surviving an OAuth redirect. Guarded to
true orphans only: a holder under any namespace the user owns (agents/services/custom)
is never rewritten. Idempotent across repeat logins. Non-revoking, unlike `move_holder`:
the user is mid-sign-in with those certs and the orphan namespace has no warrants.

**Popup lane** (`dialog.js` `primaryPopupFlow`): the BroadcastChannel handoff now
resolves WITH `reissue`/`done`. `reissue` tells the resumed page — a window we already
own — to navigate ITSELF back to the provider with the holder pinned. A same-tab
navigation needs no user gesture, so unlike re-opening a popup it cannot be blocked.
The resume page (`handoffResume`) gained the other half: acks carry `hold`, and it then
waits for `reissue` (hop, refusing any non-secure URL) or `done` (close), bounded at 60s.

**Redirect lane** (`dialog.js` `resumeDeviceAuth`): had no reconciliation at all. It now
parks `deviceAuth` and performs a second same-tab hop with the holder pinned
(`reissueViaRedirectHop`), guarded by a `holderHop` flag so it happens at most once per
sign-in, then force-re-joins so the broker records the corrected cert.

**The gate that hid all of this**: `if (certs.reissue)` at both reconcile call sites made
the entire repair — including its own popup fallback — unreachable on exactly the
OAuth-redirect path where cold logins land. Now unconditional; `reconcileBrowserHolder`
decides for itself and prefers the server's explicit assignment over a locally-derived
holder (re-issuing under any other holder would strand the pending move and leave the
orphan row).

Also factored `rejoinBroker()` / `followHolderCache()` out of three copies.

**Tests**: 4 unit tests for the backstop (orphan scheduled into browsers; owned
namespaces left alone; idempotent; prefix-less holder ignored) + 3 e2e tests in
`device-auth-resume.spec.ts` (re-hop carries the pinned holder and the SAME device key
while opening zero popups; no-repair-needed releases the window; insecure re-issue URL
refused). Full broker suite and all 12 resume e2e tests pass.

## Follow-ups (not done)

- **The two existing prod orphans** heal themselves on the next sign-in in those
  browsers once this deploys (join registers the move → `maybeCompleteHolderMove`
  re-issues), but nothing repairs them before then.
- **The UI still defaults an unknown-namespace holder to `agent`** (`account.html`
  `buildActors`). With the backstop that case should no longer arise for browsers, but
  the honest fix is a distinct kind rather than a silent guess — deliberately left out
  of scope to avoid churning the just-redesigned dashboard.
- **The redesigned account page exposes no `move_holder` control**, so a
  miscategorized actor can't be fixed from the UI at all today.
