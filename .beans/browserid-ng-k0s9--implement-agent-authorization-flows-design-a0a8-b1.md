---
# browserid-ng-k0s9
title: Implement agent-authorization flows design (A0–A8, B1–B4)
status: completed
type: feature
priority: normal
created_at: 2026-07-25T21:39:44Z
updated_at: 2026-07-25T22:17:43Z
---

Implement the design board 'Agent flows.dc.html' (claude.ai/design project 'Agent verification UI states') — the redesign the 2026-07-25 brief called for. Supersedes the interim intent-first card on account.html and the old consent.html list.

Surfaces:
- A (account.html, /agent-provision/*): A0 signed-out with pending request visible; A1 common case (on-behalf default, one sentence, For/By table, fingerprint check); A2 in-place 'not in my name' (standalone); A3 pinned grantor+grantee that check out (no controls); A4 unsatisfiable grantor pin (refuse, offer sign-in-as, tell the agent); A5 as-you demanded (danger card, default = offer it its own address); A6 generic invalid-request screen with verbatim copyable reason; A7 approved; A8 denied.
- B (consent.html, /wsapi/warrant_requests → respond): B1 common case (+tag agent, on-behalf as established); B2 agent-that-is-you (report, approve-as-me, or deny-to-reauthorize); B3 foreign service (For/By, grantor = the human — needs the server change); B4 nothing waiting.

Server changes:
- consent.rs RespondBody gains grantor: Option<String>, default = today's grantor==grantee; owned + config-cert-authorized validation.
- agent_provision.rs InfoResponse exposes grantee_holder so the page can show A6 ('a foreign grantee must supply its holder') before approval instead of after.

Rules held everywhere: common case asks nothing; branches are server facts, not user choices; only fingerprint / own addresses / owned-vs-foreign are trustworthy — requester text is quoted and marked UNVERIFIED.

- [x] registrar: RespondBody.grantor + validation + unit test
- [x] registrar: InfoResponse.grantee_holder
- [x] account.html: A-surface state machine (A0–A8)
- [x] consent.html: B-surface rewrite (B1–B4)
- [x] routes/mod.rs: INLINE_SCRIPT_HASHES for both pages
- [x] cargo tests (broker CSP guard + registrar) — also fixed two stale merged_provision_test assertions (verified.email is the ATTRIBUTED identity since 8v6c) and updated e2e paired-provisioning.spec.ts to the new card

## Summary of Changes

Implemented the 'Agent flows' design board (claude.ai/design project 'Agent verification UI states') end to end.

**Surface A — account.html** (full rewrite of the provision card as a JS-rendered state machine, design-board visual language, scoped .pv* CSS):
- A0 signed-out: pending request stays on screen ('An agent showing 21-B1-8B wants access to …'), sign-in copy becomes 'First, which email is you?'.
- A1 common case: on-behalf default, no radios; fingerprint check block; audience+scope chips (non-web audiences marked amber); For/By table — For is an identity select, By is the +tag address with an inline 'change' editor and reuse-an-existing-agent chips; blue callout; requester label quoted at the bottom under an UNVERIFIED badge.
- A2 standalone via the one escape hatch ('I don't want this on my account →'), in place, with the tag editor.
- A3 pinned grantor+grantee: rows locked and annotated ('requested · verified yours' / 'an address of yours'), no controls, card leads with the who.
- A4 unsatisfiable grantor pin: no approve button; 'Sign in as X' (logs out, prefills sign-in via sessionStorage hint) or 'Close and tell it this failed' (deny → the agent's poll learns immediately).
- A5 as-you demanded (empty grantee pin AND no suggested handle — the legacy as-you shape; a suggested handle renders A1): danger card, default action 'Offer it its own address instead' → A1; the red path is behind an explicit link + checkbox + red confirm.
- A6 invalid: one generic screen, machine reason verbatim + Copy button. Fires for info failures, contradictory pins, and a foreign grantee without grantee_holder (now detectable up front).
- A7 approved / A8 denied terminal screens (no more auto-navigate-away; 'See my agents' / return-to-app / close).
- Foreign-grantee first authorization renders the B3 shape (For/By, 'not yours · certified by <domain>', UNVERIFIED foot).
- JS identityMatches now mirrors core's subaddress rule (base identity covers +tags) so config-cert lookup works for every grantor shape.

**Surface B — consent.html** (full rewrite, same card language):
- Card chosen by server facts: external → B3 (grantor = the human; For/By table); agent == delegator → B2 ('An agent acting as you wants more access', Approve-as-me / Re-authorize-with-its-own-address [denies + explains] / Deny); else B1 (relation read from the registered warrants' grantor claims — on-behalf or standalone, stated not asked, with 'authorized <date>' and a 'What gets signed →' disclosure).
- B4 'Nothing is waiting for you' empty state. Widen-to-group checkbox removed (isolation always). Arming delay, deep-link highlight, return-to-app kept.

**Server (the design's 'one server change' + one info field):**
- consent.rs RespondBody gains grantor: Option<String> (absent = today's grantor==grantee); a named grantor is gated on owns_verified_email(delegator_of(grantor)) and validated against the config cert. Unit test pins the decision table.
- agent_provision.rs InfoResponse exposes grantee_holder so the page can refuse a holder-less foreign grantee before approval ('a foreign grantee must supply its holder').

**Tests:** broker CSP hashes updated (guard test green); fixed two stale merged_provision_test assertions (since 8v6c verified.email is the ATTRIBUTED identity — now assert email==delegator AND grantee==agent); updated e2e paired-provisioning.spec.ts to the new card (approve run verified live against a local broker: A1 renders, approve completes, poll delivers; deny renders A8 — remaining spec failure is pre-existing legacy-SDK credential drift, bean tnwb).

**Deliberately not done (per the board):** app logos, human-readable scope interpretation, namespace-wide grants; side-quest spec additions (user-chosen agent name, attribution enum, consent-request pins, audience self-description, error codes) are future work.
