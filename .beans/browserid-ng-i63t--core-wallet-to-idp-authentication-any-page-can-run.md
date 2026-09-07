---
# browserid-ng-i63t
title: 'Core: wallet-to-IdP authentication — any page can run the issuer sign-in ceremony with its own keys'
status: todo
type: feature
priority: high
created_at: 2026-09-07T20:16:28Z
updated_at: 2026-09-07T20:16:58Z
blocked_by:
    - browserid-ng-0c49
---

Found 2026-09-07 while simplifying the registry guard (bean 0c49, item 2).

## The problem

The issuer sign-in ceremony (fallback-IdP API §3.1: page opened with `email`, `device_pubkey`, `config_pubkey`, `return_origin`, `return_url` in the fragment; certs come back on `return_url#…`) authenticates the USER to the issuer but never authenticates the WALLET. Any web page can open the ceremony with keys it generated and a return URL it controls; if the user signs in, the page receives a config cert for the user's identity bound to the attacker's key — a warrant-signing takeover. `return_origin` validation only checks that the page navigates to the URL the opener supplied, not who the opener is. The only defence today is the issuer's sign-in UX making "you are authorizing a new device" unmistakable — i.e. consent phishing, the OAuth-shaped hole.

This is a core-protocol gap, not a registry one: it exists on the primary lane too (core §4.1 issuance), and it surfaced because a registry guard page that ran issuer sign-ins for "additional identities" would have normalized exactly the habit a phisher needs.

## Goal

Give the user's wallet a way to authenticate itself to the IdP during issuance, WITHOUT baking a privileged set of wallets into the protocol (no vendor allowlist, no attestation oligopoly). Directions to explore:
- Something the wallet holds that a page cannot: an existing device cert on the same IdP (device approval of the new device by an existing one, IdP-side — the registry guard pattern moved down a layer); a wallet-held secret established at first enrollment.
- Ceremony shape: the issuer page never hands certs to a caller-supplied URL; the wallet pulls them via an authenticated channel instead (e.g. the page only completes a pending request the wallet created and the wallet fetches with a proof).
- Browser-side: registered custom scheme / loopback origin as the ONLY accepted return origins (already partly in §3.1) — evaluate whether that plus UX is enough for web-page wallets.
- Whatever lands must keep first-use smooth (no other device yet) — the same D2 trade the registry guard has.

## Related
- 0c49 registry guard: kinds left as-is (device_approval / password / additional_identities / page) pending this; the "page-only guard" simplification is blocked on it.
- 9it0 (shared page validates return_origin for postMessage but not return_url).
- core §4.1 issuance, fallback-IdP API §3.1–3.2.
