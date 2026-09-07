---
# browserid-ng-i63t
title: 'Core: wallet-to-IdP authentication — any page can run the issuer sign-in ceremony with its own keys'
status: todo
type: feature
priority: deferred
created_at: 2026-09-07T20:16:28Z
updated_at: 2026-09-07T21:25:22Z
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

## Decision 2026-09-07 (discussed with Dan)

Confirmed the attack is live on the primary lane too: the dialog obtains certs by opening the same sign-in page the fallback ceremony uses, and that page (`idp-device-authorize.js`, `fb-device-authorize.js`) accepts any well-formed http(s) `return_origin`. Core §7.3's first-party model is not what is built.

Split into two layers:

1. **Accepted return origins** (spec landed in fallback-idp-api-v1 §3.1, §2 `wallet-origins`, §6 `return_origin_not_allowed`, §7 decision 8; implementation is bean qze7). Loopback and custom-scheme origins always accepted (native by construction); http(s) only from the issuer's trusted-wallet list, which is deployment policy with `browserid.me` as the reference default and an off-spec recommendation. Enforced server-side as well as in the page. Closes the drive-by web-page case.

2. **This bean stays open for the structural fix**: existing-device approval of a new device, IdP-side, first enrollment excepted. Covers what the allowlist cannot: local attackers squatting loopback/custom schemes, and consent phishing through a trusted wallet. Design question to settle: what the approval prompt looks like on an existing device for a native wallet vs the browser dialog.

Dropped from the directions list: "wallet pulls certs via an authenticated channel" does not authenticate the wallet (the attacker holds the keys too; it only prevents the 9it0 leak), and "wallet-held secret from first enrollment" is equivalent to an existing device cert.

## Shelved 2026-09-07

Dan: the existing-device approval design (pending request, second-device prompt, polling, recovery path with delay) is too much machinery for the residual it covers. The accepted-return-origin rule (qze7, deployed) closes the drive-by web case, which was the live attack. Revisit only if a concrete need appears: a local-attacker incident, or a trusted web wallet being used for consent phishing.

0c49 should not wait on this bean; the registry guard's device_approval kind can be simplified independently.
