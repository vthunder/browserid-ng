---
# browserid-ng-k67v
title: 'bsky bridge: custom-domain handle resolution hangs 15s on the well-known probe — breaks DNS-verified handles end to end'
status: todo
type: bug
priority: high
created_at: 2026-08-30T18:01:42Z
updated_at: 2026-08-30T18:01:42Z
---

Reported by Dan's friend Chris (2026-08-30): me@chris.toshokelectric.com 'didn't work' while a .bsky.social handle did. Full causal chain, verified live:

1. chris.toshokelectric.com is a VALID atproto handle, verified via DNS TXT (_atproto TXT answers in ms with the did=; the appview resolves it).
2. The bridge's forward resolution (browserid-bsky pds-bridge/src/idp/resolve.rs resolve_handle) runs dns_atproto_did AND well_known_atproto_did in tokio::join! — it WAITS FOR BOTH.
3. Chris's domain resolves an A record but serves no HTTPS — the well-known fetch (https://<handle>/.well-known/atproto-did) hangs with no RST until the guarded client's 15s timeout (idp/net.rs:151). Verified: curl hangs 20s+, /idp/resolve?domain=chris.toshokelectric.com returns valid:true after 15.4s.
4. The broker's authority probe (authority.rs BRIDGE_PROBE_TIMEOUT) gives up at 10s → handle_did None ('cannot tell' collapses into 'not a handle') → falls to MX → subdomain has no MX → Unprovable → address_info proof:'none' → the dialog never offers the Bluesky flow.
5. The degraded answer is cached 600s (AUTHORITY_CACHE_SECONDS), so retries fail for 10 minutes regardless.
.bsky.social handles work only because bsky.social's web infra answers the well-known probe fast.

FIX (bridge repo ~/src/browserid-bsky — read HANDOFF first per convention): don't let the losing verification method gate the winning one. Await DNS first; when DNS yields a valid DID, give well-known only a short grace (~2s) purely for the conflict-detection warn ('DNS wins on conflict' — waiting 15s to maybe log a warning is the bug), then proceed; when DNS misses, await well-known fully. Also lower the well-known leg's effective timeout (15s > the broker's whole 10s probe budget — any single leg must fit comfortably inside it, e.g. 5s). Any DNS-TXT-verified handle whose domain lacks a fast HTTPS responder hits this today — a large, legitimate slice of custom-domain handles.
