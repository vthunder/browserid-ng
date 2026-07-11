---
# browserid-ng-btmg
title: Agent API-key management UI on broker landing page
status: scrapped
type: task
priority: normal
created_at: 2026-07-08T19:05:55Z
updated_at: 2026-07-11T00:06:26Z
parent: browserid-ng-l8lw
---

Backend endpoints exist (/wsapi/agent_keys, /wsapi/create_agent_key, /wsapi/revoke_agent_key — session+CSRF gated) but there is no browser UI. Add a minimal section to /account (static/account.html — the landing page /agents was retired into /account by ddd7189) to mint (show-once), list, and revoke API keys when agent provisioning is enabled.

## Reasons for Scrapping (2026-07-11)

The /wsapi/agent_keys, create_agent_key, revoke_agent_key endpoints this bean targeted no longer exist — the tdxf delegation-chain redesign replaced broker-held API keys with in-browser provisioning-cert delegation (P_priv never reaches the broker). The key-management UI it asked for now exists in /account (ddd7189): '+ Add an agent' creates and registers the delegation (key shown once, in-browser), the merged agents list shows each key's identities, and revoke is per-cert with status-bit fallout. Nothing left to build.
