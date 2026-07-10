<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# browserid-ng Specifications

**browserid-ng** is a decentralized identity protocol: a person — or an agent
acting for one — proves control of an **email identity** to a relying party by
presenting a short-lived, cryptographically signed assertion, with no password
and no central login provider. It descends from Mozilla's BrowserID/Persona,
keeps its wire formats, and replaces its trust root with **DNSSEC** — which is
what makes identities verifiable *offline*, even on a ledger.

The specification is a small suite: a **core** protocol plus **modules** layered
on top. A plain relying party only needs the core.

## The documents

| Document | What it covers |
|---|---|
| **[Protocol Specification (core)](./browserid-ng-protocol.md)** | **Start here.** Discovery & the DNSSEC trust root, keys, certificates, assertions & backed assertions, verification, the primary-IdP model, and the fallback broker. |
| **[Agent Provisioning & Grant Exchange](./agent-provisioning-and-grant-api.md)** | *Module.* How an agent obtains its own delegated identity from a principal's, via a broker-endorsed provisioning chain. |
| **[SBO Attribution Specification](https://github.com/vthunder/sbo/blob/main/specs/SBO%20Attribution%20Specification.md)** *(sbo repo)* | *Module.* How a ledger attributes an email identity to an on-chain `ed25519:` key, built on the core's offline-verification primitive (§6.3). Lives in the sbo repo because it is ledger-specific and sbo depends on browserid-ng, not the reverse. |
| **[Divergence Analysis](./browserid-ng-divergence-analysis.md)** | *Background.* A point-by-point comparison with Mozilla BrowserID and the rationale for each deliberate departure. |

## Reading paths

- **Adding sign-in to an app (relying party):** core §6 (verification) and §3
  (why a domain is trusted). You verify a backed assertion; you don't run an IdP.
- **Running an IdP for your domain:** core §3 (publish the DNSSEC record), §3.1
  (endpoints), §4 (certificates), §7 (auth/provision pages).
- **Building an agent:** the Agent Provisioning module, then core §4–§6.
- **Consuming identities on a ledger / offline:** core §6.3 (offline verification
  with detached DNSSEC proofs), then the SBO Attribution Specification.
- **Understanding what changed from BrowserID:** the Divergence Analysis.

## Status

Core protocol: implemented and deployed. The one planned extension is optional
**host certificates** (core §4.2) — see bean `browserid-ng-dff5`. The Divergence
Analysis is a working document (bean `browserid-ng-v9rz`).
