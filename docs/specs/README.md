<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# browserid-ng Specifications

**browserid-ng** is a decentralized identity protocol: a person — or an agent
acting for one — proves control of an **email identity** to a relying party by
presenting a short-lived, cryptographically signed credential, with no password
and no central login provider. It descends from Mozilla's BrowserID/Persona and
keeps its JWT/Ed25519 building blocks, but re-shapes the credential into the
**device-cert model** — durable IdP-signed **device certs** (never seen by the
RP) that mint fresh-key **access certs**, plus **config certs** that sign
**warrants** — and replaces the trust root with **DNSSEC**, which is what makes
identities verifiable *offline*, even on a ledger. The RP receives a four-object
bundle `access_cert~assertion~warrant~config_cert`. Source of truth for the
model: [`../design/browserid-end-to-end-flow.md`](../design/browserid-end-to-end-flow.md);
built types `browserid-core/src/device.rs`.

The specification is a small suite: a **core** protocol plus **modules** layered
on top. A plain relying party only needs the core.

## The documents

| Document | What it covers |
|---|---|
| **[Protocol Specification (core)](./browserid-ng-protocol.md)** | **Start here.** Discovery & the DNSSEC trust root, keys, **device / access / config certificates**, assertions & the four-object bundle, verification (issuer binding + three fail-closed status checks), the primary-IdP model with **mandatory device-cert issuance + the access-cert mint API**, and the fallback broker. |
| **[Agent Provisioning, Warrants & Grant Exchange](./agent-provisioning-and-grant-api.md)** | *Module.* How an agent obtains its own **`agent`-subject device cert** (IdP-issued after user authorization) and **mints access certs headlessly**, and how **config-cert-signed warrants** confine it to the audiences and scopes its principal authorized. |
| **[SBO Attribution Specification](https://github.com/vthunder/sbo/blob/main/specs/SBO%20Attribution%20Specification.md)** *(sbo repo)* | *Module.* How a ledger attributes an email identity to an on-chain `ed25519:` key, built on the core's offline-verification primitive (§6.3). Lives in the sbo repo because it is ledger-specific and sbo depends on browserid-ng, not the reverse. |
| **[Divergence Analysis](./browserid-ng-divergence-analysis.md)** | *Background.* A point-by-point comparison with Mozilla BrowserID and the rationale for each deliberate departure. |

## Reading paths

- **Adding sign-in to an app (relying party):** core §6 (verification) and §3
  (why a domain is trusted). You verify the four-object bundle; you don't run an IdP.
- **Running an IdP for your domain:** core §3 (publish the DNSSEC record), §3.1
  (endpoints), §4 (device / access / config certs), §7 (auth/provision pages **+
  the mandatory device-cert issuance and access-cert mint API**).
- **Building an agent:** the Agent Provisioning module (device-grant + headless
  mint), then core §4–§6.
- **Consuming identities on a ledger / offline:** core §6.3 (offline verification
  with detached DNSSEC proofs), then the SBO Attribution Specification.
- **Understanding what changed from BrowserID:** the Divergence Analysis.

## Status

The spec describes the **device-cert model** (design:
`../design/browserid-end-to-end-flow.md`; built types
`browserid-core/src/device.rs`; wire vectors
`test-vectors/device-cert-v1.json`). Core device/access/config cert types and
the broker's issuance + mint + conformance verifier are implemented (DC Phases
1–6). Planned extension: the optional **host-certificate** intermediate (core
§4.4, bean `browserid-ng-dff5`). Migration/divergence detail:
`docs/plans/2026-07-18-divergence-analysis/`. The Divergence Analysis is a
working document (bean `browserid-ng-v9rz`).
