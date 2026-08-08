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
bundle `access_cert~assertion~warrant~config_cert`.

The **protocol specification is one document** — an agent is just a holder, so
issuance, minting, warrants, and verification are all specified once, for every
holder. Only on-chain attribution lives outside it.

## The documents

| Document | What it covers |
|---|---|
| **[Protocol Specification](./browserid-ng-protocol.md)** | **The whole protocol.** Actors & holders, the DNSSEC trust root & discovery, **device / access / config certificates**, warrants & the four-object bundle, verification (per-identity issuer authority + three fail-closed status checks), issuance & obtaining credentials (interactive login, the device-grant for headless holders, and just-in-time warrant consent), the fallback broker, and the optional grant-exchange binding for API relying parties. |
| **[SBO Attribution Specification](https://github.com/vthunder/sbo/blob/main/specs/SBO%20Attribution%20Specification.md)** *(sbo repo)* | *External module.* How a ledger attributes an email identity to an on-chain `ed25519:` key, built on the protocol's offline-verification primitive (§6.2). Lives in the sbo repo because it is ledger-specific and sbo depends on browserid-ng, not the reverse. |
| **[Divergence Analysis](./browserid-ng-divergence-analysis.md)** | *Background.* A point-by-point comparison with Mozilla BrowserID and the rationale for each deliberate departure. |

## Reading paths

- **Adding sign-in to an app (relying party):** §6 (verification) and §3 (why a
  domain is trusted). You verify the four-object bundle; you don't run an IdP. If
  you want to swap the bundle for your own API token, add the optional §9.
- **Running an IdP / broker:** §3 (publish the DNSSEC record), §3.1 (endpoints),
  §4 (device / access / config certs), §7 (issuance, mint, and — for headless
  holders — the device-grant and warrant consent).
- **Building an agent:** an agent is a headless holder — §7.4 (device-grant), §7.2
  (mint), §7.5 (warrants), then §4–§6.
- **Consuming identities on a ledger / offline:** §6.2 (offline verification with
  detached DNSSEC proofs), then the SBO Attribution Specification.
- **Understanding what changed from BrowserID:** the Divergence Analysis, or the
  spec's Appendix A.

## Status

Draft. The protocol is specified end to end in one document; the optional
**host-certificate** intermediate (§4.4) is a planned extension. A companion
overview lives at
[`../design/browserid-end-to-end-flow.md`](../design/browserid-end-to-end-flow.md).
