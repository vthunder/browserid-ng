// @browserid-ng/agent — the client (agent) side of browserid-ng.
//
// Provision a device identity (human-approved pairing), obtain human-approved
// warrants, and mint warrant-backed presentations to present to relying
// parties / MCP servers. A faithful Node port of the Rust `browserid-agent`
// crate (same wire formats).
//
//   import { requestProvision, DeviceAgent } from "@browserid-ng/agent";
//   const pending = await requestProvision(broker, { grants: [{ audience, scopes: ["post"] }] });
//   show(pending.verificationUriComplete, pending.fingerprint);   // the human approves
//   const { credential, grants } = await pending.wait();           // persist both
//   const agent = new DeviceAgent(credential);
//   for (const g of grants) agent.addGrant(g.grant);
//   const presentation = await agent.assertionFor(audience);      // present this to the RP

// The CURRENT protocol: device certs, access certs, four-part presentations.
export { requestProvision, PendingProvision, requestWarrants, PendingWarrants, DeviceAgent, requestProof } from "./src/device.mjs";

// Scope-entry helpers (protocol §5).
export { scopeName, scopeEntryEq } from "./src/scopes.mjs";

// Key primitives, so a consumer can verify a signature the agent made — or
// sign its own payload with the access key `assertionWithAccessKey` returns.
export { KeyPair, PublicKey } from "./src/crypto.mjs";
export {
  AgentError, RequestError, WarrantExpiredError, WarrantDeniedError, NoWarrantError,
} from "./src/errors.mjs";
