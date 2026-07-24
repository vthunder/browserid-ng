// @browserid-ng/agent — the client (agent) side of browserid-ng.
//
// Provision a delegated agent identity, obtain human-approved warrants, and mint
// warrant-backed assertions to present to relying parties / MCP servers. A
// faithful Node port of the Rust `browserid-agent` crate (same wire formats).
//
//   import { Agent } from "@browserid-ng/agent";
//   const agent = await Agent.open("agent-credential.json", "agent.identity.json");
//   const { approveUrl, approved } = await agent.requestWarrant(audience, ["post","read"]);
//   if (approveUrl) { console.log("approve:", approveUrl); await approved; }
//   const assertion = await agent.assertionFor(audience);   // present this to the RP
//   await agent.save("agent.identity.json");

// The CURRENT protocol: device certs, access certs, four-part presentations.
export { requestProvision, PendingProvision, requestWarrants, PendingWarrants, DeviceAgent } from "./src/device.mjs";

// The legacy provisioning-cert path. The broker no longer serves the
// endpoints this uses (`/provision/endorse` → 404); kept only for older
// deployments, and not what a new integration should reach for.
export { Agent } from "./src/agent.mjs";
export { Credential } from "./src/credential.mjs";

// Key primitives, so a consumer can verify a signature the agent made — or
// sign its own payload with the access key `assertionWithAccessKey` returns.
export { KeyPair, PublicKey } from "./src/crypto.mjs";
export {
  AgentError, NeedCredentialError, InvalidCredentialError, AmbiguousNameError,
  RequestError, WarrantExpiredError, WarrantDeniedError, NoWarrantError,
} from "./src/errors.mjs";
