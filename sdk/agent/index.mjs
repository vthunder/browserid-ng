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

export { Agent } from "./src/agent.mjs";
export { Credential } from "./src/credential.mjs";
export {
  AgentError, NeedCredentialError, InvalidCredentialError, AmbiguousNameError,
  RequestError, WarrantExpiredError, WarrantDeniedError, NoWarrantError,
} from "./src/errors.mjs";
