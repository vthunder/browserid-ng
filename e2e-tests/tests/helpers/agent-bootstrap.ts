// Stand-in for the removed `Agent.bootstrap` (sdk/agent 1.0.0, audit 2026-11
// W4-44): pair through `requestProvision` and hand back a `DeviceAgent`
// once the human approves. Same shape the specs relied on.
import { requestProvision, DeviceAgent } from '../../../sdk/agent/index.mjs';

export async function bootstrapAgent(broker: string, { handle, label }: { handle: string; label?: string }) {
  const pending = await requestProvision(broker, { handle, label });
  const ready = pending.wait().then(({ credential, grants }: any) => {
    const agent = new DeviceAgent(credential);
    for (const g of grants) agent.addGrant(g.grant);
    return agent;
  });
  ready.catch(() => {}); // the deny spec awaits the rejection later
  return { verificationUriComplete: pending.verificationUriComplete, fingerprint: pending.fingerprint, ready };
}
