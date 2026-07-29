// The tenant wallet store: the only module that touches plaintext credential
// material. Everything is keyed by the account email the OAuth layer
// authenticated; the MVP exposes a single agent per account (name 'default').
import { DeviceAgent } from "@browserid-ng/agent";
import { nowS } from "./db.mjs";

const AGENT_NAME = "default";

export class WalletStore {
  #db; #wrapper; #http;
  // DeviceAgent cache so minted access certs survive across tool calls. The
  // DB stays the source of truth; every mutation drops the cached instance.
  #agents = new Map(); // email -> DeviceAgent

  constructor(db, wrapper, { http = fetch } = {}) {
    this.#db = db;
    this.#wrapper = wrapper;
    this.#http = http;
  }

  ensureAccount(email) {
    this.#db
      .prepare("INSERT INTO accounts (email, created_at) VALUES (?, ?) ON CONFLICT DO NOTHING")
      .run(email, nowS());
  }

  /** The tenant's DeviceAgent with all held grants, or null if not provisioned. */
  loadAgent(email) {
    const cached = this.#agents.get(email);
    if (cached) return cached;
    const row = this.#db
      .prepare("SELECT enc_credential FROM agents WHERE account_email = ? AND name = ?")
      .get(email, AGENT_NAME);
    if (!row) return null;
    const credential = JSON.parse(this.#wrapper.unwrap(row.enc_credential));
    const agent = new DeviceAgent(credential, { http: this.#http });
    const grants = this.#db
      .prepare("SELECT grant_pair FROM grants WHERE account_email = ? AND agent_name = ?")
      .all(email, AGENT_NAME);
    for (const g of grants) {
      try { agent.addGrant(g.grant_pair); } catch {}
    }
    this.#agents.set(email, agent);
    return agent;
  }

  /** Persist a freshly provisioned credential (+ any bundled grants). */
  saveCredential(email, credential, grants = []) {
    this.ensureAccount(email);
    const enc = this.#wrapper.wrap(JSON.stringify(credential));
    const identity = credential.identity ?? "";
    this.#db
      .prepare(
        `INSERT INTO agents (account_email, name, enc_credential, identity, created_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (account_email, name)
         DO UPDATE SET enc_credential = excluded.enc_credential, identity = excluded.identity`
      )
      .run(email, AGENT_NAME, enc, identity, nowS());
    this.#db.prepare("DELETE FROM grants WHERE account_email = ? AND agent_name = ?").run(email, AGENT_NAME);
    for (const g of grants) this.saveGrant(email, g.audience, g.grant);
    this.#agents.delete(email);
  }

  saveGrant(email, audience, grantPair) {
    this.#db
      .prepare(
        `INSERT INTO grants (account_email, agent_name, audience, grant_pair, created_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (account_email, agent_name, audience) DO UPDATE SET grant_pair = excluded.grant_pair`
      )
      .run(email, AGENT_NAME, audience, grantPair, nowS());
    this.#agents.delete(email);
  }

  /** Persist the agent's in-memory grant set (after addGrant calls). */
  syncGrants(email, agent) {
    for (const { audience, grant } of agent.storedGrants()) this.saveGrant(email, audience, grant);
    // syncGrants is called on the live instance — keep it cached.
    this.#agents.set(email, agent);
  }

  dropGrant(email, audience) {
    const r = this.#db
      .prepare("DELETE FROM grants WHERE account_email = ? AND agent_name = ? AND audience = ?")
      .run(email, AGENT_NAME, audience);
    this.#agents.delete(email);
    return r.changes > 0;
  }

  /** Delete the tenant's credential + grants (the `forget` tool). */
  forget(email) {
    const g = this.#db.prepare("DELETE FROM grants WHERE account_email = ? AND agent_name = ?").run(email, AGENT_NAME);
    const a = this.#db.prepare("DELETE FROM agents WHERE account_email = ? AND name = ?").run(email, AGENT_NAME);
    this.#agents.delete(email);
    return { grants: g.changes, credentials: a.changes };
  }

  hasCredential(email) {
    return !!this.#db
      .prepare("SELECT 1 FROM agents WHERE account_email = ? AND name = ?")
      .get(email, AGENT_NAME);
  }
}
