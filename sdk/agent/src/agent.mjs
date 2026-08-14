// The agent identity: provision a delegated identity, obtain warrants (with
// human consent), and mint warrant-backed assertions. Mirrors the Rust
// browserid-agent AgentIdentity; see PORTING notes in protocol.mjs.
import { readFile, writeFile, chmod } from "node:fs/promises";
import { KeyPair, b64u, fromB64u, publicKeyField, fingerprint } from "./crypto.mjs";
import { Credential } from "./credential.mjs";
import { DeviceAgent } from "./device.mjs";
import {
  mintRequest, revokeRequest, warrantRequest, bundle, assertion as makeAssertion,
  backedPresentation, parseCert, parseWarrant, generatedName, nowS,
} from "./protocol.mjs";
import {
  AgentError, AmbiguousNameError, RequestError, WarrantExpiredError,
  WarrantDeniedError, NoWarrantError,
} from "./errors.mjs";

const CERT_REFRESH_MARGIN_S = 60;
const trim = (u) => u.replace(/\/$/, "");

// The identity file holds an ARRAY of identities (the wallet uses one today, but
// the format supports many). Accept the current `{v:2, identities:[...]}` shape
// and the legacy single-identity object.
function storedIdentities(data) {
  if (Array.isArray(data?.identities)) return data.identities;
  if (data?.email) return [data]; // legacy v1 single-identity file
  return [];
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function postJson(http, url, body) {
  const res = await http(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { res, json };
}

/** Endorse a request bundle at the broker; returns the endorsement JWT. */
async function endorse(cred, bundleStr, http) {
  const { res, json } = await postJson(http, `${trim(cred.broker)}/provision/endorse`, { request_bundle: bundleStr });
  if (!res.ok || json.success !== true) throw new RequestError("endorsement", res.status, json.reason || "no reason given");
  return json.endorsement;
}

/** endorse → mint against the IdP; returns { email, cert }. */
async function mintFlow(cred, name, agentKeyB64, http) {
  const provKey = cred.provisioningKey();
  const bundleStr = bundle(cred.delegation, mintRequest(provKey, cred.idpDomain, name, agentKeyB64));
  const endorsement = await endorse(cred, bundleStr, http);
  const { res, json } = await postJson(http, `${trim(cred.idp)}/provision/mint`, { request_bundle: bundleStr, endorsement });
  if (!res.ok || json.success !== true) throw new RequestError("mint", res.status, json.reason || "no reason given");
  return { email: json.email, cert: json.cert };
}

/** Resolve the name to provision: explicit, else the credential's default. */
function resolveName(cred, explicit) {
  if (explicit) return explicit;
  const id = cred.defaultIdentity();
  if (!id) throw new AmbiguousNameError(cred.constraint().names);
  return id.generated ? generatedName(id.prefix) : id.name;
}

export class Agent {
  #cred; #key; #cert; #email; #warrants; #http;

  constructor(credential, { email, cert, keypair, warrants = new Map(), http = fetch }) {
    this.#cred = credential;
    this.#email = email;
    this.#cert = cert;
    this.#key = keypair;
    this.#warrants = warrants;
    this.#http = http;
  }

  /** The agent's provisioning name IS its email local-part — no translation:
   *  the P_cert constraint holds the full local-part, so mint/warrant/revoke all
   *  use exactly this string. */
  #name() { return this.#email.split("@")[0]; }

  get email() { return this.#email; }
  get credential() { return this.#cred; }

  /** The reserved names/patterns + the identity provisioning would pick. */
  identity() {
    const { names, patterns } = this.#cred.constraint();
    return { names, patterns, default: this.#cred.defaultIdentity() };
  }

  /**
   * Paired provisioning (bean 74u1): generate a provisioning keypair locally and
   * ask the broker to pair — the human authorizes at the returned URL, and this
   * agent picks up the delegation and mints, all without a downloaded credential.
   * Returns entry points to show the human + a `ready` promise that resolves to a
   * provisioned Agent once they approve. The provisioning private key never leaves
   * here.
   */
  static async bootstrap({ broker = "https://browserid.me", requestedHandles, label, name, http = fetch } = {}) {
    const key = KeyPair.generate();
    const body = { provisioning_pubkey: publicKeyField(key.publicKeyB64) };
    if (requestedHandles) body.requested_handles = requestedHandles;
    if (label) body.label = label;
    const { res, json } = await postJson(http, `${trim(broker)}/agent-provision/request`, body);
    if (!res.ok || json.success !== true) throw new RequestError("provision request", res.status, json.reason || "no reason given");

    const code = json.code;
    const interval = Math.max(1, json.interval ?? 5);
    const deadline = Date.now() + (json.expires_in ?? 900) * 1000;

    const ready = (async () => {
      const url = `${trim(broker)}/agent-provision/poll`;
      for (;;) {
        await sleep(interval * 1000);
        const r = await http(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code }) });
        if (r.status === 410) throw new WarrantExpiredError();
        if (r.status !== 429) {
          const j = await r.json().catch(() => ({}));
          if (j.status === "denied") throw new WarrantDeniedError();
          if (j.status === "failed") throw new RequestError("provisioning", 0, j.reason || "provisioning failed");
          if (j.status === "completed") {
            const c = j.credential || {};
            if (c.device_cert) {
              // Device-cert model (the broker's current delivery): the
              // locally generated pairing key IS the device key the cert
              // certifies, and any bundled grants arrive as
              // `warrant~config_cert` pairs.
              const agent = new DeviceAgent(
                {
                  device_key: b64u(key.seed),
                  agent_device_cert: c.device_cert,
                  idp: c.idp,
                  identity: c.identity,
                  ...(c.access_mint ? { access_mint: c.access_mint } : {}),
                },
                { http }
              );
              for (const g of j.grants || []) {
                if (g?.warrant) agent.addGrant(g.warrant);
              }
              return agent;
            }
            // Legacy delegation delivery (pre-device-model brokers).
            const credential = new Credential({ secret_key: b64u(key.seed), delegation: c.delegation, broker: c.broker, idp: c.idp });
            // Mint under `name` if given; else the first reserved name (so a
            // multi-name credential doesn't dead-end — act as the first).
            const mintName = name || credential.constraint().names[0];
            return await Agent.provision(credential, { name: mintName, http });
          }
          if (j.status && j.status !== "pending") throw new WarrantExpiredError();
        }
        if (Date.now() > deadline) throw new WarrantExpiredError();
      }
    })();

    return {
      verificationUri: json.verification_uri,
      verificationUriComplete: json.verification_uri_complete,
      userCode: json.user_code,
      fingerprint: json.fingerprint || fingerprint(key.publicKeyB64),
      ready,
    };
  }

  /** Provision a fresh agent identity (endorse → mint). */
  static async provision(credential, { name, http = fetch } = {}) {
    const key = KeyPair.generate();
    const chosen = resolveName(credential, name);
    const { email, cert } = await mintFlow(credential, chosen, key.publicKeyB64, http);
    return new Agent(credential, { email, cert: parseCert(cert), keypair: key, warrants: new Map(), http });
  }

  /** Load a persisted identity, or provision one if the file is absent. */
  static async open(credentialPathOrObj, identityPath, { name, email, http = fetch } = {}) {
    const credential = Credential.load(credentialPathOrObj);
    try {
      const identities = storedIdentities(JSON.parse(await readFile(identityPath, "utf8")));
      const record = email ? identities.find((i) => i.email === email) : identities[0];
      if (!record) { const e = new Error("no stored identity"); e.code = "ENOENT"; throw e; }
      return Agent.#fromStored(record, credential, http);
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
      const agent = await Agent.provision(credential, { name, http });
      await agent.save(identityPath);
      return agent;
    }
  }

  static #fromStored(stored, credential, http) {
    const keypair = KeyPair.fromSeed(fromB64u(stored.key_seed));
    const agent = new Agent(credential, { email: stored.email, cert: parseCert(stored.cert), keypair, warrants: new Map(), http });
    for (const w of stored.warrants || []) agent.#addWarrant(w);
    return agent;
  }

  async save(identityPath) {
    const record = {
      email: this.#email,
      cert: this.#cert.encoded,
      key_seed: b64u(this.#key.seed),
      warrants: [...this.#warrants.values()].map((w) => w.encoded),
    };
    // Upsert this identity by email into the array, preserving any others.
    let identities = [];
    try {
      identities = storedIdentities(JSON.parse(await readFile(identityPath, "utf8"))).filter(
        (i) => i.email !== record.email
      );
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
    }
    identities.push(record);
    // 0600 — the file holds private keys. Set on create, and chmod in case it
    // already existed with looser perms.
    await writeFile(identityPath, JSON.stringify({ v: 2, identities }, null, 2), { mode: 0o600 });
    try { await chmod(identityPath, 0o600); } catch {}
  }

  // ---- warrants ------------------------------------------------------------

  warrantedAudiences() { return [...this.#warrants.keys()]; }

  /** A held warrant covers a request iff same audience and its scopes ⊇ wanted. */
  warrantCovers(audience, scopes) {
    const w = this.#warrants.get(audience);
    if (!w) return false;
    if (!scopes || scopes.length === 0) return true;
    const held = w.scopes || [];
    return scopes.every((s) => held.includes(s));
  }

  #addWarrant(encoded) {
    const w = parseWarrant(encoded);
    if (w.agent !== this.#email) throw new AgentError(`warrant is for ${w.agent}, not ${this.#email}`);
    this.#warrants.set(w.audience, w);
    return w;
  }

  /**
   * Raise a consent request for `audience` with `scopes`. Returns immediately
   * with `{ approveUrl, approved }`: show `approveUrl` to the principal and
   * `await approved` — it polls until they approve (storing the warrant),
   * rejecting on denial/expiry. If a covering warrant is already held,
   * `approveUrl` is null and `approved` resolves at once.
   */
  async requestWarrant(audience, scopes = null) {
    if (this.warrantCovers(audience, scopes)) return { approveUrl: null, approved: Promise.resolve() };
    const provKey = this.#cred.provisioningKey();
    const name = this.#name();
    const grants = [{ aud: audience, scopes: scopes || undefined }];
    const bundleStr = bundle(this.#cred.delegation, warrantRequest(provKey, this.#cred.brokerDomain, name, grants));
    const { res, json } = await postJson(this.#http, `${trim(this.#cred.broker)}/warrant/request`, { request_bundle: bundleStr });
    if (!res.ok || json.success !== true) throw new RequestError("warrant request", res.status, json.reason || "no reason given");
    const handle = { code: json.code, verificationUri: json.verification_uri, expiresIn: json.expires_in ?? 900, interval: Math.max(1, json.interval ?? 5) };
    return { approveUrl: handle.verificationUri, approved: this.#pollUntilApproved(handle), handle };
  }

  /** Convenience: raise consent, surface the URL, and await approval. */
  async obtainWarrant(audience, scopes, onApproveUrl) {
    const { approveUrl, approved } = await this.requestWarrant(audience, scopes);
    if (approveUrl && onApproveUrl) onApproveUrl(approveUrl);
    await approved;
  }

  async #pollUntilApproved(handle) {
    const deadline = Date.now() + handle.expiresIn * 1000;
    const url = `${trim(this.#cred.broker)}/warrant/poll`;
    for (;;) {
      await sleep(handle.interval * 1000);
      const res = await this.#http(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code: handle.code }) });
      if (res.status === 410) throw new WarrantExpiredError();
      if (res.status !== 429) {
        const json = await res.json().catch(() => ({}));
        if (json.status === "denied") throw new WarrantDeniedError();
        if (json.status === "approved") {
          const list = Array.isArray(json.warrants) ? json.warrants : [];
          let stored = 0;
          for (const w of list) { this.#addWarrant(w); stored++; }
          if (stored === 0 && json.warrant) this.#addWarrant(json.warrant);
          return;
        }
        if (json.status && json.status !== "pending") throw new WarrantExpiredError();
      }
      if (Date.now() > deadline) throw new WarrantExpiredError();
    }
  }

  // ---- assertions ----------------------------------------------------------

  /** A backed presentation for `audience`. Refreshes the cert if stale; for an
   *  agent identity, requires a held warrant for the audience. */
  async assertionFor(audience) {
    await this.#ensureFreshCert();
    if (this.#cert.isAgent && !this.#warrants.has(audience)) throw new NoWarrantError(audience);
    const assn = makeAssertion(this.#key, audience);
    const warrant = this.#cert.isAgent ? this.#warrants.get(audience).encoded : null;
    return backedPresentation({ cert: this.#cert.encoded, warrant, assertion: assn });
  }

  async #ensureFreshCert() {
    if (this.#cert.exp > nowS() + CERT_REFRESH_MARGIN_S) return;
    const name = this.#name();
    const { email, cert } = await mintFlow(this.#cred, name, this.#key.publicKeyB64, this.#http);
    this.#email = email;
    this.#cert = parseCert(cert);
  }

  // ---- revoke --------------------------------------------------------------

  async revoke() {
    const provKey = this.#cred.provisioningKey();
    const name = this.#name();
    const bundleStr = bundle(this.#cred.delegation, revokeRequest(provKey, this.#cred.idpDomain, name));
    const endorsement = await endorse(this.#cred, bundleStr, this.#http);
    const { res, json } = await postJson(this.#http, `${trim(this.#cred.idp)}/provision/revoke`, { request_bundle: bundleStr, endorsement });
    if (!res.ok || json.success !== true) throw new RequestError("revoke", res.status, json.reason || "no reason given");
  }
}
