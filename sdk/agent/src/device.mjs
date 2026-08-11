// The device-cert agent path — the CURRENT protocol, mirroring the Rust
// browserid-agent crate (browserid-agent/src/lib.rs).
//
// The older provisioning-cert flow in agent.mjs (`/provision/endorse` +
// `/provision/mint`, agent certs) targets endpoints the broker no longer
// serves. This module is what talks to a live deployment:
//
//   1. requestProvision()  -> POST {broker}/agent-provision/request
//        returns an approval URL + user code + fingerprint. A HUMAN opens the
//        URL and approves; nothing proceeds without that.
//   2. pending.wait()      -> POST {broker}/agent-provision/poll until the
//        human resolves it. Yields the device credential + any warrants
//        granted in the same consent.
//   3. agent.mint()        -> POST {idp}/access/mint with a device-key-signed
//        access request; the IdP certifies a FRESH access key.
//   4. agent.assertionFor(audience) -> the four-part presentation an RP
//        verifies: access_cert ~ assertion ~ warrant ~ config_cert.
//
// The device key never leaves the process; only signed requests cross the
// wire. The assertion is signed with the ACCESS key (not the device key),
// which is what binds a presentation to the cert the IdP just issued.
import { KeyPair, fromB64u, b64u, publicKeyField, decodeJwtClaims } from "./crypto.mjs";
import { accessRequest, assertion as makeAssertion, accessPresentation, nowS } from "./protocol.mjs";
import { AgentError, RequestError, NoWarrantError } from "./errors.mjs";

/** Re-mint the access cert when it expires within this margin (Rust: 60s). */
const ACCESS_REFRESH_MARGIN_S = 60;

const trim = (u) => String(u).replace(/\/$/, "");
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

/** Host of a URL — the `domain` an access request is pinned to. */
function urlHost(u) {
  try {
    return new URL(u).host;
  } catch {
    return String(u).replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  }
}

// ---------------------------------------------------------------------------
// Provisioning: the human-in-the-loop half
// ---------------------------------------------------------------------------

/**
 * Ask a broker to provision a device identity. Returns a pending approval —
 * show `verificationUriComplete`, `userCode` and `fingerprint` to the human,
 * then await `wait()`. The fingerprint lets them confirm that the page they
 * opened belongs to the agent that asked.
 *
 * `grants` is `[{ audience, scopes: [...] }]` — permissions requested in the
 * same consent, so the human approves identity and authority in one step.
 *
 * WHO ACTS FOR WHOM — the two pins that decide it:
 * - `grantor`: the identity a write is ATTRIBUTED to. Omit (or `"*"`) to let
 *   the approver choose which of their identities delegates. Pass `"self"`
 *   to pin the minted agent identity itself (grantor == grantee — the agent
 *   acts as itself, never attributed to the human); combining `"self"` with
 *   an as-you `grantee` is contradictory and refused up front.
 * - `grantee`: the identity that ACTS. Omit for **as-you** (grantee ≡ grantor,
 *   which is what provisioning an account at an RP requires). Pass `"*"` to
 *   have the approver mint a distinct actor — that is what produces an
 *   ON-BEHALF-OF warrant. Pass a concrete id for a foreign actor, and then
 *   `granteeHolder` is required, since the warrant binds to that holder.
 *
 * `handle` is the browserid identity handle to request — NOT an application's
 * account name. Don't pass an RP-side handle here.
 *
 * `label` suggests the agent's display NAME (the human confirms or changes it
 * on the naming screen); `message` is the agent's own account of why it wants
 * the bundled grants — quoted on the permission screen, marked unverified.
 */
export async function requestProvision(
  broker,
  { handle, namespace, grants = [], label, message, grantor, grantee, granteeHolder, http = fetch } = {},
) {
  const deviceKey = KeyPair.generate();
  const body = {
    provisioning_pubkey: publicKeyField(deviceKey.publicKeyB64),
    grants: grants.map((g) => ({ audience: g.audience, scopes: g.scopes ?? [] })),
  };
  if (handle) body.requested_handles = { names: [handle] };
  if (namespace) body.namespace = namespace;
  if (label) body.label = label;
  if (message) body.message = message;
  if (grantor) body.grantor = grantor;
  if (grantee) body.grantee = grantee;
  if (granteeHolder) body.grantee_holder = granteeHolder;

  const base = trim(broker);
  const { res, json } = await postJson(http, `${base}/agent-provision/request`, body);
  if (!res.ok || json.success !== true) {
    throw new RequestError("provision request", res.status, json.reason || "no reason given");
  }
  const need = (k) => {
    const v = json[k];
    if (typeof v !== "string") throw new AgentError(`provision response missing ${k}`);
    return v;
  };
  return new PendingProvision({
    http,
    broker: base,
    deviceKey,
    code: need("code"),
    userCode: need("user_code"),
    verificationUri: need("verification_uri"),
    verificationUriComplete: need("verification_uri_complete"),
    fingerprint: need("fingerprint"),
    intervalSeconds: json.interval ?? 5,
    expiresInSeconds: json.expires_in ?? 900,
  });
}

/** An approval the human has not resolved yet. */
export class PendingProvision {
  constructor(fields) {
    Object.assign(this, fields);
  }

  /**
   * Poll until the human approves or refuses. Resolves to
   * `{ credential, grants }` — a SINGLE pickup, so persist the result before
   * doing anything that can fail.
   */
  async wait({ signal } = {}) {
    const url = `${this.broker}/agent-provision/poll`;
    const interval = Math.max(1, this.intervalSeconds) * 1000;
    for (;;) {
      if (signal?.aborted) throw new AgentError("provision wait aborted");
      const { res, json } = await postJson(this.http, url, { code: this.code });
      switch (json.status) {
        case "completed": {
          const cred = json.credential ?? {};
          const need = (k) => {
            if (typeof cred[k] !== "string") throw new AgentError(`poll credential missing ${k}`);
            return cred[k];
          };
          const credential = {
            device_key: b64u(this.deviceKey.seed),
            agent_device_cert: need("device_cert"),
            idp: need("idp"),
            ...(cred.access_mint ? { access_mint: cred.access_mint } : {}),
            ...(cred.identity ? { identity: cred.identity } : {}),
          };
          // A grant's `warrant` field carries `warrant~config_cert` (the
          // warrant plus the device cert it chains from), which is why it is
          // stored and re-split as a pair rather than a single JWS.
          const grants = (json.grants ?? [])
            .filter((g) => g?.audience && g?.warrant)
            .map((g) => ({ audience: g.audience, grant: g.warrant }));
          // Two-stage flow: the identity was approved but the permission
          // screen was declined — the credential is real, the grants aren't.
          return json.grants_denied
            ? { credential, grants, grantsDenied: json.grants_denied }
            : { credential, grants };
        }
        case "denied":
          throw new AgentError("the human refused the request");
        case "expired":
          // A policy refusal at the page can clear the record, so surface any
          // reason the server gave rather than reporting a bare timeout — that
          // masking cost a real diagnosis once.
          throw new AgentError(
            json.reason
              ? `the request was resolved without a credential: ${json.reason}`
              : "the approval expired before it was resolved",
          );
        case "failed":
          throw new AgentError(`provisioning failed: ${json.reason || "no reason given"}`);
        case "pending":
          await sleep(interval);
          continue;
        default:
          // 410 means the code is gone; other 4xx (except rate limiting) are
          // terminal. Anything else is transient — keep polling.
          if (res.status === 410) {
            throw new AgentError(
              json.reason
                ? `the request is gone: ${json.reason}`
                : "the approval expired before it was resolved",
            );
          }
          if (res.status >= 400 && res.status < 500 && res.status !== 429) {
            throw new RequestError("provision poll", res.status, json.reason || "no reason given");
          }
          await sleep(interval);
      }
    }
  }
}

/**
 * Ask for MORE warrants once already provisioned — a second consent round for
 * a new audience, authenticated by the device cert rather than a fresh
 * identity. Returns a pending approval whose `wait()` resolves to the granted
 * `[{ audience, grant }]`. (Registrar: `/warrant/request` + `/warrant/poll`;
 * note the status word here is "approved", not "completed".)
 *
 * `grantor` pins who the warrants attribute to (t1jp). Omit (or `"*"`) to let
 * the approver choose — the consent page offers the agent itself or any
 * identity they own. Pass `"self"` (or the agent's own email) to require the
 * agent acts as itself, or a concrete email to require that authority; an
 * unsatisfiable pin fails this call immediately rather than expiring.
 */
export async function requestWarrants(broker, { deviceCert, identity, grants, label, message, grantor, http = fetch }) {
  const base = trim(broker);
  const { res, json } = await postJson(http, `${base}/warrant/request`, {
    device_cert: deviceCert,
    identity,
    grants: grants.map((g) => ({ audience: g.audience, scopes: g.scopes ?? [] })),
    ...(label ? { label } : {}),
    ...(message ? { message } : {}),
    ...(grantor ? { grantor } : {}),
  });
  if (!res.ok || json.success !== true) {
    throw new RequestError("warrant request", res.status, json.reason || "no reason given");
  }
  return new PendingWarrants({
    http,
    broker: base,
    code: json.code,
    verificationUri: json.verification_uri,
    verificationUriComplete: json.verification_uri_complete,
    intervalSeconds: json.interval ?? 5,
    expiresInSeconds: json.expires_in ?? 900,
  });
}

/** A warrant request the human has not resolved yet. */
export class PendingWarrants {
  constructor(fields) {
    Object.assign(this, fields);
  }

  async wait({ signal } = {}) {
    const url = `${this.broker}/warrant/poll`;
    const interval = Math.max(1, this.intervalSeconds) * 1000;
    for (;;) {
      if (signal?.aborted) throw new AgentError("warrant wait aborted");
      const { res, json } = await postJson(this.http, url, { code: this.code });
      if (json.status === "approved") {
        return (json.grants ?? [])
          .filter((g) => g?.audience && g?.warrant)
          .map((g) => ({ audience: g.audience, grant: g.warrant }));
      }
      if (json.status === "denied") {
        throw new AgentError(json.reason
          ? `the request was denied: ${json.reason}`
          : "the human refused the request");
      }
      if (res.status === 410) throw new AgentError("the request expired before it was resolved");
      if (res.status >= 400 && res.status < 500 && res.status !== 429) {
        throw new RequestError("warrant poll", res.status, json.reason || "no reason given");
      }
      await sleep(interval);
    }
  }
}

// ---------------------------------------------------------------------------
// The agent itself
// ---------------------------------------------------------------------------

/**
 * A headless agent holding a device credential. Mirrors Rust `DeviceAgent`:
 * identity and holder are read from the SIGNED device cert, never from
 * caller-supplied metadata.
 */
export class DeviceAgent {
  #deviceKey;
  // Access certs by audience. Unmanaged identities always use the "" slot
  // (one shared, audience-free cert — the mint stays RP-blind). A MANAGED
  // identity (device cert `managed: true`, spec §4.7) mints per audience so
  // the IdP can scope each cert; several concurrent certs may be held.
  #access = new Map(); // audienceKey -> { key, cert, claims }
  #grants = new Map(); // audience -> { warrant, configCert }

  constructor(credential, { http = fetch } = {}) {
    this.credential = credential;
    this.http = http;
    this.#deviceKey = KeyPair.fromSeed(fromB64u(credential.device_key));
    this.deviceCert = credential.agent_device_cert;
    const claims = decodeJwtClaims(this.deviceCert);
    if (claims.typ !== "browserid-device-cert-v1") {
      throw new AgentError(`not a device cert: typ '${claims.typ}'`);
    }
    if (claims["public-key"]?.publicKey !== this.#deviceKey.publicKeyB64) {
      throw new AgentError("device cert does not certify the held device key");
    }
    this.deviceCertClaims = claims;
    this.holder = claims.holder;
    this.email = credential.identity ?? claims.identities?.[0];
    if (!this.email) throw new AgentError("device cert has no identity");
    if (credential.identity && !authorizesIdentity(claims, credential.identity)) {
      throw new AgentError(`device cert does not authorize '${credential.identity}'`);
    }
    this.idpDomain = urlHost(credential.idp);
  }

  /**
   * Hold a warrant for its audience. Accepts either the two arguments or the
   * single `warrant~config_cert` string the provisioning poll returns.
   *
   * Checks what Rust `add_grant` checks: this agent must BE the warrant's
   * grantee (it is the actor that mints the access cert and signs), and the
   * warrant's holder must cover this agent's holder — catching a warrant
   * handed to the wrong agent before it fails opaquely at an RP.
   */
  addGrant(warrantOrPair, configCert) {
    let warrant = warrantOrPair;
    if (configCert === undefined) {
      const parts = String(warrantOrPair).split("~");
      warrant = parts[0];
      configCert = parts[1] ?? this.deviceCert;
    }
    const claims = decodeJwtClaims(warrant);
    const audience = claims.audience ?? claims.aud;
    if (!audience) throw new AgentError("warrant has no audience");
    if (claims.grantee && claims.grantee !== this.email) {
      throw new AgentError(
        `warrant grantee is '${claims.grantee}', this identity is '${this.email}'`,
      );
    }
    if (claims.holder && !holderMatches(claims.holder, this.holder)) {
      throw new AgentError("warrant holder does not cover this agent's holder");
    }
    this.#grants.set(audience, { warrant, configCert });
    return audience;
  }

  warrantedAudiences() {
    return [...this.#grants.keys()];
  }

  /** Held warrants in the `warrant~config_cert` form, for persistence — feed
   *  each `grant` back to `addGrant` after reloading the credential. */
  storedGrants() {
    return [...this.#grants.entries()].map(([audience, g]) => ({
      audience,
      grant: `${g.warrant}~${g.configCert}`,
    }));
  }

  /** Whether this identity is managed (device cert `managed: true`). */
  get isManaged() {
    return this.deviceCertClaims?.managed === true;
  }

  /** The cache slot for `audience`: managed identities key per audience. */
  #audKey(audience) {
    return this.isManaged ? (audience ?? "") : "";
  }

  /** Mint (or re-mint) an access cert over a FRESH key. For a managed
   *  identity the request names the audience (spec §4.2) so the IdP can
   *  scope the cert; unmanaged requests stay audience-free (RP-blind). */
  async mint(audience) {
    const accessKey = KeyPair.generate();
    const jti = b64u(globalThis.crypto.getRandomValues(new Uint8Array(8)));
    const request = accessRequest(this.#deviceKey, {
      domain: this.idpDomain,
      identity: this.email,
      holder: this.holder,
      accessKeyB64: accessKey.publicKeyB64,
      jti,
      ...(this.isManaged && audience ? { audience } : {}),
    });
    const url =
      this.credential.access_mint || `${trim(this.credential.idp)}/access/mint`;
    const { res, json } = await postJson(this.http, url, {
      device_cert: this.deviceCert,
      access_request: request,
    });
    // Response shapes differ across IdPs (`{success, access_cert}` vs a bare
    // `{access_cert}`), so trust the cert's presence, not a `success` flag.
    const cert = typeof json.access_cert === "string" ? json.access_cert : null;
    if (!res.ok || !cert) {
      throw new RequestError("access mint", res.status, json.reason || json.error || "no reason given");
    }
    this.#access.set(this.#audKey(audience), { key: accessKey, cert, claims: decodeJwtClaims(cert) });
    return cert;
  }

  async #ensureFreshAccess(audience) {
    const deadline = nowS() + ACCESS_REFRESH_MARGIN_S;
    const cur = this.#access.get(this.#audKey(audience));
    if (!cur || (cur.claims.exp ?? 0) <= deadline) await this.mint(audience);
    return this.#access.get(this.#audKey(audience));
  }

  /**
   * The four-part presentation for `audience`:
   * `access_cert ~ assertion ~ warrant ~ config_cert`. Re-mints the access
   * cert if stale. Requires a held warrant for the audience.
   */
  async assertionFor(audience) {
    const access = await this.#ensureFreshAccess(audience);
    const grant = this.#grants.get(audience);
    if (!grant) throw new NoWarrantError(audience);
    return accessPresentation({
      accessCert: access.cert,
      assertion: makeAssertion(access.key, audience),
      warrant: grant.warrant,
      configCert: grant.configCert,
    });
  }

  /**
   * A presentation PLUS the access key that signed it, so a caller can sign
   * an external payload with the same key the access cert certifies —
   * verifiers enforce `signer key == access cert key`. (Rust:
   * `assertion_with_access_seed`.)
   */
  async assertionWithAccessKey(audience) {
    const presentation = await this.assertionFor(audience);
    const access = this.#access.get(this.#audKey(audience));
    return { presentation, accessKey: access.key, accessCert: access.cert };
  }
}

/** A warrant's holder may be an exact holder or a `*`-suffixed prefix matcher. */
function holderMatches(matcher, holder) {
  return matcher.endsWith("*") ? holder.startsWith(matcher.slice(0, -1)) : matcher === holder;
}

/** A cert naming a base identity also authorizes its `+tag` sub-addresses. */
function authorizesIdentity(claims, identity) {
  const base = (id) => {
    const at = id.lastIndexOf("@");
    if (at < 0) return id;
    const [local, domain] = [id.slice(0, at), id.slice(at + 1)];
    return `${local.split("+")[0]}@${domain}`;
  };
  return (claims.identities ?? []).some((id) => id === identity || id === base(identity));
}
