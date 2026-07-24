// Wire artifacts for the agent protocol, matching browserid-core exactly.
// Signing input, header, and field names per the porting spec.
import { KeyPair, publicKeyField, decodeJwtClaims } from "./crypto.mjs";

const HEADER = { alg: "EdDSA", typ: "JWT" }; // JSON.stringify → {"alg":"EdDSA","typ":"JWT"}
const REQUEST_VALIDITY_S = 10 * 60;
export const ASSERTION_VALIDITY_S = 5 * 60;

export const nowS = () => Math.floor(Date.now() / 1000);

// ---- signed requests (signed with the provisioning key P_priv) -------------

/** A `browserid-provisioning-request-v1` for the given action. */
function provisioningRequest(provKey, { action, domain, name, agentKeyB64, grants }) {
  const iat = nowS();
  const claims = { typ: "browserid-provisioning-request-v1", iat, exp: iat + REQUEST_VALIDITY_S, action, domain };
  if (name != null) claims.name = name;
  if (agentKeyB64) claims["agent-key"] = publicKeyField(agentKeyB64);
  if (grants) claims["warrant-grants"] = grants.map((g) => (g.scopes && g.scopes.length ? { aud: g.aud, scopes: g.scopes } : { aud: g.aud }));
  return provKey.jws(HEADER, claims);
}

export const mintRequest = (provKey, domain, name, agentKeyB64) =>
  provisioningRequest(provKey, { action: "mint", domain, name, agentKeyB64 });

export const revokeRequest = (provKey, domain, name) =>
  provisioningRequest(provKey, { action: "revoke", domain, name });

export const warrantRequest = (provKey, registrarDomain, name, grants) =>
  provisioningRequest(provKey, { action: "warrant", domain: registrarDomain, name, grants });

/** The request bundle sent to the server: `U_cert~P_cert~R`. */
export function bundle(delegation, request) {
  return `${delegation}~${request}`; // delegation is already "U_cert~P_cert"
}

// ---- assertion (signed with the agent's own key) ---------------------------

/** A short-lived assertion for `audience`, signed by the agent key. */
export function assertion(agentKey, audience) {
  const exp = nowS() + ASSERTION_VALIDITY_S;
  return agentKey.jws(HEADER, { exp, aud: audience });
}

/** The backed presentation the RP verifies (legacy provisioning-cert path). */
export function backedPresentation({ cert, warrant, assertion: assn }) {
  return warrant ? `${cert}~${warrant}~${assn}` : `${cert}~${assn}`;
}

// ---- device-cert path (the current protocol) -------------------------------

const ACCESS_REQUEST_VALIDITY_S = 10 * 60;

/** A `browserid-access-request-v1`, signed with the DEVICE key: "certify this
 *  fresh access key for this identity". The holder is copied from the device
 *  cert — the mint must not let a requester choose a different one. */
export function accessRequest(deviceKey, { domain, identity, holder, accessKeyB64, jti }) {
  const iat = nowS();
  return deviceKey.jws(HEADER, {
    typ: "browserid-access-request-v1",
    iat,
    exp: iat + ACCESS_REQUEST_VALIDITY_S,
    jti,
    domain,
    identity,
    holder,
    "access-key": publicKeyField(accessKeyB64),
  });
}

/** The four-part presentation an RP verifies:
 *  `access_cert ~ assertion ~ warrant ~ config_cert`. Order matters —
 *  browserid-core's AccessPresentation parses positionally. */
export function accessPresentation({ accessCert, assertion: assn, warrant, configCert }) {
  return `${accessCert}~${assn}~${warrant}~${configCert}`;
}

// ---- parsing (claims only; the RP does the cryptographic verification) -----

export function parseCert(encoded) {
  const c = decodeJwtClaims(encoded);
  return {
    encoded,
    typ: c.typ || null,
    issuer: c.iss,
    email: c.principal?.email,
    exp: c.exp,
    isAgent: c.typ === "browserid-agent-cert-v1",
    agentParent: c.agent?.parent ?? null,
    registrar: c.registrar ?? null,
    publicKeyB64: c["public-key"]?.publicKey ?? null,
  };
}

export function parseWarrant(encoded) {
  const c = decodeJwtClaims(encoded);
  return {
    encoded,
    typ: c.typ || null,
    audience: c.aud,
    agent: c.agent,
    scopes: c.scopes ?? null,
    exp: c.exp,
  };
}

/** `<prefix>+<8 hex>` for a pattern-based name (matches random_hex()). */
export function generatedName(prefix) {
  const b = new Uint8Array(4);
  globalThis.crypto.getRandomValues(b);
  return `${prefix}+${[...b].map((x) => x.toString(16).padStart(2, "0")).join("")}`;
}

export { KeyPair };
