// Wire artifacts for the agent protocol, matching browserid-core exactly.
// Signing input, header, and field names per the porting spec.
import { KeyPair, publicKeyField } from "./crypto.mjs";

const HEADER = { alg: "EdDSA", typ: "JWT" }; // JSON.stringify → {"alg":"EdDSA","typ":"JWT"}
export const ASSERTION_VALIDITY_S = 5 * 60;

export const nowS = () => Math.floor(Date.now() / 1000);

// ---- assertion (signed with the access key) --------------------------------

/** A short-lived assertion for `audience`, signed by the agent key. */
export function assertion(agentKey, audience) {
  const exp = nowS() + ASSERTION_VALIDITY_S;
  return agentKey.jws(HEADER, { exp, aud: audience });
}

// ---- device-cert path (the current protocol) -------------------------------

const ACCESS_REQUEST_VALIDITY_S = 10 * 60;

/** A `browserid-access-request-v1`, signed with the DEVICE key: "certify this
 *  fresh access key for this identity". The holder is copied from the device
 *  cert — the mint must not let a requester choose a different one. */
export function accessRequest(deviceKey, { domain, identity, holder, accessKeyB64, jti, audience }) {
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
    // Managed identities only (spec §4.2): callers pass `audience` iff the
    // device cert carries `managed: true`; unmanaged mints stay RP-blind.
    ...(audience ? { audience } : {}),
  });
}

/** The four-part presentation an RP verifies:
 *  `access_cert ~ assertion ~ warrant ~ config_cert`. Order matters —
 *  browserid-core's AccessPresentation parses positionally. */
export function accessPresentation({ accessCert, assertion: assn, warrant, configCert }) {
  return `${accessCert}~${assn}~${warrant}~${configCert}`;
}

export { KeyPair };
