// Admin session cookies for the console. SECURITY-CRITICAL: the console is
// public and spawns commands, so a valid session must be UNFORGEABLE.
//
// Design: a stateless, HMAC-signed cookie. The value is
//   v1.<emailB64url>.<expEpochS>.<nonceB64url>.<hmacB64url>
// where hmac = HMAC-SHA256(secret, "v1.<emailB64url>.<exp>.<nonce>"). The secret
// is a per-install 32-byte key persisted 0600 in ~/.browserid-gate, so a
// restart does NOT log everyone out (no server-side session table to lose), and
// a tampered/forged/expired cookie fails the HMAC or the exp check → rejected.
//
// CSRF: a synchronizer token derived from the SAME nonce,
//   csrf = HMAC-SHA256(secret, "csrf." + nonce). It is bound to the session
// (only someone holding the cookie's nonce can compute it) yet needs no storage.
// State-changing calls must submit it (double-submit: the client reads it from
// the readable `gate_csrf` cookie / the login/whoami response and echoes it in
// the `x-csrf-token` header); we recompute from the session nonce and compare
// in constant time.
//
// Cookie flags: httpOnly (JS can't read the session), Secure (https only —
// dropped for http loopback in --console-local), SameSite=Lax, bounded TTL.

import { randomBytes, createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync } from "node:fs";
import { join } from "node:path";
import { gateHome } from "./credential.mjs";

const COOKIE = "gate_session";
const CSRF_COOKIE = "gate_csrf";
const VERSION = "v1";

/** Read (or generate + persist, 0600) the per-install session HMAC secret. */
export function sessionSecret() {
  const home = gateHome();
  const path = join(home, "session-secret");
  if (existsSync(path)) {
    const hex = readFileSync(path, "utf8").trim();
    if (/^[0-9a-f]{64,}$/i.test(hex)) return Buffer.from(hex, "hex");
  }
  mkdirSync(home, { recursive: true, mode: 0o700 });
  try { chmodSync(home, 0o700); } catch { /* best effort */ }
  const secret = randomBytes(32);
  writeFileSync(path, secret.toString("hex"), { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch { /* best effort */ }
  return secret;
}

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const nowS = () => Math.floor(Date.now() / 1000);

/**
 * @param {object} opts
 * @param {Buffer} [opts.secret]  HMAC key (default: persisted install secret).
 * @param {number} [opts.ttlS]    session lifetime seconds (default 12h).
 * @param {boolean} [opts.secure] set the Secure cookie flag (default true; pass
 *                                false only for http loopback / --console-local).
 */
export function createSessionManager({ secret, ttlS = 12 * 3600, secure = true, cookieName } = {}) {
  const key = secret || sessionSecret();
  const COOKIE = cookieName || "gate_session";
  const CSRF_COOKIE = cookieName ? `${cookieName}_csrf` : "gate_csrf";

  const sign = (payload) => b64u(createHmac("sha256", key).update(payload).digest());

  function csrfForNonce(nonce) {
    return b64u(createHmac("sha256", key).update("csrf." + nonce).digest());
  }

  /** Issue a session for `email`. Returns Set-Cookie header values + the csrf token. */
  function issue(email) {
    const exp = nowS() + ttlS;
    const nonce = b64u(randomBytes(32));
    const emailB = b64u(email);
    const payload = `${VERSION}.${emailB}.${exp}.${nonce}`;
    const value = `${payload}.${sign(payload)}`;
    const csrf = csrfForNonce(nonce);
    const attrs = `Path=/; HttpOnly; SameSite=Lax; Max-Age=${ttlS}${secure ? "; Secure" : ""}`;
    // The csrf cookie is deliberately NOT httpOnly — the page JS reads it to
    // echo in the x-csrf-token header (double-submit).
    const csrfAttrs = `Path=/; SameSite=Lax; Max-Age=${ttlS}${secure ? "; Secure" : ""}`;
    return {
      csrf,
      setCookies: [
        `${COOKIE}=${value}; ${attrs}`,
        `${CSRF_COOKIE}=${csrf}; ${csrfAttrs}`,
      ],
    };
  }

  /** Verify a session cookie value. Returns { email, nonce } or null. */
  function verifyValue(value) {
    if (typeof value !== "string") return null;
    const parts = value.split(".");
    if (parts.length !== 5) return null;
    const [ver, emailB, expStr, nonce, mac] = parts;
    if (ver !== VERSION) return null;
    const payload = `${ver}.${emailB}.${expStr}.${nonce}`;
    const expected = sign(payload);
    if (!constEq(mac, expected)) return null;
    const exp = Number(expStr);
    if (!Number.isFinite(exp) || exp <= nowS()) return null;
    let email;
    try { email = Buffer.from(emailB, "base64url").toString("utf8"); } catch { return null; }
    return { email, nonce };
  }

  /** Verify from a parsed cookie jar (object of name→value). */
  function verify(cookies) {
    return verifyValue(cookies?.[COOKIE]);
  }

  /** True iff `submitted` matches the csrf token derived from this session's nonce. */
  function checkCsrf(session, submitted) {
    if (!session || typeof submitted !== "string" || !submitted) return false;
    return constEq(submitted, csrfForNonce(session.nonce));
  }

  const clearCookies = () => [
    `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? "; Secure" : ""}`,
    `${CSRF_COOKIE}=; Path=/; SameSite=Lax; Max-Age=0${secure ? "; Secure" : ""}`,
  ];

  return { issue, verify, verifyValue, checkCsrf, csrfForNonce, clearCookies, COOKIE, CSRF_COOKIE };
}

/** Parse a Cookie header into { name: value }. */
export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    if (k) out[k] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function constEq(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
