// Central config. Every value has a dev default; production (WALLET_ENV=production)
// refuses to start on the dev fallbacks that would be security holes there.
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";

const trim = (u) => String(u).replace(/\/$/, "");

export const PORT = Number(process.env.PORT || 3100);
export const WALLET_ORIGIN = trim(process.env.WALLET_ORIGIN || `http://localhost:${PORT}`);
export const BROKER = trim(process.env.BROWSERID_BROKER || "https://browserid.me");
export const VERIFIER_URL = process.env.VERIFIER_URL || `${BROKER}/verify`;
export const GUESTBOOK_URL = process.env.GUESTBOOK_URL || `${BROKER}/guestbook`;
export const DATABASE_PATH = process.env.WALLET_DATABASE_PATH || "wallet.db";
export const PRODUCTION = process.env.WALLET_ENV === "production";

/** Access/refresh token lifetimes (design doc §6). */
export const ACCESS_TOKEN_TTL_S = 60 * 60;
export const REFRESH_TOKEN_TTL_S = 30 * 24 * 60 * 60;
export const AUTH_CODE_TTL_S = 10 * 60;
export const SESSION_TTL_S = 24 * 60 * 60;

/** The one scope the MVP knows. */
export const WALLET_SCOPE = "wallet";

function requireOrDevFile(envName, fileName) {
  const fromEnv = process.env[envName];
  if (fromEnv) return Buffer.from(fromEnv, "base64url");
  if (PRODUCTION) {
    throw new Error(`${envName} must be set in production (base64url, 32 bytes)`);
  }
  // Dev fallback: a generated secret persisted next to the DB, so restarts
  // don't orphan encrypted rows or invalidate sessions mid-flow.
  const dir = dirname(DATABASE_PATH) === "." ? "." : dirname(DATABASE_PATH);
  const path = join(dir, fileName);
  if (existsSync(path)) return Buffer.from(readFileSync(path, "utf8").trim(), "base64url");
  mkdirSync(dir, { recursive: true });
  const secret = randomBytes(32);
  writeFileSync(path, secret.toString("base64url"), { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch {}
  console.error(`[wallet-service] dev: generated ${envName} at ${path}`);
  return secret;
}

/** KEK wrapping tenant device-key seeds (custody.mjs). 32 bytes. */
export const KEK = requireOrDevFile("WALLET_KEK", ".dev-kek");
/** HMAC key for the authorize-page session cookie. */
export const SESSION_SECRET = requireOrDevFile("WALLET_SESSION_SECRET", ".dev-session-secret");

for (const [name, buf] of [["WALLET_KEK", KEK], ["WALLET_SESSION_SECRET", SESSION_SECRET]]) {
  if (buf.length < 32) throw new Error(`${name} must decode to at least 32 bytes`);
}
