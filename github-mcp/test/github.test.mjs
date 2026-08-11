// The GitHub App client: App JWT minting, installation resolution,
// installation-token mint + cache + refresh-on-expiry, and the one-shot
// re-mint on a surprise 401. GitHub is a local mock HTTP server that
// signature-checks the App JWT with the test keypair's public key.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync, verify as cryptoVerify } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createGitHubApp, loadPrivateKeyFromEnv } from "../src/github.mjs";

const MOCK_PORT = 43310;
const API = `http://localhost:${MOCK_PORT}`;
const APP_ID = "4563190";

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PEM = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

// --- mock GitHub ------------------------------------------------------------

const calls = { installations: 0, tokens: 0, repos: 0 };
let tokenSerial = 0;
let currentToken = null;
let failNextReposWith401 = false;

function checkAppJwt(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || "");
  assert.ok(m, "missing bearer");
  const [h, p, s] = m[1].split(".");
  const header = JSON.parse(Buffer.from(h, "base64url"));
  const payload = JSON.parse(Buffer.from(p, "base64url"));
  assert.equal(header.alg, "RS256");
  assert.equal(payload.iss, APP_ID);
  assert.ok(payload.exp > payload.iat, "exp after iat");
  assert.ok(payload.exp - payload.iat <= 600, "under GitHub's 10-minute cap");
  assert.ok(
    cryptoVerify("RSA-SHA256", Buffer.from(`${h}.${p}`), publicKey, Buffer.from(s, "base64url")),
    "App JWT signature verifies"
  );
}

const mock = createServer((req, res) => {
  const reply = (code, obj) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  try {
    if (req.method === "GET" && req.url === "/app/installations") {
      calls.installations++;
      checkAppJwt(req);
      return reply(200, [{ id: 999 }, { id: 1000 }]);
    }
    const mt = /^\/app\/installations\/(\d+)\/access_tokens$/.exec(req.url);
    if (req.method === "POST" && mt) {
      calls.tokens++;
      checkAppJwt(req);
      currentToken = `ghs_${++tokenSerial}_inst${mt[1]}`;
      return reply(201, {
        token: currentToken,
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
      });
    }
    if (req.method === "GET" && req.url === "/installation/repositories") {
      calls.repos++;
      if (failNextReposWith401) {
        failNextReposWith401 = false;
        return reply(401, { message: "Bad credentials" });
      }
      assert.equal(req.headers.authorization, `Bearer ${currentToken}`, "uses the live installation token");
      return reply(200, { total_count: 1, repositories: [{ full_name: "acme/widgets", private: false }] });
    }
    reply(404, { message: "not found" });
  } catch (e) {
    reply(500, { message: e.message });
  }
});

before(() => new Promise((r) => mock.listen(MOCK_PORT, r)));
after(() => mock.close());

const makeApp = (over = {}) =>
  createGitHubApp({ appId: APP_ID, privateKey: PEM, apiUrl: API, ...over });

// --- App JWT ----------------------------------------------------------------

test("appJwt mints a verifiable RS256 JWT with iss = the App ID", () => {
  const jwt = makeApp().appJwt();
  const [h, p, s] = jwt.split(".");
  const header = JSON.parse(Buffer.from(h, "base64url"));
  const payload = JSON.parse(Buffer.from(p, "base64url"));
  assert.deepEqual(header, { alg: "RS256", typ: "JWT" });
  assert.equal(payload.iss, APP_ID);
  assert.ok(payload.iat < payload.exp);
  assert.ok(
    cryptoVerify("RSA-SHA256", Buffer.from(`${h}.${p}`), publicKey, Buffer.from(s, "base64url"))
  );
});

// --- installation resolution ------------------------------------------------

test("resolves the FIRST installation when none is pinned (single-install v1)", async () => {
  const app = makeApp();
  assert.equal(await app.resolveInstallationId(), 999);
  const token = await app.installationToken();
  assert.match(token, /_inst999$/);
});

test("GITHUB_INSTALLATION_ID pins the installation and skips discovery", async () => {
  const before = calls.installations;
  const app = makeApp({ installationId: "1000" });
  const token = await app.installationToken();
  assert.match(token, /_inst1000$/);
  assert.equal(calls.installations, before, "no /app/installations call");
});

// --- token cache + refresh --------------------------------------------------

test("installation token is minted once and cached across calls", async () => {
  const app = makeApp({ installationId: 999 });
  const before = calls.tokens;
  const t1 = await app.installationToken();
  const t2 = await app.installationToken();
  await app.listRepos();
  assert.equal(t1, t2);
  assert.equal(calls.tokens, before + 1, "one mint serves them all");
});

test("token auto-refreshes when the clock nears its expiry", async () => {
  let now = Date.now();
  const app = makeApp({ installationId: 999, nowMs: () => now, tokenSkewS: 300 });
  const before = calls.tokens;
  const t1 = await app.installationToken();
  now += 30 * 60_000; // 30 min: still comfortably valid (1h - 5min skew)
  assert.equal(await app.installationToken(), t1);
  now += 26 * 60_000; // 56 min: inside the 5-minute skew window → refresh
  const t2 = await app.installationToken();
  assert.notEqual(t2, t1);
  assert.equal(calls.tokens, before + 2);
});

test("a surprise 401 re-mints once and retries the call", async () => {
  const app = makeApp({ installationId: 999 });
  await app.installationToken();
  const before = calls.tokens;
  failNextReposWith401 = true;
  const out = await app.listRepos();
  assert.equal(out.repositories[0].full_name, "acme/widgets");
  assert.equal(calls.tokens, before + 1, "re-minted exactly once");
});

// --- API error surface ------------------------------------------------------

test("non-2xx GitHub responses throw with status + message", async () => {
  const app = makeApp({ installationId: 999 });
  await assert.rejects(
    () => app.readFile("acme/widgets", "nope.txt"),
    (e) => /HTTP 404/.test(e.message) && /not found/.test(e.message)
  );
});

// --- key loading ------------------------------------------------------------

test("loadPrivateKeyFromEnv: FILE wins over the inline PEM", () => {
  const dir = mkdtempSync(join(tmpdir(), "ghmcp-"));
  const file = join(dir, "key.pem");
  writeFileSync(file, "FILE-PEM");
  assert.equal(
    loadPrivateKeyFromEnv({ GITHUB_APP_PRIVATE_KEY: "ENV-PEM", GITHUB_APP_PRIVATE_KEY_FILE: file }),
    "FILE-PEM"
  );
  assert.equal(loadPrivateKeyFromEnv({ GITHUB_APP_PRIVATE_KEY: "ENV-PEM" }), "ENV-PEM");
  assert.equal(loadPrivateKeyFromEnv({}), null);
});
