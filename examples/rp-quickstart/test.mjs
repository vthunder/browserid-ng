// Tests the RP glue — /api/login verify → signed session → /api/me — with a mock
// /verify so no broker or browser dialog is needed. (The browser sign-in itself
// needs a running broker; see the README.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { startMockVerifier } from "../mcp-agent-auth/mock-verifier.mjs";

const RP_ORIGIN = "http://localhost:8099";

async function boot(verifierUrl) {
  process.env.RP_ORIGIN = RP_ORIGIN;
  process.env.VERIFIER_URL = verifierUrl;
  process.env.PORT = "0";
  const { server } = await import("./server.mjs?" + Math.random());
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  return { base: `http://127.0.0.1:${port}`, close: () => server.close() };
}

test("RP: verify → session cookie → /api/me; bad assertion fails closed", async () => {
  // The mock returns a human for assertion "human"; our RP audience must match.
  const mock = await startMockVerifier(RP_ORIGIN);
  const rp = await boot(mock.url);
  try {
    // good human assertion → session established
    const login = await fetch(`${rp.base}/api/login`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ assertion: "human" }),
    });
    assert.equal(login.status, 200);
    assert.equal((await login.json()).email, "alice@acme.com");
    const cookie = login.headers.get("set-cookie").split(";")[0];

    // cookie authenticates /api/me
    const me = await fetch(`${rp.base}/api/me`, { headers: { cookie } });
    assert.equal((await me.json()).email, "alice@acme.com");

    // no cookie → anonymous
    const anon = await fetch(`${rp.base}/api/me`);
    assert.deepEqual(await anon.json(), {});

    // bad assertion → 401, fail closed
    const bad = await fetch(`${rp.base}/api/login`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ assertion: "nonsense" }),
    });
    assert.equal(bad.status, 401);

    // a tampered cookie is rejected
    const forged = await fetch(`${rp.base}/api/me`, { headers: { cookie: "sid=abc.def" } });
    assert.deepEqual(await forged.json(), {});
  } finally {
    rp.close();
    mock.close();
  }
});
