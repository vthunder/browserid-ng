import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createMcpAuth,
  createMemoryStore,
  McpAuthError,
  JWT_BEARER_GRANT,
} from "../index.mjs";

const RESOURCE = "https://mcp.example.com";

// A configurable fake broker. `verify` is the /verify JSON; `status`
// is the /status/check JSON. Either can be a function (of the request body)
// or a value; set to "throw" to simulate an unreachable broker.
function fakeBroker({ verify, status } = {}) {
  const calls = { verify: 0, status: 0 };
  const fetch = async (url, init) => {
    const body = init && init.body ? JSON.parse(init.body) : {};
    if (url.endsWith("/verify")) {
      calls.verify++;
      if (verify === "throw") throw new Error("ECONNREFUSED");
      const v = typeof verify === "function" ? verify(body) : verify;
      return jsonResponse(v?.__status ?? 200, v);
    }
    if (url.endsWith("/status/check")) {
      calls.status++;
      if (status === "throw") throw new Error("ECONNREFUSED");
      const s = typeof status === "function" ? status(body) : status;
      return jsonResponse(s?.__status ?? 200, s);
    }
    throw new Error("unexpected url " + url);
  };
  return { fetch, calls };
}
function jsonResponse(httpStatus, obj) {
  return {
    ok: httpStatus >= 200 && httpStatus < 300,
    status: httpStatus,
    json: async () => obj || {},
  };
}

const okVerify = {
  status: "okay",
  email: "dan@sandmill.org",
  grantee: "dan+claude@sandmill.org",
  holder: "agents.abc123",
  issuer: "sandmill.org",
  scopes: ["repo:read", "issues:create"],
  status_refs: [{ uri: "https://browserid.me/.well-known/browserid-status", idx: 7 }],
};

function auth(overrides = {}) {
  const broker = fakeBroker({ verify: okVerify, status: { ok: true, revoked: false }, ...overrides.broker });
  const mcp = createMcpAuth({
    resource: RESOURCE,
    broker: "https://browserid.me",
    scopesForTool: { create_issue: ["issues:create"], read_repo: ["repo:read"], admin: ["repo:admin"] },
    statusCacheS: 0, // force a re-check on every authenticate unless overridden
    fetch: broker.fetch,
    store: createMemoryStore(),
    ...overrides.opts,
  });
  return { mcp, broker };
}

const tokenReq = (over = {}) => ({ grant_type: JWT_BEARER_GRANT, assertion: "AC~AS~WR~CC", ...over });

// --- token endpoint --------------------------------------------------------

test("handleToken rejects an unsupported grant type", async () => {
  const { mcp } = auth();
  await assert.rejects(
    () => mcp.handleToken({ grant_type: "authorization_code", assertion: "x" }),
    (e) => e instanceof McpAuthError && e.oauthError === "unsupported_grant_type"
  );
});

test("handleToken rejects a missing assertion", async () => {
  const { mcp } = auth();
  await assert.rejects(
    () => mcp.handleToken({ grant_type: JWT_BEARER_GRANT }),
    (e) => e.oauthError === "invalid_request"
  );
});

test("handleToken mints a scoped bearer from a valid presentation", async () => {
  const { mcp } = auth();
  const res = await mcp.handleToken(tokenReq());
  assert.equal(res.token_type, "Bearer");
  assert.ok(res.access_token.startsWith("bat_"));
  assert.equal(res.expires_in, 3600);
  assert.equal(res.scope, "repo:read issues:create");
  const ctx = await mcp.authenticate(`Bearer ${res.access_token}`);
  assert.equal(ctx.grantor, "dan@sandmill.org");
  assert.equal(ctx.grantee, "dan+claude@sandmill.org");
  assert.equal(ctx.holder, "agents.abc123");
  assert.deepEqual(ctx.scopes, ["repo:read", "issues:create"]);
});

test("handleToken rejects a presentation that does not verify", async () => {
  const { mcp } = auth({ broker: { verify: { status: "failure", reason: "expired" } } });
  await assert.rejects(
    () => mcp.handleToken(tokenReq()),
    (e) => e.oauthError === "invalid_grant" && /expired/.test(e.message)
  );
});

test("handleToken fails closed when the verifier is unreachable", async () => {
  const { mcp } = auth({ broker: { verify: "throw" } });
  await assert.rejects(
    () => mcp.handleToken(tokenReq()),
    (e) => e.oauthError === "temporarily_unavailable" && e.httpStatus === 503
  );
});

test("requested scope may narrow but never widen the warrant", async () => {
  const { mcp } = auth();
  const narrowed = await mcp.handleToken(tokenReq({ scope: "repo:read" }));
  assert.equal(narrowed.scope, "repo:read");
  await assert.rejects(
    () => mcp.handleToken(tokenReq({ scope: "repo:read repo:admin" })),
    (e) => e.oauthError === "invalid_scope"
  );
});

// --- per-call validation + fail-closed status ------------------------------

test("authenticate rejects an unknown token", async () => {
  const { mcp } = auth();
  await assert.rejects(
    () => mcp.authenticate("Bearer nope"),
    (e) => e.oauthError === "invalid_token" && e.httpStatus === 401
  );
});

test("authenticate rejects a missing bearer header", async () => {
  const { mcp } = auth();
  await assert.rejects(() => mcp.authenticate(undefined), (e) => e.httpStatus === 401);
});

test("a revoked warrant kills the token on the next call (ok:false)", async () => {
  let revoked = false;
  const { mcp } = auth({ broker: { status: () => (revoked ? { ok: false, revoked: true } : { ok: true, revoked: false }) } });
  const { access_token } = await mcp.handleToken(tokenReq());
  await mcp.authenticate(`Bearer ${access_token}`); // fine
  revoked = true;
  await assert.rejects(
    () => mcp.authenticate(`Bearer ${access_token}`),
    (e) => e.oauthError === "invalid_token" && /revoked/.test(e.message)
  );
  // Token is forgotten after a revoke.
  await assert.rejects(() => mcp.authenticate(`Bearer ${access_token}`), (e) => /unknown|revoked/.test(e.message));
});

test("authenticate fails closed when the status list is unreachable", async () => {
  const { mcp } = auth({ broker: { status: "throw" } });
  const { access_token } = await mcp.handleToken(tokenReq());
  await assert.rejects(
    () => mcp.authenticate(`Bearer ${access_token}`),
    (e) => e.oauthError === "invalid_token" && /fail-closed/.test(e.message)
  );
});

test("a fresh status result is cached within statusCacheS", async () => {
  const { mcp, broker } = auth({ opts: { statusCacheS: 300 } });
  const { access_token } = await mcp.handleToken(tokenReq());
  const before = broker.calls.status;
  await mcp.authenticate(`Bearer ${access_token}`);
  await mcp.authenticate(`Bearer ${access_token}`);
  // /verify already established freshness; both authenticates hit cache.
  assert.equal(broker.calls.status, before);
});

test("a presentation with no status refs needs no re-check", async () => {
  const { mcp, broker } = auth({ broker: { verify: { ...okVerify, status_refs: [] } } });
  const { access_token } = await mcp.handleToken(tokenReq());
  await mcp.authenticate(`Bearer ${access_token}`);
  assert.equal(broker.calls.status, 0);
});

// --- scope enforcement -----------------------------------------------------

test("requireWarrant enforces a tool's required scopes", async () => {
  const { mcp } = auth();
  const { access_token } = await mcp.handleToken(tokenReq());
  const hdr = `Bearer ${access_token}`;
  const ctx = await mcp.requireWarrant(hdr, "create_issue"); // needs issues:create (granted)
  assert.equal(ctx.grantee, "dan+claude@sandmill.org");
  await assert.rejects(
    () => mcp.requireWarrant(hdr, "admin"), // needs repo:admin (not granted)
    (e) => e.oauthError === "insufficient_scope" && e.httpStatus === 403
  );
  // Explicit scope list works too.
  await mcp.requireWarrant(hdr, ["repo:read"]);
});

// --- discovery metadata ----------------------------------------------------

test("discovery metadata advertises the resource, AS, and jwt-bearer grant", async () => {
  const { mcp } = auth();
  const prm = mcp.protectedResourceMetadata();
  assert.equal(prm.resource, RESOURCE);
  assert.deepEqual(prm.authorization_servers, [RESOURCE]);
  assert.ok(prm.scopes_supported.includes("issues:create"));
  const asm = mcp.authorizationServerMetadata();
  assert.equal(asm.issuer, RESOURCE);
  assert.equal(asm.token_endpoint, `${RESOURCE}/token`);
  assert.deepEqual(asm.grant_types_supported, [JWT_BEARER_GRANT]);
});

test("challenge points at the protected-resource metadata", async () => {
  const { mcp } = auth();
  assert.match(mcp.challenge(), /Bearer resource_metadata="https:\/\/mcp\.example\.com\/\.well-known\/oauth-protected-resource"/);
});

test("an expired bearer is rejected", async () => {
  const { mcp } = auth({ opts: { tokenTtlS: -1 } }); // already expired
  const { access_token } = await mcp.handleToken(tokenReq());
  await assert.rejects(() => mcp.authenticate(`Bearer ${access_token}`), (e) => e.httpStatus === 401);
});
