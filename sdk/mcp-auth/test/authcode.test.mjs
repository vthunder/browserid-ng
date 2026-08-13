// The authorization-code lane, unit level: PKCE S256 verification, Dynamic
// Client Registration (redirect_uri validation), /authorize parameter
// guards (S256 required, exact-match redirect_uri, open-redirect rules),
// the /authorize/return leg, and the code store (single-use, TTL, client +
// redirect_uri + PKCE binding). The broker is an in-process fake fetch.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import {
  createMcpAuth,
  createAuthCodeLane,
  createMemoryStore,
  verifyPkceS256,
  McpAuthError,
  JWT_BEARER_GRANT,
} from "../index.mjs";
import { KeyPair } from "@browserid-ng/agent";

const RESOURCE = "https://mcp.example.com";
const BROKER = "https://broker.example";
const GATEWAY = "gate@example.com";
const HUMAN = "dan@example.com";
const REDIRECT = "https://host.example/oauth/callback";

// --- fabricated wire artifacts (claims-only JWS; the fake broker never
// verifies signatures — the real one does) -----------------------------------

const b64uJson = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJws = (claims) => `${b64uJson({ alg: "EdDSA", typ: "JWT" })}.${b64uJson(claims)}.c2ln`;
const nowS = () => Math.floor(Date.now() / 1000);

/** A gateway agent credential the DeviceAgent accepts (real keypair, canned cert). */
function gatewayCredential() {
  const kp = KeyPair.generate();
  const cert = fakeJws({
    typ: "browserid-device-cert-v1",
    "public-key": { algorithm: "Ed25519", publicKey: kp.publicKeyB64 },
    holder: "svc.gate1",
    identities: [GATEWAY],
    purpose: "authentication",
    iat: nowS(),
    exp: nowS() + 90 * 24 * 3600,
  });
  return {
    device_key: Buffer.from(kp.seed).toString("base64url"),
    agent_device_cert: cert,
    idp: BROKER,
    identity: GATEWAY,
  };
}

/** A canned approved grant: `warrant~config_cert` for RESOURCE. */
function cannedGrant(scopes = ["tool:read", "tool:write"]) {
  const warrant = fakeJws({
    typ: "browserid-warrant-v1",
    grantor: HUMAN,
    grantee: GATEWAY,
    holder: "svc.gate1",
    audience: RESOURCE,
    scopes,
    iat: nowS(),
    exp: nowS() + 90 * 24 * 3600,
  });
  const configCert = fakeJws({
    typ: "browserid-device-cert-v1",
    purpose: "authorization",
    iat: nowS(),
    exp: nowS() + 90 * 24 * 3600,
  });
  return `${warrant}~${configCert}`;
}

// --- the fake broker ---------------------------------------------------------

// `poll` controls /warrant/poll: "approved" | "denied" | "pending" | a fn.
function fakeBroker({ poll = "approved", scopes = ["tool:read", "tool:write"] } = {}) {
  const seen = { warrantRequests: [], polls: 0, verifies: [] };
  const grant = cannedGrant(scopes);
  const json = (status, obj) => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => obj,
  });
  const fetch = async (url, init) => {
    const body = init?.body ? JSON.parse(init.body) : {};
    if (url === `${BROKER}/warrant/request`) {
      seen.warrantRequests.push(body);
      return json(200, {
        success: true,
        code: `wcode-${seen.warrantRequests.length}`,
        verification_uri: `${BROKER}/consent`,
        verification_uri_complete: `${BROKER}/consent/wcode-${seen.warrantRequests.length}`,
        expires_in: 900,
        interval: 5,
      });
    }
    if (url === `${BROKER}/warrant/poll`) {
      seen.polls++;
      const mode = typeof poll === "function" ? poll(body) : poll;
      if (mode === "approved") {
        return json(200, {
          success: true,
          status: "approved",
          grants: [{ audience: RESOURCE, warrant: grant }],
        });
      }
      if (mode === "denied") {
        return json(200, { success: true, status: "denied", reason: "the human refused" });
      }
      return json(200, { success: true, status: "pending" });
    }
    if (url === `${BROKER}/access/mint`) {
      return json(200, {
        success: true,
        access_cert: fakeJws({ typ: "browserid-access-cert-v1", exp: nowS() + 3600 }),
      });
    }
    if (url === `${BROKER}/verify-access`) {
      seen.verifies.push(body);
      return json(200, {
        status: "okay",
        email: HUMAN,
        grantee: GATEWAY,
        holder: "svc.gate1",
        issuer: "example.com",
        scopes,
        status_refs: [],
      });
    }
    if (url === `${BROKER}/status/check`) {
      return json(200, { ok: true, revoked: false });
    }
    throw new Error("unexpected url " + url);
  };
  return { fetch, seen };
}

function lane(overrides = {}) {
  const broker = fakeBroker(overrides.broker);
  const mcpAuth = createMcpAuth({
    resource: RESOURCE,
    broker: BROKER,
    scopesForTool: { read_file: ["tool:read"], write_file: ["tool:write"] },
    fetch: broker.fetch,
    store: createMemoryStore(),
  });
  const authCode = createAuthCodeLane({
    mcpAuth,
    credential: gatewayCredential(),
    fetch: broker.fetch,
    returnPollTries: 2,
    returnPollDelayMs: 1,
    ...overrides.opts,
  });
  return { mcpAuth, authCode, broker };
}

const s256 = (verifier) => createHash("sha256").update(verifier, "ascii").digest("base64url");
const newVerifier = () => randomBytes(48).toString("base64url");

// The lane keeps auth_state internal (it rides the return_url through the
// broker, which is where the real browser bounce carries it). Tests recover
// it from the return_url the fake broker recorded on the warrant request —
// exactly what the consent page would navigate to.
function captureSt(broker) {
  const reqs = broker.seen.warrantRequests;
  const last = reqs[reqs.length - 1];
  return new URL(last.return_url).searchParams.get("st");
}

/** register → authorize → follow the return bounce: yields an OAuth code. */
async function fullCode(l, opts = {}) {
  const { authCode, broker } = l;
  const reg = authCode.handleRegister({ redirect_uris: [REDIRECT], client_name: "test host" });
  const verifier = opts.verifier ?? newVerifier();
  const state = opts.state ?? "host-1";
  const authz = await authCode.handleAuthorize({
    response_type: "code",
    client_id: reg.client_id,
    redirect_uri: REDIRECT,
    code_challenge: s256(verifier),
    code_challenge_method: "S256",
    scope: opts.scope ?? "tool:read tool:write",
    state,
  });
  assert.match(authz.redirect, new RegExp(`^${BROKER}/consent/`));
  const st = captureSt(broker);
  const back = await authCode.handleAuthorizeReturn({ st });
  const url = new URL(back.redirect);
  assert.equal(url.origin + url.pathname, REDIRECT);
  assert.equal(url.searchParams.get("state"), state);
  const code = url.searchParams.get("code");
  assert.ok(code, `code issued: ${back.redirect}`);
  return { reg, code, verifier, st };
}

// --- PKCE --------------------------------------------------------------------

test("verifyPkceS256 accepts a matching verifier and rejects everything else", () => {
  const v = newVerifier();
  assert.equal(verifyPkceS256(v, s256(v)), true);
  assert.equal(verifyPkceS256(v, s256(newVerifier())), false, "wrong verifier");
  assert.equal(verifyPkceS256(undefined, s256(v)), false, "missing verifier");
  assert.equal(verifyPkceS256("short", s256("short")), false, "under 43 chars");
  assert.equal(verifyPkceS256("!".repeat(64), s256("!".repeat(64))), false, "bad charset");
  assert.equal(verifyPkceS256(v, "not-base64url-of-a-digest"), false, "malformed challenge");
});

// --- DCR ----------------------------------------------------------------------

test("register mints a public client and echoes the registration", () => {
  const { authCode } = lane();
  const reg = authCode.handleRegister({ redirect_uris: [REDIRECT], client_name: "claude.ai" });
  assert.ok(reg.client_id.startsWith("mcp_"));
  assert.deepEqual(reg.redirect_uris, [REDIRECT]);
  assert.equal(reg.token_endpoint_auth_method, "none", "public PKCE client, no secret");
  assert.deepEqual(reg.grant_types, ["authorization_code"]);
  assert.deepEqual(reg.response_types, ["code"]);
  assert.equal(reg.client_name, "claude.ai");
  assert.equal("client_secret" in reg, false);
});

test("register rejects missing, relative, fragment-carrying, and plain-http redirect_uris", () => {
  const { authCode } = lane();
  const bad = (body, re) =>
    assert.throws(() => authCode.handleRegister(body), (e) => e instanceof McpAuthError && re.test(e.oauthError));
  bad({}, /invalid_client_metadata/);
  bad({ redirect_uris: [] }, /invalid_client_metadata/);
  bad({ redirect_uris: ["/relative/path"] }, /invalid_redirect_uri/);
  bad({ redirect_uris: ["http://host.example/cb"] }, /invalid_redirect_uri/);
  bad({ redirect_uris: ["https://host.example/cb#frag"] }, /invalid_redirect_uri/);
  bad({ redirect_uris: ["javascript:alert(1)"] }, /invalid_redirect_uri/);
  // localhost http is allowed for dev.
  const reg = authCode.handleRegister({ redirect_uris: ["http://localhost:3999/cb"] });
  assert.ok(reg.client_id);
});

// --- /authorize guards ---------------------------------------------------------

test("authorize refuses an unknown client and an unregistered redirect_uri WITHOUT redirecting", async () => {
  const { authCode } = lane();
  await assert.rejects(
    () => authCode.handleAuthorize({ response_type: "code", client_id: "mcp_nope", redirect_uri: REDIRECT }),
    (e) => e instanceof McpAuthError
  );
  const reg = authCode.handleRegister({ redirect_uris: [REDIRECT] });
  for (const uri of [
    "https://evil.example/cb",
    REDIRECT + "/extra", // exact match only
    REDIRECT + "?x=1",
    undefined,
  ]) {
    await assert.rejects(
      () => authCode.handleAuthorize({ response_type: "code", client_id: reg.client_id, redirect_uri: uri }),
      (e) => e instanceof McpAuthError,
      `must throw (not redirect) for ${uri}`
    );
  }
});

test("authorize REQUIRES PKCE S256: missing challenge and 'plain' are refused via error redirect", async () => {
  const { authCode, broker } = lane();
  const reg = authCode.handleRegister({ redirect_uris: [REDIRECT] });
  const base = { response_type: "code", client_id: reg.client_id, redirect_uri: REDIRECT, state: "s1" };

  for (const params of [
    base, // no challenge at all
    { ...base, code_challenge: s256("x".repeat(43)) }, // no method
    { ...base, code_challenge: "x".repeat(43), code_challenge_method: "plain" },
  ]) {
    const out = await authCode.handleAuthorize(params);
    const url = new URL(out.redirect);
    assert.equal(url.origin + url.pathname, REDIRECT, "error goes to the VALIDATED redirect_uri");
    assert.equal(url.searchParams.get("error"), "invalid_request");
    assert.equal(url.searchParams.get("state"), "s1");
  }
  assert.equal(broker.seen.warrantRequests.length, 0, "no warrant request was raised");
});

test("authorize rejects response_type != code via error redirect", async () => {
  const { authCode } = lane();
  const reg = authCode.handleRegister({ redirect_uris: [REDIRECT] });
  const out = await authCode.handleAuthorize({
    response_type: "token",
    client_id: reg.client_id,
    redirect_uri: REDIRECT,
    code_challenge: s256(newVerifier()),
    code_challenge_method: "S256",
  });
  assert.equal(new URL(out.redirect).searchParams.get("error"), "unsupported_response_type");
});

test("authorize raises the warrant request with audience = THIS resource and a return_url carrying st", async () => {
  const l = lane();
  const reg = l.authCode.handleRegister({ redirect_uris: [REDIRECT] });
  const out = await l.authCode.handleAuthorize({
    response_type: "code",
    client_id: reg.client_id,
    redirect_uri: REDIRECT,
    code_challenge: s256(newVerifier()),
    code_challenge_method: "S256",
    scope: "tool:read",
  });
  assert.equal(out.redirect, `${BROKER}/consent/wcode-1`);
  const req = l.broker.seen.warrantRequests[0];
  assert.equal(req.grants.length, 1);
  assert.equal(req.grants[0].audience, RESOURCE, "the warrant audience IS the resource");
  assert.deepEqual(req.grants[0].scopes, ["tool:read"]);
  assert.equal(req.grantor, "*", "the approver picks the delegating identity");
  const ret = new URL(req.return_url);
  assert.equal(ret.origin + ret.pathname, `${RESOURCE}/authorize/return`);
  assert.ok(ret.searchParams.get("st"), "auth_state rides the return_url");
});

// --- /authorize/return ----------------------------------------------------------

test("return with an unknown or reused st is an error (no redirect target exists)", async () => {
  const l = lane();
  await assert.rejects(() => l.authCode.handleAuthorizeReturn({ st: "nope" }), (e) => e instanceof McpAuthError);
  const { st } = await fullCode(l);
  // The pending record was consumed by fullCode's return leg.
  await assert.rejects(() => l.authCode.handleAuthorizeReturn({ st }), (e) => e instanceof McpAuthError);
});

test("a denied approval redirects to the host with error=access_denied", async () => {
  const l = lane({ broker: { poll: "denied" } });
  const reg = l.authCode.handleRegister({ redirect_uris: [REDIRECT] });
  await l.authCode.handleAuthorize({
    response_type: "code",
    client_id: reg.client_id,
    redirect_uri: REDIRECT,
    code_challenge: s256(newVerifier()),
    code_challenge_method: "S256",
    state: "s-denied",
  });
  const st = captureSt(l.broker);
  const out = await l.authCode.handleAuthorizeReturn({ st });
  const url = new URL(out.redirect);
  assert.equal(url.origin + url.pathname, REDIRECT);
  assert.equal(url.searchParams.get("error"), "access_denied");
  assert.equal(url.searchParams.get("state"), "s-denied");
});

test("a still-pending approval (never resolved) ends as access_denied, not a hang", async () => {
  const l = lane({ broker: { poll: "pending" } });
  const reg = l.authCode.handleRegister({ redirect_uris: [REDIRECT] });
  await l.authCode.handleAuthorize({
    response_type: "code",
    client_id: reg.client_id,
    redirect_uri: REDIRECT,
    code_challenge: s256(newVerifier()),
    code_challenge_method: "S256",
  });
  const st = captureSt(l.broker);
  const out = await l.authCode.handleAuthorizeReturn({ st });
  assert.equal(new URL(out.redirect).searchParams.get("error"), "access_denied");
  assert.equal(l.broker.seen.polls, 2, "bounded retries (returnPollTries)");
});

// --- /token: the code store's bindings -------------------------------------------

test("the full code exchange mints a working bearer with attribution", async () => {
  const l = lane();
  const { reg, code, verifier } = await fullCode(l);
  const tok = await l.authCode.handleToken({
    grant_type: "authorization_code",
    code,
    client_id: reg.client_id,
    redirect_uri: REDIRECT,
    code_verifier: verifier,
  });
  assert.equal(tok.token_type, "Bearer");
  assert.ok(tok.access_token.startsWith("bat_"), "same bearer shape as Lane A");
  // The presentation went through the SAME /verify-access, audience-bound.
  assert.equal(l.broker.seen.verifies.length, 1);
  assert.equal(l.broker.seen.verifies[0].audience, RESOURCE);
  // …and the bearer lives in the same store with the warrant's attribution,
  // tagged with the CONNECTION that custodies it (the OAuth client) so tools
  // can attribute "via <host>, authorized by <human>".
  const ctx = await l.mcpAuth.authenticate(`Bearer ${tok.access_token}`);
  assert.equal(ctx.grantor, HUMAN);
  assert.equal(ctx.grantee, GATEWAY);
  assert.deepEqual(ctx.client, { name: "test host", host: "host.example" });
  await l.mcpAuth.requireWarrant(`Bearer ${tok.access_token}`, "read_file");
});

test("a Lane A bearer carries NO client — the grantee is the acting party", async () => {
  const l = lane();
  const tok = await l.mcpAuth.handleToken({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: "pres-ok",
  });
  const ctx = await l.mcpAuth.authenticate(`Bearer ${tok.access_token}`);
  assert.equal(ctx.client, null);
});

test("the code is SINGLE-USE: a replay finds nothing", async () => {
  const l = lane();
  const { reg, code, verifier } = await fullCode(l);
  const params = {
    grant_type: "authorization_code",
    code,
    client_id: reg.client_id,
    redirect_uri: REDIRECT,
    code_verifier: verifier,
  };
  await l.authCode.handleToken(params);
  await assert.rejects(
    () => l.authCode.handleToken(params),
    (e) => e.oauthError === "invalid_grant" && /unknown, used, or expired/.test(e.message)
  );
});

test("an expired code is refused", async () => {
  const l = lane({ opts: { codeTtlS: -1 } });
  const { reg, code, verifier } = await fullCode(l);
  await assert.rejects(
    () =>
      l.authCode.handleToken({
        grant_type: "authorization_code",
        code,
        client_id: reg.client_id,
        redirect_uri: REDIRECT,
        code_verifier: verifier,
      }),
    (e) => e.oauthError === "invalid_grant"
  );
});

test("the code is bound to client_id, redirect_uri, and the PKCE challenge", async () => {
  for (const tamper of [
    { client_id: "mcp_other" },
    { redirect_uri: "https://host.example/other" },
    { code_verifier: newVerifier() }, // valid shape, wrong value
    { code_verifier: undefined },
  ]) {
    const l = lane();
    const { reg, code, verifier } = await fullCode(l);
    await assert.rejects(
      () =>
        l.authCode.handleToken({
          grant_type: "authorization_code",
          code,
          client_id: reg.client_id,
          redirect_uri: REDIRECT,
          code_verifier: verifier,
          ...tamper,
        }),
      (e) => e.oauthError === "invalid_grant",
      `tamper ${JSON.stringify(tamper)} must fail`
    );
    // And the tampered attempt burned the code (single-use, delete on read).
    await assert.rejects(
      () =>
        l.authCode.handleToken({
          grant_type: "authorization_code",
          code,
          client_id: reg.client_id,
          redirect_uri: REDIRECT,
          code_verifier: verifier,
        }),
      (e) => e.oauthError === "invalid_grant"
    );
  }
});

test("the lane's /token still serves the jwt-bearer branch verbatim", async () => {
  const l = lane();
  const tok = await l.authCode.handleToken({
    grant_type: JWT_BEARER_GRANT,
    assertion: "AC~AS~WR~CC",
  });
  assert.ok(tok.access_token.startsWith("bat_"));
  await assert.rejects(
    () => l.authCode.handleToken({ grant_type: "password" }),
    (e) => e.oauthError === "unsupported_grant_type"
  );
});

// --- discovery -------------------------------------------------------------------

test("lane discovery adds the auth-code endpoints and S256, keeping Lane A intact", () => {
  const l = lane();
  const asm = l.authCode.authorizationServerMetadata();
  assert.equal(asm.issuer, RESOURCE);
  assert.equal(asm.authorization_endpoint, `${RESOURCE}/authorize`);
  assert.equal(asm.registration_endpoint, `${RESOURCE}/register`);
  assert.deepEqual(asm.grant_types_supported, [JWT_BEARER_GRANT, "authorization_code"]);
  assert.deepEqual(asm.response_types_supported, ["code"]);
  assert.deepEqual(asm.code_challenge_methods_supported, ["S256"]);
  assert.deepEqual(asm.token_endpoint_auth_methods_supported, ["none"]);
  // A lane-less createMcpAuth is untouched.
  const bare = l.mcpAuth.authorizationServerMetadata();
  assert.equal("authorization_endpoint" in bare, false);
  assert.deepEqual(bare.grant_types_supported, [JWT_BEARER_GRANT]);
});
