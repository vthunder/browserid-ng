// The github-mcp server end to end: OAuth discovery, warrant → bearer at
// /token, per-tool scope gating, one happy path per tool against a mocked
// GitHub, the attribution log line, and the flagship moment — a revoke (or an
// unreachable status list) failing the agent CLOSED on its next call.
//
// Both upstreams are local mock HTTP servers wired in via env
// (BROWSERID_BROKER, GITHUB_API_URL) before the server module is imported.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { generateKeyPairSync } from "node:crypto";

const GH_PORT = 43320;
const BROKER_PORT = 43321;
const PORT = 43322;

const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
process.env.PORT = String(PORT);
process.env.MCP_RESOURCE = `http://localhost:${PORT}`;
process.env.BROWSERID_BROKER = `http://localhost:${BROKER_PORT}`;
process.env.GITHUB_API_URL = `http://localhost:${GH_PORT}`;
process.env.GITHUB_APP_ID = "123";
process.env.GITHUB_APP_PRIVATE_KEY = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
process.env.MCP_STATUS_CACHE_S = "0"; // re-check revocation on every call
delete process.env.GITHUB_APP_PRIVATE_KEY_FILE;
delete process.env.GITHUB_INSTALLATION_ID;

const { createGithubMcpService } = await import("../src/server.mjs");

const GRANTOR = "dan@example.com";
const GRANTEE = "claude@agents.example.com";

// --- mock broker: /verify-access keyed on the presentation string -----------

// presentation "warrant-full" → both scopes; "warrant-read" → repo:read only.
let statusMode = "ok"; // "ok" | "revoked" | "down"
const broker = createServer(async (req, res) => {
  const reply = (code, obj) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  let body = "";
  for await (const c of req) body += c;
  const parsed = JSON.parse(body || "{}");
  if (req.url === "/verify-access") {
    const scopes = { "warrant-full": ["repo:read", "issues:create"], "warrant-read": ["repo:read"] }[
      parsed.presentation
    ];
    if (!scopes) return reply(200, { status: "failure", reason: "verification failed" });
    assert.equal(parsed.audience, `http://localhost:${PORT}`, "verifies against this resource");
    return reply(200, {
      status: "okay",
      email: GRANTOR,
      grantee: GRANTEE,
      holder: "agents.test123",
      issuer: "example.com",
      scopes,
      status_refs: [{ uri: `http://localhost:${BROKER_PORT}/status`, idx: 1 }],
    });
  }
  if (req.url === "/status/check") {
    if (statusMode === "down") return reply(500, {});
    return reply(200, { ok: true, revoked: statusMode === "revoked" });
  }
  reply(404, {});
});

// --- mock GitHub -------------------------------------------------------------

const ghSeen = []; // {method, url, body}
const gh = createServer(async (req, res) => {
  const reply = (code, obj) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  let raw = "";
  for await (const c of req) raw += c;
  const body = raw ? JSON.parse(raw) : undefined;
  ghSeen.push({ method: req.method, url: req.url, body });
  const r = (m, re) => req.method === m && re.test(req.url);

  if (r("GET", /^\/app\/installations$/)) return reply(200, [{ id: 77 }]);
  if (r("POST", /^\/app\/installations\/77\/access_tokens$/))
    return reply(201, { token: "ghs_srv", expires_at: new Date(Date.now() + 3600_000).toISOString() });
  if (r("GET", /^\/installation\/repositories$/))
    return reply(200, {
      total_count: 2,
      repositories: [
        { full_name: "acme/widgets", private: false },
        { full_name: "acme/secrets", private: true },
      ],
    });
  if (r("GET", /^\/repos\/acme\/widgets\/contents\/README\.md/))
    return reply(200, {
      type: "file",
      encoding: "base64",
      size: 12,
      content: Buffer.from("hello world\n").toString("base64"),
    });
  if (r("GET", /^\/repos\/acme\/widgets\/issues\/?(\?.*)?$/))
    return reply(200, [
      { number: 1, state: "open", title: "first bug" },
      { number: 2, state: "open", title: "not an issue", pull_request: {} },
    ]);
  if (r("POST", /^\/repos\/acme\/widgets\/issues$/))
    return reply(201, { number: 42, html_url: "https://github.com/acme/widgets/issues/42" });
  if (r("POST", /^\/repos\/acme\/widgets\/issues\/42\/comments$/))
    return reply(201, { id: 7, html_url: "https://github.com/acme/widgets/issues/42#issuecomment-7" });
  reply(404, { message: "not found" });
});

// --- boot --------------------------------------------------------------------

const logLines = [];
let service;
before(() => new Promise((resolve) => {
  broker.listen(BROKER_PORT, () => {
    gh.listen(GH_PORT, () => {
      service = createGithubMcpService({ log: (l) => logLines.push(l) });
      service.server.listen(PORT, resolve);
    });
  });
}));
after(() => { service.server.close(); broker.close(); gh.close(); });

// --- helpers -----------------------------------------------------------------

async function getBearer(presentation) {
  const res = await fetch(`http://localhost:${PORT}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: presentation,
    }),
  });
  assert.equal(res.status, 200, `token endpoint HTTP ${res.status}`);
  return (await res.json()).access_token;
}

let nextId = 1;
async function rpcRaw(bearer, method, params = {}) {
  return fetch(`http://localhost:${PORT}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params }),
  });
}
async function rpc(bearer, method, params = {}) {
  const res = await rpcRaw(bearer, method, params);
  assert.equal(res.status, 200, `${method} HTTP ${res.status}`);
  const body = await res.json();
  assert.ok(!body.error, `${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}
const callTool = async (bearer, name, args = {}) => {
  const r = await rpc(bearer, "tools/call", { name, arguments: args });
  return r.content[0].text;
};

// --- discovery + surface -----------------------------------------------------

test("OAuth discovery advertises the resource, AS, and both scopes", async () => {
  const prm = await (await fetch(`http://localhost:${PORT}/.well-known/oauth-protected-resource`)).json();
  assert.equal(prm.resource, `http://localhost:${PORT}`);
  assert.ok(prm.scopes_supported.includes("repo:read"));
  assert.ok(prm.scopes_supported.includes("issues:create"));
  const asm = await (await fetch(`http://localhost:${PORT}/.well-known/oauth-authorization-server`)).json();
  assert.equal(asm.token_endpoint, `http://localhost:${PORT}/token`);
});

test("tool surface is the five GitHub tools", async () => {
  const bearer = await getBearer("warrant-full");
  const { tools } = await rpc(bearer, "tools/list");
  assert.deepEqual(
    tools.map((t) => t.name).sort(),
    ["comment_issue", "create_issue", "list_issues", "list_repos", "read_file"]
  );
});

test("the MCP endpoint requires a bearer (401 + resource-metadata challenge)", async () => {
  const res = await rpcRaw(null, "tools/list");
  assert.equal(res.status, 401);
  assert.match(res.headers.get("www-authenticate"), /resource_metadata=/);
});

test("a bad presentation is refused a bearer", async () => {
  const res = await fetch(`http://localhost:${PORT}/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: "nonsense",
    }),
  });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, "invalid_grant");
});

// --- happy path per tool -----------------------------------------------------

test("list_repos lists the installation's repositories", async () => {
  const bearer = await getBearer("warrant-full");
  const t = await callTool(bearer, "list_repos");
  assert.match(t, /acme\/widgets/);
  assert.match(t, /acme\/secrets \(private\)/);
});

test("read_file returns decoded file contents", async () => {
  const bearer = await getBearer("warrant-full");
  const t = await callTool(bearer, "read_file", { repo: "acme/widgets", path: "README.md" });
  assert.match(t, /hello world/);
  assert.match(t, /acme\/widgets\/README\.md/);
});

test("list_issues lists issues and filters out pull requests", async () => {
  const bearer = await getBearer("warrant-full");
  const t = await callTool(bearer, "list_issues", { repo: "acme/widgets" });
  assert.match(t, /#1 \[open\] first bug/);
  assert.ok(!t.includes("not an issue"), "PRs are excluded");
});

test("create_issue posts title+body and reports the attributed result", async () => {
  const bearer = await getBearer("warrant-full");
  const t = await callTool(bearer, "create_issue", {
    repo: "acme/widgets",
    title: "warrant-born issue",
    body: "filed by an agent, no PAT",
  });
  assert.match(t, /Created issue #42/);
  assert.match(t, new RegExp(`${GRANTEE} on behalf of ${GRANTOR}`));
  const posted = ghSeen.findLast((s) => s.method === "POST" && s.url === "/repos/acme/widgets/issues");
  assert.deepEqual(posted.body, { title: "warrant-born issue", body: "filed by an agent, no PAT" });
});

test("comment_issue posts the comment body", async () => {
  const bearer = await getBearer("warrant-full");
  const t = await callTool(bearer, "comment_issue", {
    repo: "acme/widgets",
    issue_number: 42,
    body: "agent says hi",
  });
  assert.match(t, /Commented on acme\/widgets#42/);
  const posted = ghSeen.findLast(
    (s) => s.method === "POST" && s.url === "/repos/acme/widgets/issues/42/comments"
  );
  assert.deepEqual(posted.body, { body: "agent says hi" });
});

// --- attribution -------------------------------------------------------------

test("every tool call logs one attribution line with grantor+grantee+tool+repo", async () => {
  const bearer = await getBearer("warrant-full");
  logLines.length = 0;
  await callTool(bearer, "create_issue", { repo: "acme/widgets", title: "audit me" });
  assert.equal(logLines.length, 1);
  const line = logLines[0];
  assert.ok(line.includes(`grantor=${GRANTOR}`), `grantor in: ${line}`);
  assert.ok(line.includes(`grantee=${GRANTEE}`), `grantee in: ${line}`);
  assert.ok(line.includes("tool=create_issue"), line);
  assert.ok(line.includes("repo=acme/widgets"), line);
});

// --- scope gating ------------------------------------------------------------

test("a read-only warrant is refused create_issue and comment_issue (and GitHub is never called)", async () => {
  const bearer = await getBearer("warrant-read");
  const before = ghSeen.filter((s) => s.method === "POST" && s.url.includes("/repos/")).length;
  for (const [tool, args] of [
    ["create_issue", { repo: "acme/widgets", title: "nope" }],
    ["comment_issue", { repo: "acme/widgets", issue_number: 42, body: "nope" }],
  ]) {
    const t = await callTool(bearer, tool, args);
    assert.match(t, /^INSUFFICIENT_SCOPE/, `${tool} refused`);
    assert.match(t, /issues:create/, `${tool} names the missing scope`);
  }
  const afterCount = ghSeen.filter((s) => s.method === "POST" && s.url.includes("/repos/")).length;
  assert.equal(afterCount, before, "no GitHub write happened");
});

test("the read scope still works on the read tools", async () => {
  const bearer = await getBearer("warrant-read");
  assert.match(await callTool(bearer, "list_repos"), /acme\/widgets/);
});

test("a malformed repo is rejected before GitHub is called", async () => {
  const bearer = await getBearer("warrant-full");
  const t = await callTool(bearer, "read_file", { repo: "not-a-repo", path: "x" });
  assert.match(t, /^INVALID_REPO/);
});

// --- the flagship moment: fail-closed revocation -----------------------------

test("a revoke kills the agent on its next call (401, token forgotten)", async () => {
  const bearer = await getBearer("warrant-full");
  assert.match(await callTool(bearer, "list_repos"), /acme/); // alive
  statusMode = "revoked";
  try {
    const res = await rpcRaw(bearer, "tools/call", {
      name: "create_issue",
      arguments: { repo: "acme/widgets", title: "should never land" },
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_token");
    assert.match(body.error_description, /revoked/);
  } finally {
    statusMode = "ok";
  }
});

test("an unreachable status list fails closed (401, not fail-open)", async () => {
  const bearer = await getBearer("warrant-full");
  statusMode = "down";
  try {
    const res = await rpcRaw(bearer, "tools/list");
    assert.equal(res.status, 401);
    assert.match((await res.json()).error_description, /fail-closed/);
  } finally {
    statusMode = "ok";
  }
});
