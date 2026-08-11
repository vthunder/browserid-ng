#!/usr/bin/env node
// browserid-ng GitHub flagship — a warrant-gated GitHub MCP server.
//
// The "stop putting PATs in your MCP config" demo, for real: the agent holds
// no durable GitHub credential. Two auth layers, kept distinct:
//
//   agent → server   a BrowserID warrant via @browserid-ng/mcp-auth — scoped
//                    (repo:read / issues:create), attributed (grantor +
//                    grantee), and revocable in one click at
//                    browserid.me/account, which fails the agent CLOSED on
//                    its next call. Same skeleton as mcp-demo:
//                      POST /token                the embedded AS (7521 assertion grant)
//                      GET  /.well-known/oauth-*  RFC 9728 / RFC 8414 discovery
//                      POST /mcp                  the MCP endpoint (bearer-authed)
//   server → GitHub  a GitHub App installation token (src/github.mjs): the
//                    human installs the App on the repos they choose; actions
//                    appear as the App bot. Revoking the warrant never
//                    touches a GitHub key, and vice-versa.
//
// Every tool call logs one attribution line: {grantor, grantee, tool, repo}.
//
// Design: docs/plans/2026-08-10-github-flagship-build-spec.md (bean v8ll).
import { createServer } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { createMcpAuth, McpAuthError } from "@browserid-ng/mcp-auth";
import { createGitHubApp, loadPrivateKeyFromEnv } from "./github.mjs";

// tool -> required warrant scopes (v1 coarse grammar; per-repo scopes are a
// fast follow via the same families).
export const SCOPES = {
  list_repos: ["repo:read"],
  read_file: ["repo:read"],
  list_issues: ["repo:read"],
  create_issue: ["issues:create"],
  comment_issue: ["issues:create"],
};

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const MAX_FILE_CHARS = 65536;

export function createGithubMcpService({ log = (line) => console.log(line) } = {}) {
  const PORT = Number(process.env.PORT || 3400);
  const BROKER = (process.env.BROWSERID_BROKER || "https://browserid.me").replace(/\/+$/, "");
  const RESOURCE = (process.env.MCP_RESOURCE || `http://localhost:${PORT}`).replace(/\/+$/, "");
  // Short status cache so a revoke lands within seconds — this server is the
  // "revoke kills the agent mid-conversation" demo.
  const STATUS_CACHE_S = Number(process.env.MCP_STATUS_CACHE_S ?? 5);

  const github = createGitHubApp({
    appId: requireEnv("GITHUB_APP_ID"),
    privateKey: loadPrivateKeyFromEnv() || missingKey(),
    apiUrl: process.env.GITHUB_API_URL,
    installationId: process.env.GITHUB_INSTALLATION_ID,
  });

  const mcpAuth = createMcpAuth({
    resource: RESOURCE,
    broker: BROKER,
    scopesForTool: SCOPES,
    statusCacheS: STATUS_CACHE_S,
  });

  // The one attribution line per tool call — the demo's audit trail.
  function attribute(ctx, tool, repo) {
    log(
      `[github-mcp] grantor=${ctx.grantor} grantee=${ctx.grantee} tool=${tool} repo=${repo || "-"}`
    );
  }

  // Build a fresh MCP server bound to one request's verified context (mcp-demo
  // pattern). Each tool enforces its own scopes against the warrant
  // (ctx.scopes); the fail-closed revocation re-check already ran in
  // mcpAuth.authenticate for this call.
  function buildMcpServer(ctx) {
    const server = new McpServer({ name: "browserid-github-mcp", version: "0.1.0" });

    // Wrap a tool: scope gate → attribution log → GitHub call.
    const gated = (tool, fn) => async (args) => {
      const missing = SCOPES[tool].filter((s) => !ctx.scopes.includes(s));
      if (missing.length) {
        return text(
          `INSUFFICIENT_SCOPE — your warrant lacks '${missing.join("', '")}'. ` +
            `Ask your human to re-approve with that scope at ${BROKER}/account.`
        );
      }
      if (args.repo !== undefined && !REPO_RE.test(args.repo)) {
        return text(`INVALID_REPO — 'repo' must be "owner/name", got "${args.repo}".`);
      }
      attribute(ctx, tool, args.repo);
      try {
        return await fn(args);
      } catch (e) {
        return text(`GITHUB_ERROR — ${e.message}`);
      }
    };

    const repoArg = z.string().describe('repository as "owner/name"');

    server.registerTool(
      "list_repos",
      {
        title: "List accessible repositories",
        description:
          "List the repositories this server's GitHub App installation can reach. " +
          "Requires the 'repo:read' scope in your warrant. No PAT anywhere: your " +
          "authority is your human's revocable warrant.",
        inputSchema: {},
      },
      gated("list_repos", async () => {
        const out = await github.listRepos();
        const repos = out.repositories || [];
        if (repos.length === 0) return text("The installation has no repositories.");
        const lines = repos.map((r) => `• ${r.full_name}${r.private ? " (private)" : ""}`);
        return text(`Repositories (${repos.length}):\n${lines.join("\n")}`);
      })
    );

    server.registerTool(
      "read_file",
      {
        title: "Read a file from a repository",
        description:
          "Fetch a file's contents from a repo via the GitHub contents API. " +
          "Requires the 'repo:read' scope in your warrant.",
        inputSchema: {
          repo: repoArg,
          path: z.string().describe("file path within the repository"),
          ref: z.string().optional().describe("branch, tag, or commit SHA (default: default branch)"),
        },
      },
      gated("read_file", async ({ repo, path, ref }) => {
        const out = await github.readFile(repo, path, ref);
        if (Array.isArray(out)) {
          const lines = out.map((e) => `• ${e.name}${e.type === "dir" ? "/" : ""}`);
          return text(`${repo}/${path} is a directory (${out.length} entries):\n${lines.join("\n")}`);
        }
        if (out.type !== "file" || out.encoding !== "base64") {
          return text(`GITHUB_ERROR — ${repo}/${path} is not a readable file (type ${out.type}).`);
        }
        let content = Buffer.from(out.content, "base64").toString("utf8");
        let note = "";
        if (content.length > MAX_FILE_CHARS) {
          content = content.slice(0, MAX_FILE_CHARS);
          note = `\n… [truncated at ${MAX_FILE_CHARS} chars]`;
        }
        return text(`${repo}/${path}${ref ? ` @ ${ref}` : ""} (${out.size} bytes):\n\n${content}${note}`);
      })
    );

    server.registerTool(
      "list_issues",
      {
        title: "List issues in a repository",
        description:
          "List a repository's issues. Requires the 'repo:read' scope in your warrant.",
        inputSchema: {
          repo: repoArg,
          state: z.enum(["open", "closed", "all"]).optional().describe("filter by state (default open)"),
        },
      },
      gated("list_issues", async ({ repo, state }) => {
        const issues = (await github.listIssues(repo, state)).filter((i) => !i.pull_request);
        if (issues.length === 0) return text(`No ${state || "open"} issues in ${repo}.`);
        const lines = issues.map((i) => `• #${i.number} [${i.state}] ${i.title}`);
        return text(`Issues in ${repo} (${issues.length}):\n${lines.join("\n")}`);
      })
    );

    server.registerTool(
      "create_issue",
      {
        title: "Create an issue",
        description:
          "Open a new issue in a repository. Requires the 'issues:create' scope in " +
          "your warrant. The issue is authored by the GitHub App bot; the server " +
          "records which agent acted, and on whose behalf.",
        inputSchema: {
          repo: repoArg,
          title: z.string().describe("issue title"),
          body: z.string().optional().describe("issue body (markdown)"),
        },
      },
      gated("create_issue", async ({ repo, title, body }) => {
        const issue = await github.createIssue(repo, title, body);
        return text(
          `Created issue #${issue.number} in ${repo}: ${issue.html_url}\n` +
            `attributed to ${ctx.grantee} on behalf of ${ctx.grantor}.\n` +
            `Your human can revoke this at ${BROKER}/account; the next call then fails closed.`
        );
      })
    );

    server.registerTool(
      "comment_issue",
      {
        title: "Comment on an issue",
        description:
          "Add a comment to an existing issue. Requires the 'issues:create' scope in " +
          "your warrant.",
        inputSchema: {
          repo: repoArg,
          issue_number: z.number().int().positive().describe("issue number"),
          body: z.string().describe("comment body (markdown)"),
        },
      },
      gated("comment_issue", async ({ repo, issue_number, body }) => {
        const comment = await github.commentIssue(repo, issue_number, body);
        return text(
          `Commented on ${repo}#${issue_number}: ${comment.html_url}\n` +
            `attributed to ${ctx.grantee} on behalf of ${ctx.grantor}.`
        );
      })
    );

    return server;
  }

  // --- HTTP (mcp-demo skeleton) --------------------------------------------

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, RESOURCE);
    const path = url.pathname;
    try {
      if (req.method === "GET" && path === "/healthz") return json(res, 200, { ok: true });

      if (req.method === "GET" && path === "/.well-known/oauth-protected-resource") {
        return json(res, 200, mcpAuth.protectedResourceMetadata());
      }
      if (req.method === "GET" && path === "/.well-known/oauth-authorization-server") {
        return json(res, 200, mcpAuth.authorizationServerMetadata());
      }

      // The embedded AS: 7521 assertion-grant token endpoint. Accepts form-
      // encoded (OAuth default) or JSON bodies.
      if (req.method === "POST" && path === "/token") {
        const raw = await readBody(req);
        let params;
        const ct = req.headers["content-type"] || "";
        if (ct.includes("application/json")) {
          try { params = JSON.parse(raw); } catch { params = {}; }
        } else {
          params = Object.fromEntries(new URLSearchParams(raw));
        }
        try {
          const out = await mcpAuth.handleToken(params);
          return json(res, 200, out, { "cache-control": "no-store" });
        } catch (e) {
          if (e instanceof McpAuthError) return json(res, e.httpStatus, e.toTokenErrorResponse());
          throw e;
        }
      }

      // The MCP endpoint (resource server). Bearer-gated + fail-closed status
      // re-check on every call — this is what makes the revoke land.
      if (path === "/mcp") {
        let ctx;
        try {
          ctx = await mcpAuth.authenticate(req.headers.authorization);
        } catch (e) {
          const err = e instanceof McpAuthError ? e : new McpAuthError("invalid_token", e.message, 401);
          return json(res, err.httpStatus, { error: err.oauthError, error_description: err.message }, {
            "www-authenticate": mcpAuth.challenge(),
          });
        }
        let body;
        if (req.method === "POST") {
          try { body = JSON.parse(await readBody(req)); } catch { body = undefined; }
        }
        const mcpServer = buildMcpServer(ctx);
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
          enableJsonResponse: true,
        });
        res.on("close", () => { transport.close(); mcpServer.close(); });
        await mcpServer.connect(transport);
        return transport.handleRequest(req, res, body);
      }

      if (req.method === "GET" && path === "/") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        return res.end(landingHtml(BROKER));
      }

      json(res, 404, { error: "not_found" });
    } catch (e) {
      console.error(`[github-mcp] ${req.method} ${path}:`, e);
      if (!res.headersSent) json(res, 500, { error: "server_error" });
    }
  });

  return { server, github, mcpAuth, PORT, RESOURCE, BROKER };
}

// --- helpers ----------------------------------------------------------------

const text = (s) => ({ content: [{ type: "text", text: s }] });

const json = (res, code, obj, headers = {}) => {
  res.writeHead(code, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(obj));
};

async function readBody(req, max = 1024 * 1024) {
  const chunks = [];
  let n = 0;
  for await (const c of req) {
    n += c.length;
    if (n > max) throw new Error("body too large");
    chunks.push(c);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`github-mcp: ${name} is required`);
  return v;
}
function missingKey() {
  throw new Error("github-mcp: GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_FILE is required");
}

function landingHtml(broker) {
  return `<!doctype html><meta charset=utf-8><title>browserid GitHub MCP</title>
<style>body{font:15px/1.6 -apple-system,system-ui,sans-serif;max-width:640px;margin:6vh auto;padding:0 20px;color:#1a1a1a}code{background:#f2f3f5;padding:1px 5px;border-radius:5px}</style>
<h1>browserid GitHub MCP</h1>
<p>A warrant-gated GitHub MCP server — the agent holds <b>no PAT</b>. Its authority is a
human's short-lived, scoped, <b>revocable</b> BrowserID warrant; the server talks to GitHub
as a GitHub App the human installed on the repos they chose. Every tool call is attributed
to "agent X on behalf of human Y", and a revoke at
<a href="${broker}/account">${broker}/account</a> kills the agent's GitHub access on its
next call — no key rotation.</p>
<p>OAuth discovery: <code>/.well-known/oauth-protected-resource</code> ·
<code>/.well-known/oauth-authorization-server</code>. MCP endpoint: <code>POST /mcp</code>.</p>
<p>Tools: <code>list_repos</code>, <code>read_file</code>, <code>list_issues</code>
(scope <code>repo:read</code>) · <code>create_issue</code>, <code>comment_issue</code>
(scope <code>issues:create</code>).</p>`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { server, PORT, RESOURCE, BROKER } = createGithubMcpService();
  server.listen(PORT, () => {
    console.log(`[github-mcp] listening on :${PORT} (resource ${RESOURCE}, broker ${BROKER})`);
  });
}
