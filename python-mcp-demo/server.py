#!/usr/bin/env python3
"""browserid-ng FastMCP demo — the Python parallel of mcp-demo.

A warrant-gated FastMCP server built on ``browserid-mcp-auth``: no API keys —
authority is a human's short-lived, scoped, revocable BrowserID warrant, and
every tool call is attributed to "agent X on behalf of human Y". Revoke at
browserid.me/account and the agent dies on its next call (fail-closed status
re-check in the middleware).

Surfaces:
  POST /token                            the embedded AS (7521 assertion grant)
  GET  /.well-known/oauth-*              RFC 9728 / RFC 8414 discovery
  (the FastMCP endpoint)                 tool calls gated per-call by the warrant
  GET  /healthz                          probe

Design: docs/plans/2026-08-02-mcp-distribution-design.md (bean 4w3n).
"""
from __future__ import annotations

import contextvars
import os

import anyio
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import Middleware
from starlette.responses import HTMLResponse, JSONResponse

from browserid_mcp_auth import McpAuth, McpAuthError

PORT = int(os.environ.get("PORT", "3400"))
BROKER = os.environ.get("BROWSERID_BROKER", "https://browserid.me").rstrip("/")
RESOURCE = os.environ.get("MCP_RESOURCE", f"http://localhost:{PORT}").rstrip("/")

SCOPES_FOR_TOOL = {"log_action": ["demo:write"], "read_log": []}

auth = McpAuth(resource=RESOURCE, broker=BROKER, scopes_for_tool=SCOPES_FOR_TOOL)
mcp = FastMCP("browserid-mcp-demo-py")

# The verified warrant context for the in-flight tool call.
_ctx: contextvars.ContextVar = contextvars.ContextVar("browserid_ctx", default=None)

# In-memory attributed action log (last 100).
LOG: list[dict] = []


class BrowserIDGate(Middleware):
    """Gate every tool call on a valid, unrevoked warrant bearer + its scopes."""

    async def on_call_tool(self, context, call_next):
        # include={"authorization"}: get_http_headers strips sensitive headers
        # by default, but we need the bearer for the warrant check.
        headers = get_http_headers(include={"authorization"})
        tool_name = getattr(context.message, "name", "")
        try:
            # require_warrant does sync HTTP (status re-check) — off the loop.
            ctx = await anyio.to_thread.run_sync(
                lambda: auth.require_warrant(headers.get("authorization"), tool_name)
            )
        except McpAuthError as e:
            raise ToolError(f"{e.oauth_error}: {e}")
        token = _ctx.set(ctx)
        try:
            return await call_next(context)
        finally:
            _ctx.reset(token)


mcp.add_middleware(BrowserIDGate())


@mcp.tool
def log_action(action: str) -> str:
    """Record an action in the demo log, attributed to you (the agent) acting
    on behalf of your human. Requires the 'demo:write' scope in your warrant.
    No API key — authority is the human's revocable warrant."""
    ctx = _ctx.get()
    entry = {
        "action": str(action)[:280],
        "grantor": ctx.grantor,
        "grantee": ctx.grantee,
        "holder": ctx.holder,
    }
    LOG.insert(0, entry)
    del LOG[100:]
    return (
        f'Logged ✓ — "{entry["action"]}"\n'
        f'attributed to {entry["grantee"]} on behalf of {entry["grantor"]} (holder {entry["holder"]}).\n'
        f"Your human can revoke this at {BROKER}/account; the next call then fails closed."
    )


@mcp.tool
def read_log() -> str:
    """List recent actions in the demo log with their attribution. Any valid
    warrant may read."""
    if not LOG:
        return "The log is empty. Call log_action first."
    lines = [f'• "{e["action"]}" — {e["grantee"]} for {e["grantor"]}' for e in LOG[:20]]
    return "Recent attributed actions:\n" + "\n".join(lines)


# --- OAuth surface (custom HTTP routes on the same app) ---------------------


@mcp.custom_route("/token", methods=["POST"])
async def token_endpoint(request):
    ct = request.headers.get("content-type", "")
    if "application/json" in ct:
        try:
            params = await request.json()
        except Exception:
            params = {}
    else:
        params = dict(await request.form())
    try:
        out = await anyio.to_thread.run_sync(lambda: auth.handle_token(params))
        return JSONResponse(out, headers={"cache-control": "no-store"})
    except McpAuthError as e:
        return JSONResponse(e.to_token_error_response(), status_code=e.http_status)


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def prm(request):
    return JSONResponse(auth.protected_resource_metadata())


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def asm(request):
    return JSONResponse(auth.authorization_server_metadata())


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request):
    return JSONResponse({"ok": True})


@mcp.custom_route("/", methods=["GET"])
async def landing(request):
    return HTMLResponse(
        f"<!doctype html><meta charset=utf-8><title>browserid FastMCP demo</title>"
        f"<body style='font:15px/1.6 system-ui;max-width:640px;margin:6vh auto;padding:0 20px'>"
        f"<h1>browserid FastMCP demo (Python)</h1>"
        f"<p>A warrant-gated FastMCP server on <code>browserid-mcp-auth</code> — no API keys. "
        f"Authority is a human's scoped, revocable warrant; every tool call is attributed, "
        f"and a revoke at <a href='{BROKER}/account'>{BROKER}/account</a> kills the agent's "
        f"next call.</p>"
        f"<p>OAuth: <code>/.well-known/oauth-protected-resource</code> · "
        f"<code>/.well-known/oauth-authorization-server</code> · <code>POST /token</code>. "
        f"Tools: <code>log_action</code> (scope <code>demo:write</code>), <code>read_log</code>.</p>"
    )


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=PORT, show_banner=False)
