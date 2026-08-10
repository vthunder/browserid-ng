"""Integration smoke test for the FastMCP demo: token -> bearer -> tool call,
and an unauthenticated call is rejected. Requires fastmcp installed and starts
the server + a mock broker in subprocesses. Run: python test_integration.py
"""
import asyncio, json, os, subprocess, sys, time, threading, http.server, urllib.request


class _Broker(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        if self.path.endswith("/verify-access"):
            body = {"status": "okay", "email": "dan@sandmill.org", "grantee": "dan+claude@sandmill.org",
                    "holder": "agents.abc", "issuer": "sandmill.org", "scopes": ["demo:write"],
                    "status_refs": [{"uri": "https://browserid.me/.well-known/browserid-status", "idx": 7}]}
        elif self.path.endswith("/status/check"):
            body = {"ok": True, "revoked": False, "results": []}
        else:
            self.send_response(404); self.end_headers(); return
        b = json.dumps(body).encode()
        self.send_response(200); self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)


async def _run():
    from fastmcp import Client
    from fastmcp.client.auth import BearerAuth
    import httpx

    res = "http://127.0.0.1:3457"
    async with httpx.AsyncClient() as c:
        prm = (await c.get(res + "/.well-known/oauth-protected-resource")).json()
        assert prm["resource"] == res, prm
        tok = (await c.post(res + "/token", json={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": "AC~AS~WR~CC"})).json()
        assert tok["token_type"] == "Bearer" and tok["scope"] == "demo:write", tok
        bearer = tok["access_token"]
    async with Client(res + "/mcp", auth=BearerAuth(bearer)) as client:
        tools = {t.name for t in await client.list_tools()}
        assert {"log_action", "read_log"} <= tools, tools
        r = await client.call_tool("log_action", {"action": "integration test"})
        text = r.content[0].text
        assert "dan+claude@sandmill.org" in text and "dan@sandmill.org" in text, text
    async with Client(res + "/mcp") as client:
        try:
            await client.call_tool("log_action", {"action": "nope"})
            raise SystemExit("FAIL: unauthenticated call succeeded")
        except Exception:
            pass
    print("integration OK")


def main():
    threading.Thread(target=lambda: http.server.HTTPServer(("127.0.0.1", 4699), _Broker).serve_forever(),
                     daemon=True).start()
    env = {**os.environ, "PORT": "3457", "MCP_RESOURCE": "http://127.0.0.1:3457",
           "BROWSERID_BROKER": "http://127.0.0.1:4699"}
    srv = subprocess.Popen([sys.executable, "server.py"], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(4)
        asyncio.run(_run())
    finally:
        srv.terminate()


if __name__ == "__main__":
    main()
