"""Unit tests for browserid-mcp-auth (stdlib unittest — no pytest needed)."""
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from browserid_mcp_auth import (  # noqa: E402
    JWT_BEARER_GRANT,
    McpAuth,
    McpAuthError,
)

RESOURCE = "https://mcp.example.com"

OK_VERIFY = {
    "status": "okay",
    "email": "dan@sandmill.org",
    "grantee": "dan+claude@sandmill.org",
    "holder": "agents.abc123",
    "issuer": "sandmill.org",
    "scopes": ["repo:read", "issues:create"],
    "status_refs": [{"uri": "https://browserid.me/.well-known/browserid-status", "idx": 7}],
}


class FakeBroker:
    """Configurable (status_code, json) responses for /verify-access + /status/check."""

    def __init__(self, verify=None, status=None):
        self.verify = verify
        self.status = status
        self.calls = {"verify": 0, "status": 0}

    def post(self, url, body):
        if url.endswith("/verify-access"):
            self.calls["verify"] += 1
            if self.verify == "throw":
                raise ConnectionError("refused")
            v = self.verify if self.verify is not None else {"status": "failure"}
            return v.get("__status", 200), v
        if url.endswith("/status/check"):
            self.calls["status"] += 1
            if self.status == "throw":
                raise ConnectionError("refused")
            s = self.status if self.status is not None else {"ok": True, "revoked": False}
            return s.get("__status", 200), s
        raise AssertionError("unexpected url " + url)


def make(verify=OK_VERIFY, status=None, **kw):
    broker = FakeBroker(verify=verify, status=status)
    mcp = McpAuth(resource=RESOURCE, broker="https://browserid.me", http_post=broker.post,
                  scopes_for_tool={"create_issue": ["issues:create"], "admin": ["repo:admin"]},
                  status_cache_s=kw.pop("status_cache_s", 0), **kw)
    return mcp, broker


TOKEN_REQ = {"grant_type": JWT_BEARER_GRANT, "assertion": "AC~AS~WR~CC"}


class TokenEndpoint(unittest.TestCase):
    def test_rejects_bad_grant(self):
        mcp, _ = make()
        with self.assertRaises(McpAuthError) as c:
            mcp.handle_token({"grant_type": "authorization_code", "assertion": "x"})
        self.assertEqual(c.exception.oauth_error, "unsupported_grant_type")

    def test_rejects_missing_assertion(self):
        mcp, _ = make()
        with self.assertRaises(McpAuthError) as c:
            mcp.handle_token({"grant_type": JWT_BEARER_GRANT})
        self.assertEqual(c.exception.oauth_error, "invalid_request")

    def test_mints_bearer(self):
        mcp, _ = make()
        res = mcp.handle_token(TOKEN_REQ)
        self.assertEqual(res["token_type"], "Bearer")
        self.assertTrue(res["access_token"].startswith("bat_"))
        self.assertEqual(res["scope"], "repo:read issues:create")
        ctx = mcp.authenticate("Bearer " + res["access_token"])
        self.assertEqual(ctx.grantor, "dan@sandmill.org")
        self.assertEqual(ctx.grantee, "dan+claude@sandmill.org")

    def test_bad_presentation_rejected(self):
        mcp, _ = make(verify={"status": "failure", "reason": "expired"})
        with self.assertRaises(McpAuthError) as c:
            mcp.handle_token(TOKEN_REQ)
        self.assertEqual(c.exception.oauth_error, "invalid_grant")

    def test_unreachable_verifier_fails_closed(self):
        mcp, _ = make(verify="throw")
        with self.assertRaises(McpAuthError) as c:
            mcp.handle_token(TOKEN_REQ)
        self.assertEqual(c.exception.http_status, 503)

    def test_scope_narrow_not_widen(self):
        mcp, _ = make()
        self.assertEqual(mcp.handle_token({**TOKEN_REQ, "scope": "repo:read"})["scope"], "repo:read")
        with self.assertRaises(McpAuthError) as c:
            mcp.handle_token({**TOKEN_REQ, "scope": "repo:read repo:admin"})
        self.assertEqual(c.exception.oauth_error, "invalid_scope")


class PerCall(unittest.TestCase):
    def test_unknown_token(self):
        mcp, _ = make()
        with self.assertRaises(McpAuthError) as c:
            mcp.authenticate("Bearer nope")
        self.assertEqual(c.exception.http_status, 401)

    def test_revoke_kills_token(self):
        broker = FakeBroker(verify=OK_VERIFY, status={"ok": True, "revoked": False})
        mcp = McpAuth(resource=RESOURCE, http_post=broker.post, status_cache_s=0)
        tok = mcp.handle_token(TOKEN_REQ)["access_token"]
        mcp.authenticate("Bearer " + tok)  # fine
        broker.status = {"ok": False, "revoked": True}
        with self.assertRaises(McpAuthError) as c:
            mcp.authenticate("Bearer " + tok)
        self.assertIn("revoked", str(c.exception))

    def test_status_unreachable_fails_closed(self):
        mcp, _ = make(status="throw")
        tok = mcp.handle_token(TOKEN_REQ)["access_token"]
        with self.assertRaises(McpAuthError) as c:
            mcp.authenticate("Bearer " + tok)
        self.assertIn("fail-closed", str(c.exception))

    def test_no_refs_no_recheck(self):
        v = {**OK_VERIFY, "status_refs": []}
        mcp, broker = make(verify=v)
        tok = mcp.handle_token(TOKEN_REQ)["access_token"]
        mcp.authenticate("Bearer " + tok)
        self.assertEqual(broker.calls["status"], 0)

    def test_status_cache(self):
        mcp, broker = make(status={"ok": True, "revoked": False}, status_cache_s=300)
        tok = mcp.handle_token(TOKEN_REQ)["access_token"]
        before = broker.calls["status"]
        mcp.authenticate("Bearer " + tok)
        mcp.authenticate("Bearer " + tok)
        self.assertEqual(broker.calls["status"], before)  # cached from verify


class Scopes(unittest.TestCase):
    def test_require_warrant(self):
        mcp, _ = make()
        tok = mcp.handle_token(TOKEN_REQ)["access_token"]
        hdr = "Bearer " + tok
        ctx = mcp.require_warrant(hdr, "create_issue")  # issues:create granted
        self.assertEqual(ctx.grantee, "dan+claude@sandmill.org")
        with self.assertRaises(McpAuthError) as c:
            mcp.require_warrant(hdr, "admin")  # repo:admin not granted
        self.assertEqual(c.exception.http_status, 403)
        mcp.require_warrant(hdr, ["repo:read"])  # explicit list


class Metadata(unittest.TestCase):
    def test_discovery(self):
        mcp, _ = make()
        prm = mcp.protected_resource_metadata()
        self.assertEqual(prm["resource"], RESOURCE)
        asm = mcp.authorization_server_metadata()
        self.assertEqual(asm["token_endpoint"], RESOURCE + "/token")
        self.assertEqual(asm["grant_types_supported"], [JWT_BEARER_GRANT])
        self.assertIn("resource_metadata=", mcp.challenge())


class Expiry(unittest.TestCase):
    def test_expired_bearer(self):
        mcp, _ = make(token_ttl_s=-1)
        tok = mcp.handle_token(TOKEN_REQ)["access_token"]
        time.sleep(0.01)
        with self.assertRaises(McpAuthError) as c:
            mcp.authenticate("Bearer " + tok)
        self.assertEqual(c.exception.http_status, 401)


if __name__ == "__main__":
    unittest.main()
