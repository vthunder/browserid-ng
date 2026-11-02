"""Security audit 2026-11, WS4 (bean browserid-ng-n6nn): browserid-mcp-auth.

unittest-style (what CI runs: ``python -m unittest discover -s tests``;
pytest collects these too). Tests that FAIL today are skipped with
``AUDIT-2026-11 <id>: fails today``; the rest pin what the skeptic
re-verified. No production code changed.

Parity note: the Python port implements Lane A (jwt-bearer) only — no
auth-code lane, no policy layer, no record validation, no identity
comparison — so D5, D17 and D20 have no Python surface. What it shares with
the JS Lane A is pinned here.
"""
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from browserid_mcp_auth import JWT_BEARER_GRANT, McpAuth, McpAuthError  # noqa: E402

RESOURCE = "https://mcp.example.com"
OK = {
    "status": "okay",
    "email": "dan@example.com",
    "grantee": "dan+claude@example.com",
    "holder": "agents.abc",
    "issuer": "example.com",
    "scopes": ["repo:read", "issues:create"],
    "status_refs": [{"uri": "https://broker.example/status", "idx": 7}],
}
REQ = {"grant_type": JWT_BEARER_GRANT, "assertion": "AC~AS~WR~CC"}


class Broker:
    def __init__(self, verify=OK, status=None):
        self.verify, self.status = verify, status or {"ok": True, "revoked": False}
        self.seen = []

    def post(self, url, body):
        self.seen.append((url, body))
        if url.endswith("/verify"):
            v = self.verify(body) if callable(self.verify) else self.verify
            return v.get("__status", 200), v
        if url.endswith("/status/check"):
            s = self.status
            if s == "throw":
                raise ConnectionError("refused")
            return s.get("__status", 200), s
        raise AssertionError(url)


def make(**kw):
    b = Broker(verify=kw.pop("verify", OK), status=kw.pop("status", None))
    m = McpAuth(resource=RESOURCE, broker="https://broker.example", http_post=b.post,
                scopes_for_tool={"read": ["repo:read"], "admin": ["repo:admin"]},
                status_cache_s=kw.pop("status_cache_s", 0), **kw)
    return m, b


class PerCallFailClosed(unittest.TestCase):
    def test_http_503_from_status_check_fails_closed(self):
        m, b = make(status={"__status": 503, "ok": False})
        tok = m.handle_token(REQ)["access_token"]
        with self.assertRaises(McpAuthError) as c:
            m.authenticate("Bearer " + tok)
        self.assertEqual(c.exception.http_status, 401)

    def test_http_503_from_verify_is_not_a_mint(self):
        m, _ = make(verify={"__status": 503, "status": "okay", **{k: v for k, v in OK.items() if k != "status"}})
        with self.assertRaises(McpAuthError) as c:
            m.handle_token(REQ)
        self.assertEqual(c.exception.oauth_error, "invalid_grant")

    def test_a_refless_presentation_is_never_rechecked(self):
        # Pinned behaviour: with no status refs there is nothing to re-check.
        # Spec S3 (decided 2026-11-01) retires refless records at the verifier,
        # so this branch is reachable only through a non-conforming verifier.
        m, b = make(verify={**OK, "status_refs": []})
        tok = m.handle_token(REQ)["access_token"]
        m.authenticate("Bearer " + tok)
        self.assertEqual([u for u, _ in b.seen if u.endswith("/status/check")], [])


class AudienceAndScopes(unittest.TestCase):
    def test_verify_is_audience_pinned_to_this_resource(self):
        m, b = make()
        m.handle_token(REQ)
        url, body = b.seen[0]
        self.assertEqual(body["audience"], RESOURCE)
        self.assertEqual(body["accepted_fallbacks"], ["broker.example"])

    @unittest.skip("AUDIT-2026-11 W4-14: fails today")
    def test_parameterised_scope_entries_fail_closed(self):
        # S7 relay rule: an object entry rides verbatim (or is refused) and
        # never satisfies a string tool scope. Today handle_token raises
        # TypeError while rendering the token response (W4-14).
        m, _ = make(verify={**OK, "scopes": [{"repo:read": {"mode": "prompt"}}, "issues:create"]})
        with self.assertRaises(McpAuthError) as c:
            m.handle_token({**REQ, "scope": "repo:read"})
        self.assertEqual(c.exception.oauth_error, "invalid_scope")
        tok = m.handle_token(REQ)["access_token"]
        with self.assertRaises(McpAuthError) as c:
            m.require_warrant("Bearer " + tok, "read")
        self.assertEqual(c.exception.oauth_error, "insufficient_scope")
        self.assertEqual(m.authenticate("Bearer " + tok).scopes[0], {"repo:read": {"mode": "prompt"}})

    def test_parameterised_scope_entries_crash_the_token_endpoint_today(self):
        # W4-14 pin: a verifier response carrying an object scope entry makes
        # handle_token raise TypeError (not McpAuthError) — an unhandled 500
        # at the host's /token, not a clean refusal. The narrowing branch is
        # fine (string never equals dict ⇒ invalid_scope).
        m, _ = make(verify={**OK, "scopes": [{"repo:read": {"mode": "prompt"}}, "issues:create"]})
        with self.assertRaises(McpAuthError) as c:
            m.handle_token({**REQ, "scope": "repo:read"})
        self.assertEqual(c.exception.oauth_error, "invalid_scope")
        with self.assertRaises(TypeError):
            m.handle_token(REQ)

    def test_replayed_assertion_mints_again(self):
        # Observation (not a finding): the AS keeps no jti cache; every
        # redemption re-verifies at the broker, audience-pinned. Same as JS.
        m, b = make()
        a = m.handle_token(REQ)["access_token"]
        c = m.handle_token(REQ)["access_token"]
        self.assertNotEqual(a, c)
        self.assertEqual(len([u for u, _ in b.seen if u.endswith("/verify")]), 2)


class LaneABearerLifetime(unittest.TestCase):
    @unittest.skip("AUDIT-2026-11 W4-13: fails today")
    def test_bearer_never_outlives_the_presented_warrant(self):
        # /verify returns no expiry today (verifier side, cf. WS6 D7 class);
        # once it does, the bearer must be capped at it like record bearers are.
        m, _ = make(verify={**OK, "expires_at": int(time.time()) + 30})
        res = m.handle_token(REQ)
        self.assertLessEqual(res["expires_in"], 30)

    def test_bearer_lifetime_is_token_ttl_today(self):
        m, _ = make(verify={**OK, "expires_at": int(time.time()) + 30})
        self.assertEqual(m.handle_token(REQ)["expires_in"], 3600)


if __name__ == "__main__":
    unittest.main()
