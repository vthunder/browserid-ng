"""Security audit 2026-11, WS2 — conformance-vector runner for
browserid-mcp-auth (sdk/python-mcp-auth).

The package delegates verification to the hosted ``POST /verify``; this
runner replays the response the in-process hosted verifier recorded for each
vector (``test-vectors/conformance-2026-11.hosted.json``, written by
``browserid-verifier/tests/audit_2026_11_ws2_runner.rs``) through the
injectable ``http_post``. Under test is the package's own contribution: the
request it builds (bundle and audience must reach the verifier verbatim) and
the verdict and scopes it derives. A request that does not carry the vector's
audience and bundle verbatim is answered with a failure and reported as
``request diverged``.

Vectors the package gets wrong today are listed in ``EXPECTED_FAIL`` with
the audit id they pin (``AUDIT-2026-11 <id>``); the test fails on any other
disagreement and also when a listed vector starts agreeing. Operation-A
vectors are skipped: the package has no record-validation API.

Report: docs/security-audit-2026-11-ws2-conformance.md.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from browserid_mcp_auth import JWT_BEARER_GRANT, McpAuth, McpAuthError  # noqa: E402

ROOT = Path(__file__).resolve().parents[3] / "test-vectors"
VECTORS = json.loads((ROOT / "conformance-2026-11.json").read_text())
HOSTED = json.loads((ROOT / "conformance-2026-11.hosted.json").read_text())["responses"]

EXPECTED_FAIL = {
    # AUDIT-2026-11 W4-14: an object scope entry (what a D7-fixed verifier returns) makes handle_token
    # raise TypeError from " ".join(scopes) (__init__.py:235) — an unhandled 500, not a refusal.
    "P-OK-08/entries": "W4-14",
    # AUDIT-2026-11 D7: scope entries arrive flattened and the package can only carry strings.
    "P-OK-07": "D7",
    "P-OK-08": "D7",
    # AUDIT-2026-11 W6-1 (inherited from the hosted verifier).
    "P-OK-12": "W6-1",
    # AUDIT-2026-11 D16 (inherited): no lower bound on iat.
    "P-TIME-05": "D16",
    "P-TIME-06": "D16",
    "P-TIME-07": "D16",
    "P-TIME-08": "D16",
    "P-TIME-09": "D16",
    # AUDIT-2026-11 S3 (inherited): v1 warrants still verify.
    "P-TYP-01": "S3",
    "P-TYP-02": "S3",
    # AUDIT-2026-11 W6-4 (inherited).
    "P-STAT-06": "W6-4",
    # AUDIT-2026-11 S5 (inherited).
    "P-CONS-01": "S5",
    "P-CONS-06": "S5",
}


def _post_for(v, diverged):
    def post(url, body):
        assert url.endswith("/verify"), url
        if body.get("presentation") != v["bundle"] or body.get("audience") != v["audience"]:
            intact = "intact" if body.get("presentation") == v["bundle"] else "altered"
            diverged.append(f"audience sent {body.get('audience')!r}, presentation {intact}")
            return 200, {"status": "failure", "reason": "runner: request diverged from the vector"}
        return 200, v.get("hosted_override") or HOSTED[v["id"]]

    return post


def _with_entries(v):
    """The hosted response a D7-fixed verifier would return: the vector's
    expected scope entries verbatim, objects included (W4-14 probe)."""
    return {**v, "id": v["id"] + "/entries", "hosted_override": {**HOSTED[v["id"]], "scopes": v["expect"]["scopes"]}}


def _run(v):
    """Return (ok, email, grantee, scopes, reason)."""
    diverged = []
    auth = McpAuth(resource=v["audience"], http_post=_post_for(v, diverged))
    try:
        out = auth.handle_token({"grant_type": JWT_BEARER_GRANT, "assertion": v["bundle"]})
    except McpAuthError as e:
        return False, None, None, None, str(e), diverged
    except Exception as e:  # noqa: BLE001 — an unhandled exception is a 500 at the AS, not a refusal
        return False, None, None, None, f"UNHANDLED {type(e).__name__}: {e}", diverged
    ctx = auth.authenticate("Bearer " + out["access_token"])
    return True, ctx.grantor, ctx.grantee, ctx.scopes, None, diverged


def _mismatch(expect, ok, email, grantee, scopes, reason):
    want = expect["verdict"] == "accept"
    if want and not ok:
        return f"expected accept, got reject: {reason}"
    if not want and ok:
        return f"expected reject ({expect['reason_class']}), got accept as {email}"
    if not want:
        return None
    d = []
    if email != expect["email"]:
        d.append(f"email {expect['email']} != {email}")
    if grantee != expect["grantee"]:
        d.append(f"grantee {expect['grantee']} != {grantee}")
    if scopes != expect["scopes"]:
        d.append(f"scopes {expect['scopes']!r} != {scopes!r}")
    return "; ".join(d) or None


class ConformanceVectors(unittest.TestCase):
    def test_vectors(self):
        n_pass = n_xfail = skipped = 0
        unexpected, fixed = [], []
        probes = [_with_entries(v) for v in VECTORS["vectors"] if v["id"] == "P-OK-08"]
        for v in VECTORS["vectors"] + probes:
            if v["op"] != "P":
                skipped += 1
                continue
            ok, email, grantee, scopes, reason, diverged = _run(v)
            why = _mismatch(v["expect"], ok, email, grantee, scopes, reason)
            if diverged:
                why = f"request diverged: {'; '.join(diverged)}" + (f" -> {why}" if why else "")
            fid = EXPECTED_FAIL.get(v["id"])
            vid = v["id"].ljust(10)
            if not why and not fid:
                n_pass += 1
                print(f"ok    {vid} {'accept ' + email if ok else 'reject: ' + reason}")
            elif why and fid:
                n_xfail += 1
                print(f"XFAIL {vid} [{fid}] {why}")
            elif why:
                print(f"FAIL  {vid} {why}")
                unexpected.append(f"{v['id']}: {why}")
            else:
                print(f"FIXED {vid} [{fid}] now agrees - remove it from EXPECTED_FAIL")
                fixed.append(f"{v['id']} [{fid}]")
        print(
            f"\npython-mcp-auth: {n_pass} pass, {n_xfail} expected-fail, {skipped} skipped (op A/T), "
            f"{len(unexpected)} unexpected, {len(fixed)} fixed"
        )
        self.assertEqual(unexpected, [], "vectors disagreeing with python-mcp-auth")
        self.assertEqual(fixed, [], "vectors now passing; drop them from EXPECTED_FAIL")


if __name__ == "__main__":
    unittest.main()
