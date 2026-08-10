"""browserid-mcp-auth — warrant-gated MCP tools over MCP's own OAuth 2.1.

The Python port of ``@browserid-ng/mcp-auth``: an embedded authorization
server that redeems a BrowserID warrant presentation for a short-lived scoped
bearer via the RFC 7521 ``jwt-bearer`` assertion grant, plus a per-call guard
that re-checks the warrant's revocation status **fail-closed** on every tool
call. Hosts run their stock MCP OAuth client unmodified.

No crypto in Python: verification is delegated to the broker's DNSSEC-rooted
hosted verifier (``POST /verify-access``) and revocation to ``POST
/status/check``. Framework-agnostic; wire into FastMCP / any server. See
docs/plans/2026-08-02-mcp-distribution-design.md.
"""
from __future__ import annotations

import json as _json
import secrets
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"

__all__ = [
    "JWT_BEARER_GRANT",
    "McpAuth",
    "McpAuthError",
    "WarrantContext",
    "MemoryStore",
    "default_http_post",
]


class McpAuthError(Exception):
    """Carries an OAuth error code + HTTP status for uniform rendering."""

    def __init__(self, oauth_error: str, message: str, http_status: int = 400):
        super().__init__(message)
        self.oauth_error = oauth_error
        self.http_status = http_status

    def to_token_error_response(self) -> Dict[str, str]:
        return {"error": self.oauth_error, "error_description": str(self)}


@dataclass
class WarrantContext:
    grantor: Optional[str]
    grantee: Optional[str]
    holder: Optional[str]
    issuer: Optional[str]
    scopes: List[str]


@dataclass
class _Grant:
    grantor: Optional[str]
    grantee: Optional[str]
    holder: Optional[str]
    issuer: Optional[str]
    scopes: List[str]
    status_refs: List[dict]
    exp: int
    status_checked_at: int
    status_ok: bool


class MemoryStore:
    """In-memory bearer store (single process). Swap for Redis/db in prod."""

    def __init__(self) -> None:
        self._grants: Dict[str, _Grant] = {}

    def put(self, token: str, grant: _Grant) -> None:
        self._grants[token] = grant

    def get(self, token: str) -> Optional[_Grant]:
        g = self._grants.get(token)
        if g is None:
            return None
        if g.exp <= int(time.time()):
            self._grants.pop(token, None)
            return None
        return g

    def delete(self, token: str) -> None:
        self._grants.pop(token, None)


def default_http_post(url: str, body: dict, timeout: float = 10.0):
    """POST JSON, return (status_code, parsed_json). Stdlib-only."""
    data = _json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, headers={"content-type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.status, _json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
        try:
            return e.code, _json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


class McpAuth:
    """The middleware. Construct once per MCP server.

    :param resource: canonical URL of THIS server (OAuth resource + the
        audience warrants must bind to).
    :param broker: BrowserID broker origin (default https://browserid.me).
    :param scopes_for_tool: ``{tool_name: [required scopes]}``.
    :param token_ttl_s: bearer lifetime (default 3600).
    :param status_cache_s: max seconds to trust a per-grant status result
        before a fresh re-check (default 60).
    :param accepted_fallbacks: fallback issuer domains (default [broker host]).
    :param store: bearer store (default MemoryStore()).
    :param http_post: injectable ``(url, body) -> (status, dict)`` (tests).
    """

    def __init__(
        self,
        resource: str,
        broker: str = "https://browserid.me",
        scopes_for_tool: Optional[Dict[str, List[str]]] = None,
        token_ttl_s: int = 3600,
        status_cache_s: int = 60,
        accepted_fallbacks: Optional[List[str]] = None,
        store: Optional[MemoryStore] = None,
        http_post: Optional[Callable[[str, dict], tuple]] = None,
    ) -> None:
        if not resource:
            raise ValueError("resource is required")
        self.resource = resource.rstrip("/")
        self.broker = broker.rstrip("/")
        self.scopes_for_tool = scopes_for_tool or {}
        self.token_ttl_s = token_ttl_s
        self.status_cache_s = status_cache_s
        from urllib.parse import urlparse

        self.accepted_fallbacks = accepted_fallbacks or [urlparse(self.broker).netloc]
        self.store = store or MemoryStore()
        self._http_post = http_post or default_http_post
        self._verify_url = f"{self.broker}/verify-access"
        self._status_url = f"{self.broker}/status/check"

    # -- discovery -----------------------------------------------------------

    def _all_scopes(self) -> List[str]:
        seen: List[str] = []
        for scopes in self.scopes_for_tool.values():
            for s in scopes:
                if s not in seen:
                    seen.append(s)
        return seen

    def protected_resource_metadata(self) -> dict:
        return {
            "resource": self.resource,
            "authorization_servers": [self.resource],
            "scopes_supported": self._all_scopes(),
            "bearer_methods_supported": ["header"],
        }

    def authorization_server_metadata(self) -> dict:
        return {
            "issuer": self.resource,
            "token_endpoint": f"{self.resource}/token",
            "grant_types_supported": [JWT_BEARER_GRANT],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": self._all_scopes(),
            "response_types_supported": [],
        }

    def challenge(self) -> str:
        return f'Bearer resource_metadata="{self.resource}/.well-known/oauth-protected-resource"'

    # -- token endpoint ------------------------------------------------------

    def handle_token(self, params: dict) -> dict:
        """Redeem a warrant presentation for a bearer. ``params`` is the token
        request body ({grant_type, assertion, scope?}). Raises McpAuthError."""
        if params.get("grant_type") != JWT_BEARER_GRANT:
            raise McpAuthError("unsupported_grant_type", f"only {JWT_BEARER_GRANT} is supported")
        presentation = params.get("assertion")
        if not presentation or not isinstance(presentation, str):
            raise McpAuthError("invalid_request", "missing 'assertion' (a browserid presentation)")

        try:
            code, verified = self._http_post(
                self._verify_url,
                {
                    "presentation": presentation,
                    "audience": self.resource,
                    "accepted_fallbacks": self.accepted_fallbacks,
                },
            )
        except Exception as e:  # fail-closed: an unreachable verifier is not approval
            raise McpAuthError("temporarily_unavailable", f"verifier unreachable: {e}", 503)
        if code < 200 or code >= 300:
            raise McpAuthError("invalid_grant", f"verifier HTTP {code}")
        if verified.get("status") != "okay":
            raise McpAuthError("invalid_grant", verified.get("reason") or "presentation did not verify")

        granted = verified.get("scopes") or []
        requested = (params.get("scope") or "").split()
        if requested:
            scopes = [s for s in requested if s in granted]
            if len(scopes) != len(requested):
                raise McpAuthError("invalid_scope", "requested scope exceeds the warrant's grant")
        else:
            scopes = list(granted)

        token = "bat_" + secrets.token_urlsafe(32)
        now = int(time.time())
        self.store.put(
            token,
            _Grant(
                grantor=verified.get("email"),
                grantee=verified.get("grantee") or verified.get("email"),
                holder=verified.get("holder"),
                issuer=verified.get("issuer"),
                scopes=scopes,
                status_refs=verified.get("status_refs") or [],
                exp=now + self.token_ttl_s,
                status_checked_at=now,
                status_ok=True,
            ),
        )
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": self.token_ttl_s,
            "scope": " ".join(scopes),
        }

    # -- per-call validation -------------------------------------------------

    def authenticate(self, authorization_header: Optional[str]) -> WarrantContext:
        """Validate a Bearer header, re-check status fail-closed, return ctx."""
        if not authorization_header:
            raise McpAuthError("invalid_request", "missing Bearer token", 401)
        parts = authorization_header.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise McpAuthError("invalid_request", "missing Bearer token", 401)
        token = parts[1].strip()
        grant = self.store.get(token)
        if grant is None:
            raise McpAuthError("invalid_token", "unknown or expired token", 401)
        self._ensure_unrevoked(token, grant)
        return WarrantContext(
            grantor=grant.grantor,
            grantee=grant.grantee,
            holder=grant.holder,
            issuer=grant.issuer,
            scopes=list(grant.scopes),
        )

    def _ensure_unrevoked(self, token: str, grant: _Grant) -> None:
        refs = grant.status_refs
        if not refs:
            return
        now = int(time.time())
        if grant.status_ok and now - grant.status_checked_at < self.status_cache_s:
            return
        try:
            code, body = self._http_post(self._status_url, {"refs": refs})
            if code < 200 or code >= 300:
                raise RuntimeError(f"HTTP {code}")
        except Exception as e:  # fail-closed
            grant.status_ok = False
            raise McpAuthError("invalid_token", f"status unavailable (fail-closed): {e}", 401)
        if body.get("ok") is not True or body.get("revoked") is True:
            grant.status_ok = False
            self.store.delete(token)
            raise McpAuthError("invalid_token", "warrant revoked", 401)
        grant.status_ok = True
        grant.status_checked_at = now

    def require_warrant(self, authorization_header: Optional[str], tool_or_scopes) -> WarrantContext:
        """authenticate + enforce a tool's required scopes (name or list)."""
        ctx = self.authenticate(authorization_header)
        required = (
            list(tool_or_scopes)
            if isinstance(tool_or_scopes, (list, tuple))
            else self.scopes_for_tool.get(tool_or_scopes, [])
        )
        missing = [s for s in required if s not in ctx.scopes]
        if missing:
            raise McpAuthError(
                "insufficient_scope",
                f"this tool needs scope(s) {missing} not in the warrant",
                403,
            )
        return ctx
