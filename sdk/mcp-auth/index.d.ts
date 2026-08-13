// Type definitions for @browserid-ng/mcp-auth

export const JWT_BEARER_GRANT: "urn:ietf:params:oauth:grant-type:jwt-bearer";
export const AUTH_CODE_GRANT: "authorization_code";

/** A revocation status pointer carried by a verified presentation. */
export interface StatusRef {
  uri: string;
  idx: number;
}

/** The OAuth client (connection) a bearer belongs to — auth-code lane only.
 *  E.g. { name: "Claude", host: "claude.ai" }. Null on the assertion lane,
 *  where the grantee itself is the acting party. */
export interface ClientInfo {
  name: string;
  host: string | null;
}

/** A stored bearer grant. */
export interface Grant {
  /** Attributed identity (the human the action is on behalf of). */
  grantor: string | null;
  /** Acting identity (the agent). Equals grantor for an as-you grant. */
  grantee: string | null;
  /** Opaque holder id the presentation carried. */
  holder: string | null;
  /** The issuer that vouched for the acting identity. */
  issuer: string | null;
  /** The connection custodying this bearer (auth-code lane), or null. */
  client: ClientInfo | null;
  scopes: string[];
  statusRefs: StatusRef[];
  /** UNIX seconds. */
  exp: number;
  statusCheckedAt: number;
  statusOk: boolean;
}

export interface BearerStore {
  put(token: string, grant: Grant): Promise<void>;
  get(token: string): Promise<Grant | null>;
  del(token: string): Promise<void>;
  sweep?(): Promise<void>;
}

export function createMemoryStore(): BearerStore;

export class McpAuthError extends Error {
  oauthError: string;
  httpStatus: number;
  constructor(oauthError: string, message: string, httpStatus?: number);
  toTokenErrorResponse(): { error: string; error_description: string };
}

/** The live authorization context for a validated bearer. */
export interface WarrantContext {
  grantor: string | null;
  grantee: string | null;
  holder: string | null;
  issuer: string | null;
  /** The connection custodying this bearer (auth-code lane), or null. */
  client: ClientInfo | null;
  scopes: string[];
}

export interface McpAuthOptions {
  /** Canonical URL of THIS MCP server (OAuth resource + warrant audience). */
  resource: string;
  /** BrowserID broker origin. Default "https://browserid.me". */
  broker?: string;
  /** toolName -> required scopes. */
  scopesForTool?: Record<string, string[]>;
  /** Bearer lifetime seconds. Default 3600. */
  tokenTtlS?: number;
  /** Max seconds to trust a per-grant status result before re-check. Default 60. */
  statusCacheS?: number;
  /** Accepted fallback issuer domains (spec §8.1). Default [broker host]. */
  acceptedFallbacks?: string[];
  /** Bearer store. Default in-memory. */
  store?: BearerStore;
  /** Injectable fetch (tests). */
  fetch?: typeof fetch;
}

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
}

export interface McpAuth {
  resource: string;
  broker: string;
  protectedResourceMetadata(): Record<string, unknown>;
  authorizationServerMetadata(): Record<string, unknown>;
  /** Redeem a presentation (token-request body) for a bearer. */
  handleToken(params: { grant_type?: string; assertion?: string; scope?: string }): Promise<TokenResponse>;
  /** The shared bearer mint: verify a presentation via the broker's
   *  /verify-access (audience = this resource, fail-closed) and store a
   *  scoped bearer. Both grants (jwt-bearer + authorization_code) end here. */
  redeemPresentation(presentation: string, scope?: string): Promise<TokenResponse>;
  /** Validate a Bearer header, re-check status fail-closed, return context. */
  authenticate(authorizationHeader: string | undefined): Promise<WarrantContext>;
  /** authenticate + enforce a tool's required scopes. */
  requireWarrant(
    authorizationHeader: string | undefined,
    toolNameOrScopes: string | string[]
  ): Promise<WarrantContext>;
  /** RFC 6750 WWW-Authenticate challenge value for a 401. */
  challenge(): string;
  store: BearerStore;
}

export function createMcpAuth(opts: McpAuthOptions): McpAuth;

// ---------------------------------------------------------------------------
// The OPTIONAL authorization-code lane (Lane B)
// ---------------------------------------------------------------------------

/** The gateway agent's device credential (the wallet's ~/.browserid shape). */
export interface DeviceCredential {
  /** base64url 32-byte Ed25519 seed. */
  device_key: string;
  /** The IdP-signed agent device cert (JWS). */
  agent_device_cert: string;
  /** The agent's IdP origin (access-cert mint). */
  idp: string;
  /** Explicit mint URL, when it differs from `${idp}/access/mint`. */
  access_mint?: string;
  /** Which identity in the cert this agent acts as. */
  identity?: string;
}

/** PKCE S256 (RFC 7636): base64url(sha256(verifier)) === challenge. */
export function verifyPkceS256(verifier: unknown, challenge: unknown): boolean;

export interface AuthCodeLaneOptions {
  /** The `createMcpAuth` instance to extend (bearers land in its store). */
  mcpAuth: McpAuth;
  /** Gateway agent credential; enables the lane (and lazily loads
   *  `@browserid-ng/agent` — Lane-A-only users never do). */
  credential: DeviceCredential;
  /** Broker origin. Default: mcpAuth.broker. */
  broker?: string;
  /** Injectable fetch (tests). */
  fetch?: typeof fetch;
  /** Display label on the consent card. Default "mcp gateway". */
  label?: string;
  /** OAuth code lifetime in seconds (single-use regardless). Default 60. */
  codeTtlS?: number;
  /** /authorize → /authorize/return window in seconds. Default 900. */
  pendingTtlS?: number;
  /** Poll attempts on the return leg. Default 5. */
  returnPollTries?: number;
  /** Delay between those attempts (ms). Default 500. */
  returnPollDelayMs?: number;
}

/** A handler result that redirects the browser. */
export interface Redirect {
  redirect: string;
}

export interface AuthCodeLane {
  resource: string;
  broker: string;
  /** Lane-A metadata + authorization_endpoint / DCR / S256 additions —
   *  serve this from /.well-known/oauth-authorization-server. */
  authorizationServerMetadata(): Record<string, unknown>;
  /** POST /register (RFC 7591 DCR, public PKCE clients). Throws McpAuthError. */
  handleRegister(body: unknown): Record<string, unknown>;
  /** GET /authorize. Resolves to a redirect (consent page, or an OAuth error
   *  back to the validated redirect_uri). Throws McpAuthError for errors
   *  that must NOT redirect (unknown client / unregistered redirect_uri). */
  handleAuthorize(query: Record<string, unknown>): Promise<Redirect>;
  /** GET /authorize/return?st=… (the consent page's validated bounce).
   *  Resolves to a redirect to the host's redirect_uri with ?code= or
   *  ?error=. Throws McpAuthError when the pending record is gone. */
  handleAuthorizeReturn(query: Record<string, unknown>): Promise<Redirect>;
  /** POST /token: the authorization_code branch; jwt-bearer requests are
   *  delegated verbatim to mcpAuth.handleToken. */
  handleToken(params: Record<string, unknown>): Promise<TokenResponse>;
}

export function createAuthCodeLane(opts: AuthCodeLaneOptions): AuthCodeLane;
