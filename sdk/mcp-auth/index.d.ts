// Type definitions for @browserid-ng/mcp-auth

export const JWT_BEARER_GRANT: "urn:ietf:params:oauth:grant-type:jwt-bearer";

/** A revocation status pointer carried by a verified presentation. */
export interface StatusRef {
  uri: string;
  idx: number;
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
