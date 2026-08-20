// Types for @browserid-ng/nextauth (server entry).

export interface StatusRef {
  uri: string;
  idx: number;
}

export interface BrowserIDClaims {
  issuer: string;
  /** The ACTOR of record; differs from the user's email for delegated
   *  presentations (an agent acting on the user's behalf). */
  grantee: string;
  scopes: string[];
  statusRefs: StatusRef[];
}

export interface BrowserIDUser {
  id: string;
  email: string;
  name: string;
  browserid: BrowserIDClaims;
}

export interface BrowserIDConfig {
  /** REQUIRED — your canonical origin (or `<origin>/<path>` for scoped access). */
  audience: string;
  /** BrowserID broker origin. Default "https://browserid.me". */
  broker?: string;
  /** Hosted verifier URL. Default `${broker}/verify-access`. */
  verifierUrl?: string;
  acceptedFallbacks?: string[];
  /** Injectable fetch (tests). */
  fetch?: typeof fetch;
}

export type AuthorizeFn = (
  credentials: Record<string, unknown> | undefined
) => Promise<BrowserIDUser | null>;

export function browseridAuthorize(config: BrowserIDConfig): AuthorizeFn;

export interface CredentialsProviderOptions {
  id: "browserid";
  name: "BrowserID";
  type: "credentials";
  credentials: { presentation: { label: string; type: string } };
  authorize: AuthorizeFn;
}

/** Auth.js Credentials-provider options for BrowserID. */
export function BrowserID(config: BrowserIDConfig): CredentialsProviderOptions;

/** Re-check a session's revocation status (fail-closed). */
export function browseridSessionValid(
  statusRefs: StatusRef[],
  opts?: { broker?: string; verifierUrl?: string; fetch?: typeof fetch }
): Promise<{ ok: boolean; revoked: boolean; reason?: string }>;
