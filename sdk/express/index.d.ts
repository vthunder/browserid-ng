// Types for @browserid-ng/express

export interface StatusRef { uri: string; idx: number; }

export interface BrowserIDIdentity {
  /** The ATTRIBUTED identity (who the session belongs to). */
  email: string;
  issuer: string;
  /** The ACTOR of record; differs from `email` for delegated presentations. */
  grantee: string;
  scopes: string[];
  statusRefs: StatusRef[];
}

export interface BrowserIDConfig {
  /** REQUIRED — your canonical origin. */
  audience: string;
  broker?: string;
  verifierUrl?: string;
  acceptedFallbacks?: string[];
  fetch?: typeof fetch;
}

export function verifyBrowserID(
  config: BrowserIDConfig
): (presentation: string) => Promise<BrowserIDIdentity | null>;

/** Express middleware; attaches `req.browserid` on success, 401 on failure. */
export function browseridLogin(
  config: BrowserIDConfig
): (req: any, res: any, next: (err?: any) => void) => Promise<void>;

export type VerifyCallback = (
  user: BrowserIDIdentity,
  done: (err: any, out?: any, info?: any) => void
) => void;

/** Passport-compatible strategy (no passport dependency). */
export class Strategy {
  name: string;
  constructor(config: BrowserIDConfig, verify?: VerifyCallback);
  authenticate(req: any): void;
}

export function browseridSessionValid(
  statusRefs: StatusRef[],
  opts?: { broker?: string; verifierUrl?: string; fetch?: typeof fetch }
): Promise<{ ok: boolean; revoked: boolean; reason?: string }>;
