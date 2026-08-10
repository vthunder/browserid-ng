// Types for @browserid-ng/hono
export interface StatusRef { uri: string; idx: number; }
export interface BrowserIDIdentity {
  email: string; issuer: string; grantee: string; subject: string;
  scopes: string[]; statusRefs: StatusRef[];
}
export interface BrowserIDConfig {
  audience: string; broker?: string; verifierUrl?: string;
  acceptedFallbacks?: string[]; allowAgent?: boolean; fetch?: typeof fetch;
}
export function verifyBrowserID(config: BrowserIDConfig): (presentation: string) => Promise<BrowserIDIdentity | null>;
/** Hono middleware: sets c.get("browserid") on success, 401 on failure. */
export function browseridLogin(config: BrowserIDConfig): (c: any, next: () => Promise<void>) => Promise<Response | void>;
export function browseridSessionValid(statusRefs: StatusRef[], opts?: { broker?: string; verifierUrl?: string; fetch?: typeof fetch }): Promise<{ ok: boolean; revoked: boolean; reason?: string }>;
