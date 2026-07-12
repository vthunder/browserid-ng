// Type definitions for @browserid/agent

export interface ReservedIdentity {
  /** Fixed reserved names the credential authorizes. */
  names: string[];
  /** `<prefix>+*` patterns the credential authorizes. */
  patterns: string[];
  /** The identity `provision` picks with no explicit name, or null if ambiguous. */
  default:
    | { name: string; generated: false; domain: string }
    | { name: null; generated: true; prefix: string; domain: string }
    | null;
}

export interface WarrantRequest {
  /** URL to show the principal to approve the warrant, or null if already held. */
  approveUrl: string | null;
  /** Resolves when approved (warrant stored); rejects on denial/expiry. */
  approved: Promise<void>;
  handle?: { code: string; verificationUri: string; expiresIn: number; interval: number };
}

export interface OpenOptions {
  /** Reserved name to provision as (for multi-name credentials). */
  name?: string;
  /** Custom fetch implementation. */
  http?: typeof fetch;
}

export class Credential {
  static load(pathOrObject: string | object): Credential;
  readonly broker: string;
  readonly idp: string;
  readonly brokerDomain: string;
  readonly idpDomain: string;
  constraint(): { names: string[]; patterns: string[] };
  defaultIdentity(): ReservedIdentity["default"];
}

export class Agent {
  /** Provision a fresh delegated identity (endorse → mint). */
  static provision(credential: Credential, opts?: OpenOptions): Promise<Agent>;
  /** Load a persisted identity, or provision + save one if absent. */
  static open(
    credential: string | object,
    identityPath: string,
    opts?: OpenOptions
  ): Promise<Agent>;

  readonly email: string;
  readonly credential: Credential;

  /** Reserved names/patterns and the default identity. */
  identity(): ReservedIdentity;

  /** Audiences this agent currently holds warrants for. */
  warrantedAudiences(): string[];
  /** Whether a held warrant covers this audience + scopes. */
  warrantCovers(audience: string, scopes?: string[] | null): boolean;

  /** Raise a consent request; returns an approve URL + an `approved` promise. */
  requestWarrant(audience: string, scopes?: string[] | null): Promise<WarrantRequest>;
  /** Raise consent, surface the URL via the callback, and await approval. */
  obtainWarrant(
    audience: string,
    scopes: string[] | null,
    onApproveUrl?: (url: string) => void
  ): Promise<void>;

  /** A backed presentation for `audience` (refreshes the cert; needs a warrant for agents). */
  assertionFor(audience: string): Promise<string>;

  /** Persist the identity (key, cert, warrants) to a file. */
  save(identityPath: string): Promise<void>;

  /** Revoke this identity at the IdP. */
  revoke(): Promise<void>;
}

export class AgentError extends Error {}
export class NeedCredentialError extends AgentError { path: string; }
export class InvalidCredentialError extends AgentError {}
export class AmbiguousNameError extends AgentError { names: string[]; }
export class RequestError extends AgentError { status: number; reason: string; }
export class WarrantExpiredError extends AgentError {}
export class WarrantDeniedError extends AgentError {}
export class NoWarrantError extends AgentError { audience: string; }
