// Type definitions for @browserid-ng/agent

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
  /** Which stored identity to load, by email (the file holds an array). Default: the first. */
  email?: string;
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

export interface BootstrapOptions {
  /** Broker to pair with. Default: https://browserid.me */
  broker?: string;
  /** Handles to suggest to the human (they confirm/edit). */
  requestedHandles?: { names?: string[]; patterns?: string[] };
  /** Human-readable label shown on the pairing page. */
  label?: string;
  http?: typeof fetch;
}

export interface Pairing {
  /** URL for the human to type `userCode` at (headless/cross-device). */
  verificationUri: string;
  /** URL with the code embedded — one click (desktop). */
  verificationUriComplete: string;
  /** Short typeable code. */
  userCode: string;
  /** Provisioning-key fingerprint for pairing confirmation. */
  fingerprint: string;
  /** Resolves to a provisioned Agent once the human approves; rejects on denial/expiry. */
  ready: Promise<Agent>;
}

export class Agent {
  /**
   * Paired provisioning: generate a provisioning key locally, ask the broker to
   * pair, and return entry points to show the human + a `ready` Agent. The
   * provisioning private key never leaves this process; no credential file.
   */
  static bootstrap(opts?: BootstrapOptions): Promise<Pairing>;

  /** Provision a fresh delegated identity (endorse → mint) from an existing credential. */
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

// ---------------------------------------------------------------------------
// The current protocol: device certs, access certs, four-part presentations.
// ---------------------------------------------------------------------------

export interface DeviceCredential {
  /** base64url Ed25519 seed of the device key */
  device_key: string;
  /** the IdP-signed device cert certifying it */
  agent_device_cert: string;
  idp: string;
  access_mint?: string;
  identity?: string;
}

/** A held warrant, as `warrant~config_cert` — feed `grant` back to `addGrant`. */
export interface StoredGrant {
  audience: string;
  grant: string;
}

export interface GrantRequest {
  audience: string;
  scopes?: string[];
}

export class PendingProvision {
  /** Show these to the human — nothing proceeds until they approve. */
  verificationUri: string;
  verificationUriComplete: string;
  userCode: string;
  fingerprint: string;
  /** Poll until approved. Single delivery: persist the result immediately. */
  wait(opts?: { signal?: AbortSignal }): Promise<{ credential: DeviceCredential; grants: StoredGrant[]; grantsDenied?: string }>;
}

export class PendingWarrants {
  verificationUri: string;
  verificationUriComplete: string;
  wait(opts?: { signal?: AbortSignal }): Promise<StoredGrant[]>;
}

/** Ask a broker to provision a device identity, with grants approved in the
 *  same consent. */
export function requestProvision(
  broker: string,
  opts?: {
    /** browserid identity handle to request — NOT an RP-side account name. */
    handle?: string;
    namespace?: string;
    grants?: GrantRequest[];
    /** Suggests the agent's display NAME (the human confirms or changes it). */
    label?: string;
    /** The agent's own account of why it wants the bundled grants — quoted on
     *  the permission screen, marked unverified. */
    message?: string;
    /** Identity a write is attributed to; omit/"*" lets the approver choose;
     *  "self" pins the minted agent itself (grantor == grantee). */
    grantor?: string;
    /** Identity that acts. Omit for as-you (grantee ≡ grantor); "*" has the
     *  approver mint a distinct actor — an ON-BEHALF-OF warrant. */
    grantee?: string;
    /** Required when `grantee` names an identity the approver does not own. */
    granteeHolder?: string;
    http?: typeof fetch;
  }
): Promise<PendingProvision>;

/** A second consent round for new audiences, once already provisioned. */
export function requestWarrants(
  broker: string,
  opts: {
    deviceCert: string;
    identity: string;
    grants: GrantRequest[];
    label?: string;
    /** The agent's own account of why it wants this — quoted, unverified. */
    message?: string;
    /** Grantor pin: omit/"*" = approver chooses (agent itself or any identity
     *  they own); "self"/the agent's email or a concrete email pins it. An
     *  unsatisfiable pin rejects the request immediately. */
    grantor?: string;
    http?: typeof fetch;
  }
): Promise<PendingWarrants>;

export class DeviceAgent {
  constructor(credential: DeviceCredential, opts?: { http?: typeof fetch });
  /** Read from the SIGNED device cert, never from caller metadata. */
  email: string;
  holder: string;
  deviceCert: string;
  credential: DeviceCredential;
  /** Accepts `warrant~config_cert` or the two parts separately. */
  addGrant(warrantOrPair: string, configCert?: string): string;
  warrantedAudiences(): string[];
  storedGrants(): StoredGrant[];
  /** Mint (or re-mint) an access cert over a fresh key. */
  mint(): Promise<string>;
  /** `access_cert ~ assertion ~ warrant ~ config_cert` for `audience`. */
  assertionFor(audience: string): Promise<string>;
  /** The presentation plus the access key that signed it, for binding an
   *  external payload to the same cert. */
  assertionWithAccessKey(audience: string): Promise<{
    presentation: string;
    accessKey: KeyPair;
    accessCert: string;
  }>;
}

export class KeyPair {
  static generate(): KeyPair;
  static fromSeed(seed: Uint8Array | Buffer): KeyPair;
  publicKeyB64: string;
  seed: Uint8Array;
  /** base64url Ed25519 signature over `message`. */
  sign(message: string | Uint8Array): string;
  signRaw(message: string | Uint8Array): Uint8Array;
  jws(header: object, payload: object): string;
}

export class PublicKey {
  static fromB64u(s: string): PublicKey;
  static fromRaw(raw: Uint8Array | Buffer): PublicKey;
  publicKeyB64: string;
  verify(message: string | Uint8Array, sigB64u: string): boolean;
}
