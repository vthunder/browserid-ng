/**
 * A warrant scope ENTRY (protocol §5): a bare scope string, or an object
 * carrying parameters — attenuations, stricter-wins. `mode` is
 * wallet-enforced (sign: scopes); `cap`, `counterparties`, `max_duration` and `min_reputation`
 * are AUDIENCE-enforced (a custodian) — never by the wallet.
 */
export type ScopeEntry =
  | string
  | {
      scope: string;
      mode?: "auto" | "prompt";
      /** Decimal `amount` (never a float), ISO 4217 `currency`, optional ISO-8601 `window` rolling from the warrant's iat. */
      cap?: { amount: string; currency: string; window?: string };
      /** Exact emails or `*@domain`. */
      counterparties?: string[];
      /** ISO-8601 duration. */
      max_duration?: string;
      /** Deal only with accounts rated at least `score` (0..100) by the one https `indexer` the grantor chose. Audience-enforced. */
      min_reputation?: { indexer: string; score: number };
    };
export function scopeName(e: ScopeEntry): string | undefined;
export function scopeEntryEq(a: ScopeEntry, b: ScopeEntry): boolean;

// Type definitions for @browserid-ng/agent

export class AgentError extends Error {}
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
  scopes?: ScopeEntry[];
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
    /** Where the consent page bounces the browser after resolution (the
     *  OAuth authorization-code lane). Origin-validated by the registrar
     *  against this requester; a foreign origin refuses the request. */
    returnUrl?: string;
    http?: typeof fetch;
  }
): Promise<PendingWarrants>;

export class DeviceAgent {
  constructor(credential: DeviceCredential, opts?: { http?: typeof fetch });
  /** Read from the SIGNED device cert, never from caller metadata. */
  email: string;
  holder: string;
  deviceCert: string;
  /** The device credential (an explicit read; holds the device key seed —
   *  never printed by util.inspect / JSON.stringify of the agent). */
  readonly credential: DeviceCredential;
  /** The IdP domain: the SIGNED device cert's `iss`. The agent mints only
   *  there, over https (loopback exempt); a credential `idp` / `access_mint`
   *  on another host is refused. */
  readonly idpDomain: string;
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
  /** The raw seed (a copy) — an explicit read for persistence; inspect and
   *  JSON never print it. */
  readonly seed: Uint8Array | undefined;
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
