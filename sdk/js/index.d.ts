// Type definitions for @browserid/verify

export interface AgentAttribution {
  /** The delegator (human identity) the agent acts for. */
  parent: string;
  /** Scopes the delegator's warrant grants at this audience. */
  scopes: string[];
}

export type VerifyResult =
  | {
      ok: true;
      /** The verified email / identity. */
      email: string;
      /** The issuing domain. */
      issuer?: string;
      /** Expiry (unix seconds). */
      expires?: number;
      /** Present iff this was an agent presentation and `allowAgent` was set. */
      agent: AgentAttribution | null;
    }
  | {
      ok: false;
      /** Human-readable failure reason. */
      reason: string;
    };

export interface CreateVerifierOptions {
  /** Hosted /verify URL. Default: https://browserid.me/verify */
  verifierUrl?: string;
  /** Default accepted fallback-IdP issuer domains (spec §8.1). */
  acceptedFallbacks?: string[];
  /** Request timeout in ms. Default: 10000. */
  timeoutMs?: number;
  /** Custom fetch implementation. Default: global fetch. */
  fetch?: typeof fetch;
}

export interface VerifyCallOptions {
  /** Override the accepted fallback set for this call. */
  acceptedFallbacks?: string[];
  /** Accept agent presentations (default false → agents are rejected). */
  allowAgent?: boolean;
}

export interface Verifier {
  verify(
    assertion: string,
    audience: string,
    opts?: VerifyCallOptions
  ): Promise<VerifyResult>;
  verifierUrl: string;
}

export function createVerifier(opts?: CreateVerifierOptions): Verifier;

export function verifyAssertion(
  assertion: string,
  audience: string,
  opts?: CreateVerifierOptions & VerifyCallOptions
): Promise<VerifyResult>;
