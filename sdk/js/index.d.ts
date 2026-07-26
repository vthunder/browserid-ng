// Type definitions for @browserid-ng/verify (device-cert model)

export type VerifyResult =
  | {
      ok: true;
      /** The verified email — the ATTRIBUTED identity (the human). */
      email: string;
      /** The ACTING identity — the agent that carried the actions out.
       *  Equals `email` when the identity acted for itself. */
      grantee: string;
      /** The issuing IdP domain (the identity's IdP). */
      issuer?: string;
      /** Which kind of identity authenticated. */
      subject: "user" | "agent";
      /** Scopes the warrant grants at this audience. */
      scopes: string[];
    }
  | {
      ok: false;
      /** Human-readable failure reason. */
      reason: string;
    };

export interface CreateVerifierOptions {
  /** Hosted /verify-access URL. Default: https://browserid.me/verify-access */
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
    presentation: string,
    audience: string,
    opts?: VerifyCallOptions
  ): Promise<VerifyResult>;
  verifierUrl: string;
}

export function createVerifier(opts?: CreateVerifierOptions): Verifier;

export function verifyPresentation(
  presentation: string,
  audience: string,
  opts?: CreateVerifierOptions & VerifyCallOptions
): Promise<VerifyResult>;
