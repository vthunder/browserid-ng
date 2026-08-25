// Type definitions for @browserid-ng/verify (device-cert model)

export type VerifyResult =
  | {
      ok: true;
      /** The verified email — the ATTRIBUTED identity (who the
       *  session/action belongs to; the warrant grantor). */
      email: string;
      /** The ACTOR of record (the warrant grantee). Equals `email` when the
       *  identity acted for itself; differs when another identity acted on
       *  `email`'s behalf under a user-approved, audience-bound warrant.
       *  Compare with `email` for delegation policy — there is no
       *  human/agent flag (an "as-you" agent is indistinguishable from its
       *  owner by design). */
      grantee: string;
      /** The issuing IdP domain (the identity's IdP). */
      issuer?: string;
      /** Scopes the warrant grants at this audience. */
      scopes: string[];
      /** Revocation pointers for later re-checks via checkStatus().
       *  Retain with the session; the presentation expires in minutes. */
      statusRefs: StatusRef[];
    }
  | {
      ok: false;
      /** Human-readable failure reason. */
      reason: string;
    };

/** A revocation pointer: where a credential's status bit lives (spec §6.4). */
export interface StatusRef {
  uri: string;
  idx: number;
}

export type CheckStatusResult =
  | { ok: true; revoked: boolean }
  | { ok: false; reason: string };

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
}

export interface Verifier {
  verify(
    presentation: string,
    audience: string,
    opts?: VerifyCallOptions
  ): Promise<VerifyResult>;
  /** Re-check revocation for a session's statusRefs ("logged out
   *  everywhere"). Fail-closed: treat {ok: false} as revoked. */
  checkStatus(refs: StatusRef[]): Promise<CheckStatusResult>;
  verifierUrl: string;
}

export function createVerifier(opts?: CreateVerifierOptions): Verifier;

export function verifyPresentation(
  presentation: string,
  audience: string,
  opts?: CreateVerifierOptions & VerifyCallOptions
): Promise<VerifyResult>;
