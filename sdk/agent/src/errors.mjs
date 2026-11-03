// Typed errors — so callers branch on a class, not a string match.

export class AgentError extends Error {
  constructor(message) {
    super(message);
    this.name = new.target.name;
  }
}

/** A server call returned a failure. Carries the HTTP status and server reason. */
export class RequestError extends AgentError {
  constructor(what, status, reason) {
    super(`${what} failed (HTTP ${status}): ${reason}`);
    this.status = status;
    this.reason = reason;
  }
}

export class WarrantExpiredError extends AgentError {
  constructor() {
    super("the consent request expired before it was approved");
  }
}

export class WarrantDeniedError extends AgentError {
  constructor() {
    super("the principal denied the consent request");
  }
}

/** assertionFor() called for an agent identity with no warrant for the audience. */
export class NoWarrantError extends AgentError {
  constructor(audience) {
    super(`no warrant held for ${audience} — obtain one first`);
    this.audience = audience;
  }
}
