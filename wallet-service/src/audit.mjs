// Audit log write path (design doc §9): every mint, assertion, warrant
// request, and admin action, per tenant. Operational metadata only — never
// message content, never key material. Retention: 90 days.
import { nowS } from "./db.mjs";

const RETENTION_S = 90 * 24 * 60 * 60;

export class Audit {
  #db;
  #insert;

  constructor(db) {
    this.#db = db;
    this.#insert = db.prepare(
      "INSERT INTO audit_log (ts, account_email, op, audience, detail, client_id, ip) VALUES (?, ?, ?, ?, ?, ?, ?)"
    );
  }

  /**
   * @param {string} email tenant
   * @param {string} op e.g. provision.request, warrant.grant, assertion.issue
   */
  log(email, op, { audience = null, detail = null, clientId = null, ip = null } = {}) {
    try {
      this.#insert.run(nowS(), email, op, audience, detail, clientId, ip);
    } catch (e) {
      // The audit log must never take the wallet down — but a silent write
      // failure is itself an incident signal, so say so loudly.
      console.error(`[wallet-service] AUDIT WRITE FAILED (${op} for ${email}):`, e.message);
    }
  }

  /** Drop entries older than the retention window. Called on a timer. */
  prune() {
    this.#db.prepare("DELETE FROM audit_log WHERE ts < ?").run(nowS() - RETENTION_S);
  }
}
