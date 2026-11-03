// SQLite persistence (node:sqlite — no native deps). One database holds
// tenants, their encrypted credentials + grants, the OAuth state, and the
// audit log. All timestamps are unix seconds.
import { DatabaseSync } from "node:sqlite";

export function openDb(path) {
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS accounts (
      email       TEXT PRIMARY KEY,
      created_at  INTEGER NOT NULL
    );

    -- One row per (tenant, agent name); MVP uses name 'default' only.
    -- enc_credential is a custody envelope over the DeviceAgent credential JSON
    -- ({device_key, agent_device_cert, idp, ...}).
    CREATE TABLE IF NOT EXISTS agents (
      account_email  TEXT NOT NULL REFERENCES accounts(email),
      name           TEXT NOT NULL DEFAULT 'default',
      enc_credential TEXT NOT NULL,
      identity       TEXT NOT NULL,
      created_at     INTEGER NOT NULL,
      PRIMARY KEY (account_email, name)
    );

    -- Held warrants, 'warrant~config_cert' pairs, one per audience.
    CREATE TABLE IF NOT EXISTS grants (
      account_email TEXT NOT NULL,
      agent_name    TEXT NOT NULL DEFAULT 'default',
      audience      TEXT NOT NULL,
      grant_pair    TEXT NOT NULL,
      created_at    INTEGER NOT NULL,
      PRIMARY KEY (account_email, agent_name, audience)
    );

    CREATE TABLE IF NOT EXISTS oauth_clients (
      client_id     TEXT PRIMARY KEY,
      name          TEXT,
      redirect_uris TEXT NOT NULL,  -- JSON array
      created_at    INTEGER NOT NULL
    );

    -- status_refs: the sign-in's revocation pointers (JSON [{uri, idx}]),
    -- carried from the login session into the connection it approves so a
    -- refresh can re-check the login fail-closed (audit 2026-11 D13).
    CREATE TABLE IF NOT EXISTS oauth_codes (
      code           TEXT PRIMARY KEY,  -- sha256 hex of the code
      client_id      TEXT NOT NULL,
      account_email  TEXT NOT NULL,
      redirect_uri   TEXT NOT NULL,
      code_challenge TEXT NOT NULL,
      scope          TEXT NOT NULL,
      resource       TEXT,
      expires_at     INTEGER NOT NULL,
      used           INTEGER NOT NULL DEFAULT 0,
      status_refs    TEXT
    );

    -- Access and refresh tokens, stored hashed. rotated_from links a refresh
    -- token to its predecessor so replay of a rotated token can burn the family.
    CREATE TABLE IF NOT EXISTS oauth_tokens (
      token_hash    TEXT PRIMARY KEY,  -- sha256 hex
      kind          TEXT NOT NULL CHECK (kind IN ('access','refresh')),
      client_id     TEXT NOT NULL,
      account_email TEXT NOT NULL,
      scope         TEXT NOT NULL,
      expires_at    INTEGER NOT NULL,
      revoked       INTEGER NOT NULL DEFAULT 0,
      rotated_from  TEXT,
      created_at    INTEGER NOT NULL,
      status_refs   TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_tokens_account ON oauth_tokens(account_email, client_id);

    -- Design doc §9: operational metadata only, no message content.
    CREATE TABLE IF NOT EXISTS audit_log (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      ts            INTEGER NOT NULL,
      account_email TEXT NOT NULL,
      op            TEXT NOT NULL,
      audience      TEXT,
      detail        TEXT,
      client_id     TEXT,
      ip            TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_account ON audit_log(account_email, ts);
  `);
  // Databases created before D13 lack the status_refs columns: add them.
  // A pre-existing refresh token then carries no refs and is refused at
  // refresh (fail-closed) — the human reconnects once.
  for (const table of ["oauth_codes", "oauth_tokens"]) {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
    if (!cols.includes("status_refs")) db.exec(`ALTER TABLE ${table} ADD COLUMN status_refs TEXT`);
  }
  return db;
}

export const nowS = () => Math.floor(Date.now() / 1000);
