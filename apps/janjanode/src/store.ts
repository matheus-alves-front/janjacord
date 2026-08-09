import { EncryptedDatabase } from "@janjacord/persistence";
import type BetterSqlite3 from "better-sqlite3";

type Db = BetterSqlite3.Database & {
  key(key: Buffer): void;
  pragma(sql: string): unknown;
};

const SCHEMA = `
CREATE TABLE IF NOT EXISTS server_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS roles (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, level INTEGER NOT NULL,
  permissions TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
  identity_id TEXT PRIMARY KEY, nickname TEXT NOT NULL, role_id TEXT NOT NULL,
  joined_at INTEGER NOT NULL, presence TEXT NOT NULL DEFAULT 'offline'
);
CREATE TABLE IF NOT EXISTS bans (identity_id TEXT PRIMARY KEY, banned_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS channels (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL,
  overrides TEXT NOT NULL DEFAULT '[]', created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
  id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, initial_role_id TEXT NOT NULL,
  max_uses INTEGER NOT NULL DEFAULT 1, used INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER, revoked INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS spool (
  message_id TEXT PRIMARY KEY, channel_id TEXT NOT NULL, envelope TEXT NOT NULL,
  expires_at INTEGER NOT NULL, recipients TEXT NOT NULL, consumed TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS op_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, op TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS key_packages (
  identity_id TEXT PRIMARY KEY, key_package TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS welcomes (
  identity_id TEXT PRIMARY KEY, welcome TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS attachments (
  asset_id TEXT PRIMARY KEY, data TEXT NOT NULL, size_bytes INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL
);
`;

export class Store {
  private db: EncryptedDatabase;

  constructor(
    readonly file: string,
    rawKey: Buffer,
  ) {
    this.db = new EncryptedDatabase(file, rawKey);
    this.db.open();
    this.db.migrate(SCHEMA);
  }

  get raw(): Db {
    return this.db.raw;
  }

  close() {
    this.db.close();
  }

  /** Op-log append-only (ADR-011): base da replicação. */
  appendOp(op: unknown): void {
    this.raw
      .prepare("INSERT INTO op_log (op, created_at) VALUES (?, ?)")
      .run(JSON.stringify(op), Date.now());
  }
}
