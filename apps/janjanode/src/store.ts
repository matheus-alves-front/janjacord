import { EncryptedDatabase } from "@janjacord/persistence";
import { ed25519PublicKey } from "@janjacord/crypto";
import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import type BetterSqlite3 from "better-sqlite3";

type Db = BetterSqlite3.Database & {
  key(key: Buffer): void;
  pragma(sql: string): unknown;
};

export interface StoreSnapshotMetadata {
  serverId: string;
  authorityPublicKey: string;
  epoch: number;
  seq: number;
}

export interface StoreSnapshot extends StoreSnapshotMetadata {
  encryptedDb: Buffer;
}

interface SnapshotExpectation {
  serverId: string;
  authorityPublicKey: string;
  minimumEpoch?: number;
  minimumSeq?: number;
  exactEpoch?: number;
  exactSeq?: number;
}

export interface PreservedHostRegistration {
  hostId: string;
  recordSeq: number;
  recordHash: string;
  registration: string;
  committedAt: number;
}

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
CREATE TABLE IF NOT EXISTS member_devices (
  identity_id TEXT NOT NULL, device_public_key TEXT NOT NULL,
  added_at INTEGER NOT NULL, revoked_at INTEGER,
  PRIMARY KEY(identity_id, device_public_key)
);
CREATE TABLE IF NOT EXISTS device_link_capabilities (
  token_hash TEXT PRIMARY KEY, identity_id TEXT NOT NULL, device_public_key TEXT NOT NULL,
  issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_device_link_capabilities_identity
  ON device_link_capabilities(identity_id, expires_at);
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
  created_at INTEGER NOT NULL, sender_id TEXT NOT NULL DEFAULT '', size_bytes INTEGER NOT NULL DEFAULT 0
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
  expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL,
  owner_id TEXT NOT NULL DEFAULT '', channel_id TEXT NOT NULL DEFAULT '',
  audience TEXT NOT NULL DEFAULT '[]', linked_message_id TEXT,
  total_chunks INTEGER NOT NULL DEFAULT 1, ciphertext_hash TEXT NOT NULL DEFAULT '',
  completed_at INTEGER
);
CREATE TABLE IF NOT EXISTS attachment_chunks (
  asset_id TEXT NOT NULL, chunk_index INTEGER NOT NULL, data TEXT NOT NULL,
  size_bytes INTEGER NOT NULL, hash TEXT NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY(asset_id, chunk_index)
);
CREATE INDEX IF NOT EXISTS idx_attachment_chunks_asset ON attachment_chunks(asset_id, chunk_index);
CREATE TRIGGER IF NOT EXISTS attachment_chunks_after_delete
AFTER DELETE ON attachments BEGIN
  DELETE FROM attachment_chunks WHERE asset_id = OLD.asset_id;
END;
CREATE TABLE IF NOT EXISTS spool_usage (
  scope_id TEXT PRIMARY KEY, size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0)
);
CREATE TABLE IF NOT EXISTS host_grants (
  grant_id TEXT PRIMARY KEY, subject_identity_id TEXT NOT NULL, host_id TEXT NOT NULL,
  subject_auth_public_key TEXT NOT NULL, device_public_key TEXT NOT NULL,
  enrollment_public_key TEXT NOT NULL DEFAULT '',
  capabilities TEXT NOT NULL, payload TEXT NOT NULL,
  signature TEXT NOT NULL, expires_at INTEGER, created_at INTEGER NOT NULL,
  accepted_at INTEGER, revoked_at INTEGER, revocation_payload TEXT, revocation_signature TEXT
);
CREATE INDEX IF NOT EXISTS idx_host_grants_subject ON host_grants(subject_identity_id);
CREATE TABLE IF NOT EXISTS host_candidates (
  candidate_id TEXT PRIMARY KEY, subject_identity_id TEXT NOT NULL,
  subject_auth_public_key TEXT NOT NULL, host_public_key TEXT NOT NULL,
  enrollment_public_key TEXT NOT NULL, host_id TEXT NOT NULL,
  device_proof TEXT NOT NULL, host_proof TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_host_candidates_subject ON host_candidates(subject_identity_id, created_at);
CREATE TABLE IF NOT EXISTS security_proofs (
  proof_id TEXT PRIMARY KEY, purpose TEXT NOT NULL, consumed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS replica_enrollments (
  enrollment_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, generation INTEGER NOT NULL,
  snapshot_hash TEXT NOT NULL, epoch INTEGER NOT NULL, seq INTEGER NOT NULL,
  issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER
);
CREATE TABLE IF NOT EXISTS host_record_chains (
  host_id TEXT NOT NULL, record_seq INTEGER NOT NULL, record_hash TEXT NOT NULL UNIQUE,
  registration TEXT NOT NULL, committed_at INTEGER NOT NULL
  ,PRIMARY KEY(host_id, record_seq)
);
`;

export class Store {
  private db: EncryptedDatabase;

  constructor(
    readonly file: string,
    private readonly rawKey: Buffer,
  ) {
    this.db = new EncryptedDatabase(file, rawKey);
    this.openAndMigrate();
  }

  private openAndMigrate(): void {
    this.db.open();
    this.db.migrate(SCHEMA);
    this.ensureColumn("host_grants", "subject_auth_public_key", "TEXT NOT NULL DEFAULT ''");
    this.ensureColumn("host_grants", "accepted_at", "INTEGER");
    this.ensureColumn("host_grants", "enrollment_public_key", "TEXT NOT NULL DEFAULT ''");
    this.ensureColumn("invites", "access_hash", "TEXT");
    this.ensureColumn("spool", "sender_id", "TEXT NOT NULL DEFAULT ''");
    this.ensureColumn("spool", "size_bytes", "INTEGER NOT NULL DEFAULT 0");
    this.ensureColumn("attachments", "owner_id", "TEXT NOT NULL DEFAULT ''");
    this.ensureColumn("attachments", "channel_id", "TEXT NOT NULL DEFAULT ''");
    this.ensureColumn("attachments", "audience", "TEXT NOT NULL DEFAULT '[]'");
    this.ensureColumn("attachments", "linked_message_id", "TEXT");
    this.ensureColumn("attachments", "total_chunks", "INTEGER NOT NULL DEFAULT 1");
    this.ensureColumn("attachments", "ciphertext_hash", "TEXT NOT NULL DEFAULT ''");
    this.ensureColumn("attachments", "completed_at", "INTEGER");
    this.ensureSpoolAccounting();
    this.migrateAuthorityMetadata();
  }

  private ensureColumn(table: string, column: string, definition: string): void {
    const columns = this.raw.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
    if (!columns.some((entry) => entry.name === column)) this.raw.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }

  private ensureSpoolAccounting(): void {
    this.raw.exec(`
      CREATE INDEX IF NOT EXISTS idx_attachments_pending_owner
        ON attachments(owner_id, created_at) WHERE linked_message_id IS NULL;
      CREATE INDEX IF NOT EXISTS idx_spool_sender ON spool(sender_id);

      CREATE TRIGGER IF NOT EXISTS attachments_usage_insert
      AFTER INSERT ON attachments BEGIN
        INSERT INTO spool_usage(scope_id, size_bytes) VALUES ('global', NEW.size_bytes)
          ON CONFLICT(scope_id) DO UPDATE SET size_bytes = size_bytes + NEW.size_bytes;
        INSERT INTO spool_usage(scope_id, size_bytes) VALUES ('member:' || NEW.owner_id, NEW.size_bytes)
          ON CONFLICT(scope_id) DO UPDATE SET size_bytes = size_bytes + NEW.size_bytes;
      END;
      CREATE TRIGGER IF NOT EXISTS attachments_usage_delete
      AFTER DELETE ON attachments BEGIN
        INSERT INTO spool_usage(scope_id, size_bytes) VALUES ('global', 0)
          ON CONFLICT(scope_id) DO UPDATE SET size_bytes = MAX(0, size_bytes - OLD.size_bytes);
        INSERT INTO spool_usage(scope_id, size_bytes) VALUES ('member:' || OLD.owner_id, 0)
          ON CONFLICT(scope_id) DO UPDATE SET size_bytes = MAX(0, size_bytes - OLD.size_bytes);
      END;
      CREATE TRIGGER IF NOT EXISTS attachments_usage_update
      AFTER UPDATE OF size_bytes, owner_id ON attachments BEGIN
        INSERT INTO spool_usage(scope_id, size_bytes) VALUES ('global', 0)
          ON CONFLICT(scope_id) DO UPDATE SET size_bytes = MAX(0, size_bytes - OLD.size_bytes) + NEW.size_bytes;
        INSERT INTO spool_usage(scope_id, size_bytes) VALUES ('member:' || OLD.owner_id, 0)
          ON CONFLICT(scope_id) DO UPDATE SET size_bytes = MAX(0, size_bytes - OLD.size_bytes);
        INSERT INTO spool_usage(scope_id, size_bytes) VALUES ('member:' || NEW.owner_id, NEW.size_bytes)
          ON CONFLICT(scope_id) DO UPDATE SET size_bytes = size_bytes + NEW.size_bytes;
      END;

      CREATE TRIGGER IF NOT EXISTS spool_usage_insert
      AFTER INSERT ON spool BEGIN
        INSERT INTO spool_usage(scope_id, size_bytes) VALUES ('global', NEW.size_bytes)
          ON CONFLICT(scope_id) DO UPDATE SET size_bytes = size_bytes + NEW.size_bytes;
        INSERT INTO spool_usage(scope_id, size_bytes) VALUES ('member:' || NEW.sender_id, NEW.size_bytes)
          ON CONFLICT(scope_id) DO UPDATE SET size_bytes = size_bytes + NEW.size_bytes;
      END;
      CREATE TRIGGER IF NOT EXISTS spool_usage_delete
      AFTER DELETE ON spool BEGIN
        INSERT INTO spool_usage(scope_id, size_bytes) VALUES ('global', 0)
          ON CONFLICT(scope_id) DO UPDATE SET size_bytes = MAX(0, size_bytes - OLD.size_bytes);
        INSERT INTO spool_usage(scope_id, size_bytes) VALUES ('member:' || OLD.sender_id, 0)
          ON CONFLICT(scope_id) DO UPDATE SET size_bytes = MAX(0, size_bytes - OLD.size_bytes);
      END;
      CREATE TRIGGER IF NOT EXISTS spool_usage_update
      AFTER UPDATE OF size_bytes, sender_id ON spool BEGIN
        INSERT INTO spool_usage(scope_id, size_bytes) VALUES ('global', 0)
          ON CONFLICT(scope_id) DO UPDATE SET size_bytes = MAX(0, size_bytes - OLD.size_bytes) + NEW.size_bytes;
        INSERT INTO spool_usage(scope_id, size_bytes) VALUES ('member:' || OLD.sender_id, 0)
          ON CONFLICT(scope_id) DO UPDATE SET size_bytes = MAX(0, size_bytes - OLD.size_bytes);
        INSERT INTO spool_usage(scope_id, size_bytes) VALUES ('member:' || NEW.sender_id, NEW.size_bytes)
          ON CONFLICT(scope_id) DO UPDATE SET size_bytes = size_bytes + NEW.size_bytes;
      END;
    `);

    this.raw.transaction(() => {
      this.raw.prepare("DELETE FROM spool_usage").run();
      this.raw.prepare(`
        INSERT INTO spool_usage(scope_id, size_bytes)
        SELECT 'global',
          (SELECT COALESCE(SUM(size_bytes), 0) FROM attachments)
          + (SELECT COALESCE(SUM(size_bytes), 0) FROM spool)
      `).run();
      this.raw.prepare(`
        INSERT INTO spool_usage(scope_id, size_bytes)
        SELECT 'member:' || owner_id, SUM(size_bytes)
        FROM (
          SELECT owner_id, size_bytes FROM attachments
          UNION ALL
          SELECT sender_id AS owner_id, size_bytes FROM spool
        )
        WHERE owner_id <> ''
        GROUP BY owner_id
      `).run();
    })();
  }

  /**
   * `server_key` historically served both as the authority private key and invite HMAC key.
   * Preserve only the non-authority invite hashing behavior and the derived public key, then
   * remove the private authority material before this database can be snapshotted.
   */
  private migrateAuthorityMetadata(): void {
    const legacy = this.raw.prepare("SELECT value FROM server_meta WHERE key = 'server_key'").get() as
      | { value: string }
      | undefined;
    const legacySeed = legacy && /^[0-9a-f]{64}$/i.test(legacy.value)
      ? Buffer.from(legacy.value, "hex")
      : null;

    this.raw.transaction(() => {
      const authority = this.raw.prepare("SELECT 1 FROM server_meta WHERE key = 'authority_public_key'").get();
      if (!authority && legacySeed) {
        this.raw.prepare("INSERT INTO server_meta (key, value) VALUES ('authority_public_key', ?)")
          .run(ed25519PublicKey(legacySeed).toString("base64url"));
      }

      const inviteHashKey = this.raw.prepare("SELECT 1 FROM server_meta WHERE key = 'invite_hash_key'").get();
      if (!inviteHashKey) {
        this.raw.prepare("INSERT INTO server_meta (key, value) VALUES ('invite_hash_key', ?)")
          .run((legacySeed ?? randomBytes(32)).toString("hex"));
      }

      this.raw.prepare("DELETE FROM server_meta WHERE key = 'server_key'").run();
    })();
  }

  get raw(): Db {
    return this.db.raw;
  }

  close() {
    this.db.close();
  }

  /**
   * Produces a point-in-time copy of the SQLCipher file. The checkpoint is completed first and
   * an exclusive transaction prevents this connection (the sole Store owner) from changing the
   * file while it is read. The returned bytes remain SQLCipher ciphertext.
   */
  consistentSnapshot(): StoreSnapshot {
    const checkpoint = this.raw.pragma("wal_checkpoint(TRUNCATE)") as
      | { busy?: number }[]
      | undefined;
    if (checkpoint?.some((entry) => Number(entry.busy ?? 0) !== 0)) {
      throw new Error("could not complete SQLite checkpoint for replica snapshot");
    }

    this.raw.exec("BEGIN EXCLUSIVE");
    try {
      const metadata = Store.readMetadata(this.raw);
      const encryptedDb = readFileSync(this.file);
      Store.assertEncrypted(encryptedDb);
      this.raw.exec("COMMIT");
      return { ...metadata, encryptedDb };
    } catch (error) {
      try {
        this.raw.exec("ROLLBACK");
      } catch {
        // Preserve the original snapshot error.
      }
      throw error;
    }
  }

  /** DB key export is deliberately limited to the authorized enrollment use case. */
  enrollmentDbKey(): Buffer {
    return Buffer.from(this.rawKey);
  }

  /**
   * Replaces the live DB only through the Store boundary: validate staged ciphertext, close the
   * connection, fsync+rename atomically, reopen/migrate, then revalidate identity and fencing.
   */
  replaceEncryptedSnapshot(
    encryptedDb: Buffer,
    expected: SnapshotExpectation,
    preservedMeta: Readonly<Record<string, string>> = {},
    preservedHostRegistrations: readonly PreservedHostRegistration[] = [],
  ): StoreSnapshotMetadata {
    const staged = Store.stageAndValidate(
      this.file,
      encryptedDb,
      this.rawKey,
      expected,
      preservedMeta,
      preservedHostRegistrations,
    );
    this.db.close();
    const previous = existsSync(this.file) ? readFileSync(this.file) : null;
    try {
      Store.removeSidecars(this.file);
      renameSync(staged, this.file);
      Store.fsyncDirectory(this.file);
      this.db = new EncryptedDatabase(this.file, this.rawKey);
      this.openAndMigrate();
      return Store.validateMetadata(Store.readMetadata(this.raw), expected);
    } catch (error) {
      this.db.close();
      if (previous) Store.atomicWrite(this.file, previous);
      this.db = new EncryptedDatabase(this.file, this.rawKey);
      this.openAndMigrate();
      throw error;
    } finally {
      if (existsSync(staged)) unlinkSync(staged);
    }
  }

  static installEncryptedSnapshot(
    file: string,
    encryptedDb: Buffer,
    rawKey: Buffer,
    expected: SnapshotExpectation,
  ): StoreSnapshotMetadata {
    const staged = Store.stageAndValidate(file, encryptedDb, rawKey, expected);
    try {
      Store.removeSidecars(file);
      renameSync(staged, file);
      Store.fsyncDirectory(file);
      return Store.validateEncryptedFile(file, rawKey, expected);
    } finally {
      if (existsSync(staged)) unlinkSync(staged);
    }
  }

  static validateEncryptedFile(file: string, rawKey: Buffer, expected: SnapshotExpectation): StoreSnapshotMetadata {
    const candidate = new EncryptedDatabase(file, rawKey);
    try {
      candidate.open();
      return Store.validateMetadata(Store.readMetadata(candidate.raw), expected);
    } finally {
      candidate.close();
    }
  }

  private static stageAndValidate(
    file: string,
    encryptedDb: Buffer,
    rawKey: Buffer,
    expected: SnapshotExpectation,
    preservedMeta: Readonly<Record<string, string>> = {},
    preservedHostRegistrations: readonly PreservedHostRegistration[] = [],
  ): string {
    Store.assertEncrypted(encryptedDb);
    const staged = Store.writeStaged(file, encryptedDb);
    try {
      Store.validateEncryptedFile(staged, rawKey, expected);
      const entries = Object.entries(preservedMeta);
      if (entries.length > 0 || preservedHostRegistrations.length > 0) {
        const candidate = new EncryptedDatabase(staged, rawKey);
        try {
          candidate.open();
          candidate.raw.transaction(() => {
            const upsert = candidate.raw.prepare(
              "INSERT INTO server_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            );
            for (const [key, value] of entries) upsert.run(key, value);
            const existing = candidate.raw.prepare(
              "SELECT record_hash, registration, committed_at FROM host_record_chains WHERE host_id = ? AND record_seq = ?",
            );
            const insert = candidate.raw.prepare(
              "INSERT INTO host_record_chains (host_id, record_seq, record_hash, registration, committed_at) VALUES (?, ?, ?, ?, ?)",
            );
            for (const record of preservedHostRegistrations) {
              const collision = existing.get(record.hostId, record.recordSeq) as
                | { record_hash: string; registration: string; committed_at: number }
                | undefined;
              if (collision) {
                if (collision.record_hash !== record.recordHash || collision.registration !== record.registration) {
                  throw new Error("replica snapshot conflicts with the local host registration chain");
                }
                continue;
              }
              insert.run(record.hostId, record.recordSeq, record.recordHash, record.registration, record.committedAt);
            }
          })();
          candidate.raw.pragma("wal_checkpoint(TRUNCATE)");
        } finally {
          candidate.close();
        }
        Store.validateEncryptedFile(staged, rawKey, expected);
      }
      return staged;
    } catch (error) {
      if (existsSync(staged)) unlinkSync(staged);
      throw error;
    }
  }

  private static readMetadata(db: Db): StoreSnapshotMetadata {
    const rows = db.prepare(
      "SELECT key, value FROM server_meta WHERE key IN ('server_id', 'authority_public_key', 'epoch')",
    ).all() as { key: string; value: string }[];
    const values = new Map(rows.map((row) => [row.key, row.value]));
    const seq = db.prepare("SELECT COALESCE(MAX(seq), 0) AS seq FROM op_log").get() as { seq: number };
    const serverId = values.get("server_id") ?? "";
    const authorityPublicKey = values.get("authority_public_key") ?? "";
    const epoch = Number(values.get("epoch") ?? 0);
    if (!serverId || !authorityPublicKey || !Number.isSafeInteger(epoch) || epoch < 0) {
      throw new Error("replica snapshot is missing valid server identity metadata");
    }
    return { serverId, authorityPublicKey, epoch, seq: Number(seq.seq ?? 0) };
  }

  private static validateMetadata(metadata: StoreSnapshotMetadata, expected: SnapshotExpectation): StoreSnapshotMetadata {
    if (metadata.serverId !== expected.serverId) throw new Error("replica snapshot serverId mismatch");
    if (metadata.authorityPublicKey !== expected.authorityPublicKey) {
      throw new Error("replica snapshot authority mismatch");
    }
    if (metadata.epoch < (expected.minimumEpoch ?? 0)) throw new Error("replica snapshot epoch downgrade");
    if (metadata.seq < (expected.minimumSeq ?? 0)) throw new Error("replica snapshot sequence downgrade");
    if (expected.exactEpoch !== undefined && metadata.epoch !== expected.exactEpoch) {
      throw new Error("replica snapshot epoch envelope mismatch");
    }
    if (expected.exactSeq !== undefined && metadata.seq !== expected.exactSeq) {
      throw new Error("replica snapshot sequence envelope mismatch");
    }
    return metadata;
  }

  private static assertEncrypted(data: Buffer): void {
    if (data.length < 512) throw new Error("replica snapshot is too small");
    if (data.subarray(0, 16).toString("utf8") === "SQLite format 3\u0000") {
      throw new Error("plaintext SQLite snapshots are forbidden");
    }
  }

  private static writeStaged(file: string, data: Buffer): string {
    mkdirSync(dirname(file), { recursive: true });
    const staged = `${file}.replica-${process.pid}-${randomBytes(8).toString("hex")}.tmp`;
    const fd = openSync(staged, "wx", 0o600);
    try {
      writeFileSync(fd, data);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    return staged;
  }

  private static atomicWrite(file: string, data: Buffer): void {
    const staged = Store.writeStaged(file, data);
    try {
      Store.removeSidecars(file);
      renameSync(staged, file);
      Store.fsyncDirectory(file);
    } finally {
      if (existsSync(staged)) unlinkSync(staged);
    }
  }

  private static removeSidecars(file: string): void {
    for (const sidecar of [`${file}-wal`, `${file}-shm`]) {
      if (existsSync(sidecar)) unlinkSync(sidecar);
    }
  }

  private static fsyncDirectory(file: string): void {
    let fd: number | null = null;
    try {
      fd = openSync(dirname(file), "r");
      fsyncSync(fd);
    } catch (error) {
      if (process.platform !== "win32") throw error;
    } finally {
      if (fd !== null) closeSync(fd);
    }
  }

  /** Op-log append-only (ADR-011): base da replicação. */
  appendOp(op: unknown): void {
    this.raw
      .prepare("INSERT INTO op_log (op, created_at) VALUES (?, ?)")
      .run(JSON.stringify(op), Date.now());
  }
}
