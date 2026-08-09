import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3-multiple-ciphers";
import type BetterSqlite3 from "better-sqlite3";
import { wrapKey, unwrapKey } from "@janjacord/crypto";

type Db = BetterSqlite3.Database & {
  key(key: Buffer): void;
  pragma(sql: string): unknown;
};

/**
 * SQLite cifrado com SQLCipher (ADR-016): raw key 32B via `PRAGMA key = x'hex'` após
 * `cipher='sqlcipher'` + `legacy=4` (interop com expo-sqlite/mobile). NUNCA passphrase
 * (KDF interno do SQLCipher é PBKDF2 fraco).
 */
export class EncryptedDatabase {
  private db: Db | null = null;

  constructor(
    private readonly file: string,
    private readonly rawKey: Buffer,
  ) {}

  open(): Db {
    if (this.db) return this.db;
    mkdirSync(dirname(this.file), { recursive: true });
    const db = new Database(this.file) as Db;
    db.pragma(`cipher='sqlcipher'`);
    db.pragma("legacy = 4");
    db.key(this.rawKey);
    db.pragma("secure_delete = ON");
    // valida a chave (SQLCipher: primeira query falha com chave errada)
    db.prepare("SELECT count(*) FROM sqlite_master").get();
    this.db = db;
    return db;
  }

  get raw(): Db {
    return this.open();
  }

  migrate(sql: string): void {
    this.open().exec(sql);
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  /** Purge definitivo (ADR-004): secure_delete + vacuum após remoções. */
  vacuum(): void {
    this.open().pragma("vacuum");
  }
}

export interface VaultRecord {
  version: 1;
  identityId: string;
  nickname: string;
  seedEncrypted: string; // base64 AES-GCM (KEK)
  dbKeyEncrypted: string; // base64 AES-GCM (KEK)
  salt: string; // base64 (KDF)
  kdf: { memoryKiB: number; passes: number; parallelism: number };
  createdAt: number;
}

/** Arquivo de vault (ADR-001): seed + dbKey cifrados pela KEK; nunca plaintext. */
export class VaultFile {
  constructor(private readonly path: string) {}

  exists(): boolean {
    try {
      readFileSync(this.path);
      return true;
    } catch {
      return false;
    }
  }

  write(record: VaultRecord): void {
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify(record, null, 2), { mode: 0o600 });
  }

  read(): VaultRecord {
    const raw = readFileSync(this.path, "utf8");
    const rec = JSON.parse(raw) as VaultRecord;
    if (rec.version !== 1) throw new Error(`unsupported vault version: ${rec.version}`);
    return rec;
  }

  /** Conteúdo cifrado (seed/dbKey) — usados pelo IdentityManager. */
  unwrap(kek: Buffer): { seed: Buffer; dbKey: Buffer } {
    const rec = this.read();
    return {
      seed: unwrapKey(kek, Buffer.from(rec.seedEncrypted, "base64")),
      dbKey: unwrapKey(kek, Buffer.from(rec.dbKeyEncrypted, "base64")),
    };
  }

  static build(
    identityId: string,
    nickname: string,
    kek: Buffer,
    seed: Buffer,
    dbKey: Buffer,
    salt: Buffer,
    kdf: VaultRecord["kdf"],
  ): VaultRecord {
    return {
      version: 1,
      identityId,
      nickname,
      seedEncrypted: wrapKey(kek, seed).toString("base64"),
      dbKeyEncrypted: wrapKey(kek, dbKey).toString("base64"),
      salt: salt.toString("base64"),
      kdf,
      createdAt: Date.now(),
    };
  }
}
