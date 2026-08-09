declare module "better-sqlite3-multiple-ciphers" {
  import type BetterSqlite3 from "better-sqlite3";

  interface CipherDatabase extends BetterSqlite3.Database {
    /** SQLCipher raw key (32B Buffer) — chamar após cipher='sqlcipher' + legacy=4. */
    key(key: Buffer): void;
    /** PRAGMA genérico (aceita string com aspas). */
    pragma(sql: string): unknown;
  }

  const Database: {
    new (file: string, options?: Record<string, unknown>): CipherDatabase;
    prototype: CipherDatabase;
  };

  export default Database;
}
