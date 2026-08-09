import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EncryptedDatabase } from "../src/index.js";

const KEY = Buffer.from("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "hex");

function tmpFile(): { dir: string; file: string } {
  const dir = mkdtempSync(join(tmpdir(), "jc-db-"));
  return { dir, file: join(dir, "data.db") };
}

describe("EncryptedDatabase", () => {
  it("abre com raw key, persiste e reabre", () => {
    const { dir, file } = tmpFile();
    try {
      {
        const db = new EncryptedDatabase(file, KEY);
        db.migrate("CREATE TABLE t (v TEXT)");
        db.raw.prepare("INSERT INTO t VALUES (?)").run("secreto");
        db.close();
      }
      {
        const db = new EncryptedDatabase(file, KEY);
        expect(db.raw.prepare("SELECT v FROM t").get()).toEqual({ v: "secreto" });
        db.close();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejeita chave errada (arquivo ilegível)", () => {
    const { dir, file } = tmpFile();
    try {
      new EncryptedDatabase(file, KEY).migrate("CREATE TABLE t (v TEXT)");
      const wrong = new EncryptedDatabase(file, Buffer.from("f".repeat(64), "hex"));
      expect(() => wrong.open()).toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
