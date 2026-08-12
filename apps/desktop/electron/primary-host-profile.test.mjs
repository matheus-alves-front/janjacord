import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { EncryptedDatabase } from "@janjacord/persistence";
import { durableAtomicWrite, ensureEncryptedDatabaseKey } from "./primary-host-profile.mjs";

const directories = [];
const oldKey = Buffer.alloc(32, 1);
const newKey = Buffer.alloc(32, 2);

function fixture() {
  const directory = mkdtempSync(path.join(tmpdir(), "jc-primary-rekey-"));
  directories.push(directory);
  const file = path.join(directory, "server.db");
  const database = new EncryptedDatabase(file, oldKey);
  database.open();
  database.raw.exec("CREATE TABLE durable_value (value TEXT NOT NULL)");
  database.raw.prepare("INSERT INTO durable_value VALUES (?)").run("preserved");
  database.close();
  return file;
}

function readValue(file) {
  const database = new EncryptedDatabase(file, newKey);
  try {
    database.open();
    return database.raw.prepare("SELECT value FROM durable_value").get().value;
  } finally {
    database.close();
  }
}

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("primary Community Host key migration", () => {
  it("recovers a crash after the durable backup and completes rekey", () => {
    const file = fixture();
    expect(() => ensureEncryptedDatabaseKey({ file, oldKey, newKey, failpoint: "after_backup" })).toThrow("simulated crash");
    ensureEncryptedDatabaseKey({ file, oldKey, newKey });
    expect(readValue(file)).toBe("preserved");
  });

  it("recovers a crash after rekey from the already durable new key", () => {
    const file = fixture();
    expect(() => ensureEncryptedDatabaseKey({ file, oldKey, newKey, failpoint: "after_rekey" })).toThrow("simulated crash");
    ensureEncryptedDatabaseKey({ file, oldKey, newKey });
    expect(readValue(file)).toBe("preserved");
  });

  it("restores a damaged live file from the named backup", () => {
    const file = fixture();
    expect(() => ensureEncryptedDatabaseKey({ file, oldKey, newKey, failpoint: "after_backup" })).toThrow();
    writeFileSync(file, Buffer.alloc(1024, 0x7f));
    ensureEncryptedDatabaseKey({ file, oldKey, newKey });
    expect(readValue(file)).toBe("preserved");
  });

  it("durably replaces a profile file", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "jc-primary-profile-"));
    directories.push(directory);
    const file = path.join(directory, "profile.json");
    durableAtomicWrite(file, "first\n");
    durableAtomicWrite(file, "second\n");
    expect(readFileSync(file, "utf8")).toBe("second\n");
  });
});
