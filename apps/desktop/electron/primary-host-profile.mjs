import { EncryptedDatabase } from "@janjacord/persistence";
import {
  chmodSync,
  closeSync,
  copyFileSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

function fsyncFile(file) {
  const descriptor = openSync(file, "r");
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function fsyncParentDirectory(file) {
  try {
    const descriptor = openSync(path.dirname(file), "r");
    try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
  } catch (error) {
    if (process.platform !== "win32") throw error;
  }
}

function removeSidecars(file) {
  for (const sidecar of [`${file}-wal`, `${file}-shm`]) {
    if (existsSync(sidecar)) unlinkSync(sidecar);
  }
}

function validateDatabase(database) {
  const rows = database.raw.pragma("wal_checkpoint(TRUNCATE)");
  const checkpoint = Array.isArray(rows) ? rows[0] : rows;
  if (checkpoint && Number(checkpoint.busy ?? 0) !== 0) throw new Error("WAL checkpoint remained busy");
  const integrity = database.raw.pragma("integrity_check", { simple: true });
  if (integrity !== "ok") throw new Error(`database integrity check failed: ${String(integrity)}`);
  database.raw.prepare("SELECT count(*) AS count FROM sqlite_master").get();
}

function validateFile(file, key) {
  const database = new EncryptedDatabase(file, key);
  try {
    database.open();
    validateDatabase(database);
  } finally {
    database.close();
  }
}

function opensWith(file, key) {
  try {
    validateFile(file, key);
    return true;
  } catch {
    return false;
  }
}

export function durableAtomicWrite(file, contents, mode = 0o600) {
  mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.tmp`;
  writeFileSync(temporary, contents, { mode });
  chmodSync(temporary, mode);
  fsyncFile(temporary);
  if (process.platform === "win32" && existsSync(file)) unlinkSync(file);
  renameSync(temporary, file);
  chmodSync(file, mode);
  fsyncFile(file);
  fsyncParentDirectory(file);
}

function restoreBackup(file, backup) {
  const restore = `${file}.${process.pid}.restore`;
  copyFileSync(backup, restore);
  chmodSync(restore, 0o600);
  fsyncFile(restore);
  removeSidecars(file);
  if (process.platform === "win32" && existsSync(file)) unlinkSync(file);
  renameSync(restore, file);
  fsyncFile(file);
  fsyncParentDirectory(file);
}

class SimulatedCrash extends Error {}

function migrateDatabaseKey(file, oldKey, newKey, failpoint) {
  const backup = `${file}.db-key-migration-backup`;
  let database = null;
  try {
    if (!existsSync(backup)) {
      database = new EncryptedDatabase(file, oldKey);
      database.open();
      validateDatabase(database);
      database.close();
      database = null;
      copyFileSync(file, backup);
      chmodSync(backup, 0o600);
      fsyncFile(backup);
      fsyncParentDirectory(backup);
    }
    validateFile(backup, oldKey);
    if (failpoint === "after_backup") throw new SimulatedCrash("simulated crash after backup");

    database = new EncryptedDatabase(file, oldKey);
    database.open();
    database.rekey(newKey);
    validateDatabase(database);
    database.close();
    database = null;
    fsyncFile(file);
    fsyncParentDirectory(file);
    validateFile(file, newKey);
    if (failpoint === "after_rekey") throw new SimulatedCrash("simulated crash after rekey");

    unlinkSync(backup);
    fsyncParentDirectory(backup);
  } catch (error) {
    try { database?.close(); } catch { /* recovery below owns the durable state */ }
    if (error instanceof SimulatedCrash) throw error;
    if (existsSync(backup) && opensWith(backup, oldKey)) {
      restoreBackup(file, backup);
      validateFile(file, oldKey);
    }
    throw error;
  }
}

export function ensureEncryptedDatabaseKey({ file, oldKey, newKey, failpoint = null }) {
  if (!existsSync(file)) return;
  const backup = `${file}.db-key-migration-backup`;
  if (opensWith(file, newKey)) {
    if (existsSync(backup)) {
      unlinkSync(backup);
      fsyncParentDirectory(backup);
    }
    return;
  }
  if (opensWith(file, oldKey)) {
    migrateDatabaseKey(file, oldKey, newKey, failpoint);
    return;
  }
  if (existsSync(backup) && opensWith(backup, oldKey)) {
    restoreBackup(file, backup);
    migrateDatabaseKey(file, oldKey, newKey, failpoint);
    return;
  }
  const header = existsSync(file) ? readFileSync(file).subarray(0, 16).toString("hex") : "missing";
  throw new Error(`Community Host DB cannot be opened or recovered (header ${header})`);
}
