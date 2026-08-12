#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

function fail(message) {
  console.error(`linux packaging preflight failed: ${message}`);
  process.exitCode = 1;
}

if (process.platform !== "linux") {
  fail(`expected Linux, got ${process.platform}`);
} else if (!existsSync("/etc/fedora-release")) {
  console.log("linux packaging preflight: non-Fedora host; no Fedora compatibility check needed");
} else {
  const compatibilityDirectory = process.env.JANJACORD_LIBCRYPT_COMPAT_DIR
    ? resolve(process.env.JANJACORD_LIBCRYPT_COMPAT_DIR)
    : null;
  if (compatibilityDirectory && !existsSync(resolve(compatibilityDirectory, "libcrypt.so.1"))) {
    fail(`JANJACORD_LIBCRYPT_COMPAT_DIR does not contain libcrypt.so.1: ${compatibilityDirectory}`);
    process.exit(1);
  }
  const candidates = [
    ...(compatibilityDirectory ? [resolve(compatibilityDirectory, "libcrypt.so.1")] : []),
    "/usr/lib64/libcrypt.so.1",
    "/lib64/libcrypt.so.1",
    "/usr/lib/libcrypt.so.1",
    "/lib/libcrypt.so.1",
  ];
  const found = candidates.some(existsSync);

  if (!found) {
    let release = "Fedora";
    try {
      release = readFileSync("/etc/fedora-release", "utf8").trim();
    } catch {}
    fail(`${release} is missing libcrypt.so.1, required by electron-builder's bundled fpm Ruby. Install the build-only dependency with: sudo dnf install libxcrypt-compat, or set JANJACORD_LIBCRYPT_COMPAT_DIR to an extracted trusted package directory`);
  } else {
    let owner = "available";
    try {
      owner = execFileSync("rpm", ["-qf", candidates.find(existsSync)], { encoding: "utf8" }).trim();
    } catch {}
    console.log(`linux packaging preflight: libcrypt.so.1 available (${owner})`);
  }
}
