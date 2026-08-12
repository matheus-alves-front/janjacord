#!/usr/bin/env node
import { createHmac, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const [outputPathRaw] = process.argv.slice(2);
if (!outputPathRaw) {
  console.error("Usage: ./scripts/mint-turn-diagnostic-credentials.mjs <new-output.json>");
  process.exit(2);
}

const rootDir = resolve(import.meta.dirname, "..");
const values = Object.fromEntries(readFileSync(resolve(rootDir, ".env"), "utf8")
  .split("\n")
  .filter((line) => line && !line.startsWith("#") && line.includes("="))
  .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
const secret = readFileSync(resolve(rootDir, "secrets/turn-shared-secret"), "utf8").trim();
const turnDomain = values.TURN_DOMAIN ?? "";
const turnTlsPort = Number(values.TURN_TLS_PORT ?? "443");
const coturnImage = values.COTURN_IMAGE ?? "";

if (!/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(turnDomain)) throw new Error("invalid TURN_DOMAIN");
if (!Number.isSafeInteger(turnTlsPort) || turnTlsPort < 1 || turnTlsPort > 65535) throw new Error("invalid TURN_TLS_PORT");
if (!coturnImage.includes("@sha256:")) throw new Error("COTURN_IMAGE must be pinned by digest");
if (secret.length < 32) throw new Error("TURN shared secret is invalid");

const expiresAtSeconds = Math.floor(Date.now() / 1000) + 300;
const username = `${expiresAtSeconds}:external-${randomBytes(12).toString("hex")}`;
const credential = createHmac("sha1", secret).update(username).digest("base64");
const outputPath = resolve(outputPathRaw);

writeFileSync(outputPath, `${JSON.stringify({
  version: 1,
  turnDomain,
  turnTlsPort,
  username,
  credential,
  expiresAt: expiresAtSeconds * 1000,
  coturnImage,
}, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });

console.log(`TURN diagnostic credential written to ${outputPath}`);
console.log(`Expires at ${new Date(expiresAtSeconds * 1000).toISOString()}; transfer securely and delete after use.`);
