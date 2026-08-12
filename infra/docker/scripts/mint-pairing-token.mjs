import { createHash, createHmac, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const [descriptorPath, adminKeyPath, outputPath, ttlHoursRaw = "24"] = process.argv.slice(2);
if (!descriptorPath || !adminKeyPath || !outputPath) {
  throw new Error("usage: mint-pairing-token.mjs <descriptor.json> <pairing-admin-key> <output.json> [ttl-hours]");
}
const ttlHours = Number(ttlHoursRaw);
if (!Number.isInteger(ttlHours) || ttlHours < 1 || ttlHours > 30 * 24) throw new Error("pairing TTL must be 1..720 hours");
const descriptor = JSON.parse(readFileSync(descriptorPath, "utf8"));
const bridgeId = descriptor?.payload?.bridgeId;
if (typeof bridgeId !== "string" || !/^ed25519:[0-9a-f]{64}$/.test(bridgeId)) throw new Error("invalid bridge descriptor");
const adminKey = readFileSync(adminKeyPath, "utf8").trim();
if (adminKey.length < 32) throw new Error("pairing admin key is too short");
const issuedAt = Date.now();
const payload = {
  version: 1,
  bridgeId,
  tokenId: randomUUID(),
  issuedAt,
  expiresAt: issuedAt + ttlHours * 3600_000,
};
const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
const prefix = `JCP1.${encoded}`;
const pairingToken = `${prefix}.${createHmac("sha256", adminKey).update(prefix).digest("base64url")}`;
const pairing = {
  schema: "janjacord.bridge-pairing.v1",
  descriptor,
  pairingToken,
  pairingKeyId: `sha256:${createHash("sha256").update(pairingToken).digest("hex")}`,
};
writeFileSync(outputPath, `${JSON.stringify(pairing, null, 2)}\n`, { mode: 0o600 });
process.stdout.write(`pairing token minted; expires ${new Date(payload.expiresAt).toISOString()}\n`);
