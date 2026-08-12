import { createHmac, randomUUID } from "node:crypto";

export function mintPairingToken(bridgeId, adminKey, now = Date.now()) {
  const payload = {
    version: 1,
    bridgeId,
    tokenId: randomUUID(),
    issuedAt: now,
    expiresAt: now + 60_000,
  };
  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const prefix = `JCP1.${encoded}`;
  return `${prefix}.${createHmac("sha256", adminKey).update(prefix).digest("base64url")}`;
}
