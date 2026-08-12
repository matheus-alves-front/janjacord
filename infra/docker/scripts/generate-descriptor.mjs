import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const [domain, turnDomain, turnTlsPortRaw, descriptorPath, privateKeyPath, existingPrivateKeyPath] = process.argv.slice(2);

if (!domain || !turnDomain || !turnTlsPortRaw || !descriptorPath || !privateKeyPath) {
  throw new Error("descriptor: bridge domain, TURN domain, TURN TLS port and output paths are required");
}
if (!/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) {
  throw new Error("descriptor: invalid bridge domain");
}
if (!/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(turnDomain) || turnDomain === domain) {
  throw new Error("descriptor: TURN domain must be a distinct valid hostname");
}
const turnTlsPort = Number(turnTlsPortRaw);
if (!Number.isSafeInteger(turnTlsPort) || turnTlsPort < 1 || turnTlsPort > 65535) throw new Error("descriptor: invalid TURN TLS port");

function canonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  throw new Error(`descriptor: cannot canonicalize ${typeof value}`);
}

const canonicalJson = (value) => JSON.stringify(canonicalize(value));
const keyPair = existingPrivateKeyPath
  ? (() => {
      const privateKey = createPrivateKey(readFileSync(existingPrivateKeyPath));
      return { privateKey, publicKey: createPublicKey(privateKey) };
    })()
  : generateKeyPairSync("ed25519");
const { privateKey, publicKey } = keyPair;
const publicJwk = publicKey.export({ format: "jwk" });
if (typeof publicJwk.x !== "string") throw new Error("descriptor: missing Ed25519 public key");

const publicKeyRaw = Buffer.from(publicJwk.x, "base64url");
const fingerprint = createHash("sha256").update(publicKeyRaw).digest("hex");
const issuedAt = Date.now();
const payload = {
  version: 1,
  bridgeId: `ed25519:${fingerprint}`,
  endpoints: [
    `wss://${domain}/rendezvous`,
    `wss://${domain}/signaling`,
    `wss://${domain}/turn-credentials`,
    `stun:${turnDomain}:3478`,
    `turn:${turnDomain}:3478?transport=udp`,
    `turn:${turnDomain}:3478?transport=tcp`,
    `turns:${turnDomain}:${turnTlsPort}?transport=tcp`,
  ],
  issuedAt,
  expiresAt: issuedAt + 365 * 24 * 60 * 60 * 1000,
};
const message = Buffer.concat([
  Buffer.from("janjacord.bridge-descriptor.v1\0", "utf8"),
  Buffer.from(canonicalJson(payload), "utf8"),
]);
const descriptor = {
  payload,
  publicKey: publicJwk.x,
  signature: sign(null, message, privateKey).toString("base64url"),
};
writeFileSync(descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`, { mode: 0o644 });
writeFileSync(privateKeyPath, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
