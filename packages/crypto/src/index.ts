import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";
import { argon2id } from "@noble/hashes/argon2.js";

/**
 * KDF — Argon2id (RFC 9106) via node:crypto (Node >= 24.7; Electron 43 = Node 24.18).
 * Parâmetros: desktop m=64MiB t=3 p=4 (RFC 9106 segunda recomendada); mobile m=19MiB t=2 p=1
 * (OWASP mínimo). Nunca usar senha como identidade (ADR-001).
 */
export interface Argon2Params {
  memoryKiB: number;
  passes: number;
  parallelism: number;
}

export const ARGON2_DESKTOP: Argon2Params = { memoryKiB: 65536, passes: 3, parallelism: 4 };
export const ARGON2_MOBILE: Argon2Params = { memoryKiB: 19456, passes: 2, parallelism: 1 };

export async function deriveKEK(
  password: string,
  salt: Buffer,
  params: Argon2Params = ARGON2_DESKTOP,
): Promise<Buffer> {
  // noble-hashes argon2id (JS puro, auditado Cure53) — funciona em Node, Electron
  // (BoringSSL não expõe crypto.argon2) e mobile; parâmetros por plataforma.
  const out = argon2id(new TextEncoder().encode(password), new Uint8Array(salt), {
    t: params.passes,
    m: params.memoryKiB,
    p: params.parallelism,
  });
  return Buffer.from(out.slice(0, 32));
}

/** AES-256-GCM wrap: nonce(12) | tag(16) | ciphertext. */
export function wrapKey(key: Buffer, data: Buffer): Buffer {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, tag, ct]);
}

/** AES-256-GCM unwrap (falha em tag inválida — senha errada detectada aqui). */
export function unwrapKey(key: Buffer, blob: Buffer): Buffer {
  if (blob.length < 28) throw new Error("invalid ciphertext blob");
  const nonce = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ct = blob.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

export function randomBytes32(): Buffer {
  return randomBytes(32);
}

const ED25519_PKCS8_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PUBLIC_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function ed25519PrivateKey(seed: Buffer) {
  if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes");
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_SEED_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function ed25519PublicKeyObject(publicKey: Buffer) {
  if (publicKey.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PUBLIC_PREFIX, publicKey]),
    format: "der",
    type: "spki",
  });
}

/** Deterministic Ed25519 public key derived from a persisted 32-byte seed. */
export function ed25519PublicKey(seed: Buffer): Buffer {
  const spki = createPublicKey(ed25519PrivateKey(seed)).export({ format: "der", type: "spki" });
  return Buffer.from(spki).subarray(-32);
}

export function ed25519Fingerprint(publicKey: Buffer): string {
  if (publicKey.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  return sha256Hex(publicKey);
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonical JSON rejects non-finite numbers");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value === "object") {
    const out = Object.create(null) as Record<string, unknown>;
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const item = (value as Record<string, unknown>)[key];
      if (item === undefined) throw new Error("canonical JSON rejects undefined values");
      out[key] = canonicalize(item);
    }
    return out;
  }
  throw new Error(`canonical JSON rejects ${typeof value}`);
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export interface AuthenticatedStoreEnvelope<T> {
  version: 1;
  counter: number;
  payload: T;
  mac: string;
}

export interface AuthenticatedCounterAnchor {
  version: 1;
  counter: number;
  storeMac: string;
  mac: string;
}

function hmacHex(key: Buffer, domain: string, value: unknown): string {
  if (key.length < 32) throw new Error("authenticated store key must be at least 32 bytes");
  return createHmac("sha256", key).update(`${domain}\0${canonicalJson(value)}`, "utf8").digest("hex");
}

function equalHex(left: unknown, right: string): boolean {
  if (typeof left !== "string" || !/^[0-9a-f]{64}$/.test(left)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

export function createAuthenticatedStoreEnvelope<T>(key: Buffer, counter: number, payload: T): AuthenticatedStoreEnvelope<T> {
  if (!Number.isSafeInteger(counter) || counter < 1) throw new Error("authenticated store counter must be positive");
  const body = { version: 1 as const, counter, payload };
  return { ...body, mac: hmacHex(key, "janjacord.local-store.v1", body) };
}

export function verifyAuthenticatedStoreEnvelope<T>(key: Buffer, value: unknown): AuthenticatedStoreEnvelope<T> | null {
  if (!value || typeof value !== "object") return null;
  const candidate = value as Partial<AuthenticatedStoreEnvelope<T>>;
  if (candidate.version !== 1 || !Number.isSafeInteger(candidate.counter) || Number(candidate.counter) < 1
    || !("payload" in candidate)) return null;
  const body = { version: 1 as const, counter: Number(candidate.counter), payload: candidate.payload as T };
  const expected = hmacHex(key, "janjacord.local-store.v1", body);
  return equalHex(candidate.mac, expected) ? { ...body, mac: candidate.mac as string } : null;
}

export function createAuthenticatedCounterAnchor(key: Buffer, counter: number, storeMac: string): AuthenticatedCounterAnchor {
  if (!Number.isSafeInteger(counter) || counter < 1 || !/^[0-9a-f]{64}$/.test(storeMac)) {
    throw new Error("invalid authenticated counter anchor");
  }
  const body = { version: 1 as const, counter, storeMac };
  return { ...body, mac: hmacHex(key, "janjacord.local-store-anchor.v1", body) };
}

export function verifyAuthenticatedCounterAnchor(key: Buffer, value: unknown, counter: number, storeMac: string): boolean {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<AuthenticatedCounterAnchor>;
  if (candidate.version !== 1 || candidate.counter !== counter || candidate.storeMac !== storeMac) return false;
  const body = { version: 1 as const, counter, storeMac };
  return equalHex(candidate.mac, hmacHex(key, "janjacord.local-store-anchor.v1", body));
}

function signatureMessage(domain: string, payload: unknown): Buffer {
  if (!/^[a-z0-9._-]{1,64}$/.test(domain)) throw new Error("invalid signature domain");
  return Buffer.from(`${domain}\0${canonicalJson(payload)}`, "utf8");
}

export function signCanonicalPayload(seed: Buffer, domain: string, payload: unknown): Buffer {
  return sign(null, signatureMessage(domain, payload), ed25519PrivateKey(seed));
}

export function verifyCanonicalPayload(
  publicKey: Buffer,
  domain: string,
  payload: unknown,
  signature: Buffer,
): boolean {
  if (signature.length !== 64) return false;
  try {
    return verify(null, signatureMessage(domain, payload), ed25519PublicKeyObject(publicKey), signature);
  } catch {
    return false;
  }
}

/** Asset key 32B por arquivo (ADR-012); a key viaja dentro do ciphertext MLS. */
export function newAssetKey(): Buffer {
  return randomBytes32();
}

/** Cifra asset (AES-256-GCM): nonce(12) | tag(16) | ciphertext. */
export function encryptAsset(assetKey: Buffer, data: Buffer): Buffer {
  return wrapKey(assetKey, data);
}

export function decryptAsset(assetKey: Buffer, blob: Buffer): Buffer {
  return unwrapKey(assetKey, blob);
}

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function toBase32(data: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function fromBase32(input: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of input.toUpperCase()) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error("invalid base32 char");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/**
 * Invite key — autocontida (ADR: convite carrega o que precisa para entrar).
 * - JC1: JC1-<serverId-b32>-<secret-b32> (sem endpoint — legado; exige host manual/rendezvous)
 * - JC2: JC2-<endpointB32>-<serverId-b32>-<secret-b32> — endpoint "host:porta" viaja no
 *   convite; o cliente monta ws://<endpoint>/signal. Um campo só para entrar.
 */
export function formatInviteKey(serverId: string, secret: Buffer, endpoint?: string): string {
  const sid = Buffer.from(serverId.replace(/-/g, ""), "hex");
  const b32 = (endpoint ? toBase32(Buffer.from(endpoint, "utf8")) : "") + toBase32(sid) + toBase32(secret);
  const groups = (b32.match(/.{1,4}/g) ?? []).slice(0, 32);
  return [(endpoint ? "JC2" : "JC1"), ...groups].join("-");
}

export interface ParsedInvite {
  serverId: string;
  secret: Buffer;
  /** endereço "host:porta" embutido no convite (JC2) — undefined em JC1. */
  endpoint?: string;
}

/** serverId (16B) e secret (16B) → base32 de 26 chars cada (padrão fixo). */
const INVITE_SEGMENT_CHARS = 26;

export function parseInviteKey(key: string): ParsedInvite | null {
  const m = key.trim().match(/^JC([12])-([A-Za-z2-7]+(?:-[A-Za-z2-7]+)*)$/);
  if (!m) return null;
  const version = m[1]!;
  try {
    const compact = m[2]!.replace(/-/g, "");
    if (version === "1" && compact.length !== INVITE_SEGMENT_CHARS * 2) return null;
    if (version === "2" && compact.length < INVITE_SEGMENT_CHARS * 2) return null;
    // serverId+secret = os 2 segmentos finais fixos; o que sobrar antes = endpoint (JC2)
    const sidBytes = fromBase32(compact.slice(-INVITE_SEGMENT_CHARS * 2, -INVITE_SEGMENT_CHARS));
    const secretBytes = fromBase32(compact.slice(-INVITE_SEGMENT_CHARS));
    if (sidBytes.length !== 16 || secretBytes.length !== 16) return null;
    const h = sidBytes.toString("hex");
    const serverId = `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
    const epB32 = compact.slice(0, -INVITE_SEGMENT_CHARS * 2);
    if (version === "2" && !epB32) return null;
    const endpoint = epB32 ? fromBase32(epB32).toString("utf8") : undefined;
    return { serverId, secret: Buffer.from(secretBytes), endpoint };
  } catch {
    return null;
  }
}
