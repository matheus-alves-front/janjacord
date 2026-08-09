import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
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

/** Invite key: JC1-<serverId-b32>-<secret-b32> (serverId + secret de 128 bits, base32). */
export function formatInviteKey(serverId: string, secret: Buffer): string {
  const sid = Buffer.from(serverId.replace(/-/g, ""), "hex");
  const b32 = toBase32(sid) + toBase32(secret);
  const groups = (b32.match(/.{1,4}/g) ?? []).slice(0, 16);
  return ["JC1", ...groups].join("-");
}

export interface ParsedInvite {
  serverId: string;
  secret: Buffer;
}

/** serverId (16B) e secret (16B) → base32 de 26 chars cada (padrão fixo). */
const INVITE_SEGMENT_CHARS = 26;

export function parseInviteKey(key: string): ParsedInvite | null {
  const m = key.trim().match(/^JC1-([A-Za-z2-7]+(?:-[A-Za-z2-7]+)*)$/);
  if (!m) return null;
  try {
    const compact = m[1]!.replace(/-/g, "");
    if (compact.length !== INVITE_SEGMENT_CHARS * 2) return null;
    // decodifica cada segmento separadamente (evita vazamento de bits de padding)
    const sidBytes = fromBase32(compact.slice(0, INVITE_SEGMENT_CHARS));
    const secretBytes = fromBase32(compact.slice(INVITE_SEGMENT_CHARS));
    if (sidBytes.length !== 16 || secretBytes.length !== 16) return null;
    const h = sidBytes.toString("hex");
    const serverId = `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
    return { serverId, secret: Buffer.from(secretBytes) };
  } catch {
    return null;
  }
}
