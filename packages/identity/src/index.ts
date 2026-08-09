import { randomBytes, randomUUID } from "node:crypto";
import { deriveKEK, randomBytes32, wrapKey, unwrapKey, ARGON2_DESKTOP, sha256Hex } from "@janjacord/crypto";
import { VaultFile, type VaultRecord } from "@janjacord/persistence";

/**
 * Identidade pseudônima local (ADR-001/015): seed 32B de alta entropia gerado localmente;
 * a senha apenas protege o vault (KEK via Argon2id). A senha NUNCA deriva a identidade.
 */
export interface IdentityMaterial {
  identityId: string; // UUID v4 (estável, referenciado em servers)
  nickname: string;
  seed: Buffer; // 32 bytes — raiz criptográfica (signature keys MLS, PSK, recovery)
}

export interface UnlockedIdentity extends IdentityMaterial {
  dbKey: Buffer; // 32 bytes — chave do SQLite cifrado local
}

/** Cria identidade + vault file no diretório de dados do app. */
export async function createIdentity(
  nickname: string,
  password: string,
  vaultPath: string,
): Promise<UnlockedIdentity> {
  if (nickname.trim().length < 1) throw new Error("nickname required");
  if (password.length < 8) throw new Error("password too weak (min 8 chars)");
  const identityId = randomUUID();
  const seed = randomBytes32();
  const dbKey = randomBytes32();
  const salt = randomBytes(16);
  const kek = await deriveKEK(password, salt, ARGON2_DESKTOP);
  const vault = VaultFile.build(identityId, nickname.trim(), kek, seed, dbKey, salt, ARGON2_DESKTOP);
  new VaultFile(vaultPath).write(vault);
  return { identityId, nickname: nickname.trim(), seed, dbKey };
}

/** Desbloqueia identidade existente com senha (falha = senha errada, tag AES-GCM). */
export async function unlockIdentity(
  password: string,
  vaultPath: string,
): Promise<UnlockedIdentity> {
  const vault = new VaultFile(vaultPath);
  if (!vault.exists()) throw new Error("vault not found");
  const rec = vault.read();
  const kek = await deriveKEK(password, Buffer.from(rec.salt, "base64"), rec.kdf);
  const { seed, dbKey } = vault.unwrap(kek); // lança em senha errada
  return { identityId: rec.identityId, nickname: rec.nickname, seed, dbKey };
}

/** Troca de senha = re-wrap (seed/dbKey intactos; ADR-001). */
export async function changePassword(
  oldPassword: string,
  newPassword: string,
  vaultPath: string,
): Promise<void> {
  const current = await unlockIdentity(oldPassword, vaultPath);
  const salt = randomBytes(16);
  const kek = await deriveKEK(newPassword, salt, ARGON2_DESKTOP);
  const rec: VaultRecord = {
    version: 1,
    identityId: current.identityId,
    nickname: current.nickname,
    seedEncrypted: wrapKey(kek, current.seed).toString("base64"),
    dbKeyEncrypted: wrapKey(kek, current.dbKey).toString("base64"),
    salt: salt.toString("base64"),
    kdf: ARGON2_DESKTOP,
    createdAt: Date.now(),
  };
  new VaultFile(vaultPath).write(rec);
}

/**
 * Recovery key (ADR-015): seed em hex legível + prova de integridade.
 * Perdeu devices + recovery = identidade perdida (por design, sem backdoor central).
 */
export function generateRecoveryKey(seed: Buffer): string {
  const hex = seed.toString("hex");
  const checksum = sha256Hex(seed).slice(0, 4);
  // agrupa em 8 grupos de 8 chars
  const groups = hex.match(/.{1,8}/g) ?? [];
  return `${groups.join("-")}-${checksum}`;
}

export function parseRecoveryKey(key: string): Buffer {
  const compact = key.trim().replace(/-/g, "");
  if (compact.length !== 68) throw new Error("invalid recovery key length");
  const hex = compact.slice(0, 64);
  const checksum = compact.slice(64);
  const seed = Buffer.from(hex, "hex");
  if (sha256Hex(seed).slice(0, 4) !== checksum) throw new Error("recovery key checksum mismatch");
  return seed;
}

/** Restaura identidade a partir da recovery key (re-cifra com nova senha). */
export async function restoreIdentity(
  recoveryKey: string,
  nickname: string,
  newPassword: string,
  vaultPath: string,
): Promise<UnlockedIdentity> {
  const seed = parseRecoveryKey(recoveryKey);
  const identityId = randomUUID(); // nova identidade com o mesmo material raiz
  const dbKey = randomBytes32();
  const salt = randomBytes(16);
  const kek = await deriveKEK(newPassword, salt, ARGON2_DESKTOP);
  const vault = VaultFile.build(identityId, nickname.trim(), kek, seed, dbKey, salt, ARGON2_DESKTOP);
  new VaultFile(vaultPath).write(vault);
  return { identityId, nickname: nickname.trim(), seed, dbKey };
}

/**
 * Device linking (spec multi-device): sessão efêmera 1-scan (TTL curto, escopo 1 device).
 * O payload NUNCA contém o seed em plaintext — contém a chave pública do novo device + nonce;
 * o desktop autoriza e entrega o material re-cifrado para a chave do novo device.
 * V1 simplificada e segura: envelope de linking assinado pelo seed (HMAC) com nonce.
 */
/**
 * Device linking (spec multi-device): sessão efêmera 1-scan (TTL curto).
 * O QR contém { linkId, nonce, mac } — o mac prova posse do seed do desktop
 * (o mobile só confia no QR gerado pelo próprio desktop autenticado). O secret
 * do seed NUNCA sai do device; a adição do novo device ao grupo MLS usa o
 * KeyPackage do novo device (add_member), nunca o seed.
 */
export interface LinkSession {
  linkId: string;
  nonce: string;
  expiresAt: number;
  payload: string; // base64 JSON: { linkId, nonce, mac }
}

export function createLinkSession(seed: Buffer, ttlMs = 5 * 60_000): LinkSession {
  const nonce = randomBytes(16).toString("hex");
  const linkId = randomUUID();
  const mac = sha256Hex(Buffer.concat([Buffer.from(seed), Buffer.from(nonce)]));
  const payload = Buffer.from(JSON.stringify({ linkId, nonce, mac })).toString("base64");
  return { linkId, nonce, expiresAt: Date.now() + ttlMs, payload };
}

export function verifyLinkSession(session: LinkSession, seed: Buffer): boolean {
  if (Date.now() > session.expiresAt) return false;
  try {
    const parsed = JSON.parse(Buffer.from(session.payload, "base64").toString("utf8")) as {
      linkId?: string;
      nonce?: string;
      mac?: string;
    };
    if (parsed.linkId !== session.linkId || parsed.nonce !== session.nonce) return false;
    const expectedMac = sha256Hex(Buffer.concat([Buffer.from(seed), Buffer.from(parsed.nonce)]));
    return expectedMac === parsed.mac;
  } catch {
    return false;
  }
}
