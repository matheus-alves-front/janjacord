/**
 * Identidade no mobile: seed local guardado no SecureStore (Keychain/Keystore —
 * criptografia de repouso do SO), senha validada via Argon2id.
 * O Argon2id roda NATIVO (react-native-quick-crypto/OpenSSL) — em JS puro
 * (noble-hashes) no Hermes a main thread fica bloqueada dezenas de segundos e o
 * Android mata o app (ANR). O seed NUNCA é derivado da senha.
 */
import * as Crypto from "expo-crypto";
import * as SecureStore from "expo-secure-store";
import { argon2 } from "react-native-quick-crypto";

const KEY = "janjacord:identity";

// Mesmos parâmetros do desktop: t=2, m=19456 KiB, p=1 → hash idêntico (Argon2id v1.3).
const ARGON2_PARAMS = { parallelism: 1, tagLength: 32, memory: 19456, passes: 2 };

function argon2idNative(password: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    argon2(
      "argon2id",
      {
        message: password,
        nonce: salt,
        ...ARGON2_PARAMS,
      },
      (err, result) => (err ? reject(err) : resolve(new Uint8Array(result)))
    );
  });
}

function toBase64(d: Uint8Array): string {
  let s = "";
  for (const b of d) s += String.fromCharCode(b);
  return btoa(s);
}
function fromBase64(s: string): Uint8Array {
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
function toHex(d: Uint8Array): string {
  return Array.from(d).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export interface MobileIdentity {
  identityId: string;
  nickname: string;
  seedHex: string;
}

export async function hasIdentity(): Promise<boolean> {
  return !!(await SecureStore.getItemAsync(KEY));
}

export async function createIdentityMobile(nickname: string, password: string): Promise<MobileIdentity> {
  if (password.length < 8) throw new Error("senha muito curta (mínimo 8)");
  const seed = Crypto.getRandomBytes(32);
  const salt = Crypto.getRandomBytes(16);
  const kekHash = await argon2idNative(new TextEncoder().encode(password), salt);
  const identityId = Crypto.randomUUID();
  const record = {
    identityId,
    nickname: nickname.trim(),
    seedB64: toBase64(seed),
    saltB64: toBase64(salt),
    kekHashHex: toHex(kekHash),
    createdAt: Date.now(),
  };
  await SecureStore.setItemAsync(KEY, JSON.stringify(record));
  return { identityId, nickname: nickname.trim(), seedHex: toHex(seed) };
}

export async function unlockIdentityMobile(password: string): Promise<MobileIdentity> {
  const raw = await SecureStore.getItemAsync(KEY);
  if (!raw) throw new Error("identidade não existe");
  const rec = JSON.parse(raw);
  const kekHash = await argon2idNative(new TextEncoder().encode(password), fromBase64(rec.saltB64));
  if (toHex(kekHash) !== rec.kekHashHex) throw new Error("senha incorreta");
  return { identityId: rec.identityId, nickname: rec.nickname, seedHex: toHex(fromBase64(rec.seedB64)) };
}

export async function resetIdentityMobile(): Promise<void> {
  await SecureStore.deleteItemAsync(KEY);
}
