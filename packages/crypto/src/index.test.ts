import { describe, it, expect, beforeAll } from "vitest";
import { randomBytes } from "node:crypto";
import {
  canonicalJson,
  createAuthenticatedCounterAnchor,
  createAuthenticatedStoreEnvelope,
  deriveKEK,
  ed25519Fingerprint,
  ed25519PublicKey,
  formatInviteKey,
  parseInviteKey,
  signCanonicalPayload,
  unwrapKey,
  verifyCanonicalPayload,
  verifyAuthenticatedCounterAnchor,
  verifyAuthenticatedStoreEnvelope,
  wrapKey,
} from "../src/index.js";
import * as mls from "@janjacord/crypto-core";

// O crypto-core é WASM (CJS gerado pelo wasm-pack); inicialização lazy.
beforeAll(async () => {
  await (mls as unknown as { default?: Promise<unknown> }).default;
});

describe("KDF e wrap", () => {
  it("deriva KEK determinística e unwrap detecta senha errada", async () => {
    const salt = randomBytes(16);
    const kek = await deriveKEK("senha-segura-123", salt);
    expect(kek.length).toBe(32);
    const blob = wrapKey(kek, Buffer.from("seed-material"));
    expect(unwrapKey(kek, blob).toString()).toBe("seed-material");
    const wrong = await deriveKEK("outra-senha", salt);
    expect(() => unwrapKey(wrong, blob)).toThrow();
  });

  it("parâmetros mobile (OWASP mínimo) funcionam", async () => {
    const kek = await deriveKEK("x", randomBytes(16), { memoryKiB: 19456, passes: 2, parallelism: 1 });
    expect(kek.length).toBe(32);
  });
});

describe("invite key", () => {
  it("formata e parseia roundtrip (JC1-<serverId>-<secret>)", () => {
    const serverId = "b2f456e6-7543-4962-bf84-a09aa827cb9f";
    const secret = randomBytes(16);
    const key = formatInviteKey(serverId, secret);
    expect(key.startsWith("JC1-")).toBe(true);
    const parsed = parseInviteKey(key);
    expect(parsed).not.toBeNull();
    expect(parsed!.serverId).toBe(serverId);
    expect(parsed!.secret.equals(secret)).toBe(true);
  });

  it("rejeita key malformada", () => {
    expect(parseInviteKey("NAO-INVITE")).toBeNull();
    expect(parseInviteKey("JC1-")).toBeNull();
    expect(parseInviteKey("JC1-" + "A".repeat(10))).toBeNull(); // comprimento inválido

    // JC2: convite autocontido (endpoint embutido)
    const ep = "192.168.3.44:8931";
    const key2 = formatInviteKey("00112233-4455-6677-8899-aabbccddeeff", Buffer.from("11223344556677881122334455667788", "hex"), ep);
    expect(key2.startsWith("JC2-")).toBe(true);
    const p2 = parseInviteKey(key2);
    expect(p2).not.toBeNull();
    expect(p2!.serverId).toBe("00112233-4455-6677-8899-aabbccddeeff");
    expect(p2!.endpoint).toBe(ep);
    expect(p2!.secret.toString("hex")).toBe("11223344556677881122334455667788");
    // convite JC1 continua sem endpoint
    const key1 = formatInviteKey("00112233-4455-6677-8899-aabbccddeeff", Buffer.from("11223344556677881122334455667788", "hex"));
    expect(key1.startsWith("JC1-")).toBe(true);
    const p1 = parseInviteKey(key1);
    expect(p1!.endpoint).toBeUndefined();
    // endpoint com tailscale (mais longo)
    const key3 = formatInviteKey("00112233-4455-6677-8899-aabbccddeeff", Buffer.from("11223344556677881122334455667788", "hex"), "100.107.202.109:8931");
    expect(parseInviteKey(key3)!.endpoint).toBe("100.107.202.109:8931");
  });
});

describe("assinaturas Ed25519 canônicas", () => {
  it("assina payload canônico e rejeita adulteração ou outro domínio", () => {
    const seed = Buffer.alloc(32, 7);
    const publicKey = ed25519PublicKey(seed);
    const payload = { z: [3, 2, 1], a: { y: true, x: "ok" } };
    const signature = signCanonicalPayload(seed, "janjacord.test", payload);

    expect(publicKey).toHaveLength(32);
    expect(ed25519Fingerprint(publicKey)).toHaveLength(64);
    expect(canonicalJson(payload)).toBe('{"a":{"x":"ok","y":true},"z":[3,2,1]}');
    expect(verifyCanonicalPayload(publicKey, "janjacord.test", payload, signature)).toBe(true);
    expect(verifyCanonicalPayload(publicKey, "janjacord.test", { ...payload, z: [1] }, signature)).toBe(false);
    expect(verifyCanonicalPayload(publicKey, "janjacord.other", payload, signature)).toBe(false);
  });

  it("rejeita seed, chave e JSON não canônico inválidos", () => {
    expect(() => ed25519PublicKey(Buffer.alloc(31))).toThrow(/32 bytes/);
    expect(() => canonicalJson({ value: Number.NaN })).toThrow(/non-finite/);
    expect(verifyCanonicalPayload(Buffer.alloc(31), "janjacord.test", {}, Buffer.alloc(64))).toBe(false);
    const proto = JSON.parse('{"__proto__":{"admin":true},"text":"ação"}') as Record<string, unknown>;
    expect(canonicalJson(proto)).toBe('{"__proto__":{"admin":true},"text":"ação"}');
  });
});

describe("authenticated local store", () => {
  it("detects payload, counter and anchor tampering or rollback mismatch", () => {
    const key = Buffer.alloc(32, 33);
    const envelope = createAuthenticatedStoreEnvelope(key, 4, { trust: ["bridge-a"] });
    const anchor = createAuthenticatedCounterAnchor(key, envelope.counter, envelope.mac);

    expect(verifyAuthenticatedStoreEnvelope(key, envelope)?.payload).toEqual({ trust: ["bridge-a"] });
    expect(verifyAuthenticatedCounterAnchor(key, anchor, envelope.counter, envelope.mac)).toBe(true);
    expect(verifyAuthenticatedStoreEnvelope(key, { ...envelope, payload: { trust: ["evil"] } })).toBeNull();
    expect(verifyAuthenticatedStoreEnvelope(key, { ...envelope, counter: 3 })).toBeNull();
    expect(verifyAuthenticatedCounterAnchor(key, anchor, 3, envelope.mac)).toBe(false);
    expect(verifyAuthenticatedCounterAnchor(key, { ...anchor, storeMac: "00".repeat(32) }, envelope.counter, envelope.mac)).toBe(false);
  });
});
