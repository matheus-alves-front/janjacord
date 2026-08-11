import { describe, it, expect, beforeAll } from "vitest";
import { randomBytes } from "node:crypto";
import { deriveKEK, wrapKey, unwrapKey, formatInviteKey, parseInviteKey } from "../src/index.js";
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
