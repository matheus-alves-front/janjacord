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
  });
});
