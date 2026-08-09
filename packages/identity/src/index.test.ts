import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createIdentity,
  unlockIdentity,
  changePassword,
  generateRecoveryKey,
  parseRecoveryKey,
  restoreIdentity,
} from "../src/index.js";

function tmpVault(): { dir: string; path: string } {
  const dir = mkdtempSync(join(tmpdir(), "jc-id-"));
  return { dir, path: join(dir, "vault.json") };
}

describe("identity", () => {
  it("cria, desbloqueia e rejeita senha errada", async () => {
    const { dir, path } = tmpVault();
    try {
      await createIdentity("matheus", "senha-forte-123", path);
      const unlocked = await unlockIdentity("senha-forte-123", path);
      expect(unlocked.nickname).toBe("matheus");
      expect(unlocked.seed.length).toBe(32);
      await expect(unlockIdentity("senha-errada", path)).rejects.toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("troca de senha preserva seed (re-wrap)", async () => {
    const { dir, path } = tmpVault();
    try {
      const first = await createIdentity("ana", "senha-1-abc", path);
      await changePassword("senha-1-abc", "senha-2-def", path);
      const second = await unlockIdentity("senha-2-def", path);
      expect(second.seed.equals(first.seed)).toBe(true);
      await expect(unlockIdentity("senha-1-abc", path)).rejects.toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("recovery key roundtrip restaura identidade", async () => {
    const { dir, path } = tmpVault();
    try {
      const original = await createIdentity("luiz", "senha-1-abc", path);
      const rk = generateRecoveryKey(original.seed);
      expect(rk.split("-").length).toBe(9); // 8 grupos + checksum
      const seed = parseRecoveryKey(rk);
      expect(seed.equals(original.seed)).toBe(true);
      // restore com nova senha
      const restored = await restoreIdentity(rk, "luiz", "nova-senha-9", path);
      expect(restored.seed.equals(original.seed)).toBe(true);
      // senha antiga não abre mais
      await expect(unlockIdentity("senha-1-abc", path)).rejects.toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("recovery key com checksum errado falha", () => {
    expect(() => parseRecoveryKey("a".repeat(64) + "0000")).toThrow();
  });
});
