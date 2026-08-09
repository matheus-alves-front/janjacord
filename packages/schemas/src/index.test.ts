import { describe, it, expect } from "vitest";
import { MessageEnvelopeSchema, HostCommandSchema, PROTOCOL_VERSION } from "../src/index.js";

describe("schemas", () => {
  it("valida envelope completo", () => {
    const env = {
      protocolVersion: PROTOCOL_VERSION,
      messageId: "11111111-1111-4111-8111-111111111111",
      serverId: "22222222-2222-4222-8222-222222222222",
      channelId: "33333333-3333-4333-8333-333333333333",
      sender: "alice",
      cryptoEpoch: 2,
      audience: { algo: "sha256", commitment: "c".repeat(64), members: ["alice", "bob"] },
      ciphertext: Buffer.from("ct").toString("base64"),
      attachments: [],
      ordering: { seq: 3 },
      createdAt: 1,
    };
    expect(MessageEnvelopeSchema.parse(env).messageId).toBe(env.messageId);
  });

  it("rejeita messageId não-uuid", () => {
    const bad = { protocolVersion: 1, messageId: "x", serverId: "y", channelId: "z", sender: "a", cryptoEpoch: 0, audience: { algo: "sha256", commitment: "c", members: [] }, ciphertext: "a", ordering: { seq: 0 }, createdAt: 0 };
    expect(() => MessageEnvelopeSchema.parse(bad)).toThrow();
  });

  it("valida comandos de call e welcome", () => {
    expect(HostCommandSchema.parse({ type: "call.join", channelId: "11111111-1111-4111-8111-111111111111" }).type).toBe("call.join");
    const wp = HostCommandSchema.parse({ type: "welcome.push", targetIdentityId: "bob", welcomeB64: "abc" });
    expect(wp.type).toBe("welcome.push");
    if (wp.type === "welcome.push") expect(wp.targetIdentityId).toBe("bob");
    expect(HostCommandSchema.safeParse({ type: "unknown.cmd" }).success).toBe(false);
  });
});
