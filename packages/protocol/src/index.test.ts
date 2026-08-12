import { describe, it, expect } from "vitest";
import {
  encodeEnvelope,
  decodeEnvelope,
  fragmentMessage,
  defragment,
  ReplayGuard,
  SequenceTracker,
  buildEnvelope,
  encodeFragment,
  decodeFragment,
  attachmentChunkCount,
  attachmentSha256,
  decodeAttachmentChunk,
  encodeAttachmentChunks,
  expectedAttachmentChunkBytes,
} from "../src/index.js";
import { ATTACHMENT_CHUNK_BYTES, PROTOCOL_VERSION } from "@janjacord/schemas";

const base = {
  serverId: "11111111-1111-4111-8111-111111111111",
  channelId: "22222222-2222-4222-8222-222222222222",
  sender: "alice",
  cryptoEpoch: 1,
  audience: {
    algo: "sha256" as const,
    commitment: "c".repeat(64),
    members: ["alice", "bob"],
  },
  ciphertext: Buffer.from("ct").toString("base64"),
  ordering: { seq: 1 },
};

describe("envelope", () => {
  it("roundtrip mantém integridade e versão", () => {
    const env = buildEnvelope({ ...base, expiresAt: Date.now() + 1000 });
    const decoded = decodeEnvelope(encodeEnvelope(env));
    expect(decoded.messageId).toBe(env.messageId);
    expect(decoded.protocolVersion).toBe(PROTOCOL_VERSION);
    expect(decoded.audience.members).toEqual(["alice", "bob"]);
  });

  it("rejeita envelope sem versão correta", () => {
    const bad = { ...base, protocolVersion: 99 };
    expect(() => decodeEnvelope(JSON.stringify(bad))).toThrow();
  });
});

describe("fragmentação", () => {
  it("fragmenta e remonta payload de 200KiB (teto DC)", () => {
    const payload = new Uint8Array(200 * 1024).fill(7);
    const frags = fragmentMessage("m1", payload);
    expect(frags.length).toBe(4);
    const reassembled = defragment(frags.map((f) => decodeFragment(encodeFragment(f))));
    expect(Buffer.from(reassembled)).toEqual(Buffer.from(payload));
  });

  it("fragmentos incompletos falham", () => {
    const frags = fragmentMessage("m1", new Uint8Array(130 * 1024));
    expect(() => defragment(frags.slice(0, 1))).toThrow();
  });
});

describe("anti-replay", () => {
  it("rejeita messageId duplicado dentro do TTL", () => {
    const guard = new ReplayGuard(60_000);
    expect(guard.check("m1")).toBe(true);
    expect(guard.check("m1")).toBe(false);
    expect(guard.check("m2")).toBe(true);
  });

  it("aceita id antigo após TTL (sem tombstone infinito)", () => {
    let now = 0;
    const guard = new ReplayGuard(1000, () => now);
    guard.check("m1");
    now = 2000;
    expect(guard.check("m1")).toBe(true);
  });
});

describe("attachment chunk transport", () => {
  it("roundtrips a multi-chunk ciphertext with exact aggregate bounds", () => {
    const ciphertext = Buffer.alloc(ATTACHMENT_CHUNK_BYTES * 2 + 17, 11);
    const chunks = encodeAttachmentChunks(ciphertext);
    expect(chunks).toHaveLength(attachmentChunkCount(ciphertext.length));
    const decoded = chunks.map((chunk, index) => {
      expect(chunk.sizeBytes).toBe(expectedAttachmentChunkBytes(ciphertext.length, chunks.length, index));
      return decodeAttachmentChunk(chunk.data, chunk.sizeBytes, chunk.hash);
    });
    expect(Buffer.concat(decoded, ciphertext.length)).toEqual(ciphertext);
    expect(attachmentSha256(Buffer.concat(decoded))).toBe(attachmentSha256(ciphertext));
  });

  it("rejects encoded overflow, non-canonical base64, size lies and hash corruption before acceptance", () => {
    const bytes = Buffer.alloc(64, 3);
    const encoded = bytes.toString("base64");
    expect(() => decodeAttachmentChunk(`${"A".repeat(ATTACHMENT_CHUNK_BYTES / 3 * 4)}AAAA`, ATTACHMENT_CHUNK_BYTES))
      .toThrow(/encoded length/);
    expect(() => decodeAttachmentChunk("AB==", 1)).toThrow(/canonical/);
    expect(() => decodeAttachmentChunk(encoded, 63)).toThrow(/declared size/);
    expect(() => decodeAttachmentChunk(encoded, 64, "0".repeat(64))).toThrow(/hash mismatch/);
  });
});

describe("ordenação", () => {
  it("sequência monótona por remetente", () => {
    const t = new SequenceTracker();
    expect(t.next("alice")).toBe(1);
    expect(t.next("alice")).toBe(2);
    expect(t.next("bob")).toBe(1);
    expect(t.last("alice")).toBe(2);
  });
});
