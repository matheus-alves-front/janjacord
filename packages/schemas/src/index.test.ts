import { describe, it, expect } from "vitest";
import {
  ATTACHMENT_CHUNK_BYTES,
  AttachmentChunkResultSchema,
  CallIceCandidateSchema,
  CallSignalPayloadSchema,
  HostCommandSchema,
  MAX_CALL_ICE_CANDIDATE_BYTES,
  MAX_CALL_SDP_BYTES,
  MAX_FRAME_BYTES,
  MessageEnvelopeSchema,
  PROTOCOL_VERSION,
  canonicalBase64DecodedLength,
} from "../src/index.js";

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
    expect(HostCommandSchema.parse({ type: "welcome.ackConsumed", welcomeId: "a".repeat(64) }).type)
      .toBe("welcome.ackConsumed");
    expect(HostCommandSchema.safeParse({ type: "welcome.ackConsumed", welcomeId: "not-a-hash" }).success).toBe(false);
    expect(HostCommandSchema.safeParse({ type: "unknown.cmd" }).success).toBe(false);
  });

  it("keeps attachment chunk commands below the gateway frame and rejects the legacy monolith", () => {
    const data = Buffer.alloc(ATTACHMENT_CHUNK_BYTES, 7).toString("base64");
    const command = {
      type: "attachment.upload.chunk",
      assetId: "11111111-1111-4111-8111-111111111111",
      index: 0,
      data,
      sizeBytes: ATTACHMENT_CHUNK_BYTES,
      hash: "a".repeat(64),
    };
    expect(HostCommandSchema.safeParse(command).success).toBe(true);
    expect(Buffer.byteLength(JSON.stringify({ event: "command", data: command }))).toBeLessThan(MAX_FRAME_BYTES);
    const response = { event: "result", data: { ok: true, data: { index: 0, data, sizeBytes: ATTACHMENT_CHUNK_BYTES, hash: "a".repeat(64) } } };
    expect(AttachmentChunkResultSchema.safeParse(response.data.data).success).toBe(true);
    expect(Buffer.byteLength(JSON.stringify(response))).toBeLessThan(MAX_FRAME_BYTES);
    expect(HostCommandSchema.safeParse({
      type: "attachment.upload",
      assetId: command.assetId,
      data,
      sizeBytes: ATTACHMENT_CHUNK_BYTES,
    }).success).toBe(false);
    expect(HostCommandSchema.safeParse({ ...command, data: `${data}AAAA` }).success).toBe(false);
  });

  it("computes canonical base64 length without decoding and rejects non-zero padding bits", () => {
    expect(canonicalBase64DecodedLength("AA==")).toBe(1);
    expect(canonicalBase64DecodedLength("AAA=")).toBe(2);
    expect(canonicalBase64DecodedLength("AB==")).toBeNull();
    expect(canonicalBase64DecodedLength("AAB=")).toBeNull();
    expect(canonicalBase64DecodedLength("AAAA=")).toBeNull();
  });

  it("accepts strict bounded call offer, answer, and trickle ICE payloads", () => {
    const channelId = "11111111-1111-4111-8111-111111111111";
    const sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
    const candidate = JSON.stringify({
      candidate: "candidate:1 1 UDP 2122260223 192.0.2.1 5000 typ host",
      sdpMid: "audio-0",
      sdpMLineIndex: 0,
      usernameFragment: "iceUfrag/1",
    });
    for (const payload of [
      { type: "offer", sdp },
      { type: "answer", sdp },
      { type: "candidate", candidate },
    ] as const) {
      expect(CallSignalPayloadSchema.safeParse(payload).success).toBe(true);
      expect(HostCommandSchema.safeParse({
        type: "call.signal",
        channelId,
        to: "bob",
        payload,
      }).success).toBe(true);
    }
  });

  it("rejects malformed, oversized, NUL-bearing, or non-exact call signaling", () => {
    const channelId = "11111111-1111-4111-8111-111111111111";
    const command = (payload: unknown) => ({ type: "call.signal", channelId, to: "bob", payload });
    const validCandidate = {
      candidate: "candidate:1 1 UDP 2122260223 192.0.2.1 5000 typ host",
      sdpMid: "0",
      sdpMLineIndex: 0,
    };
    const invalidPayloads = [
      { type: "offer", sdp: "o=- missing-version" },
      { type: "offer", sdp: `v=0\r\n${"a".repeat(MAX_CALL_SDP_BYTES)}` },
      { type: "answer", sdp: "v=0\0\r\n" },
      { type: "answer", sdp: "v=0\r\n", candidate: "unexpected" },
      { type: "candidate", candidate: "not-json" },
      { type: "candidate", candidate: JSON.stringify({ candidate: validCandidate.candidate, mid: "audio-0" }) },
      { type: "candidate", candidate: JSON.stringify({ ...validCandidate, candidate: "not-a-candidate" }) },
      { type: "candidate", candidate: JSON.stringify({ ...validCandidate, candidate: `candidate:${"a".repeat(MAX_CALL_ICE_CANDIDATE_BYTES)}` }) },
      { type: "candidate", candidate: JSON.stringify({ ...validCandidate, sdpMid: "unsafe mid" }) },
      { type: "candidate", candidate: JSON.stringify({ ...validCandidate, sdpMid: "m".repeat(65) }) },
      { type: "candidate", candidate: JSON.stringify({ ...validCandidate, sdpMLineIndex: -1 }) },
      { type: "candidate", candidate: JSON.stringify({ ...validCandidate, sdpMLineIndex: 1.5 }) },
      { type: "candidate", candidate: JSON.stringify({ ...validCandidate, sdpMLineIndex: 65_536 }) },
      { type: "candidate", candidate: JSON.stringify({ ...validCandidate, extra: true }) },
      { type: "candidate", candidate: JSON.stringify({ candidate: validCandidate.candidate }) },
      { type: "unknown", sdp: "v=0\r\n" },
    ];

    for (const payload of invalidPayloads) {
      expect(CallSignalPayloadSchema.safeParse(payload).success).toBe(false);
      expect(HostCommandSchema.safeParse(command(payload)).success).toBe(false);
    }
    expect(CallIceCandidateSchema.safeParse(validCandidate).success).toBe(true);
  });
});
