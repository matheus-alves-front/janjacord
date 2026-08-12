import { describe, expect, it, vi } from "vitest";
import { AttachmentBeginTokenBucket, authenticatedOriginKey, SignalingGateway } from "./gateway.js";

describe("signaling origin/session limits", () => {
  it("accepts an ICE session discriminator only from loopback and within strict syntax bounds", () => {
    const session = "a".repeat(32);
    expect(authenticatedOriginKey("::ffff:127.0.0.1", session)).toEqual({ ip: "127.0.0.1", iceSession: session });
    expect(authenticatedOriginKey("::1", "B".repeat(128))).toEqual({ ip: "::1", iceSession: "B".repeat(128) });
    expect(authenticatedOriginKey("127.0.0.1", "a".repeat(31)).iceSession).toBeNull();
    expect(authenticatedOriginKey("127.0.0.1", `${session}!`).iceSession).toBeNull();
    expect(authenticatedOriginKey("203.0.113.7", session)).toEqual({ ip: "203.0.113.7", iceSession: null });
  });
});

describe("attachment begin rate limit", () => {
  it("bounds bursts per socket and refills at a fixed rate", () => {
    const bucket = new AttachmentBeginTokenBucket();
    const socket = {};
    for (let index = 0; index < 8; index += 1) expect(bucket.consume(socket, 1_000)).toBe(true);
    expect(bucket.consume(socket, 1_000)).toBe(false);
    expect(bucket.consume(socket, 1_499)).toBe(false);
    expect(bucket.consume(socket, 1_500)).toBe(true);
  });
});

describe("MLS command routing", () => {
  it("routes recipient Welcome acknowledgement with the authenticated identity", () => {
    const welcomeAckConsumed = vi.fn(() => ({ ok: true, data: null }));
    const gateway = new SignalingGateway({ welcomeAckConsumed } as never);
    const route = (gateway as unknown as {
      route(client: unknown, identityId: string, command: { type: "welcome.ackConsumed"; welcomeId: string }): unknown;
    }).route.bind(gateway);

    const welcomeId = "a".repeat(64);
    expect(route({}, "recipient", { type: "welcome.ackConsumed", welcomeId })).toEqual({ ok: true, data: null });
    expect(welcomeAckConsumed).toHaveBeenCalledExactlyOnceWith("recipient", welcomeId);
  });
});

describe("attachment command routing", () => {
  it("routes every bounded transfer phase with the authenticated identity", () => {
    const service = {
      attachmentUploadBegin: vi.fn(() => ({ ok: true, data: { receivedChunks: [] } })),
      attachmentUploadChunk: vi.fn(() => ({ ok: true, data: null })),
      attachmentUploadComplete: vi.fn(() => ({ ok: true, data: null })),
      attachmentUploadAbort: vi.fn(() => ({ ok: true, data: null })),
      attachmentDownload: vi.fn(() => ({ ok: true, data: { sizeBytes: 29, totalChunks: 1, hash: "a".repeat(64) } })),
      attachmentDownloadChunk: vi.fn(() => ({ ok: true, data: null })),
    };
    const gateway = new SignalingGateway(service as never);
    const route = (gateway as unknown as {
      route(client: unknown, identityId: string, command: Record<string, unknown>): unknown;
    }).route.bind(gateway);
    const assetId = "11111111-1111-4111-8111-111111111111";
    const channelId = "22222222-2222-4222-8222-222222222222";

    route({}, "owner", {
      type: "attachment.upload.begin", assetId, channelId, audienceMembers: ["owner"],
      sizeBytes: 29, totalChunks: 1, hash: "a".repeat(64), ttlHours: 1,
    });
    route({}, "owner", { type: "attachment.upload.chunk", assetId, index: 0, data: "AA==", sizeBytes: 1, hash: "b".repeat(64) });
    route({}, "owner", { type: "attachment.upload.complete", assetId });
    route({}, "owner", { type: "attachment.upload.abort", assetId });
    route({}, "owner", { type: "attachment.download", assetId });
    route({}, "owner", { type: "attachment.download.chunk", assetId, index: 0 });

    expect(service.attachmentUploadBegin).toHaveBeenCalledWith("owner", assetId, channelId, ["owner"], 29, 1, "a".repeat(64), 1);
    expect(service.attachmentUploadChunk).toHaveBeenCalledWith("owner", assetId, 0, "AA==", 1, "b".repeat(64));
    expect(service.attachmentUploadComplete).toHaveBeenCalledWith("owner", assetId);
    expect(service.attachmentUploadAbort).toHaveBeenCalledWith("owner", assetId);
    expect(service.attachmentDownload).toHaveBeenCalledWith("owner", assetId);
    expect(service.attachmentDownloadChunk).toHaveBeenCalledWith("owner", assetId, 0);
  });
});
