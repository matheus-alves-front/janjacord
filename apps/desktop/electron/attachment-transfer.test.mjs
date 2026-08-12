import { describe, expect, it } from "vitest";
import { ATTACHMENT_CHUNK_BYTES } from "@janjacord/schemas";
import {
  MAX_RENDERER_ATTACHMENT_BASE64_CHARS,
  decodeRendererAttachment,
  decryptDownloadedAttachment,
  encryptAttachmentForUpload,
  parseDownloadChunk,
  parseDownloadManifest,
  parseUploadBeginResponse,
  rendererAttachmentEncodedLengthIsAllowed,
  uploadAttachmentWithResume,
} from "./attachment-transfer.mjs";

describe("desktop attachment transfer runtime", () => {
  it("encrypts, chunks, validates remote responses and decrypts a multi-chunk attachment", () => {
    const raw = Buffer.alloc(ATTACHMENT_CHUNK_BYTES + 101, 13);
    const encrypted = encryptAttachmentForUpload(raw, {
      assetKey: Buffer.alloc(32, 7),
      nonce: Buffer.alloc(12, 8),
    });
    const received = parseUploadBeginResponse({ ok: true, data: { receivedChunks: [0] } }, encrypted.chunks.length);
    expect(received.has(0)).toBe(true);

    const ref = {
      sizeBytes: raw.length,
      totalChunks: encrypted.chunks.length,
      hash: encrypted.plaintextHash,
    };
    const manifest = parseDownloadManifest({
      ok: true,
      data: {
        sizeBytes: encrypted.encryptedSizeBytes,
        totalChunks: encrypted.chunks.length,
        hash: encrypted.ciphertextHash,
      },
    }, ref);
    const downloaded = [];
    let aggregateBytes = 0;
    for (const chunk of encrypted.chunks) {
      const decoded = parseDownloadChunk({ ok: true, data: chunk }, manifest, chunk.index, aggregateBytes);
      downloaded.push(decoded);
      aggregateBytes += decoded.length;
    }
    expect(decryptDownloadedAttachment(downloaded, manifest, encrypted.assetKey.toString("base64"), ref)).toEqual(raw);
  });

  it("rejects encoded input limits before decode and fails closed on malformed remote state", () => {
    expect(rendererAttachmentEncodedLengthIsAllowed(MAX_RENDERER_ATTACHMENT_BASE64_CHARS)).toBe(true);
    expect(rendererAttachmentEncodedLengthIsAllowed(MAX_RENDERER_ATTACHMENT_BASE64_CHARS + 4)).toBe(false);
    expect(() => decodeRendererAttachment("AB==")).toThrow(/canonical/);
    expect(() => parseUploadBeginResponse({ ok: true, data: { receivedChunks: [0, 0] } }, 1)).toThrow(/progress/);
    expect(() => parseDownloadManifest({ ok: true, data: { sizeBytes: 29, totalChunks: 2, hash: "a".repeat(64) } }, {
      sizeBytes: 1,
      totalChunks: 2,
      hash: "b".repeat(64),
    })).toThrow(/reference/);
  });

  it("rejects oversized and corrupted remote chunk responses", () => {
    const raw = Buffer.alloc(128, 2);
    const encrypted = encryptAttachmentForUpload(raw, { assetKey: Buffer.alloc(32, 1), nonce: Buffer.alloc(12, 2) });
    const manifest = {
      sizeBytes: encrypted.encryptedSizeBytes,
      totalChunks: encrypted.chunks.length,
      hash: encrypted.ciphertextHash,
    };
    const chunk = encrypted.chunks[0];
    expect(() => parseDownloadChunk({ ok: true, data: { ...chunk, data: `${chunk.data}${"A".repeat(50_000)}` } }, manifest, 0, 0))
      .toThrow(/malformed/);
    expect(() => parseDownloadChunk({ ok: true, data: { ...chunk, hash: "0".repeat(64) } }, manifest, 0, 0))
      .toThrow(/hash mismatch/);
  });

  it("resumes the same transfer after a persisted chunk ACK is lost", async () => {
    const encrypted = encryptAttachmentForUpload(Buffer.alloc(64, 3), {
      assetKey: Buffer.alloc(32, 4),
      nonce: Buffer.alloc(12, 5),
    });
    const persisted = new Set();
    let beginCalls = 0;
    let chunkCalls = 0;
    const result = await uploadAttachmentWithResume({
      chunks: encrypted.chunks,
      begin: async () => {
        beginCalls += 1;
        return { ok: true, data: { receivedChunks: [...persisted] } };
      },
      uploadChunk: async (chunk) => {
        chunkCalls += 1;
        persisted.add(chunk.index);
        return chunkCalls === 1 ? null : { ok: true, data: null };
      },
      complete: async () => ({ ok: true, data: null }),
      wait: async () => {},
    });
    expect(result).toEqual({ ok: true, data: null });
    expect(beginCalls).toBe(2);
    expect(chunkCalls).toBe(1);
  });

  it("does not retry terminal attachment upload errors", async () => {
    let begins = 0;
    const result = await uploadAttachmentWithResume({
      chunks: [{ index: 0 }],
      begin: async () => {
        begins += 1;
        return { ok: false, error: { code: "forbidden", message: "no send_files" } };
      },
      uploadChunk: async () => ({ ok: true, data: null }),
      complete: async () => ({ ok: true, data: null }),
      wait: async () => {},
    });
    expect(result).toMatchObject({ ok: false, error: { code: "forbidden" } });
    expect(begins).toBe(1);
  });
});
