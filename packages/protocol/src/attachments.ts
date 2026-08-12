import { createHash } from "node:crypto";
import {
  ATTACHMENT_CHUNK_BYTES,
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENT_CHUNK_BASE64_CHARS,
  canonicalBase64DecodedLength,
} from "@janjacord/schemas";

const SHA256_HEX = /^[0-9a-f]{64}$/;

export interface EncodedAttachmentChunk {
  index: number;
  data: string;
  sizeBytes: number;
  hash: string;
}

export function attachmentChunkCount(sizeBytes: number): number {
  if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 1 || sizeBytes > MAX_ATTACHMENT_BYTES) {
    throw new Error("attachment size is outside the supported range");
  }
  return Math.ceil(sizeBytes / ATTACHMENT_CHUNK_BYTES);
}

export function expectedAttachmentChunkBytes(totalBytes: number, totalChunks: number, index: number): number {
  if (totalChunks !== attachmentChunkCount(totalBytes)) throw new Error("attachment chunk count mismatch");
  if (!Number.isSafeInteger(index) || index < 0 || index >= totalChunks) throw new Error("attachment chunk index out of range");
  return index === totalChunks - 1
    ? totalBytes - ATTACHMENT_CHUNK_BYTES * (totalChunks - 1)
    : ATTACHMENT_CHUNK_BYTES;
}

export function attachmentSha256(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export function encodeAttachmentChunks(data: Uint8Array): EncodedAttachmentChunk[] {
  const total = attachmentChunkCount(data.byteLength);
  const chunks: EncodedAttachmentChunk[] = [];
  for (let index = 0; index < total; index += 1) {
    const bytes = data.subarray(index * ATTACHMENT_CHUNK_BYTES, (index + 1) * ATTACHMENT_CHUNK_BYTES);
    chunks.push({
      index,
      data: Buffer.from(bytes).toString("base64"),
      sizeBytes: bytes.byteLength,
      hash: attachmentSha256(bytes),
    });
  }
  return chunks;
}

/**
 * Decodes one untrusted wire chunk only after all allocation-free length and
 * canonical-form checks pass.
 */
export function decodeAttachmentChunk(
  data: unknown,
  expectedSizeBytes: number,
  expectedHash?: string,
): Buffer {
  if (typeof data !== "string" || data.length > MAX_ATTACHMENT_CHUNK_BASE64_CHARS) {
    throw new Error("attachment chunk encoded length exceeds limit");
  }
  const decodedLength = canonicalBase64DecodedLength(data);
  if (decodedLength === null) throw new Error("attachment chunk is not canonical base64");
  if (!Number.isSafeInteger(expectedSizeBytes) || expectedSizeBytes < 1
    || expectedSizeBytes > ATTACHMENT_CHUNK_BYTES || decodedLength !== expectedSizeBytes) {
    throw new Error("attachment chunk declared size mismatch");
  }
  if (expectedHash !== undefined && !SHA256_HEX.test(expectedHash)) {
    throw new Error("attachment chunk hash is malformed");
  }
  const decoded = Buffer.from(data, "base64");
  if (decoded.length !== decodedLength) throw new Error("attachment chunk decoded size mismatch");
  if (expectedHash !== undefined && attachmentSha256(decoded) !== expectedHash) {
    throw new Error("attachment chunk hash mismatch");
  }
  return decoded;
}

export function assertAttachmentCiphertextHash(chunks: readonly Uint8Array[], expectedHash: string): void {
  if (!SHA256_HEX.test(expectedHash)) throw new Error("attachment ciphertext hash is malformed");
  const hash = createHash("sha256");
  for (const chunk of chunks) hash.update(chunk);
  if (hash.digest("hex") !== expectedHash) throw new Error("attachment ciphertext hash mismatch");
}
