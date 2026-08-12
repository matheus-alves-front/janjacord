import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import {
  ATTACHMENT_ENCRYPTION_OVERHEAD_BYTES,
  AttachmentChunkResultSchema,
  AttachmentDownloadManifestSchema,
  AttachmentUploadBeginResultSchema,
  MAX_ATTACHMENT_PLAINTEXT_BYTES,
  canonicalBase64DecodedLength,
} from "@janjacord/schemas";
import {
  assertAttachmentCiphertextHash,
  attachmentChunkCount,
  attachmentSha256,
  decodeAttachmentChunk,
  encodeAttachmentChunks,
  expectedAttachmentChunkBytes,
} from "@janjacord/protocol";

const SHA256_HEX = /^[0-9a-f]{64}$/;
export const MAX_RENDERER_ATTACHMENT_BASE64_CHARS = Math.ceil(MAX_ATTACHMENT_PLAINTEXT_BYTES / 3) * 4;

export function rendererAttachmentEncodedLengthIsAllowed(encodedLength) {
  return Number.isSafeInteger(encodedLength) && encodedLength >= 4
    && encodedLength <= MAX_RENDERER_ATTACHMENT_BASE64_CHARS;
}

export function decodeRendererAttachment(dataB64) {
  if (typeof dataB64 !== "string" || !rendererAttachmentEncodedLengthIsAllowed(dataB64.length)) {
    throw new Error("attachment encoded length exceeds the 50 MB encrypted spool limit");
  }
  const decodedLength = canonicalBase64DecodedLength(dataB64);
  if (decodedLength === null || decodedLength < 1 || decodedLength > MAX_ATTACHMENT_PLAINTEXT_BYTES) {
    throw new Error("attachment must be non-empty canonical base64 within the size limit");
  }
  const raw = Buffer.from(dataB64, "base64");
  if (raw.length !== decodedLength) throw new Error("attachment decoded size mismatch");
  return raw;
}

export function encryptAttachmentForUpload(raw, options = {}) {
  if (!Buffer.isBuffer(raw) || raw.length < 1 || raw.length > MAX_ATTACHMENT_PLAINTEXT_BYTES) {
    throw new Error("attachment plaintext size is outside the supported range");
  }
  const assetKey = options.assetKey ?? randomBytes(32);
  const nonce = options.nonce ?? randomBytes(12);
  if (!Buffer.isBuffer(assetKey) || assetKey.length !== 32 || !Buffer.isBuffer(nonce) || nonce.length !== 12) {
    throw new Error("attachment encryption material is invalid");
  }
  const cipher = createCipheriv("aes-256-gcm", assetKey, nonce);
  const ciphertext = Buffer.concat([cipher.update(raw), cipher.final()]);
  const encrypted = Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]);
  const chunks = encodeAttachmentChunks(encrypted);
  return {
    assetKey,
    encryptedSizeBytes: encrypted.length,
    chunks,
    plaintextHash: attachmentSha256(raw),
    ciphertextHash: attachmentSha256(encrypted),
  };
}

export function parseUploadBeginResponse(response, totalChunks) {
  if (!response || response.ok !== true) throw new Error(response?.error?.message ?? "attachment upload begin failed");
  const parsed = AttachmentUploadBeginResultSchema.safeParse(response.data);
  if (!parsed.success) throw new Error("host returned a malformed attachment upload state");
  const received = new Set();
  for (const index of parsed.data.receivedChunks) {
    if (index >= totalChunks || received.has(index)) throw new Error("host returned invalid attachment chunk progress");
    received.add(index);
  }
  return received;
}

function retryableUploadFailure(response) {
  const code = response?.error?.code;
  return !response || ["host_offline", "timeout", "internal"].includes(code);
}

export async function uploadAttachmentWithResume({
  chunks,
  begin,
  uploadChunk,
  complete,
  maxAttempts = 3,
  wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
}) {
  if (!Array.isArray(chunks) || chunks.length < 1 || !Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 5) {
    throw new Error("attachment upload retry policy is invalid");
  }
  let lastFailure = { ok: false, error: { code: "host_offline", message: "host unavailable" } };
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    let begun;
    try {
      begun = await begin();
    } catch {
      begun = null;
    }
    if (!begun?.ok) {
      lastFailure = begun ?? lastFailure;
      if (!retryableUploadFailure(begun)) return lastFailure;
    } else {
      const received = parseUploadBeginResponse(begun, chunks.length);
      let shouldRetry = false;
      for (const chunk of chunks) {
        if (received.has(chunk.index)) continue;
        let uploaded;
        try {
          uploaded = await uploadChunk(chunk);
        } catch {
          uploaded = null;
        }
        if (!uploaded?.ok) {
          lastFailure = uploaded ?? lastFailure;
          if (!retryableUploadFailure(uploaded)) return lastFailure;
          shouldRetry = true;
          break;
        }
      }
      if (!shouldRetry) {
        let completed;
        try {
          completed = await complete();
        } catch {
          completed = null;
        }
        if (completed?.ok) return completed;
        lastFailure = completed ?? lastFailure;
        if (!retryableUploadFailure(completed)) return lastFailure;
      }
    }
    if (attempt + 1 < maxAttempts) await wait(150 * 2 ** attempt);
  }
  return lastFailure;
}

export function parseDownloadManifest(response, ref) {
  if (!response || response.ok !== true) throw new Error(response?.error?.message ?? "attachment download failed");
  const parsed = AttachmentDownloadManifestSchema.safeParse(response.data);
  if (!parsed.success) throw new Error("host returned a malformed attachment manifest");
    const expectedCiphertextBytes = Number(ref?.sizeBytes) + ATTACHMENT_ENCRYPTION_OVERHEAD_BYTES;
  if (!Number.isSafeInteger(ref?.sizeBytes) || ref.sizeBytes < 1 || ref.sizeBytes > MAX_ATTACHMENT_PLAINTEXT_BYTES
    || parsed.data.sizeBytes !== expectedCiphertextBytes
    || parsed.data.totalChunks !== attachmentChunkCount(expectedCiphertextBytes)
    || !Number.isSafeInteger(ref.totalChunks) || ref.totalChunks < 1) {
    throw new Error("attachment manifest does not match the encrypted message reference");
  }
  return parsed.data;
}

export function parseDownloadChunk(response, manifest, expectedIndex, aggregateBytes) {
  if (!response || response.ok !== true) throw new Error(response?.error?.message ?? "attachment chunk download failed");
  const parsed = AttachmentChunkResultSchema.safeParse(response.data);
  if (!parsed.success || parsed.data.index !== expectedIndex) throw new Error("host returned a malformed attachment chunk");
  const expectedSize = expectedAttachmentChunkBytes(manifest.sizeBytes, manifest.totalChunks, expectedIndex);
  if (parsed.data.sizeBytes !== expectedSize || aggregateBytes + expectedSize > manifest.sizeBytes) {
    throw new Error("attachment chunk exceeds its declared transfer bounds");
  }
  return decodeAttachmentChunk(parsed.data.data, expectedSize, parsed.data.hash);
}

function decodeAssetKey(value) {
  if (typeof value !== "string" || value.length !== 44 || canonicalBase64DecodedLength(value) !== 32) {
    throw new Error("attachment key is invalid");
  }
  const key = Buffer.from(value, "base64");
  if (key.length !== 32) throw new Error("attachment key is invalid");
  return key;
}

export function decryptDownloadedAttachment(chunks, manifest, keyB64, ref) {
  if (!Array.isArray(chunks) || chunks.length !== manifest.totalChunks || !SHA256_HEX.test(String(ref?.hash ?? ""))) {
    throw new Error("attachment download is incomplete or malformed");
  }
  let totalBytes = 0;
  for (const chunk of chunks) totalBytes += chunk.length;
  if (totalBytes !== manifest.sizeBytes) throw new Error("attachment download aggregate size mismatch");
  assertAttachmentCiphertextHash(chunks, manifest.hash);
  const encrypted = Buffer.concat(chunks, totalBytes);
  if (encrypted.length < ATTACHMENT_ENCRYPTION_OVERHEAD_BYTES + 1) throw new Error("attachment ciphertext is too short");
  const key = decodeAssetKey(keyB64);
  const decipher = createDecipheriv("aes-256-gcm", key, encrypted.subarray(0, 12));
  decipher.setAuthTag(encrypted.subarray(12, 28));
  const raw = Buffer.concat([decipher.update(encrypted.subarray(28)), decipher.final()]);
  if (raw.length !== ref.sizeBytes || createHash("sha256").update(raw).digest("hex") !== ref.hash) {
    throw new Error("attachment plaintext integrity check failed");
  }
  return raw;
}
