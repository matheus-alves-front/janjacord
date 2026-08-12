import { z } from "zod";

/**
 * Wire protocol constants (v0).
 * protocolVersion: monotonic integer. Frame-level versioning lives here;
 * handshake rejects incompatible versions (ADR-013).
 */
export const PROTOCOL_VERSION = 1;

export const MAX_FRAME_BYTES = 64 * 1024; // fragmentacao: teto pratico (RFC 8841 default)
/** Maximum encrypted attachment bytes reserved in the host spool (ADR-012). */
export const MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024;
/** AES-256-GCM wire layout: 12-byte nonce + 16-byte authentication tag. */
export const ATTACHMENT_ENCRYPTION_OVERHEAD_BYTES = 28;
export const MAX_ATTACHMENT_PLAINTEXT_BYTES = MAX_ATTACHMENT_BYTES - ATTACHMENT_ENCRYPTION_OVERHEAD_BYTES;
/**
 * Divisible by three so every non-final base64 chunk has no padding. The encoded
 * data is 40 KiB, leaving ample room for the command/response JSON below 64 KiB.
 */
export const ATTACHMENT_CHUNK_BYTES = 30 * 1024;
export const MAX_ATTACHMENT_CHUNKS = Math.ceil(MAX_ATTACHMENT_BYTES / ATTACHMENT_CHUNK_BYTES);
export const MAX_ATTACHMENT_CHUNK_BASE64_CHARS = (ATTACHMENT_CHUNK_BYTES / 3) * 4;
export const DEFAULT_RETENTION_HOURS = 168; // 7 dias (ADR-004)
export const AUDIENCE_COMMITMENT_ALGO = "sha256";

export const uuidSchema = z
  .string()
  .uuid({ message: "expected uuid" })
  .describe("uuid v4");

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Returns the decoded byte length only for canonical padded RFC 4648 base64.
 * This is intentionally allocation-free so callers can enforce byte limits
 * before `Buffer.from` sees untrusted input.
 */
export function canonicalBase64DecodedLength(value: string): number | null {
  if (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return null;
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  const firstPadding = value.indexOf("=");
  if (firstPadding >= 0 && firstPadding !== value.length - padding) return null;
  if (value.length === 0) return 0;
  if (padding === 2) {
    const sextet = BASE64_ALPHABET.indexOf(value[value.length - 3]!);
    if (sextet < 0 || (sextet & 0x0f) !== 0) return null;
  } else if (padding === 1) {
    const sextet = BASE64_ALPHABET.indexOf(value[value.length - 2]!);
    if (sextet < 0 || (sextet & 0x03) !== 0) return null;
  }
  return (value.length / 4) * 3 - padding;
}

export const base64Schema = z.string().superRefine((value, ctx) => {
  if (canonicalBase64DecodedLength(value) === null) {
    ctx.addIssue({ code: "custom", message: "invalid or non-canonical base64" });
  }
}).describe("canonical base64-encoded bytes");

/** Attachment reference inside a message envelope (ADR-012). */
export const AttachmentRefSchema = z.object({
  assetId: uuidSchema,
  name: z.string().max(255),
  mimeType: z.string().max(128),
  sizeBytes: z.number().int().positive().max(MAX_ATTACHMENT_PLAINTEXT_BYTES),
  totalChunks: z.number().int().positive().max(MAX_ATTACHMENT_CHUNKS),
  hash: z.string().regex(/^[0-9a-f]{64}$/, "expected lowercase sha256 hex").describe("sha256 hex of the plaintext asset"),
});

export type AttachmentRef = z.infer<typeof AttachmentRefSchema>;

/**
 * Audience snapshot commitment (ADR-004/017): hash of the sorted identity list
 * that the message was encrypted to. Members joining later are not added.
 */
export const AudienceSnapshotSchema = z.object({
  algo: z.literal(AUDIENCE_COMMITMENT_ALGO),
  commitment: z.string().regex(/^[0-9a-f]{64}$/).describe("sha256 hex over sorted member identity ids"),
  members: z.array(z.string().min(1).max(128)).min(1).max(1024).describe("identity ids at send time"),
}).superRefine((value, ctx) => {
  if (new Set(value.members).size !== value.members.length) ctx.addIssue({ code: "custom", path: ["members"], message: "audience members must be unique" });
});

export type AudienceSnapshot = z.infer<typeof AudienceSnapshotSchema>;

/** Ordered, anti-replay metadata (ADR-013). */
export const OrderingSchema = z.object({
  seq: z.number().int().nonnegative(),
  prevMessageId: uuidSchema.optional(),
});

export type Ordering = z.infer<typeof OrderingSchema>;

/**
 * MessageEnvelope — application-layer ciphertext container (ADR-013, ADR-004).
 * ciphertext is a base64 MLS PrivateMessage; the host MUST NOT be able to
 * decrypt it (group E2EE, ADR-005).
 */
export const MessageEnvelopeSchema = z.object({
  protocolVersion: z.literal(PROTOCOL_VERSION),
  messageId: uuidSchema,
  serverId: uuidSchema,
  channelId: uuidSchema,
  sender: z.string().min(1).max(128).describe("sender identity id"),
  senderDevice: z.string().optional(),
  cryptoEpoch: z.number().int().nonnegative(),
  audience: AudienceSnapshotSchema,
  ciphertext: base64Schema,
  attachments: z.array(AttachmentRefSchema).default([]),
  ordering: OrderingSchema,
  createdAt: z.number().int().nonnegative(),
  expiresAt: z.number().int().nonnegative().optional(),
});

export type MessageEnvelope = z.infer<typeof MessageEnvelopeSchema>;
