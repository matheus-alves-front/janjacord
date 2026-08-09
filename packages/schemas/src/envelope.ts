import { z } from "zod";

/**
 * Wire protocol constants (v0).
 * protocolVersion: monotonic integer. Frame-level versioning lives here;
 * handshake rejects incompatible versions (ADR-013).
 */
export const PROTOCOL_VERSION = 1;

export const MAX_FRAME_BYTES = 64 * 1024; // fragmentacao: teto pratico (RFC 8841 default)
export const MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024; // default quota por arquivo (ADR-012)
export const DEFAULT_RETENTION_HOURS = 168; // 7 dias (ADR-004)
export const AUDIENCE_COMMITMENT_ALGO = "sha256";

export const uuidSchema = z
  .string()
  .uuid({ message: "expected uuid" })
  .describe("uuid v4");

export const base64Schema = z
  .string()
  .regex(/^[A-Za-z0-9+/]*={0,2}$/, "invalid base64")
  .describe("base64-encoded bytes");

/** Attachment reference inside a message envelope (ADR-012). */
export const AttachmentRefSchema = z.object({
  assetId: uuidSchema,
  name: z.string().max(255),
  mimeType: z.string().max(128),
  sizeBytes: z.number().int().positive(),
  totalChunks: z.number().int().positive(),
  hash: z.string().describe("sha256 hex of the plaintext asset"),
});

export type AttachmentRef = z.infer<typeof AttachmentRefSchema>;

/**
 * Audience snapshot commitment (ADR-004/017): hash of the sorted identity list
 * that the message was encrypted to. Members joining later are not added.
 */
export const AudienceSnapshotSchema = z.object({
  algo: z.literal(AUDIENCE_COMMITMENT_ALGO),
  commitment: z.string().describe("sha256 hex over sorted member identity ids"),
  members: z.array(z.string()).describe("identity ids at send time"),
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
