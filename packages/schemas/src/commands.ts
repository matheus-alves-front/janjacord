import { z } from "zod";
import {
  ATTACHMENT_CHUNK_BYTES,
  ATTACHMENT_ENCRYPTION_OVERHEAD_BYTES,
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENT_CHUNK_BASE64_CHARS,
  MAX_ATTACHMENT_CHUNKS,
  MessageEnvelopeSchema,
  canonicalBase64DecodedLength,
  uuidSchema,
} from "./envelope.js";
import { HostCapabilitySchema, PublicKeySchema, SignatureSchema } from "./connectivity.js";

const HostPossessionProofSchema = z.object({
  proofId: uuidSchema,
  issuedAt: z.number().int().nonnegative(),
  signature: SignatureSchema,
}).strict();

const AttachmentHashSchema = z.string().regex(/^[0-9a-f]{64}$/, "expected lowercase sha256 hex");
const AttachmentChunkDataSchema = z.string()
  .min(4)
  .max(MAX_ATTACHMENT_CHUNK_BASE64_CHARS)
  .superRefine((value, ctx) => {
    const decodedLength = canonicalBase64DecodedLength(value);
    if (decodedLength === null || decodedLength < 1 || decodedLength > ATTACHMENT_CHUNK_BYTES) {
      ctx.addIssue({ code: "custom", message: "attachment chunk must be canonical bounded base64" });
    }
  });

export const AttachmentUploadBeginResultSchema = z.object({
  receivedChunks: z.array(z.number().int().nonnegative().max(MAX_ATTACHMENT_CHUNKS - 1)).max(MAX_ATTACHMENT_CHUNKS),
}).strict();

export const AttachmentDownloadManifestSchema = z.object({
  sizeBytes: z.number().int().positive().max(MAX_ATTACHMENT_BYTES),
  totalChunks: z.number().int().positive().max(MAX_ATTACHMENT_CHUNKS),
  hash: AttachmentHashSchema,
}).strict();

export const AttachmentChunkResultSchema = z.object({
  index: z.number().int().nonnegative().max(MAX_ATTACHMENT_CHUNKS - 1),
  data: AttachmentChunkDataSchema,
  sizeBytes: z.number().int().positive().max(ATTACHMENT_CHUNK_BYTES),
  hash: AttachmentHashSchema,
}).strict();

export const MAX_CALL_SDP_BYTES = 48 * 1024;
export const MAX_CALL_ICE_CANDIDATE_BYTES = 4 * 1024;
export const MAX_CALL_ICE_CANDIDATE_JSON_BYTES = 8 * 1024;
export const MAX_CALL_SDP_MID_LENGTH = 64;
export const MAX_CALL_SDP_MLINE_INDEX = 65_535;

const utf8ByteLength = (value: string): number => new TextEncoder().encode(value).byteLength;

export const CallSdpSchema = z.string()
  .min(3)
  .max(MAX_CALL_SDP_BYTES)
  .superRefine((value, ctx) => {
    if (utf8ByteLength(value) > MAX_CALL_SDP_BYTES) {
      ctx.addIssue({ code: "custom", message: "SDP exceeds 48 KiB" });
    }
    if (!value.startsWith("v=0")) {
      ctx.addIssue({ code: "custom", message: "SDP must start with v=0" });
    }
    if (value.includes("\0")) {
      ctx.addIssue({ code: "custom", message: "SDP must not contain NUL" });
    }
  });

const CallIceCandidateValueSchema = z.string()
  .min(1)
  .max(MAX_CALL_ICE_CANDIDATE_BYTES)
  .superRefine((value, ctx) => {
    if (utf8ByteLength(value) > MAX_CALL_ICE_CANDIDATE_BYTES) {
      ctx.addIssue({ code: "custom", message: "ICE candidate exceeds 4 KiB" });
    }
    if (!/^(?:a=)?candidate:[\x20-\x7e]+$/i.test(value)) {
      ctx.addIssue({ code: "custom", message: "invalid ICE candidate format" });
    }
  });

const CallSdpMidSchema = z.string()
  .min(1)
  .max(MAX_CALL_SDP_MID_LENGTH)
  .regex(/^[A-Za-z0-9._~-]+$/, "invalid SDP MID");

export const CallIceCandidateSchema = z.object({
  candidate: CallIceCandidateValueSchema,
  sdpMid: CallSdpMidSchema.nullable().optional(),
  sdpMLineIndex: z.number().int().min(0).max(MAX_CALL_SDP_MLINE_INDEX).nullable().optional(),
  usernameFragment: z.string().min(1).max(256).regex(/^[A-Za-z0-9+/]+$/, "invalid ICE username fragment").nullable().optional(),
}).strict().superRefine((value, ctx) => {
  if (value.sdpMid == null && value.sdpMLineIndex == null) {
    ctx.addIssue({ code: "custom", message: "ICE candidate requires sdpMid or sdpMLineIndex" });
  }
});

export type CallIceCandidate = z.infer<typeof CallIceCandidateSchema>;

const CallIceCandidateJsonSchema = z.string()
  .min(1)
  .max(MAX_CALL_ICE_CANDIDATE_JSON_BYTES)
  .superRefine((value, ctx) => {
    if (utf8ByteLength(value) > MAX_CALL_ICE_CANDIDATE_JSON_BYTES) {
      ctx.addIssue({ code: "custom", message: "serialized ICE candidate exceeds 8 KiB" });
      return;
    }
    try {
      const result = CallIceCandidateSchema.safeParse(JSON.parse(value));
      if (!result.success) {
        ctx.addIssue({ code: "custom", message: "invalid serialized ICE candidate" });
      }
    } catch {
      ctx.addIssue({ code: "custom", message: "ICE candidate must be valid JSON" });
    }
  });

export const CallSignalPayloadSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("offer"), sdp: CallSdpSchema }).strict(),
  z.object({ type: z.literal("answer"), sdp: CallSdpSchema }).strict(),
  z.object({ type: z.literal("candidate"), candidate: CallIceCandidateJsonSchema }).strict(),
]);

export type CallSignalPayload = z.infer<typeof CallSignalPayloadSchema>;

/** Erro estruturado do host (códigos estáveis para a UI). */
export const ErrorCodeSchema = z.enum([
  "not_found",
  "unauthorized",
  "forbidden",
  "invalid_invite",
  "invite_expired",
  "invite_revoked",
  "invite_exhausted",
  "banned",
  "channel_full",
  "host_offline",
  "invalid_input",
  "conflict",
  "rate_limited",
  "internal",
]);

export type ErrorCode = z.infer<typeof ErrorCodeSchema>;

export const HostResponseSchema = z.discriminatedUnion("ok", [
  z.object({ ok: z.literal(true), data: z.unknown() }),
  z.object({
    ok: z.literal(false),
    error: z.object({
      code: ErrorCodeSchema,
      message: z.string(),
    }),
  }),
]);

export type HostResponse<T = unknown> =
  | { ok: true; data: T }
  | { ok: false; error: { code: ErrorCode; message: string } };

/** Comandos do cliente para o host (via signaling WebSocket). */
export const HostCommandSchema = z.discriminatedUnion("type", [
  // identity/server
  z.object({ type: z.literal("server.create"), name: z.string().min(1).max(64) }),
  z.object({
    type: z.literal("server.join"),
    inviteKey: z.string().min(1).max(2048),
    nickname: z.string().trim().min(1).max(64).optional(),
  }),
  z.object({ type: z.literal("server.leave") }),
  z.object({ type: z.literal("server.state") }),
  z.object({ type: z.literal("connectivity.iceConfig") }),
  z.object({ type: z.literal("server.transferOwnership"), newOwnerIdentityId: z.string().min(1) }),
  z.object({
    type: z.literal("server.updateConfig"),
    config: z.object({
      maxRetentionHours: z.number().int().refine((v) => [1, 24, 168, 720].includes(v)),
      networkPrivacy: z.enum(["direct", "relay"]),
      maxVoiceParticipants: z.number().int().positive().optional(),
      maxVideoParticipants: z.number().int().positive().optional(),
    }),
  }),
  // invites
  z.object({
    type: z.literal("invite.create"),
    initialRoleId: z.string().min(1),
    maxUses: z.number().int().positive().default(1),
    expiresInMs: z.number().int().positive().optional(),
  }),
  z.object({ type: z.literal("invite.revoke"), inviteId: z.string().min(1) }),
  z.object({ type: z.literal("invite.list") }),
  // channels
  z.object({
    type: z.literal("channel.create"),
    channelType: z.enum(["text", "call"]),
    name: z.string().min(1).max(64),
  }),
  z.object({
    type: z.literal("channel.updateOverrides"),
    channelId: uuidSchema,
    overrides: z.array(
      z.object({
        roleId: z.string().min(1),
        allow: z.array(z.enum(["view_channel", "send_messages", "send_files", "join_call", "speak", "enable_camera"])),
        deny: z.array(z.enum(["view_channel", "send_messages", "send_files", "join_call", "speak", "enable_camera"])),
      }),
    ),
  }),
  // roles
  z.object({
    type: z.literal("role.create"),
    name: z.string().min(1).max(64),
    level: z.number().int().nonnegative().max(99),
    permissions: z.array(z.enum(["manage_server", "manage_channels", "manage_roles", "manage_invites", "manage_hosts", "kick_members", "ban_members", "assign_roles", "view_channel", "send_messages", "send_files", "join_call", "speak", "enable_camera", "mute_members", "remove_from_call"])),
  }),
  z.object({ type: z.literal("role.assign"), memberIdentityId: z.string().min(1), roleId: z.string().min(1) }),
  // community host grants (separate from membership roles)
  z.object({
    type: z.literal("host.candidate.register"),
    /** Generated and retained locally by the candidate device. */
    hostPublicKey: PublicKeySchema,
    /** Raw X25519 public key whose private half never leaves the candidate device. */
    enrollmentPublicKey: PublicKeySchema,
    hostId: z.string().min(1).max(128),
    /** Explicit binding to the authenticated identity/device key. */
    deviceProof: HostPossessionProofSchema,
    /** Separate proof that the candidate controls the host signing key. */
    hostProof: HostPossessionProofSchema,
  }),
  z.object({
    type: z.literal("host.grant.create"),
    subjectIdentityId: z.string().min(1).max(128),
    /** Selected from server.state.hostCandidates; the owner never handles key material. */
    candidateId: uuidSchema,
    capabilities: z
      .array(HostCapabilitySchema)
      .min(1)
      .max(3)
      .refine((capabilities) => new Set(capabilities).size === capabilities.length, {
        message: "capabilities must be unique",
      }),
    expiresInMs: z.number().int().positive().optional(),
  }),
  z.object({
    type: z.literal("host.grant.revoke"),
    grantId: uuidSchema,
    reason: z.string().min(1).max(512).optional(),
  }),
  z.object({ type: z.literal("host.grant.accept"), grantId: uuidSchema, hostProof: HostPossessionProofSchema }),
  z.object({ type: z.literal("host.grant.list") }),
  z.object({
    type: z.literal("device.link.authorize"),
    newDevicePublicKey: PublicKeySchema,
    expiresInMs: z.number().int().positive().max(10 * 60_000).optional(),
  }),
  z.object({
    type: z.literal("device.enroll"),
    capability: z.string().regex(/^JDL1-[A-Za-z0-9_-]{43}$/),
  }),
  // members
  z.object({ type: z.literal("member.kick"), memberIdentityId: z.string().min(1) }),
  z.object({ type: z.literal("member.ban"), memberIdentityId: z.string().min(1) }),
  // message lifecycle (host-level)
  z.object({ type: z.literal("message.send"), envelope: MessageEnvelopeSchema }),
  z.object({ type: z.literal("message.ackConsumed"), messageId: uuidSchema }),
  z.object({ type: z.literal("message.getPending") }),
  // presence
  z.object({ type: z.literal("presence.set"), state: z.enum(["online", "offline", "in_call"]) }),
  // replicação (ADR-011): todo controle é vinculado ao grant aceito e ao epoch.
  z.object({ type: z.literal("replica.enroll"), grantId: uuidSchema, hostProof: HostPossessionProofSchema }),
  z.object({ type: z.literal("replica.snapshot"), grantId: uuidSchema, serverId: uuidSchema }),
  z.object({
    type: z.literal("replica.ping"),
    grantId: uuidSchema,
    serverId: uuidSchema,
    epoch: z.number().int().nonnegative(),
  }),
  // attachments: bounded encrypted chunks; asset key travels only inside MLS ciphertext.
  z.object({
    type: z.literal("attachment.upload.begin"),
    assetId: uuidSchema,
    channelId: uuidSchema,
    audienceMembers: z.array(z.string().min(1).max(128)).min(1).max(1024)
      .refine((members) => new Set(members).size === members.length, "audience members must be unique"),
    sizeBytes: z.number().int().min(ATTACHMENT_ENCRYPTION_OVERHEAD_BYTES + 1).max(MAX_ATTACHMENT_BYTES),
    totalChunks: z.number().int().positive().max(MAX_ATTACHMENT_CHUNKS),
    hash: AttachmentHashSchema,
    ttlHours: z.number().int().min(1).max(24).optional(),
  }).superRefine((value, ctx) => {
    if (value.totalChunks !== Math.ceil(value.sizeBytes / ATTACHMENT_CHUNK_BYTES)) {
      ctx.addIssue({ code: "custom", path: ["totalChunks"], message: "chunk count does not match attachment size" });
    }
  }),
  z.object({
    type: z.literal("attachment.upload.chunk"),
    assetId: uuidSchema,
    index: z.number().int().nonnegative().max(MAX_ATTACHMENT_CHUNKS - 1),
    data: AttachmentChunkDataSchema,
    sizeBytes: z.number().int().positive().max(ATTACHMENT_CHUNK_BYTES),
    hash: AttachmentHashSchema,
  }),
  z.object({ type: z.literal("attachment.upload.complete"), assetId: uuidSchema }),
  z.object({ type: z.literal("attachment.upload.abort"), assetId: uuidSchema }),
  z.object({ type: z.literal("attachment.download"), assetId: uuidSchema }),
  z.object({
    type: z.literal("attachment.download.chunk"),
    assetId: uuidSchema,
    index: z.number().int().nonnegative().max(MAX_ATTACHMENT_CHUNKS - 1),
  }),
  // call (WebRTC mesh — signaling relé pelo host)
  z.object({ type: z.literal("call.join"), channelId: uuidSchema }),
  z.object({ type: z.literal("call.leave"), channelId: uuidSchema }),
  z.object({
    type: z.literal("call.signal"),
    channelId: uuidSchema,
    to: z.string().min(1),
    payload: CallSignalPayloadSchema,
  }),
  // MLS key packages / welcome
  z.object({ type: z.literal("keypackage.upload"), keyPackageB64: z.string().min(1) }),
  z.object({ type: z.literal("keypackage.get"), targetIdentityId: z.string().min(1) }),
  z.object({ type: z.literal("welcome.push"), targetIdentityId: z.string().min(1), welcomeB64: z.string().min(1) }),
  z.object({ type: z.literal("welcome.pending") }),
  z.object({ type: z.literal("welcome.ackConsumed"), welcomeId: z.string().regex(/^[a-f0-9]{64}$/) }),
]);

export type HostCommand = z.infer<typeof HostCommandSchema>;

/** Eventos do host para o cliente. */
export const HostEventSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("server.state"), server: z.unknown() }),
  z.object({ type: z.literal("envelope.deliver"), envelope: z.unknown() }),
  z.object({ type: z.literal("member.presence"), identityId: z.string(), state: z.enum(["online", "offline", "in_call"]) }),
  z.object({ type: z.literal("invite.used"), inviteId: z.string() }),
  z.object({ type: z.literal("member.added"), member: z.unknown() }),
  z.object({ type: z.literal("member.removed"), identityId: z.string(), reason: z.enum(["kick", "ban", "left"]) }),
  z.object({ type: z.literal("epoch.changed"), cryptoEpoch: z.number().int().nonnegative() }),
  z.object({ type: z.literal("error"), code: ErrorCodeSchema, message: z.string() }),
]);

export type HostEvent = z.infer<typeof HostEventSchema>;

/** Frame de signaling entre cliente e host: { event, data } (WsAdapter). */
export const SignalingFrameSchema = z.object({
  event: z.string().min(1),
  data: z.unknown(),
});

export type SignalingFrame = z.infer<typeof SignalingFrameSchema>;
