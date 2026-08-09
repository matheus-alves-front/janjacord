import { z } from "zod";
import { uuidSchema } from "./envelope.js";

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
  z.object({ type: z.literal("server.join"), inviteKey: z.string().min(1).max(256) }),
  z.object({ type: z.literal("server.leave") }),
  z.object({ type: z.literal("server.state") }),
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
    permissions: z.array(z.enum(["manage_server", "manage_channels", "manage_roles", "manage_invites", "kick_members", "ban_members", "assign_roles", "view_channel", "send_messages", "send_files", "join_call", "speak", "enable_camera", "mute_members", "remove_from_call"])),
  }),
  z.object({ type: z.literal("role.assign"), memberIdentityId: z.string().min(1), roleId: z.string().min(1) }),
  // members
  z.object({ type: z.literal("member.kick"), memberIdentityId: z.string().min(1) }),
  z.object({ type: z.literal("member.ban"), memberIdentityId: z.string().min(1) }),
  // message lifecycle (host-level)
  z.object({ type: z.literal("message.ackConsumed"), messageId: uuidSchema }),
  z.object({ type: z.literal("message.getPending") }),
  // presence
  z.object({ type: z.literal("presence.set"), state: z.enum(["online", "offline", "in_call"]) }),
  // replicação (ADR-011): snapshot do DB cifrado + promoção com epoch
  z.object({ type: z.literal("replica.snapshot") }),
  z.object({ type: z.literal("replica.promote") }),
  z.object({ type: z.literal("replica.ping") }),
  // attachments (chunks cifrados spoolados; asset key viaja no ciphertext MLS)
  z.object({ type: z.literal("attachment.upload"), assetId: uuidSchema, data: z.string().min(1), sizeBytes: z.number().int().positive(), ttlHours: z.number().int().positive().optional() }),
  z.object({ type: z.literal("attachment.download"), assetId: uuidSchema }),
  // call (WebRTC mesh — signaling relé pelo host)
  z.object({ type: z.literal("call.join"), channelId: uuidSchema }),
  z.object({ type: z.literal("call.leave"), channelId: uuidSchema }),
  z.object({
    type: z.literal("call.signal"),
    channelId: uuidSchema,
    to: z.string().min(1),
    payload: z.unknown(),
  }),
  // MLS key packages / welcome
  z.object({ type: z.literal("keypackage.upload"), keyPackageB64: z.string().min(1) }),
  z.object({ type: z.literal("keypackage.get"), targetIdentityId: z.string().min(1) }),
  z.object({ type: z.literal("welcome.push"), targetIdentityId: z.string().min(1), welcomeB64: z.string().min(1) }),
  z.object({ type: z.literal("welcome.pending") }),
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
