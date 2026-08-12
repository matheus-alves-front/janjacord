import { z } from "zod";

/** Role hierarchy levels (V1 defaults, ADR/permissions spec). */
export const ROLE_LEVELS = {
  owner: 100,
  admin: 80,
  moderator: 50,
  member: 10,
} as const;

export type RoleLevel = (typeof ROLE_LEVELS)[keyof typeof ROLE_LEVELS];

/** Permission flags (V1, contrato LOCKED §42). */
export const PERMISSIONS = [
  // server
  "manage_server",
  "manage_channels",
  "manage_roles",
  "manage_invites",
  "manage_hosts",
  // members
  "kick_members",
  "ban_members",
  "assign_roles",
  // text
  "view_channel",
  "send_messages",
  "send_files",
  // call
  "join_call",
  "speak",
  "enable_camera",
  "mute_members",
  "remove_from_call",
] as const;

export const PermissionFlagSchema = z.enum(PERMISSIONS);
export type PermissionFlag = z.infer<typeof PermissionFlagSchema>;

export const RoleSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1).max(64),
  level: z.number().int().nonnegative(),
  permissions: z.array(PermissionFlagSchema).default([]),
});

export type Role = z.infer<typeof RoleSchema>;

/** Channel permission override: deny explícito vence allow de role (precedencia ADR). */
export const PermissionOverrideSchema = z.object({
  roleId: z.string().min(1),
  allow: z.array(PermissionFlagSchema).default([]),
  deny: z.array(PermissionFlagSchema).default([]),
});

export type PermissionOverride = z.infer<typeof PermissionOverrideSchema>;

export const ChannelTypeSchema = z.enum(["text", "call"]);
export type ChannelType = z.infer<typeof ChannelTypeSchema>;

export const ChannelSchema = z.object({
  id: z.string().min(1),
  serverId: z.string().min(1),
  type: ChannelTypeSchema,
  name: z.string().min(1).max(64),
  overrides: z.array(PermissionOverrideSchema).default([]),
  createdAt: z.number().int().nonnegative(),
});

export type Channel = z.infer<typeof ChannelSchema>;

export const RETENTION_OPTIONS = [1, 24, 168, 720] as const;
export const RetentionHoursSchema = z.union([
  z.literal(1),
  z.literal(24),
  z.literal(168),
  z.literal(720),
]);

export type RetentionHours = z.infer<typeof RetentionHoursSchema>;

export const NetworkPrivacySchema = z.enum(["direct", "relay"]);
export type NetworkPrivacy = z.infer<typeof NetworkPrivacySchema>;

/** Server-level policy, administrada pelo Owner (ADR-002). */
export const ServerConfigSchema = z.object({
  maxRetentionHours: RetentionHoursSchema.default(168),
  networkPrivacy: NetworkPrivacySchema.default("direct"),
  maxAttachmentBytes: z.number().int().positive().default(50 * 1024 * 1024),
  maxSpoolBytes: z.number().int().positive().default(2 * 1024 * 1024 * 1024),
  maxVoiceParticipants: z.number().int().positive().default(10),
  maxVideoParticipants: z.number().int().positive().default(6),
});

export type ServerConfig = z.infer<typeof ServerConfigSchema>;

export const PresenceStateSchema = z.enum(["online", "offline", "in_call"]);
export type PresenceState = z.infer<typeof PresenceStateSchema>;

/** Member identity within a server: authority is the cryptographic identity. */
export const MemberSchema = z.object({
  identityId: z.string().min(1),
  nickname: z.string().min(1).max(64),
  roleId: z.string().min(1),
  joinedAt: z.number().int().nonnegative(),
});

export type Member = z.infer<typeof MemberSchema>;

export const InviteSchema = z.object({
  inviteId: z.string().min(1),
  serverId: z.string().min(1),
  initialRoleId: z.string().min(1),
  maxUses: z.number().int().positive().default(1),
  used: z.number().int().nonnegative().default(0),
  expiresAt: z.number().int().nonnegative().nullable(),
  revoked: z.boolean().default(false),
  nonce: z.string().min(1),
});

export type Invite = z.infer<typeof InviteSchema>;
