import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { networkInterfaces } from "node:os";
import { EventEmitter } from "node:events";
import type { Channel, HostEvent, MessageEnvelope, Role } from "@janjacord/schemas";
import { ROLE_LEVELS, PermissionFlagSchema } from "@janjacord/schemas";
import { evaluatePermission, canModify, type MemberContext } from "@janjacord/permissions";
import { formatInviteKey, parseInviteKey, sha256Hex } from "@janjacord/crypto";
import { ReplayGuard, SequenceTracker, decodeEnvelope } from "@janjacord/protocol";
import { readFileSync as _readFileSync } from "node:fs";
import type { Store } from "./store.js";

// helper para acesso a fs sem import no topo do TS (usado no snapshot)
function require_node_fs(): typeof import("node:fs") {
  return { readFileSync: _readFileSync } as unknown as typeof import("node:fs");
}

export type HostResult<T> = { ok: true; data: T } | { ok: false; error: { code: string; message: string } };

const ok = <T>(data: T): HostResult<T> => ({ ok: true, data });
const fail = (code: string, message: string): HostResult<never> => ({ ok: false, error: { code, message } });

interface MemberRow {
  identity_id: string;
  nickname: string;
  role_id: string;
  joined_at: number;
  presence: string;
}

export class ServerService {
  /** Eventos para o gateway: deliver(identityId, envelope), presence(identityId, state), stateChanged(). */
  readonly events = new EventEmitter();
  readonly replay = new ReplayGuard(60 * 60 * 1000); // 1h janela anti-replay (retention default 7d > janela)
  readonly sequences = new Map<string, SequenceTracker>();

  constructor(
    private readonly store: Store,
    private readonly serverId: string,
    private readonly dbPath: string,
    private readonly ownerIdentity: string,
    private readonly ownerNickname: string,
    private readonly serverName: string,
  ) {}

  /** Boot do host: roles default, owner, canal #general (idempotente). */
  bootstrap(): void {
    const db = this.store.raw;
    const hasRoles = db.prepare("SELECT 1 FROM roles LIMIT 1").get();
    if (!hasRoles) {
      db.transaction(() => {
        db.prepare("INSERT INTO server_meta (key, value) VALUES (?, ?)").run("server_name", this.serverName);
        db.prepare("INSERT INTO server_meta (key, value) VALUES (?, ?)").run(
          "server_key",
          randomBytes(32).toString("hex"),
        );
        db.prepare("INSERT INTO server_meta (key, value) VALUES (?, ?)").run(
          "config",
          JSON.stringify({
            maxRetentionHours: 168,
            networkPrivacy: "direct",
            maxAttachmentBytes: 50 * 1024 * 1024,
            maxSpoolBytes: 2 * 1024 * 1024 * 1024,
            maxVoiceParticipants: 10,
            maxVideoParticipants: 6,
          }),
        );
        const roles: Role[] = [
          { id: "role-owner", name: "Owner", level: ROLE_LEVELS.owner, permissions: [] },
          { id: "role-admin", name: "Admin", level: ROLE_LEVELS.admin, permissions: ["manage_server", "manage_channels", "manage_roles", "manage_invites", "kick_members", "ban_members", "assign_roles", "view_channel", "send_messages", "send_files", "join_call", "speak", "enable_camera", "mute_members", "remove_from_call"] },
          { id: "role-mod", name: "Moderator", level: ROLE_LEVELS.moderator, permissions: ["kick_members", "view_channel", "send_messages", "send_files", "join_call", "speak", "enable_camera", "mute_members", "remove_from_call"] },
          { id: "role-member", name: "Member", level: ROLE_LEVELS.member, permissions: ["view_channel", "send_messages", "send_files", "join_call", "speak", "enable_camera"] },
        ];
        for (const r of roles) {
          db.prepare("INSERT INTO roles (id, name, level, permissions, created_at) VALUES (?,?,?,?,?)").run(
            r.id, r.name, r.level, JSON.stringify(r.permissions), Date.now(),
          );
        }
        db.prepare("INSERT INTO members (identity_id, nickname, role_id, joined_at) VALUES (?,?,?,?)").run(
          this.ownerIdentity, this.ownerNickname, "role-owner", Date.now(),
        );
        db.prepare("INSERT INTO channels (id, type, name, overrides, created_at) VALUES (?,?,?,?,?)").run(
          randomUUID(), "text", "general", "[]", Date.now(),
        );
        this.store.appendOp({ type: "bootstrap", serverId: this.serverId });
      })();
      this.events.emit("stateChanged");
    }
  }

  // ------------------------------------------------------------------ state

  updateConfig(actorId: string, patch: Record<string, unknown>): HostResult<Record<string, unknown>> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const actorRole = this.getRole(actor.role_id)!;
    if (!evaluatePermission(this.memberContext(actor), actorRole, null, "manage_server")) {
      return fail("forbidden", "no manage_server");
    }
    const cur = this.getConfig();
    const next = { ...cur, ...patch };
    this.store.raw
      .prepare("INSERT INTO server_meta (key, value) VALUES ('config', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .run(JSON.stringify(next));
    this.store.appendOp({ type: "updateConfig", patch });
    this.events.emit("stateChanged");
    return ok(next);
  }

  getConfig(): Record<string, unknown> {
    const row = this.store.raw.prepare("SELECT value FROM server_meta WHERE key = 'config'").get() as
      | { value: string }
      | undefined;
    return row ? JSON.parse(row.value) : {};
  }

  getState(identityId: string): HostResult<Record<string, unknown>> {
    const member = this.getMember(identityId);
    if (!member) return fail("forbidden", "not a member");
    const rawRoles = this.allRows("roles") as unknown as {
      id: string; name: string; level: number; permissions: string; created_at: number;
    }[];
    const roles: Role[] = rawRoles.map((r) => ({
      id: r.id,
      name: r.name,
      level: r.level,
      permissions: JSON.parse(r.permissions) as Role["permissions"],
      created_at: r.created_at,
    }));
    const rawChannels = this.allRows("channels") as unknown as {
      id: string; type: string; name: string; overrides: string; created_at: number;
    }[];
    const channels: Channel[] = rawChannels.map((c) => ({
      id: c.id,
      serverId: this.serverId,
      type: c.type as Channel["type"],
      name: c.name,
      overrides: JSON.parse(c.overrides) as Channel["overrides"],
      createdAt: c.created_at,
    }));
    const members = this.allRows("members") as unknown as MemberRow[];
    return ok({
      serverId: this.serverId,
      serverName: this.serverName,
      config: this.getConfig(),
      roles,
      channels,
      members: members.map((m) => ({ identityId: m.identity_id, nickname: m.nickname, roleId: m.role_id, presence: m.presence })),
      me: { identityId, nickname: member.nickname, roleId: member.role_id },
    });
  }

  // ----------------------------------------------------------------- helpers

  private allRows(table: string): unknown[] {
    return this.store.raw.prepare(`SELECT * FROM ${table}`).all();
  }

  private getMember(identityId: string): MemberRow | undefined {
    return this.store.raw
      .prepare("SELECT * FROM members WHERE identity_id = ?")
      .get(identityId) as MemberRow | undefined;
  }

  private getRole(roleId: string): Role | undefined {
    return this.store.raw
      .prepare("SELECT * FROM roles WHERE id = ?")
      .get(roleId) as unknown as Role | undefined;
  }

  private getChannel(channelId: string): Channel | undefined {
    const row = this.store.raw
      .prepare("SELECT * FROM channels WHERE id = ?")
      .get(channelId) as
      | { id: string; serverId?: string; type: string; name: string; overrides: string; created_at: number }
      | undefined;
    if (!row) return undefined;
    return {
      id: row.id,
      serverId: this.serverId,
      type: row.type as Channel["type"],
      name: row.name,
      overrides: JSON.parse(row.overrides) as Channel["overrides"],
      createdAt: row.created_at,
    };
  }

  private memberContext(m: MemberRow): MemberContext {
    return { identityId: m.identity_id, roleId: m.role_id, isOwner: m.role_id === "role-owner" };
  }

  private seqFor(channelId: string): SequenceTracker {
    let t = this.sequences.get(channelId);
    if (!t) {
      t = new SequenceTracker();
      this.sequences.set(channelId, t);
    }
    return t;
  }

  getServerId(): string {
    return this.serverId;
  }

  getEpochPublic(): number {
    return this.getEpoch();
  }

  private serverKey(): Buffer {
    const row = this.store.raw.prepare("SELECT value FROM server_meta WHERE key = 'server_key'").get() as { value: string };
    return Buffer.from(row.value, "hex");
  }

  private isBanned(identityId: string): boolean {
    return !!this.store.raw.prepare("SELECT 1 FROM bans WHERE identity_id = ?").get(identityId);
  }

  // ------------------------------------------------------------- membership

  joinByInvite(identityId: string, nickname: string, secret: string): HostResult<Record<string, unknown>> {
    if (this.getMember(identityId)) return fail("conflict", "already a member");
    if (this.isBanned(identityId)) return fail("banned", "identity banned from this server");
    const parsed = parseInviteKey(secret);
    if (!parsed) return fail("invalid_invite", "invite malformado");
    if (parsed.serverId !== this.serverId) return fail("invalid_invite", "invite de outro server");
    const secretBytes = parsed.secret;
    const hash = sha256Hex(createHmac("sha256", this.serverKey()).update(secretBytes).digest());
    const invite = this.store.raw
      .prepare("SELECT * FROM invites WHERE secret_hash = ?")
      .get(hash) as
      | { id: string; initial_role_id: string; max_uses: number; used: number; expires_at: number | null; revoked: number }
      | undefined;
    if (!invite) return fail("invalid_invite", "invite not found");
    if (invite.revoked) return fail("invite_revoked", "invite revoked");
    if (invite.expires_at && invite.expires_at < Date.now()) return fail("invite_expired", "invite expired");
    if (invite.used >= invite.max_uses) return fail("invite_exhausted", "invite exhausted");
    this.store.raw.transaction(() => {
      this.store.raw.prepare("UPDATE invites SET used = used + 1 WHERE id = ?").run(invite.id);
      this.store.raw
        .prepare("INSERT INTO members (identity_id, nickname, role_id, joined_at) VALUES (?,?,?,?)")
        .run(identityId, nickname, invite.initial_role_id, Date.now());
      this.store.appendOp({ type: "join", identityId, inviteId: invite.id });
    })();
    this.events.emit("stateChanged");
    return this.getState(identityId);
  }

  leave(identityId: string): HostResult<null> {
    const m = this.getMember(identityId);
    if (!m) return fail("not_found", "not a member");
    if (m.role_id === "role-owner") return fail("forbidden", "owner cannot leave; transfer ownership first");
    this.store.raw.prepare("DELETE FROM members WHERE identity_id = ?").run(identityId);
    this.store.appendOp({ type: "leave", identityId });
    this.events.emit("memberRemoved", identityId, "left");
    this.events.emit("stateChanged");
    return ok(null);
  }

  transferOwnership(actorId: string, newOwnerId: string): HostResult<null> {
    const actor = this.getMember(actorId);
    const target = this.getMember(newOwnerId);
    if (!actor || actor.role_id !== "role-owner") return fail("forbidden", "only owner can transfer");
    if (!target) return fail("not_found", "target not a member");
    this.store.raw.transaction(() => {
      this.store.raw.prepare("UPDATE members SET role_id = 'role-member' WHERE identity_id = ?").run(actorId);
      this.store.raw.prepare("UPDATE members SET role_id = 'role-owner' WHERE identity_id = ?").run(newOwnerId);
      this.store.appendOp({ type: "transferOwnership", from: actorId, to: newOwnerId });
    })();
    this.events.emit("stateChanged");
    return ok(null);
  }

  // ----------------------------------------------------------------- invites

  inviteCreate(
    actorId: string,
    initialRoleId: string,
    maxUses: number,
    expiresInMs?: number,
  ): HostResult<{ inviteKey: string }> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const role = this.getRole(initialRoleId);
    if (!role) return fail("not_found", "role not found");
    const actorRole = this.getRole(actor.role_id)!;
    const actorCtx = this.memberContext(actor);
    if (!evaluatePermission(actorCtx, actorRole, null, "manage_invites")) {
      return fail("forbidden", "no manage_invites");
    }
    const secret = randomBytes(16);
    const hash = sha256Hex(createHmac("sha256", this.serverKey()).update(secret).digest());
    const id = randomUUID();
    this.store.raw
      .prepare("INSERT INTO invites (id, secret_hash, initial_role_id, max_uses, used, expires_at, revoked, created_at) VALUES (?,?,?,?,0,?,0,?)")
      .run(id, hash, initialRoleId, maxUses, expiresInMs ? Date.now() + expiresInMs : null, Date.now());
    this.store.appendOp({ type: "inviteCreate", inviteId: id });
    this.events.emit("stateChanged");
    return ok({ inviteKey: formatInviteKey(this.serverId, secret, detectHostEndpoint()) });
  }

  inviteRevoke(actorId: string, inviteId: string): HostResult<null> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const actorRole = this.getRole(actor.role_id)!;
    if (!evaluatePermission(this.memberContext(actor), actorRole, null, "manage_invites")) {
      return fail("forbidden", "no manage_invites");
    }
    const r = this.store.raw.prepare("UPDATE invites SET revoked = 1 WHERE id = ?").run(inviteId);
    if (r.changes === 0) return fail("not_found", "invite not found");
    this.store.appendOp({ type: "inviteRevoke", inviteId });
    this.events.emit("stateChanged");
    return ok(null);
  }

  listInvites(actorId: string): HostResult<unknown[]> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const actorRole = this.getRole(actor.role_id)!;
    if (!evaluatePermission(this.memberContext(actor), actorRole, null, "manage_invites")) {
      return fail("forbidden", "no manage_invites");
    }
    const rows = this.store.raw
      .prepare("SELECT id, initial_role_id, max_uses, used, expires_at, revoked, created_at FROM invites")
      .all();
    return ok(rows);
  }

  // -------------------------------------------------------------- channels

  channelCreate(actorId: string, type: "text" | "call", name: string): HostResult<Channel> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const actorRole = this.getRole(actor.role_id)!;
    if (!evaluatePermission(this.memberContext(actor), actorRole, null, "manage_channels")) {
      return fail("forbidden", "no manage_channels");
    }
    const channel: Channel = { id: randomUUID(), serverId: this.serverId, type, name, overrides: [], createdAt: Date.now() };
    this.store.raw
      .prepare("INSERT INTO channels (id, type, name, overrides, created_at) VALUES (?,?,?,?,?)")
      .run(channel.id, channel.type, channel.name, "[]", channel.createdAt);
    this.store.appendOp({ type: "channelCreate", channelId: channel.id });
    this.events.emit("stateChanged");
    return ok(channel);
  }

  channelUpdateOverrides(
    actorId: string,
    channelId: string,
    overrides: Channel["overrides"],
  ): HostResult<Channel> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const actorRole = this.getRole(actor.role_id)!;
    if (!evaluatePermission(this.memberContext(actor), actorRole, null, "manage_channels")) {
      return fail("forbidden", "no manage_channels");
    }
    const channel = this.getChannel(channelId);
    if (!channel) return fail("not_found", "channel not found");
    this.store.raw.prepare("UPDATE channels SET overrides = ? WHERE id = ?").run(JSON.stringify(overrides), channelId);
    this.store.appendOp({ type: "channelOverrides", channelId });
    this.events.emit("stateChanged");
    return ok({ ...channel, overrides });
  }

  // ----------------------------------------------------------------- roles

  roleCreate(actorId: string, name: string, level: number, permissions: string[]): HostResult<Role> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const actorRole = this.getRole(actor.role_id)!;
    if (!evaluatePermission(this.memberContext(actor), actorRole, null, "manage_roles")) {
      return fail("forbidden", "no manage_roles");
    }
    const role: Role = { id: randomUUID(), name, level, permissions: PermissionFlagSchema.options.filter((p) => permissions.includes(p)) };
    this.store.raw
      .prepare("INSERT INTO roles (id, name, level, permissions, created_at) VALUES (?,?,?,?,?)")
      .run(role.id, role.name, role.level, JSON.stringify(role.permissions), Date.now());
    this.store.appendOp({ type: "roleCreate", roleId: role.id });
    this.events.emit("stateChanged");
    return ok(role);
  }

  roleAssign(actorId: string, memberIdentityId: string, roleId: string): HostResult<null> {
    const actor = this.getMember(actorId);
    const target = this.getMember(memberIdentityId);
    if (!actor || !target) return fail("not_found", "member not found");
    const actorRole = this.getRole(actor.role_id)!;
    const targetRole = this.getRole(target.role_id)!;
    if (!canModify({ ...this.memberContext(actor), role: actorRole }, targetRole, "assign_roles")) {
      return fail("forbidden", "cannot assign roles at/above your level");
    }
    const newRole = this.getRole(roleId);
    if (!newRole) return fail("not_found", "role not found");
    this.store.raw.prepare("UPDATE members SET role_id = ? WHERE identity_id = ?").run(roleId, memberIdentityId);
    this.store.appendOp({ type: "roleAssign", member: memberIdentityId, roleId });
    this.events.emit("stateChanged");
    return ok(null);
  }

  // ------------------------------------------------------------------ kick/ban

  kick(actorId: string, targetId: string): HostResult<null> {
    const actor = this.getMember(actorId);
    const target = this.getMember(targetId);
    if (!actor || !target) return fail("not_found", "member not found");
    const actorRole = this.getRole(actor.role_id)!;
    const targetRole = this.getRole(target.role_id)!;
    if (!canModify({ ...this.memberContext(actor), role: actorRole }, targetRole, "kick_members")) {
      return fail("forbidden", "cannot kick member at/above your level");
    }
    this.store.raw.prepare("DELETE FROM members WHERE identity_id = ?").run(targetId);
    this.store.appendOp({ type: "kick", member: targetId });
    this.events.emit("memberRemoved", targetId, "kick");
    this.events.emit("stateChanged");
    return ok(null);
  }

  ban(actorId: string, targetId: string): HostResult<null> {
    const actor = this.getMember(actorId);
    const target = this.getMember(targetId);
    if (!actor || !target) return fail("not_found", "member not found");
    const actorRole = this.getRole(actor.role_id)!;
    const targetRole = this.getRole(target.role_id)!;
    if (!canModify({ ...this.memberContext(actor), role: actorRole }, targetRole, "ban_members")) {
      return fail("forbidden", "cannot ban member at/above your level");
    }
    this.store.raw.transaction(() => {
      this.store.raw.prepare("DELETE FROM members WHERE identity_id = ?").run(targetId);
      this.store.raw.prepare("INSERT INTO bans (identity_id, banned_at) VALUES (?, ?)").run(targetId, Date.now());
      this.store.appendOp({ type: "ban", member: targetId });
    })();
    this.events.emit("memberRemoved", targetId, "ban");
    this.events.emit("stateChanged");
    return ok(null);
  }

  // ------------------------------------------------------------------- spool

  sendEnvelope(actorId: string, envelope: MessageEnvelope): HostResult<null> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    if (envelope.serverId !== this.serverId) return fail("invalid_input", "server mismatch");
    const channel = this.getChannel(envelope.channelId);
    if (!channel) return fail("not_found", "channel not found");
    const actorRole = this.getRole(actor.role_id)!;
    const need: "send_messages" | "send_files" = envelope.attachments.length > 0 ? "send_files" : "send_messages";
    if (!evaluatePermission(this.memberContext(actor), actorRole, channel, need)) {
      return fail("forbidden", `no ${need}`);
    }
    if (envelope.sender !== actorId) return fail("forbidden", "sender mismatch");
    if (!this.replay.check(envelope.messageId)) return fail("conflict", "duplicate messageId (replay)");
    const seq = this.seqFor(envelope.channelId).next(actorId);
    envelope.ordering = { seq, prevMessageId: undefined };

    // recipients = audiência ∩ membros com view_channel
    const members = this.allRows("members") as unknown as MemberRow[];
    const recipients: string[] = [];
    for (const m of members) {
      const role = this.getRole(m.role_id)!;
      if (envelope.audience.members.includes(m.identity_id) && evaluatePermission(this.memberContext(m), role, channel, "view_channel")) {
        recipients.push(m.identity_id);
      }
    }
    const retentionH = (this.getConfig().maxRetentionHours as number) ?? 168;
    const expiresAt = Math.min(
      Date.now() + retentionH * 3600_000,
      envelope.expiresAt ?? Number.POSITIVE_INFINITY,
    );
    this.store.raw
      .prepare("INSERT INTO spool (message_id, channel_id, envelope, expires_at, recipients, consumed, created_at) VALUES (?,?,?,?,?,?,?)")
      .run(envelope.messageId, envelope.channelId, JSON.stringify(envelope), expiresAt, JSON.stringify(recipients), "[]", Date.now());
    this.store.appendOp({ type: "envelope", messageId: envelope.messageId });

    for (const r of recipients) {
      if (r !== actorId) this.events.emit("deliver", r, envelope);
    }
    this.events.emit("activity");
    return ok(null);
  }

  getPending(identityId: string): HostResult<MessageEnvelope[]> {
    const member = this.getMember(identityId);
    if (!member) return fail("forbidden", "not a member");
    const rows = this.store.raw
      .prepare("SELECT envelope, recipients FROM spool WHERE recipients LIKE ?")
      .all(`%${identityId}%`) as { envelope: string }[];
    const out: MessageEnvelope[] = [];
    for (const r of rows) {
      const env = JSON.parse(r.envelope) as MessageEnvelope;
      if (env.audience.members.includes(identityId)) out.push(env);
    }
    return ok(out.sort((a, b) => a.createdAt - b.createdAt));
  }

  ackConsumed(identityId: string, messageId: string): HostResult<null> {
    const member = this.getMember(identityId);
    if (!member) return fail("forbidden", "not a member");
    const row = this.store.raw.prepare("SELECT recipients, consumed FROM spool WHERE message_id = ?").get(messageId) as
      | { recipients: string; consumed: string }
      | undefined;
    if (!row) return ok(null); // já purgada — idempotente
    const recipients = JSON.parse(row.recipients) as string[];
    const consumed = new Set(JSON.parse(row.consumed) as string[]);
    if (recipients.includes(identityId)) consumed.add(identityId);
    this.store.raw.prepare("UPDATE spool SET consumed = ? WHERE message_id = ?").run(JSON.stringify([...consumed]), messageId);
    if (recipients.every((r) => consumed.has(r))) {
      // purge imediato (ADR-004: todos consumiram)
      this.purgeMessage(messageId);
    }
    return ok(null);
  }

  private purgeMessage(messageId: string): void {
    this.store.raw.prepare("DELETE FROM spool WHERE message_id = ?").run(messageId);
    this.store.appendOp({ type: "purge", messageId });
    this.events.emit("purged", messageId);
  }

  /** Cron de retenção: hard purge de expirados (default 7d; ADR-004). */
  startRetentionLoop(intervalMs = 60_000): NodeJS.Timeout {
    return setInterval(() => {
      const rows = this.store.raw.prepare("SELECT message_id FROM spool WHERE expires_at < ?").all(Date.now()) as {
        message_id: string;
      }[];
      for (const r of rows) this.purgeMessage(r.message_id);
    }, intervalMs);
  }

  // ------------------------------------------------- key packages / welcome (MLS)

  /** Publica o KeyPackage MLS do membro (TTL 24h; o owner puxa para add ao grupo). */
  keyPackageUpload(identityId: string, keyPackageB64: string): HostResult<null> {
    const m = this.getMember(identityId);
    if (!m) return fail("forbidden", "not a member");
    this.store.raw
      .prepare("INSERT INTO key_packages (identity_id, key_package, expires_at) VALUES (?,?,?) ON CONFLICT(identity_id) DO UPDATE SET key_package=excluded.key_package, expires_at=excluded.expires_at")
      .run(identityId, keyPackageB64, Date.now() + 24 * 3600_000);
    return ok(null);
  }

  keyPackageGet(identityId: string, targetId: string): HostResult<{ keyPackageB64: string }> {
    if (!this.getMember(identityId)) return fail("forbidden", "not a member");
    const row = this.store.raw
      .prepare("SELECT key_package FROM key_packages WHERE identity_id = ? AND expires_at > ?")
      .get(targetId, Date.now()) as { key_package: string } | undefined;
    if (!row) return fail("not_found", "no key package for member");
    return ok({ keyPackageB64: row.key_package });
  }

  /** Owner entrega o welcome MLS ao novo membro (cifrado para o KeyPackage dele). */
  welcomePush(actorId: string, targetIdentityId: string, welcomeB64: string): HostResult<null> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const target = this.getMember(targetIdentityId);
    if (!target) return fail("not_found", "target not a member");
    this.store.raw
      .prepare("INSERT INTO welcomes (identity_id, welcome, created_at) VALUES (?,?,?) ON CONFLICT(identity_id) DO UPDATE SET welcome=excluded.welcome, created_at=excluded.created_at")
      .run(targetIdentityId, welcomeB64, Date.now());
    this.events.emit("welcome", targetIdentityId, welcomeB64);
    return ok(null);
  }

  welcomePending(identityId: string): HostResult<{ welcomeB64: string } | null> {
    const row = this.store.raw
      .prepare("SELECT welcome FROM welcomes WHERE identity_id = ?")
      .get(identityId) as { welcome: string } | undefined;
    if (!row) return ok(null);
    this.store.raw.prepare("DELETE FROM welcomes WHERE identity_id = ?").run(identityId);
    return ok({ welcomeB64: row.welcome });
  }

  // -------------------------------------------------------------- replicação

  /** Snapshot do DB cifrado (o arquivo inteiro é SQLCipher — seguro copiar). */
  getSnapshot(): HostResult<{ dbB64: string; epoch: number; seq: number }> {
    const { readFileSync } = require_node_fs();
    const file = this.storeFile();
    const dbB64 = readFileSync(file).toString("base64");
    const epoch = this.getEpoch();
    const row = this.store.raw.prepare("SELECT MAX(seq) AS s FROM op_log").get() as { s: number | null };
    return ok({ dbB64, epoch, seq: row.s ?? 0 });
  }

  private storeFile(): string {
    return this.dbPath;
  }

  private getEpoch(): number {
    const row = this.store.raw.prepare("SELECT value FROM server_meta WHERE key = 'epoch'").get() as
      | { value: string }
      | undefined;
    return row ? Number(row.value) : 0;
  }

  /** Promoção de réplica (ADR-011): incrementa o epoch (fencing) e assume como primary. */
  promote(actorId: string): HostResult<{ epoch: number }> {
    const m = this.getMember(actorId);
    if (!m) return fail("forbidden", "not a member");
    const next = this.getEpoch() + 1;
    this.store.raw
      .prepare("INSERT INTO server_meta (key, value) VALUES ('epoch', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .run(String(next));
    this.store.appendOp({ type: "promote", epoch: next });
    this.events.emit("stateChanged");
    return ok({ epoch: next });
  }

  // ------------------------------------------------------------- attachments

  attachmentUpload(
    actorId: string,
    assetId: string,
    dataB64: string,
    sizeBytes: number,
    ttlHours = 24,
  ): HostResult<null> {
    if (!this.getMember(actorId)) return fail("forbidden", "not a member");
    const maxBytes = (this.getConfig().maxAttachmentBytes as number) ?? 50 * 1024 * 1024;
    if (sizeBytes > maxBytes) return fail("invalid_input", `attachment exceeds limit (${maxBytes})`);
    const spoolQuota = (this.getConfig().maxSpoolBytes as number) ?? 2 * 1024 * 1024 * 1024;
    const total = this.store.raw.prepare("SELECT COALESCE(SUM(size_bytes),0) AS t FROM attachments").get() as { t: number };
    if (total.t + sizeBytes > spoolQuota) return fail("rate_limited", "spool quota exceeded");
    this.store.raw
      .prepare("INSERT INTO attachments (asset_id, data, size_bytes, expires_at, created_at) VALUES (?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET data=excluded.data, size_bytes=excluded.size_bytes, expires_at=excluded.expires_at")
      .run(assetId, dataB64, sizeBytes, Date.now() + ttlHours * 3600_000, Date.now());
    return ok(null);
  }

  attachmentDownload(actorId: string, assetId: string): HostResult<{ data: string; sizeBytes: number }> {
    if (!this.getMember(actorId)) return fail("forbidden", "not a member");
    const row = this.store.raw
      .prepare("SELECT data, size_bytes FROM attachments WHERE asset_id = ? AND expires_at > ?")
      .get(assetId, Date.now()) as { data: string; size_bytes: number } | undefined;
    if (!row) return fail("not_found", "attachment not found or expired");
    return ok({ data: row.data, sizeBytes: row.size_bytes });
  }

  /** Cleanup de attachments expirados (alinhado à retention). */
  startAttachmentCleanup(intervalMs = 60_000): NodeJS.Timeout {
    return setInterval(() => {
      this.store.raw.prepare("DELETE FROM attachments WHERE expires_at < ?").run(Date.now());
    }, intervalMs);
  }

  // -------------------------------------------------------------------- call

  private calls = new Map<string, Set<string>>(); // channelId -> identityIds (efêmero)

  callJoin(identityId: string, channelId: string): HostResult<{ participants: string[] }> {
    const m = this.getMember(identityId);
    if (!m) return fail("forbidden", "not a member");
    const channel = this.getChannel(channelId);
    if (!channel || channel.type !== "call") return fail("not_found", "call channel not found");
    const role = this.getRole(m.role_id)!;
    if (!evaluatePermission(this.memberContext(m), role, channel, "join_call")) {
      return fail("forbidden", "no join_call");
    }
    const limit = (this.getConfig().maxVoiceParticipants as number) ?? 10;
    const participants = this.calls.get(channelId) ?? new Set<string>();
    if (!participants.has(identityId) && participants.size >= limit) {
      return fail("channel_full", `call limit reached (${limit})`);
    }
    participants.add(identityId);
    this.calls.set(channelId, participants);
    this.events.emit("callMembership", channelId, [...participants]);
    return ok({ participants: [...participants] });
  }

  callLeave(identityId: string, channelId: string): HostResult<null> {
    const participants = this.calls.get(channelId);
    if (participants) {
      participants.delete(identityId);
      this.events.emit("callMembership", channelId, [...participants]);
    }
    return ok(null);
  }

  /** Rele de signaling entre peers (SDP/candidates passam pelo host; conteúdo é E2EE). */
  callSignal(identityId: string, channelId: string, to: string, payload: unknown): HostResult<null> {
    const participants = this.calls.get(channelId);
    if (!participants?.has(to) || !participants.has(identityId)) {
      return fail("forbidden", "both peers must be in the call");
    }
    this.events.emit("callSignal", to, { channelId, from: identityId, payload });
    return ok(null);
  }

  // ---------------------------------------------------------------- presence

  setPresence(identityId: string, state: "online" | "offline" | "in_call"): HostResult<null> {
    const m = this.getMember(identityId);
    if (!m) return fail("forbidden", "not a member");
    this.store.raw.prepare("UPDATE members SET presence = ? WHERE identity_id = ?").run(state, identityId);
    this.events.emit("presence", identityId, state);
    return ok(null);
  }
}

/** Endpoint alcançável do host para o convite autocontido (JC2).
 * Prioridade: Tailscale (100.x, estável entre redes) → primeiro IPv4 privado não-loopback. */
function detectHostEndpoint(port = 8931): string | undefined {
  const candidates: string[] = [];
  for (const list of Object.values(networkInterfaces())) {
    for (const i of list ?? []) {
      if (i.family === "IPv4" && !i.internal) {
        if (i.address.startsWith("100.")) candidates.unshift(i.address);
        else candidates.push(i.address);
      }
    }
  }
  return candidates.length ? `${candidates[0]}:${port}` : undefined;
}
