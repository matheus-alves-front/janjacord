import { WebSocket } from "ws";
import { randomBytes, randomUUID } from "node:crypto";
import { OnGatewayConnection, OnGatewayDisconnect, WebSocketGateway, WebSocketServer } from "@nestjs/websockets";
import { HostCommandSchema, PublicKeySchema, type HostCommand, type MessageEnvelope } from "@janjacord/schemas";
import { decodeEnvelope, verifySignedSessionAuth } from "@janjacord/protocol";
import { ServerService } from "./server.service.js";
import type { IncomingMessage } from "node:http";

const AUTH_DEADLINE_MS = 8_000;
const MAX_AUTH_ATTEMPTS_PER_ORIGIN_MINUTE = 20;
const MAX_ICE_CONNECTIONS_PER_SESSION = 4;
const ATTACHMENT_BEGIN_BUCKET_CAPACITY = 8;
const ATTACHMENT_BEGIN_REFILL_PER_SECOND = 2;

export class AttachmentBeginTokenBucket {
  private readonly buckets = new WeakMap<object, { tokens: number; updatedAt: number }>();

  consume(client: object, now = Date.now()): boolean {
    const current = this.buckets.get(client) ?? { tokens: ATTACHMENT_BEGIN_BUCKET_CAPACITY, updatedAt: now };
    const elapsedSeconds = Math.max(0, now - current.updatedAt) / 1_000;
    const tokens = Math.min(
      ATTACHMENT_BEGIN_BUCKET_CAPACITY,
      current.tokens + elapsedSeconds * ATTACHMENT_BEGIN_REFILL_PER_SECOND,
    );
    if (tokens < 1) {
      this.buckets.set(client, { tokens, updatedAt: now });
      return false;
    }
    this.buckets.set(client, { tokens: tokens - 1, updatedAt: now });
    return true;
  }
}

export function authenticatedOriginKey(remoteAddress: string | undefined, iceSessionHeader: string | string[] | undefined): { ip: string; iceSession: string | null } {
  const ip = (remoteAddress ?? "unknown").replace(/^::ffff:/, "");
  const candidate = typeof iceSessionHeader === "string" ? iceSessionHeader : "";
  const loopback = ip === "127.0.0.1" || ip === "::1";
  return { ip, iceSession: loopback && /^[A-Za-z0-9_-]{32,128}$/.test(candidate) ? candidate : null };
}

/**
 * Gateway de signaling (JanjaNode). O WsAdapter do Nest não expõe o socket aos handlers;
 * por isso o bind de mensagens é manual (handleConnection), mantendo controle total do
 * socket para resposta e push por identidade.
 */
@WebSocketGateway(Number(process.env.JC_PORT ?? 8931), { path: "/signal", maxPayload: 64 * 1024, perMessageDeflate: false })
export class SignalingGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() server!: unknown;
  private identities = new Map<WebSocket, string>();
  private devicePublicKeys = new Map<WebSocket, string>();
  private pendingDeviceEnrollment = new Set<WebSocket>();
  private challenges = new Map<WebSocket, { challengeId: string; nonce: string; identityId: string; publicKey: string; expiresAt: number }>();
  private malformedCount = new Map<WebSocket, { count: number; windowStart: number }>();
  private connectionIps = new Map<WebSocket, string>();
  private ipConnections = new Map<string, number>();
  private iceSessionConnections = new Map<string, number>();
  private connectionIceSessions = new Map<WebSocket, string>();
  private authDeadlines = new Map<WebSocket, ReturnType<typeof setTimeout>>();
  private authAttempts = new Map<string, { count: number; windowStart: number }>();
  private attachmentBeginBucket = new AttachmentBeginTokenBucket();
  private readonly MAX_MALFORMED_PER_MIN = 20;
  private readonly MAX_CONNECTIONS_PER_IP = 8;

  private trackMalformed(client: WebSocket): void {
    const now = Date.now();
    const cur = this.malformedCount.get(client);
    const bucket = !cur || now - cur.windowStart > 60_000 ? { count: 1, windowStart: now } : { count: cur.count + 1, windowStart: cur.windowStart };
    this.malformedCount.set(client, bucket);
    if (bucket.count > this.MAX_MALFORMED_PER_MIN) {
      console.warn(`[janjanode] malformed flood — encerrando socket`);
      client.close(1008, "rate_limited");
      this.malformedCount.delete(client);
    }
  }

  private acceptConnection(client: WebSocket, request?: IncomingMessage): boolean {
    const origin = authenticatedOriginKey(
      request?.socket.remoteAddress ?? (client as unknown as { _socket?: { remoteAddress?: string } })._socket?.remoteAddress,
      request?.headers["x-jc-ice-session"],
    );
    const ip = origin.ip;
    const cur = this.ipConnections.get(ip) ?? 0;
    const maxForOrigin = origin.iceSession ? 32 : this.MAX_CONNECTIONS_PER_IP;
    if (cur >= maxForOrigin) {
      client.close(1013, "too many connections");
      return false;
    }
    this.ipConnections.set(ip, cur + 1);
    this.connectionIps.set(client, ip);
    if (origin.iceSession) {
      const sessionCount = this.iceSessionConnections.get(origin.iceSession) ?? 0;
      if (sessionCount >= MAX_ICE_CONNECTIONS_PER_SESSION) {
        client.close(1013, "ICE session connection limit reached");
        this.ipConnections.set(ip, cur);
        this.connectionIps.delete(client);
        return false;
      }
      this.iceSessionConnections.set(origin.iceSession, sessionCount + 1);
      this.connectionIceSessions.set(client, origin.iceSession);
    }
    const timer = setTimeout(() => {
      if (!this.identityOf(client)) client.close(1008, "authentication deadline exceeded");
    }, AUTH_DEADLINE_MS);
    this.authDeadlines.set(client, timer);
    return true;
  }

  private consumeAuthAttempt(client: WebSocket): boolean {
    const key = `${this.connectionIps.get(client) ?? "unknown"}:${this.connectionIceSessions.get(client) ?? "direct"}`;
    const now = Date.now();
    const current = this.authAttempts.get(key);
    const next = !current || now - current.windowStart >= 60_000
      ? { count: 1, windowStart: now }
      : { count: current.count + 1, windowStart: current.windowStart };
    this.authAttempts.set(key, next);
    return next.count <= MAX_AUTH_ATTEMPTS_PER_ORIGIN_MINUTE;
  }

  private releaseConnection(client: WebSocket): void {
    const ip = this.connectionIps.get(client);
    if (ip) {
      this.ipConnections.set(ip, Math.max(0, (this.ipConnections.get(ip) ?? 1) - 1));
      this.connectionIps.delete(client);
    }
    this.malformedCount.delete(client);
    const sessionId = this.connectionIceSessions.get(client);
    if (sessionId) {
      const next = Math.max(0, (this.iceSessionConnections.get(sessionId) ?? 1) - 1);
      if (next === 0) this.iceSessionConnections.delete(sessionId);
      else this.iceSessionConnections.set(sessionId, next);
      this.connectionIceSessions.delete(client);
    }
    const deadline = this.authDeadlines.get(client);
    if (deadline) clearTimeout(deadline);
    this.authDeadlines.delete(client);
  }

  constructor(private readonly serverService: ServerService) {}

  afterInit(): void {
    this.serverService.events.on("deliver", (identityId: string, env: MessageEnvelope) => {
      this.push(identityId, { type: "envelope.deliver", envelope: env });
    });
    this.serverService.events.on("presence", (identityId: string, state: string) => {
      this.broadcast({ type: "member.presence", identityId, state });
    });
    this.serverService.events.on("memberRemoved", (identityId: string, reason: string) => {
      this.push(identityId, { type: "member.removed", identityId, reason });
      this.broadcast({ type: "member.removed", identityId, reason });
    });
    this.serverService.events.on("inviteUsed", (inviteId: string) => {
      this.broadcast({ type: "invite.used", inviteId });
    });
    this.serverService.events.on("stateChanged", () => {
      this.broadcast({ type: "server.stateChanged" });
    });
    this.serverService.events.on("welcome", (identityId: string, welcomeId: string, welcomeB64: string) => {
      this.push(identityId, { type: "welcome.deliver", welcomeId, welcomeB64 });
    });
    this.serverService.events.on("callMembership", (channelId: string, participants: string[]) => {
      for (const p of participants) this.push(p, { type: "call.members", channelId, participants });
    });
    this.serverService.events.on("callSignal", (to: string, data: unknown) => {
      this.push(to, { type: "call.signal", ...(data as object) });
    });
    console.log(`[janjanode] signaling ready on /signal`);
  }

  handleConnection(client: WebSocket, request?: IncomingMessage): void {
    if (!this.acceptConnection(client, request)) return;
    this.identities.set(client, "");
    client.on("message", (raw, isBinary) => {
      const frameBytes = Array.isArray(raw) ? raw.reduce((sum, entry) => sum + entry.byteLength, 0) : raw.byteLength;
      if (isBinary || frameBytes > 64 * 1024) {
        client.close(isBinary ? 1003 : 1009, isBinary ? "binary frames are forbidden" : "frame exceeds limit");
        return;
      }
      let frame: { event?: string; data?: unknown };
      try {
        frame = JSON.parse(raw.toString()) as { event?: string; data?: unknown };
        if (!frame || typeof frame !== "object") throw new Error("malformed");
      } catch {
        // frame malformado: conta como abuso e ignora
        this.trackMalformed(client);
        return;
      }
      this.handleFrame(client, frame);
    });
  }

  handleDisconnect(client: WebSocket): void {
    const id = this.identities.get(client);
    if (id && this.serverService.isWriter()) this.serverService.setPresence(id, "offline");
    this.identities.delete(client);
    this.devicePublicKeys.delete(client);
    this.pendingDeviceEnrollment.delete(client);
    this.challenges.delete(client);
    this.releaseConnection(client);
  }

  private identityOf(client: WebSocket): string {
    return this.identities.get(client) ?? "";
  }

  private send(client: WebSocket, frame: unknown): void {
    if (client.readyState === WebSocket.OPEN) client.send(JSON.stringify(frame));
  }

  private push(identityId: string, data: unknown): void {
    let sent = 0;
    for (const [ws, id] of this.identities) {
      if (id === identityId) {
        this.send(ws, { event: "event", data });
        sent++;
      }
    }
    if (sent === 0 && process.env.JC_DEBUG_LOGS === "1") console.log("[janjanode] push sem socket online");
  }

  private broadcast(data: unknown): void {
    for (const ws of this.identities.keys()) this.send(ws, { event: "event", data });
  }

  private handleFrame(client: WebSocket, frame: { event?: string; data?: unknown }): void {
    switch (frame.event) {
      case "auth.begin": {
        if (this.identityOf(client) || this.challenges.has(client) || !this.consumeAuthAttempt(client)) {
          client.close(1008, "authentication attempt rejected");
          return;
        }
        const input = (frame.data ?? {}) as { identityId?: string; publicKey?: string };
        if (!input.identityId || !PublicKeySchema.safeParse(input.publicKey).success) {
          this.send(client, { event: "auth.error", data: { code: "invalid_input", message: "identityId and device public key required" } });
          client.close(1008, "invalid authentication begin");
          return;
        }
        const challenge = {
          challengeId: randomUUID(),
          nonce: randomBytes(32).toString("base64url"),
          identityId: input.identityId,
          publicKey: input.publicKey!,
          expiresAt: Date.now() + AUTH_DEADLINE_MS,
        };
        this.challenges.set(client, challenge);
        this.send(client, {
          event: "auth.challenge",
          data: this.serverService.signedAuthChallenge(challenge.challengeId, challenge.nonce, challenge.expiresAt),
        });
        return;
      }
      case "auth.prove": {
        if (!this.consumeAuthAttempt(client)) {
          client.close(1008, "authentication rate limit exceeded");
          return;
        }
        const challenge = this.challenges.get(client);
        if (!challenge || challenge.expiresAt <= Date.now()) {
          this.send(client, { event: "auth.error", data: { code: "unauthorized", message: "challenge missing or expired" } });
          client.close(1008, "authentication challenge expired");
          return;
        }
        const proof = verifySignedSessionAuth(frame.data, {
          serverId: this.serverService.getServerId(),
          challengeId: challenge.challengeId,
          nonce: challenge.nonce,
        });
        this.challenges.delete(client);
        if (!proof || proof.payload.identityId !== challenge.identityId || proof.payload.publicKey !== challenge.publicKey) {
          this.send(client, { event: "auth.error", data: { code: "unauthorized", message: "invalid device proof" } });
          client.close(1008, "invalid device proof");
          return;
        }
        const needsEnrollment = this.serverService.isMember(proof.payload.identityId) && !this.serverService.isAuthorizedDevice(proof.payload.identityId, proof.payload.publicKey);
        this.identities.set(client, proof.payload.identityId);
        this.devicePublicKeys.set(client, proof.payload.publicKey);
        if (needsEnrollment) this.pendingDeviceEnrollment.add(client);
        const deadline = this.authDeadlines.get(client);
        if (deadline) clearTimeout(deadline);
        this.authDeadlines.delete(client);
        this.send(client, { event: "auth.ready", data: { identityId: proof.payload.identityId, needsEnrollment } });
        return;
      }
      case "hello": {
        const p = (frame.data ?? {}) as { identityId?: string };
        let identityId = this.identityOf(client);
        if (!identityId && process.env.JC_ALLOW_LEGACY_AUTH === "1") {
          identityId = p.identityId ?? "";
          this.identities.set(client, identityId);
        }
        if (!identityId) {
          this.send(client, { event: "result", data: { ok: false, error: { code: "unauthorized", message: "device authentication required" } } });
          return;
        }
        if (p.identityId && p.identityId !== identityId) {
          this.send(client, { event: "result", data: { ok: false, error: { code: "unauthorized", message: "identity mismatch" } } });
          return;
        }
        if (this.pendingDeviceEnrollment.has(client)) {
          this.send(client, { event: "result", data: { ok: false, error: { code: "unauthorized", message: "device enrollment required" } } });
          return;
        }
        if (this.serverService.isWriter()) this.serverService.setPresence(identityId, "online");
        this.send(client, { event: "result", data: this.serverService.getState(identityId) });
        return;
      }
      case "command": {
        const identityId = this.identityOf(client);
        if (!identityId) {
          this.send(client, { event: "result", data: { ok: false, error: { code: "unauthorized", message: "hello first" } } });
          return;
        }
        const parsed = HostCommandSchema.safeParse(frame.data);
        if (!parsed.success) {
          this.send(client, { event: "result", data: { ok: false, error: { code: "invalid_input", message: "malformed command" } } });
          return;
        }
        if (this.pendingDeviceEnrollment.has(client) && parsed.data.type !== "device.enroll") {
          this.send(client, { event: "result", data: { ok: false, error: { code: "unauthorized", message: "device enrollment required" } } });
          return;
        }
        if (!this.serverService.canAcceptCommand(parsed.data.type)) {
          this.send(client, { event: "result", data: { ok: false, error: { code: "conflict", message: "replica is read-only until promoted" } } });
          return;
        }
        if (parsed.data.type === "attachment.upload.begin" && !this.attachmentBeginBucket.consume(client)) {
          this.send(client, { event: "result", data: { ok: false, error: { code: "rate_limited", message: "attachment upload rate exceeded" } } });
          return;
        }
        const result = this.route(client, identityId, parsed.data as HostCommand);
        if (parsed.data.type === "device.enroll" && (result as { ok?: boolean }).ok) this.pendingDeviceEnrollment.delete(client);
        this.send(client, { event: "result", data: result });
        return;
      }
      case "envelope.send": {
        const identityId = this.identityOf(client);
        if (!identityId) {
          this.send(client, { event: "result", data: { ok: false, error: { code: "unauthorized", message: "hello first" } } });
          return;
        }
        if (!this.serverService.isWriter()) {
          this.send(client, { event: "result", data: { ok: false, error: { code: "conflict", message: "replica is read-only until promoted" } } });
          return;
        }
        try {
          const env = decodeEnvelope(JSON.stringify(frame.data));
          this.send(client, { event: "result", data: this.serverService.sendEnvelope(identityId, env) });
        } catch (err) {
          console.error("[janjanode] envelope rejeitado:", (err as Error).message);
          this.send(client, { event: "result", data: { ok: false, error: { code: "invalid_input", message: "malformed envelope" } } });
        }
        return;
      }
      default:
        this.send(client, { event: "result", data: { ok: false, error: { code: "invalid_input", message: "unknown event" } } });
        if (!this.identityOf(client)) client.close(1008, "authenticate first");
    }
  }

  private route(client: WebSocket, identityId: string, cmd: HostCommand): unknown {
    const svc = this.serverService;
    switch (cmd.type) {
      case "server.create":
        return { ok: false, error: { code: "conflict", message: "server already provisioned on this host" } };
      case "server.join":
        return svc.joinByInvite(identityId, cmd.nickname ?? identityId, cmd.inviteKey, this.devicePublicKeys.get(client) ?? "");
      case "server.leave":
        return svc.leave(identityId);
      case "server.state":
        return svc.getState(identityId);
      case "connectivity.iceConfig":
        return svc.connectivityIceConfig(identityId);
      case "server.transferOwnership":
        return svc.transferOwnership(identityId, cmd.newOwnerIdentityId);
      case "server.updateConfig":
        return svc.updateConfig(identityId, cmd.config);
      case "invite.create":
        return svc.inviteCreate(identityId, cmd.initialRoleId, cmd.maxUses, cmd.expiresInMs);
      case "invite.revoke":
        return svc.inviteRevoke(identityId, cmd.inviteId);
      case "invite.list":
        return svc.inviteList(identityId);
      case "channel.create":
        return svc.channelCreate(identityId, cmd.channelType, cmd.name);
      case "channel.updateOverrides":
        return svc.channelUpdateOverrides(identityId, cmd.channelId, cmd.overrides);
      case "role.create":
        return svc.roleCreate(identityId, cmd.name, cmd.level, cmd.permissions);
      case "role.assign":
        return svc.roleAssign(identityId, cmd.memberIdentityId, cmd.roleId);
      case "host.grant.create":
        return svc.hostGrantCreate(
          identityId,
          cmd.subjectIdentityId,
          cmd.candidateId,
          cmd.capabilities,
          cmd.expiresInMs,
        );
      case "host.candidate.register":
        return svc.hostCandidateRegister(
          identityId,
          this.devicePublicKeys.get(client) ?? "",
          cmd.hostPublicKey,
          cmd.enrollmentPublicKey,
          cmd.hostId,
          cmd.deviceProof,
          cmd.hostProof,
        );
      case "host.grant.revoke":
        return svc.hostGrantRevoke(identityId, cmd.grantId, cmd.reason);
      case "host.grant.accept":
        return svc.hostGrantAccept(identityId, this.devicePublicKeys.get(client) ?? "", cmd.grantId, cmd.hostProof);
      case "host.grant.list":
        return svc.hostGrantList(identityId);
      case "device.link.authorize":
        return svc.authorizeDeviceLink(
          identityId,
          this.devicePublicKeys.get(client) ?? "",
          cmd.newDevicePublicKey,
          cmd.expiresInMs,
        );
      case "device.enroll":
        return svc.enrollDevice(identityId, this.devicePublicKeys.get(client) ?? "", cmd.capability);
      case "member.kick":
        return svc.kick(identityId, cmd.memberIdentityId);
      case "member.ban":
        return svc.ban(identityId, cmd.memberIdentityId);
      case "message.ackConsumed":
        return svc.ackConsumed(identityId, cmd.messageId);
      case "message.send":
        return svc.sendEnvelope(identityId, cmd.envelope);
      case "message.getPending":
        return svc.getPending(identityId);
      case "presence.set":
        return svc.setPresence(identityId, cmd.state);
      case "call.join":
        return svc.callJoin(identityId, cmd.channelId);
      case "call.leave":
        return svc.callLeave(identityId, cmd.channelId);
      case "call.signal":
        return svc.callSignal(identityId, cmd.channelId, cmd.to, cmd.payload);
      case "keypackage.upload":
        return svc.keyPackageUpload(identityId, cmd.keyPackageB64);
      case "keypackage.get":
        return svc.keyPackageGet(identityId, cmd.targetIdentityId);
      case "welcome.push":
        return svc.welcomePush(identityId, cmd.targetIdentityId, cmd.welcomeB64);
      case "welcome.pending":
        return svc.welcomePending(identityId);
      case "welcome.ackConsumed":
        return svc.welcomeAckConsumed(identityId, cmd.welcomeId);
      case "attachment.upload.begin":
        return svc.attachmentUploadBegin(
          identityId,
          cmd.assetId,
          cmd.channelId,
          cmd.audienceMembers,
          cmd.sizeBytes,
          cmd.totalChunks,
          cmd.hash,
          cmd.ttlHours,
        );
      case "attachment.upload.chunk":
        return svc.attachmentUploadChunk(identityId, cmd.assetId, cmd.index, cmd.data, cmd.sizeBytes, cmd.hash);
      case "attachment.upload.complete":
        return svc.attachmentUploadComplete(identityId, cmd.assetId);
      case "attachment.upload.abort":
        return svc.attachmentUploadAbort(identityId, cmd.assetId);
      case "attachment.download":
        return svc.attachmentDownload(identityId, cmd.assetId);
      case "attachment.download.chunk":
        return svc.attachmentDownloadChunk(identityId, cmd.assetId, cmd.index);
      case "replica.snapshot":
        return svc.getSnapshot(identityId, this.devicePublicKeys.get(client) ?? "", cmd.grantId, cmd.serverId);
      case "replica.enroll":
        return svc.enrollReplica(identityId, this.devicePublicKeys.get(client) ?? "", cmd.grantId, cmd.hostProof);
      case "replica.ping":
        return svc.replicaPing(
          identityId,
          this.devicePublicKeys.get(client) ?? "",
          cmd.grantId,
          cmd.serverId,
          cmd.epoch,
        );
      default: {
        const exhaustive: never = cmd;
        return { ok: false, error: { code: "invalid_input", message: `unhandled ${(exhaustive as { type: string }).type}` } };
      }
    }
  }
}
