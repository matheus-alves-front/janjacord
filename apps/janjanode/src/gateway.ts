import { WebSocket } from "ws";
import { OnGatewayConnection, OnGatewayDisconnect, WebSocketGateway, WebSocketServer } from "@nestjs/websockets";
import { HostCommandSchema, type HostCommand, type MessageEnvelope } from "@janjacord/schemas";
import { decodeEnvelope } from "@janjacord/protocol";
import { ServerService } from "./server.service.js";

/**
 * Gateway de signaling (JanjaNode). O WsAdapter do Nest não expõe o socket aos handlers;
 * por isso o bind de mensagens é manual (handleConnection), mantendo controle total do
 * socket para resposta e push por identidade.
 */
@WebSocketGateway(Number(process.env.JC_PORT ?? 8931), { path: "/signal" })
export class SignalingGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() server!: unknown;
  private identities = new Map<WebSocket, string>();

  constructor(private readonly serverService: ServerService) {}

  afterInit(): void {
    this.serverService.events.on("deliver", (identityId: string, env: MessageEnvelope) => {
      console.log(`[janjanode] deliver -> ${identityId} (${env.messageId})`);
      this.push(identityId, { type: "envelope.deliver", envelope: env });
    });
    this.serverService.events.on("presence", (identityId: string, state: string) => {
      this.broadcast({ type: "member.presence", identityId, state });
    });
    this.serverService.events.on("memberRemoved", (identityId: string, reason: string) => {
      this.push(identityId, { type: "member.removed", identityId, reason });
      this.broadcast({ type: "member.removed", identityId, reason });
    });
    this.serverService.events.on("stateChanged", () => {
      this.broadcast({ type: "server.stateChanged" });
    });
    this.serverService.events.on("welcome", (identityId: string, welcomeB64: string) => {
      this.push(identityId, { type: "welcome.deliver", welcomeB64 });
    });
    this.serverService.events.on("callMembership", (channelId: string, participants: string[]) => {
      for (const p of participants) this.push(p, { type: "call.members", channelId, participants });
    });
    this.serverService.events.on("callSignal", (to: string, data: unknown) => {
      console.log(`[janjanode] callSignal -> ${to}`);
      this.push(to, { type: "call.signal", ...(data as object) });
    });
    console.log(`[janjanode] signaling ready on /signal`);
  }

  handleConnection(client: WebSocket): void {
    this.identities.set(client, "");
    client.on("message", (raw) => {
      try {
        const frame = JSON.parse(raw.toString()) as { event?: string; data?: unknown };
        this.handleFrame(client, frame);
      } catch {
        // frame malformado: ignora (anti-abuso)
      }
    });
  }

  handleDisconnect(client: WebSocket): void {
    const id = this.identities.get(client);
    if (id) this.serverService.setPresence(id, "offline");
    this.identities.delete(client);
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
    if (sent === 0) console.log(`[janjanode] push ${identityId}: nenhum socket (online=${[...this.identities.values()].join(",")})`);
  }

  private broadcast(data: unknown): void {
    for (const ws of this.identities.keys()) this.send(ws, { event: "event", data });
  }

  private handleFrame(client: WebSocket, frame: { event?: string; data?: unknown }): void {
    switch (frame.event) {
      case "hello": {
        const p = (frame.data ?? {}) as { identityId?: string };
        const identityId = p.identityId ?? "";
        if (!identityId) {
          this.send(client, { event: "result", data: { ok: false, error: { code: "invalid_input", message: "identityId required" } } });
          return;
        }
        this.identities.set(client, identityId);
        this.serverService.setPresence(identityId, "online");
        this.send(client, { event: "result", data: this.serverService.getState(identityId) });
        return;
      }
      case "command": {
        console.log(`[janjanode] command frame: ${JSON.stringify(frame.data)?.slice(0, 100)}`);
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
        this.send(client, { event: "result", data: this.route(identityId, parsed.data as HostCommand) });
        return;
      }
      case "envelope.send": {
        const identityId = this.identityOf(client);
        if (!identityId) {
          this.send(client, { event: "result", data: { ok: false, error: { code: "unauthorized", message: "hello first" } } });
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
    }
  }

  private route(identityId: string, cmd: HostCommand): unknown {
    const svc = this.serverService;
    switch (cmd.type) {
      case "server.create":
        return { ok: false, error: { code: "conflict", message: "server already provisioned on this host" } };
      case "server.join":
        return svc.joinByInvite(identityId, identityId, cmd.inviteKey);
      case "server.leave":
        return svc.leave(identityId);
      case "server.state":
        return svc.getState(identityId);
      case "server.transferOwnership":
        return svc.transferOwnership(identityId, cmd.newOwnerIdentityId);
      case "server.updateConfig":
        return { ok: true, data: { ...svc.getConfig(), ...cmd.config } };
      case "invite.create":
        return svc.inviteCreate(identityId, cmd.initialRoleId, cmd.maxUses, cmd.expiresInMs);
      case "invite.revoke":
        return svc.inviteRevoke(identityId, cmd.inviteId);
      case "channel.create":
        return svc.channelCreate(identityId, cmd.channelType, cmd.name);
      case "channel.updateOverrides":
        return svc.channelUpdateOverrides(identityId, cmd.channelId, cmd.overrides);
      case "role.create":
        return svc.roleCreate(identityId, cmd.name, cmd.level, cmd.permissions);
      case "role.assign":
        return svc.roleAssign(identityId, cmd.memberIdentityId, cmd.roleId);
      case "member.kick":
        return svc.kick(identityId, cmd.memberIdentityId);
      case "member.ban":
        return svc.ban(identityId, cmd.memberIdentityId);
      case "message.ackConsumed":
        return svc.ackConsumed(identityId, cmd.messageId);
      case "message.getPending":
        return svc.getPending(identityId);
      case "presence.set":
        return svc.setPresence(identityId, cmd.state);
      case "call.join":
        return svc.callJoin(identityId, cmd.channelId);
      case "call.leave":
        return svc.callLeave(identityId, cmd.channelId);
      case "call.signal":
        console.log(`[janjanode] call.signal cmd from ${identityId} to ${cmd.to}`);
        return svc.callSignal(identityId, cmd.channelId, cmd.to, cmd.payload);
      case "keypackage.upload":
        return svc.keyPackageUpload(identityId, cmd.keyPackageB64);
      case "keypackage.get":
        return svc.keyPackageGet(identityId, cmd.targetIdentityId);
      case "welcome.push":
        return svc.welcomePush(identityId, cmd.targetIdentityId, cmd.welcomeB64);
      case "welcome.pending":
        return svc.welcomePending(identityId);
      case "attachment.upload":
        return svc.attachmentUpload(identityId, cmd.assetId, cmd.data, cmd.sizeBytes, cmd.ttlHours);
      case "attachment.download":
        return svc.attachmentDownload(identityId, cmd.assetId);
      case "replica.snapshot":
        return svc.getSnapshot();
      case "replica.promote":
        return svc.promote(identityId);
      default: {
        const exhaustive: never = cmd;
        return { ok: false, error: { code: "invalid_input", message: `unhandled ${(exhaustive as { type: string }).type}` } };
      }
    }
  }
}
