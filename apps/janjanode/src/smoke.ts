/**
 * Smoke de integração do JanjaNode (2 clientes WS reais).
 * Roda contra o dist compilado (tsc com emitDecoratorMetadata — necessário ao DI Nest).
 */
import "reflect-metadata";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { WebSocket } from "ws";
import { NestFactory } from "@nestjs/core";
import { WsAdapter } from "@nestjs/platform-ws";
import { AppModule } from "./app.module.js";
import type { MessageEnvelope } from "@janjacord/schemas";

const DB_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OWNER = "owner-identity";
const BOB = "bob-identity";
const PORT = 8931;

function wsConnect(): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}/signal`);
    ws.on("open", () => resolve(ws));
    ws.on("error", reject);
  });
}

function waitFor(ws: WebSocket, event: string, timeoutMs = 10000): Promise<{ event: string; data: any }> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout esperando ${event}`)), timeoutMs);
    const onMsg = (raw: Buffer) => {
      const frame = JSON.parse(raw.toString());
      if (frame.event === event) {
        clearTimeout(timer);
        ws.off("message", onMsg);
        resolve(frame);
      }
    };
    ws.on("message", onMsg);
  });
}

const send = (ws: WebSocket, event: string, data: unknown): void =>
  ws.send(JSON.stringify({ event, data }));

function envelope(serverId: string, channelId: string, sender: string): MessageEnvelope {
  return {
    protocolVersion: 1,
    messageId: randomUUID(),
    serverId,
    channelId,
    sender,
    cryptoEpoch: 1,
    audience: { algo: "sha256", commitment: "c".repeat(64), members: [OWNER, BOB] },
    ciphertext: Buffer.from("ct-opaco-ao-host").toString("base64"),
    attachments: [],
    ordering: { seq: 1 },
    createdAt: Date.now(),
  };
}

let failures = 0;
function assert(cond: unknown, label: string): void {
  if (cond) console.log(`  ✓ ${label}`);
  else {
    failures++;
    console.error(`  ✗ ${label}`);
  }
}

async function main(): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "jc-janjanode-"));
  process.env.JC_DB_KEY = DB_KEY;
  process.env.JC_DB_PATH = join(dir, "server.db");
  process.env.JC_OWNER_IDENTITY = OWNER;
  process.env.JC_OWNER_NICKNAME = "matheus";
  process.env.JC_SERVER_NAME = "Teste";

  console.log("[smoke] subindo JanjaNode...");
  const app = await NestFactory.create(AppModule, { logger: false });
  app.useWebSocketAdapter(new WsAdapter(app));
  await app.init();
  await new Promise((r) => setTimeout(r, 300));

  const owner = await wsConnect();
  const bob = await wsConnect();

  // hello owner
  send(owner, "hello", { identityId: OWNER });
  const hello = (await waitFor(owner, "result")).data as {
    ok: boolean;
    data: { serverId: string; channels: { id: string; name: string }[] };
  };
  assert(hello.ok, "owner hello + estado do server");
  const serverId = hello.data.serverId;
  const general = hello.data.channels.find((c) => c.name === "general") ?? hello.data.channels[0]!;

  // invite
  send(owner, "command", { type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
  const inv = (await waitFor(owner, "result")).data as { ok: boolean; data: { inviteKey: string } };
  assert(inv.ok && inv.data.inviteKey.startsWith("JC1-"), "owner cria invite JC1-...");

  // bob join
  send(bob, "hello", { identityId: BOB });
  await waitFor(bob, "result");
  send(bob, "command", { type: "server.join", inviteKey: inv.data.inviteKey });
  const joinRes = (await waitFor(bob, "result")).data as { ok: boolean; data: { me: { roleId: string } }; error?: { code: string; message: string } };
  assert(joinRes.ok && joinRes.data.me.roleId === "role-member", `bob entra via invite (role member)${joinRes.ok ? "" : " -> " + joinRes.error?.code + ": " + joinRes.error?.message}`);

  // envelope bob -> owner (listener registrado ANTES do envio — push é síncrono no host)
  const env = envelope(serverId, general.id, BOB);
  const deliverPromise = waitFor(owner, "event");
  send(bob, "envelope.send", env);
  const sent = (await waitFor(bob, "result")).data as { ok: boolean; error?: { code: string; message: string } };
  assert(sent.ok, `bob envia envelope (spool)${sent.ok ? "" : " -> " + sent.error?.code + ": " + sent.error?.message}`);

  const deliver = (await deliverPromise).data as { type: string; envelope: MessageEnvelope };
  assert(deliver.type === "envelope.deliver" && deliver.envelope.messageId === env.messageId, "owner recebe envelope");

  // consumos -> purge
  send(owner, "command", { type: "message.ackConsumed", messageId: env.messageId });
  await waitFor(owner, "result");
  send(bob, "command", { type: "message.ackConsumed", messageId: env.messageId });
  await waitFor(bob, "result");
  send(owner, "command", { type: "message.getPending" });
  const pending = (await waitFor(owner, "result")).data as { ok: boolean; data: MessageEnvelope[] };
  assert(pending.ok && !pending.data.some((m) => m.messageId === env.messageId), "purge global após consumo");

  // replay
  send(bob, "envelope.send", env);
  const replay = (await waitFor(bob, "result")).data as { ok: boolean; error: { code: string } };
  assert(!replay.ok && replay.error.code === "conflict", "replay de messageId rejeitado");

  // permissão: member sem manage_invites
  send(bob, "command", { type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
  const deny = (await waitFor(bob, "result")).data as { ok: boolean; error: { code: string } };
  assert(!deny.ok && deny.error.code === "forbidden", "member sem manage_invites bloqueado");

  owner.close();
  bob.close();
  await app.close();
  rmSync(dir, { recursive: true, force: true });

  if (failures > 0) {
    console.error(`[smoke] ${failures} falhas`);
    process.exit(1);
  }
  console.log("[smoke] INTEGRAÇÃO JANJANODE OK");
  process.exit(0);
}

main().catch((e) => {
  console.error("[smoke] erro:", e);
  process.exit(1);
});
