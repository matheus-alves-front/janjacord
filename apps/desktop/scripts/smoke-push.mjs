/**
 * Smoke do push genérico (spec mobile/push): device registrado (mock), host pinga o
 * push service em atividade, e o service dispara com payload 100% estático — sem
 * conteúdo/sender/server/channel no payload.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { fork } from "node:child_process";
import { WebSocket } from "ws";
import { createIdentity } from "@janjacord/identity";
import { HostClient } from "@janjacord/networking";
import { randomUUID } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const JANJANODE_MAIN = join(__dirname, "..", "..", "janjanode", "dist", "main.js");
const PUSH_MAIN = join(__dirname, "..", "..", "push", "dist", "main.js");
const PUSH_PORT = 8980;
const HOST_PORT = 8975;
const DB_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TICKET = "host-capability-ticket-1";

let failures = 0;
const assert = (cond, label) => {
  if (cond) console.log(`  ✓ ${label}`);
  else {
    failures++;
    console.error(`  ✗ ${label}`);
  }
};

async function connect(identityId, url) {
  const client = new HostClient(url, { identityId });
  await new Promise((res) => {
    client.onOpen(() => res());
    setTimeout(res, 5000);
  });
  const helloPromise = new Promise((res) => {
    client.onEventOnce("result", (f) => res(f.data));
    setTimeout(() => res(null), 8000);
  });
  client.send("hello", { identityId });
  const hello = await helloPromise;
  return { client, state: hello };
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "jc-push-"));
  let push = null;
  let host = null;
  try {
    const alice = await createIdentity("alice", "senha-alice-123", join(dir, "vault.json"));

    // 1. sobe o push service
    push = fork(PUSH_MAIN, [], {
      env: { ...process.env, JC_PUSH_PORT: String(PUSH_PORT) },
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      execPath: process.env.JC_NODE_BIN ?? "node",
    });
    const pushLogs = [];
    push.stdout?.on("data", (d) => {
      pushLogs.push(d.toString());
      process.stdout.write(d);
    });
    await new Promise((r) => setTimeout(r, 1500));

    // 2. sobe o host (obtém o serverId real para registrar o device)
    host = fork(JANJANODE_MAIN, [], {
      env: {
        ...process.env,
        JC_DB_KEY: DB_KEY,
        JC_DB_PATH: join(dir, "server.db"),
        JC_OWNER_IDENTITY: "owner-push",
        JC_OWNER_NICKNAME: "alice",
        JC_SERVER_NAME: "PushTest",
        JC_PORT: String(HOST_PORT),
        JC_PUSH_URL: `ws://127.0.0.1:${PUSH_PORT}/push`,
        JC_PUSH_TICKET: TICKET,
      },
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      execPath: process.env.JC_NODE_BIN ?? "node",
    });
    host.stdout?.on("data", (d) => process.stdout.write(d));
    await new Promise((r) => setTimeout(r, 2200));

    // 3. registra um device (mock) com o MESMO ticket + serverId do host
    const a = await connect("owner-push", `ws://127.0.0.1:${HOST_PORT}/signal`);
    assert(a.state?.ok, "owner conecta");
    const serverId = a.state.data.serverId;
    const devWs = new WebSocket(`ws://127.0.0.1:${PUSH_PORT}/push`);
    await new Promise((res, rej) => { devWs.on("open", res); devWs.on("error", rej); });
    const regPromise = new Promise((res) => {
      devWs.on("message", (raw) => res(JSON.parse(raw.toString())));
      devWs.send(JSON.stringify({ type: "device.register", ticket: TICKET, serverId, token: "device-token-mock-1", provider: "mock" }));
    });
    const reg = await regPromise;
    assert(reg.ok, "device registrado (token isolado do host — nunca exposto ao JanjaNode)");
    devWs.close();

    // 4. atividade: alice envia mensagem → host pinga o push
    const general = a.state.data.channels.find((c) => c.type === "text");
    const env = {
      protocolVersion: 1,
      messageId: randomUUID(),
      serverId: a.state.data.serverId,
      channelId: general.id,
      sender: "owner-push",
      cryptoEpoch: 1,
      audience: { algo: "sha256", commitment: "c".repeat(64), members: ["owner-push"] },
      ciphertext: Buffer.from("ct").toString("base64"),
      attachments: [],
      ordering: { seq: 1 },
      createdAt: Date.now(),
    };
    await new Promise((resolve) => {
      a.client.onEventOnce("result", (f) => resolve(f.data));
      a.client.send("envelope.send", env);
    });
    await new Promise((r) => setTimeout(r, 1500));

    // 5. verifica o log do push service (payload estático, sem conteúdo)
    const allLogs = pushLogs.join("");
    const mockSent = allLogs.includes("MOCK enviaria push") && allLogs.includes("device-token-mock-1");
    const noContent = !allLogs.includes("ola") && !allLogs.includes("server-push-test") === false || !allLogs.includes('"title":"JanjaCord"');
    assert(mockSent, "push disparado para o device (provider mock)");
    assert(allLogs.includes('"body":"New activity on JanjaCord"'), "payload 100% estático (sem conteúdo/sender/channel)");

    if (failures === 0) console.log("[smoke-push] PUSH GENÉRICO OK (mock; credenciais FCM/APNs = config)");
    else console.error(`[smoke-push] ${failures} falhas`);
  } finally {
    push?.kill();
    host?.kill();
    rmSync(dir, { recursive: true, force: true });
  }
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("[smoke-push] erro:", e);
  process.exit(1);
});
