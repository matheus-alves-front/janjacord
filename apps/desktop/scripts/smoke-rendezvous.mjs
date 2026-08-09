/**
 * Smoke do rendezvous (ADR-003): host se registra por serverId; cliente resolve o
 * serverId no rendezvous, descobre o endpoint e entra por invite — sem URL manual.
 */
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { fork } from "node:child_process";
import { createIdentity } from "@janjacord/identity";
import { HostClient } from "@janjacord/networking";
import { formatInviteKey } from "@janjacord/crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const JANJANODE_MAIN = join(__dirname, "..", "..", "janjanode", "dist", "main.js");
const RENDEZVOUS_MAIN = join(__dirname, "..", "..", "rendezvous", "dist", "main.js");
const RENDEZVOUS_PORT = 8950;
const HOST_PORT = 8951;
const DB_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OWNER = "owner-rzv";
const BOB = "bob-rzv";

let failures = 0;
const assert = (cond, label) => {
  if (cond) console.log(`  ✓ ${label}`);
  else {
    failures++;
    console.error(`  ✗ ${label}`);
  }
};

function waitFor(ws, event, t = 8000) {
  return new Promise((res, rej) => {
    const tm = setTimeout(() => rej(new Error(`timeout ${event}`)), t);
    ws.on("message", function h(raw) {
      const f = JSON.parse(raw.toString());
      if (f.event === event) {
        clearTimeout(tm);
        ws.off("message", h);
        res(f.data);
      }
    });
  });
}

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

async function resolveRendezvous(serverId) {
  const { WebSocket } = await import("ws");
  const ws = new WebSocket(`ws://127.0.0.1:${RENDEZVOUS_PORT}/rendezvous`);
  await new Promise((res, rej) => {
    ws.on("open", res);
    ws.on("error", rej);
  });
  const res = await new Promise((resolve) => {
    ws.on("message", (raw) => resolve(JSON.parse(raw.toString())));
    ws.send(JSON.stringify({ type: "resolve", serverId }));
    setTimeout(() => resolve({ ok: false, error: { code: "timeout", message: "timeout" } }), 5000);
  });
  ws.close();
  return res;
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "jc-rzv-"));
  let rendezvous = null;
  let host = null;
  try {
    const alice = await createIdentity("alice", "senha-alice-123", join(dir, "vault.json"));

    // 1. sobe o rendezvous
    rendezvous = fork(RENDEZVOUS_MAIN, [], {
      env: { ...process.env, JC_RENDEZVOUS_PORT: String(RENDEZVOUS_PORT) },
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      execPath: process.env.JC_NODE_BIN ?? "node",
    });
    rendezvous.stderr?.on("data", (d) => process.stderr.write(d));
    await new Promise((r) => setTimeout(r, 1500));

    // 2. host registra no rendezvous
    host = fork(JANJANODE_MAIN, [], {
      env: {
        ...process.env,
        JC_DB_KEY: DB_KEY,
        JC_DB_PATH: join(dir, "server.db"),
        JC_OWNER_IDENTITY: OWNER,
        JC_OWNER_NICKNAME: "alice",
        JC_SERVER_NAME: "RzvTest",
        JC_PORT: String(HOST_PORT),
        JC_RENDEZVOUS_URL: `ws://127.0.0.1:${RENDEZVOUS_PORT}/rendezvous`,
        JC_PUBLIC_URL: `ws://127.0.0.1:${HOST_PORT}/signal`,
      },
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      execPath: process.env.JC_NODE_BIN ?? "node",
    });
    host.stderr?.on("data", (d) => process.stderr.write(d));
    await new Promise((r) => setTimeout(r, 2500));

    // 3. owner conecta direto e cria invite (com serverId)
    const a = await connect(OWNER, `ws://127.0.0.1:${HOST_PORT}/signal`);
    assert(a.state?.ok, "owner conecta ao host (direto)");
    const serverId = a.state.data.serverId;
    const inv = await a.client.request({ type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
    assert(inv.ok && inv.data.inviteKey.startsWith("JC1-"), "invite criado (JC1-… com serverId)");

    // 4. cliente resolve o serverId no rendezvous (SEM URL manual)
    const resolved = await resolveRendezvous(serverId);
    assert(resolved.ok && resolved.data.endpoint === `ws://127.0.0.1:${HOST_PORT}/signal`, "rendezvous resolve serverId → endpoint");
    const resolvedBad = await resolveRendezvous("00000000-0000-4000-8000-000000000000");
    assert(!resolvedBad.ok && resolvedBad.error.code === "not_found", "serverId desconhecido → not_found");

    // 5. bob entra: resolve via rendezvous + join por invite
    const bob = await connect(BOB, resolved.data.endpoint);
    const joinRes = await bob.client.request({ type: "server.join", inviteKey: inv.data.inviteKey });
    assert(joinRes.ok && joinRes.data.serverId === serverId, "bob entra via invite (serverId consistente)");

    // 6. invite de outro server é rejeitado (validação de serverId)
    const carol = await connect("carol-rzv", resolved.data.endpoint);
    const wrong = await carol.client.request({ type: "server.join", inviteKey: "JC1-" + "A".repeat(52) });
    assert(!wrong.ok && wrong.error.code === "invalid_invite", "invite malformado/outro server rejeitado");

    if (failures === 0) console.log("[smoke-rendezvous] RENDEZVOUS + DESCOBERTA OK");
    else console.error(`[smoke-rendezvous] ${failures} falhas`);
  } finally {
    rendezvous?.kill();
    host?.kill();
    rmSync(dir, { recursive: true, force: true });
  }
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("[smoke-rendezvous] erro:", e);
  process.exit(1);
});
