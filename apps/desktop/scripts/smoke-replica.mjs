/**
 * Smoke de replicação/failover (ADR-011 pragmático):
 * 1. primary hosta o server (owner + membro por invite)
 * 2. réplica baixa o snapshot do DB cifrado e sobe com o mesmo serverId
 * 3. kill do primary → promoção da réplica (epoch+1)
 * 4. cliente reconecta à réplica promovida e o server continua operacional
 */
import { mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { fork } from "node:child_process";
import { createIdentity } from "@janjacord/identity";
import { HostClient } from "@janjacord/networking";

const __dirname = dirname(fileURLToPath(import.meta.url));
const JANJANODE_MAIN = join(__dirname, "..", "..", "janjanode", "dist", "main.js");
const PRIMARY_PORT = 8940;
const REPLICA_PORT = 8941;
const DB_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OWNER = "owner-replica";
const BOB = "bob-replica";

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

function spawnHost(port, dbPath, ownerNick) {
  const host = fork(JANJANODE_MAIN, [], {
    env: {
      ...process.env,
      JC_DB_KEY: DB_KEY,
      JC_DB_PATH: dbPath,
      JC_OWNER_IDENTITY: OWNER,
      JC_OWNER_NICKNAME: ownerNick,
      JC_SERVER_NAME: "ReplicaTest",
      JC_PORT: String(port),
    },
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    execPath: process.env.JC_NODE_BIN ?? "node",
  });
  host.stderr?.on("data", (d) => process.stderr.write(d));
  return host;
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "jc-replica-"));
  const primaryDb = join(dir, "primary.db");
  const replicaDb = join(dir, "replica.db");
  let primary = null;
  let replica = null;
  try {
    const alice = await createIdentity("alice", "senha-alice-123", join(dir, "vault.json"));

    // 1. primary
    console.log("[smoke-replica] 1. primary hosta o server…");
    primary = spawnHost(PRIMARY_PORT, primaryDb, "alice");
    await new Promise((r) => setTimeout(r, 2000));
    const a = await connect(OWNER, `ws://127.0.0.1:${PRIMARY_PORT}/signal`);
    assert(a.state?.ok, "alice conecta ao primary");
    const inv = await a.client.request({ type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
    const b = await connect(BOB, `ws://127.0.0.1:${PRIMARY_PORT}/signal`);
    const joinRes = await b.client.request({ type: "server.join", inviteKey: inv.data.inviteKey });
    assert(joinRes.ok, "bob entra no server (primary)");
    // cria um canal de texto extra (estado durável a replicar)
    const ch = await a.client.request({ type: "channel.create", channelType: "text", name: "replicado" });
    assert(ch.ok, "canal 'replicado' criado no primary");

    // 2. snapshot + réplica
    console.log("[smoke-replica] 2. réplica baixa snapshot e sobe…");
    const snap = await a.client.request({ type: "replica.snapshot" });
    assert(snap.ok && snap.data.dbB64.length > 100, "snapshot do DB cifrado obtido");
    writeFileSync(replicaDb, Buffer.from(snap.data.dbB64, "base64"));
    replica = spawnHost(REPLICA_PORT, replicaDb, "alice");
    await new Promise((r) => setTimeout(r, 2500));

    // 3. kill primary
    console.log("[smoke-replica] 3. kill do primary…");
    primary.kill();
    await new Promise((r) => setTimeout(r, 800));

    // 4. cliente conecta à réplica e promove
    console.log("[smoke-replica] 4. promoção da réplica…");
    const a2 = await connect(OWNER, `ws://127.0.0.1:${REPLICA_PORT}/signal`);
    assert(a2.state?.ok && a2.state.data.serverId === a.state.data.serverId, "réplica tem o MESMO serverId (consistência)");
    const stateRep = a2.state.data;
    const hasChannel = stateRep.channels.some((c) => c.name === "replicado");
    assert(hasChannel, "estado durável replicado (canal 'replicado' presente)");
    const members = stateRep.members.map((m) => m.identityId);
    assert(members.includes(OWNER) && members.includes(BOB), "membros replicados (owner + bob)");
    const prom = await a2.client.request({ type: "replica.promote" });
    assert(prom.ok && prom.data.epoch >= 1, `réplica promovida (epoch ${prom.data.epoch}) — fencing`);

    // 5. server continua operacional na réplica
    console.log("[smoke-replica] 5. server operacional pós-failover…");
    const inviteAfter = await a2.client.request({ type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
    assert(inviteAfter.ok, "owner cria invite na réplica promovida (escrita funciona)");
    const b2 = await connect(BOB, `ws://127.0.0.1:${REPLICA_PORT}/signal`);
    assert(b2.state?.ok, "bob reconecta à réplica promovida");
    assert(b2.state.data.serverId === a.state.data.serverId, "bob vê o mesmo serverId");

    if (failures === 0) console.log("[smoke-replica] REPLICAÇÃO + FAILOVER OK");
    else console.error(`[smoke-replica] ${failures} falhas`);
  } finally {
    primary?.kill();
    replica?.kill();
    rmSync(dir, { recursive: true, force: true });
  }
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("[smoke-replica] erro:", e);
  process.exit(1);
});
