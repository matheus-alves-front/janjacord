/**
 * Smoke do lease automático (ADR-011): a réplica monitora o primary; quando o
 * lease expira (primary morto), a réplica se PROMOVE AUTOMATICAMENTE e o server
 * continua aceitando escritas — sem intervenção manual.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { fork } from "node:child_process";
import { createIdentity } from "@janjacord/identity";
import { HostClient } from "@janjacord/networking";

const __dirname = dirname(fileURLToPath(import.meta.url));
const JANJANODE_MAIN = join(__dirname, "..", "..", "janjanode", "dist", "main.js");
const PRIMARY_PORT = 8960;
const REPLICA_PORT = 8961;
const DB_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OWNER = "owner-lease";

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

function spawnHost(port, dbPath, extraEnv = {}) {
  const host = fork(JANJANODE_MAIN, [], {
    env: {
      ...process.env,
      JC_DB_KEY: DB_KEY,
      JC_DB_PATH: dbPath,
      JC_OWNER_IDENTITY: OWNER,
      JC_OWNER_NICKNAME: "owner",
      JC_SERVER_NAME: "LeaseTest",
      JC_PORT: String(port),
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    execPath: process.env.JC_NODE_BIN ?? "node",
  });
  host.stdout?.on("data", (d) => process.stdout.write(d));
  host.stderr?.on("data", (d) => process.stderr.write(d));
  return host;
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "jc-lease-"));
  let primary = null;
  let replica = null;
  try {
    const alice = await createIdentity("alice", "senha-alice-123", join(dir, "vault.json"));
    const primaryDb = join(dir, "primary.db");
    const replicaDb = join(dir, "replica.db");

    // 1. primary
    primary = spawnHost(PRIMARY_PORT, primaryDb);
    await new Promise((r) => setTimeout(r, 2000));
    const a = await connect(OWNER, `ws://127.0.0.1:${PRIMARY_PORT}/signal`);
    assert(a.state?.ok, "owner conecta ao primary");

    // 2. réplica com lease rápido (intervalo 1s, revoke 3s)
    replica = spawnHost(REPLICA_PORT, replicaDb, {
      JC_REPLICA_OF: `ws://127.0.0.1:${PRIMARY_PORT}/signal`,
      JC_LEASE_INTERVAL_MS: "1000",
      JC_LEASE_REVOKE_MS: "3000",
    });
    await new Promise((r) => setTimeout(r, 4000)); // sincroniza snapshot do primary

    // 3. kill primary → réplica deve se promover sozinha
    console.log("[smoke-lease] kill do primary…");
    primary.kill();
    await new Promise((r) => setTimeout(r, 8000)); // lease 3s + promoção

    // 4. cliente conecta à réplica e escreve
    const a2 = await connect(OWNER, `ws://127.0.0.1:${REPLICA_PORT}/signal`);
    assert(a2.state?.ok, "owner conecta à réplica (pós-kill)");
    const state = a2.state.data;
    assert(state.serverId === a.state.data.serverId, "mesmo serverId (consistência)");
    const inv = await a2.client.request({ type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
    assert(inv.ok, "escrita funciona na réplica promovida automaticamente");
    const pingRep = await a2.client.request({ type: "replica.ping" });
    assert(pingRep.ok && pingRep.data.epoch >= 1, `réplica promovida (epoch ${pingRep.data.epoch}) — fencing automático`);

    if (failures === 0) console.log("[smoke-lease] LEASE AUTOMÁTICO + FAILOVER OK");
    else console.error(`[smoke-lease] ${failures} falhas`);
  } finally {
    primary?.kill();
    replica?.kill();
    rmSync(dir, { recursive: true, force: true });
  }
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("[smoke-lease] erro:", e);
  process.exit(1);
});
