/**
 * Smoke de abuse (spec abuse-resource-and-dos-guardrails): fuzz de frames
 * malformados não derruba o host; rate limit fecha socket após flood; limite de
 * conexões por IP é aplicado.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { fork } from "node:child_process";
import { WebSocket } from "ws";
import { createIdentity } from "@janjacord/identity";
import { HostClient } from "@janjacord/networking";

const __dirname = dirname(fileURLToPath(import.meta.url));
const JANJANODE_MAIN = join(__dirname, "..", "..", "janjanode", "dist", "main.js");
const PORT = 8970;
const DB_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

let failures = 0;
const assert = (cond, label) => {
  if (cond) console.log(`  ✓ ${label}`);
  else {
    failures++;
    console.error(`  ✗ ${label}`);
  }
};

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "jc-fuzz-"));
  let host = null;
  try {
    const alice = await createIdentity("alice", "senha-alice-123", join(dir, "vault.json"));
    host = fork(JANJANODE_MAIN, [], {
      env: {
        ...process.env,
        JC_DB_KEY: DB_KEY,
        JC_DB_PATH: join(dir, "server.db"),
        JC_OWNER_IDENTITY: "owner-fuzz",
        JC_OWNER_NICKNAME: "alice",
        JC_SERVER_NAME: "FuzzTest",
        JC_PORT: String(PORT),
      },
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      execPath: process.env.JC_NODE_BIN ?? "node",
    });
    host.stderr?.on("data", (d) => process.stderr.write(d));
    await new Promise((r) => setTimeout(r, 2000));

    // 1. fuzz: 200 frames malformados aleatórios — host não crasha
    const fuzzWs = new WebSocket(`ws://127.0.0.1:${PORT}/signal`);
    await new Promise((res, rej) => { fuzzWs.on("open", res); fuzzWs.on("error", rej); });
    let closedByServer = false;
    fuzzWs.on("close", (code) => {
      if (code === 1008) closedByServer = true; // rate_limited
    });
    const garbage = [">>>", "{", "null", "[]", '{"event":123}', "not json at all", '{"event":"x"}', Buffer.alloc(64, 0xff).toString()];
    for (let i = 0; i < 200; i++) {
      fuzzWs.send(garbage[i % garbage.length]);
    }
    await new Promise((r) => setTimeout(r, 1500));
    assert(closedByServer, "flood de malformed frames → socket fechado (rate limit)");
    assert(host.exitCode === null || host.exitCode === undefined, "host continua vivo após fuzz");

    // 2. host ainda responde a cliente legítimo
    const client = new HostClient(`ws://127.0.0.1:${PORT}/signal`, { identityId: "owner-fuzz" });
    await new Promise((res) => { client.onOpen(() => res()); setTimeout(res, 5000); });
    const helloPromise = new Promise((res) => {
      client.onEventOnce("result", (f) => res(f.data));
      setTimeout(() => res(null), 8000);
    });
    client.send("hello", { identityId: "owner-fuzz" });
    const hello = await helloPromise;
    assert(hello?.ok === true, "host saudável após fuzz (cliente legítimo responde)");
    client.close();

    // 3. limite de conexões por IP (max 8) — a 9ª é rejeitada
    const sockets = [];
    let ninthRejected = false;
    for (let i = 0; i < 9; i++) {
      const ws = new WebSocket(`ws://127.0.0.1:${PORT}/signal`);
      if (i === 8) {
        ws.on("close", (code) => {
          if (code === 1013) ninthRejected = true;
        });
      }
      sockets.push(ws);
    }
    await new Promise((r) => setTimeout(r, 1500));
    assert(ninthRejected, "9ª conexão do mesmo IP rejeitada (max 8)");
    sockets.forEach((s) => s.terminate());

    if (failures === 0) console.log("[smoke-fuzz] ABUSE + RATE LIMITS OK");
    else console.error(`[smoke-fuzz] ${failures} falhas`);
  } finally {
    host?.kill();
    rmSync(dir, { recursive: true, force: true });
  }
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("[smoke-fuzz] erro:", e);
  process.exit(1);
});
