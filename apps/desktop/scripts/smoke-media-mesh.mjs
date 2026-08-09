/**
 * Smoke de media mesh REAL entre 2 peers (desktop Electron, dispositivos sintéticos):
 * peer 1 cria server + canal de call; peer 2 entra via invite (descoberta no rendezvous);
 * ambos com getUserMedia fake → mesh WebRTC troca streams → screenshots mostram os tiles.
 */
import { mkdtempSync, rmSync, existsSync, statSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { fork, spawn } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const RENDEZVOUS_MAIN = join(__dirname, "..", "..", "rendezvous", "dist", "main.js");
const ELECTRON = join(__dirname, "..", "node_modules", ".bin", "electron");
const RENDEZVOUS_PORT = 8955;

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "jc-media-mesh-"));
  const inviteFile = join(dir, "invite.txt");
  let rendezvous = null;
  let peers = [];
  try {
    rendezvous = fork(RENDEZVOUS_MAIN, [], {
      env: { ...process.env, JC_RENDEZVOUS_PORT: String(RENDEZVOUS_PORT) },
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      execPath: process.env.JC_NODE_BIN ?? "node",
    });
    await new Promise((r) => setTimeout(r, 1500));

    const peerEnv = (n) => ({
      ...process.env,
      JC_SMOKE_MEDIA_PEER: String(n),
      JC_SMOKE_DIR: join(dir, `peer${n}`),
      JC_INVITE_FILE: inviteFile,
      JC_RENDEZVOUS_URL: `ws://127.0.0.1:${RENDEZVOUS_PORT}/rendezvous`,
      JC_PUBLIC_URL: n === 1 ? `ws://127.0.0.1:8931/signal` : undefined,
      ELECTRON_DISABLE_SECURITY_WARNINGS: "true",
    });

    console.log("[media-mesh] iniciando peer 1 (cria server + call)…");
    const p1 = spawn(ELECTRON, [".", "--no-sandbox"], {
      cwd: join(__dirname, ".."),
      env: peerEnv(1),
      stdio: ["ignore", "pipe", "pipe"],
    });
    p1.stdout?.on("data", (d) => process.stdout.write(d));
    p1.stderr?.on("data", (d) => process.stderr.write(d));
    peers.push(p1);

    // aguarda o invite do peer 1
    let waited = 0;
    while (!existsSync(inviteFile) && waited < 70) {
      await new Promise((r) => setTimeout(r, 1000));
      waited++;
    }
    if (!existsSync(inviteFile)) throw new Error("peer 1 não criou o invite a tempo");
    console.log("[media-mesh] invite pronto — iniciando peer 2…");

    const p2 = spawn(ELECTRON, [".", "--no-sandbox"], {
      cwd: join(__dirname, ".."),
      env: peerEnv(2),
      stdio: ["ignore", "pipe", "pipe"],
    });
    p2.stdout?.on("data", (d) => process.stdout.write(d));
    p2.stderr?.on("data", (d) => process.stderr.write(d));
    peers.push(p2);

    // aguarda ambos saírem (timeout total 60s)
    await Promise.race([
      Promise.all(peers.map((p) => new Promise((res) => p.on("exit", res)))),
      new Promise((r) => setTimeout(r, 70000)),
    ]);

    console.log("[media-mesh] DONE — copiando evidências…");
    const evDir = process.env.JC_MEDIA_EVIDENCE ?? "/tmp/jc-mesh-evidence";
    mkdirSync(evDir, { recursive: true });
    const { copyFileSync } = await import("node:fs");
    for (const n of [1, 2]) {
      for (const s of ["in-call", "final"]) {
        const f = join(dir, `peer${n}`, `peer${n}-${s}.png`);
        if (existsSync(f)) {
          copyFileSync(f, join(evDir, `mesh-peer${n}-${s}.png`));
          console.log(`  evidência: mesh-peer${n}-${s}.png (${statSync(f).size}B)`);
        }
      }
    }
  } finally {
    for (const p of peers) p?.kill();
    rendezvous?.kill();
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error("[media-mesh] erro:", e);
  process.exit(1);
});
