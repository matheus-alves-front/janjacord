import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { WsAdapter } from "@nestjs/platform-ws";
import { WebSocket } from "ws";
import { AppModule } from "./app.module.js";
import { ServerService } from "./server.service.js";

async function registerRendezvous(app: Awaited<ReturnType<typeof NestFactory.create>>, serverId: string): Promise<void> {
  const url = process.env.JC_RENDEZVOUS_URL;
  if (!url) return;
  const publicUrl = process.env.JC_PUBLIC_URL;
  if (!publicUrl) {
    console.warn("[janjanode] JC_RENDEZVOUS_URL definido mas JC_PUBLIC_URL ausente — pulando registro");
    return;
  }
  try {
    const ws = new WebSocket(url);
    await new Promise<void>((res, rej) => {
      ws.on("open", () => res());
      ws.on("error", rej);
      setTimeout(() => rej(new Error("rendezvous timeout")), 5000);
    });
    ws.send(JSON.stringify({ type: "register", serverId, endpoint: publicUrl }));
    console.log(`[janjanode] registrado no rendezvous: ${serverId} → ${publicUrl}`);
    // heartbeat de renovação (TTL 2h; renova a cada hora)
    setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "register", serverId, endpoint: publicUrl }));
      }
    }, 3600_000).unref();
  } catch (e) {
    console.warn(`[janjanode] falha ao registrar no rendezvous: ${(e as Error).message}`);
  }
}

async function bootstrap(): Promise<void> {
  // réplica: sincroniza o snapshot do primary ANTES de abrir o banco (serverId consistente)
  if (process.env.JC_REPLICA_OF) {
    await syncSnapshotOnce(process.env.JC_REPLICA_OF, process.env.JC_DB_PATH ?? "./janjanode-data/server.db");
  }
  const app = await NestFactory.create(AppModule, { logger: ["error", "warn", "log"] });
  app.useWebSocketAdapter(new WsAdapter(app));
  await app.init();
  const port = Number(process.env.JC_PORT ?? 8931);
  console.log(`[janjanode] JanjaNode host ativo — ws://127.0.0.1:${port}/signal`);
  console.log(`[janjanode] server db: ${process.env.JC_DB_PATH ?? "./janjanode-data/server.db"}`);
  const svc = app.get(ServerService);
  await registerRendezvous(app, svc.getServerId());
  startPushPinger(svc);
  if (process.env.JC_REPLICA_OF) {
    startReplicaLoop(svc, process.env.JC_REPLICA_OF, Number(process.env.JC_PORT ?? 8931));
  }
}

/** Push genérico (spec mobile/push): em atividade, pinga o push service com o ticket
 *  do host — payload 100% estático, sem conteúdo/sender/server/channel. */
function startPushPinger(svc: ServerService): void {
  const pushUrl = process.env.JC_PUSH_URL;
  const ticket = process.env.JC_PUSH_TICKET;
  if (!pushUrl || !ticket) return;
  const serverId = svc.getServerId();
  let lastPing = 0;
  svc.events.on("activity", () => {
    const now = Date.now();
    if (now - lastPing < 5000) return; // debounce (evita flood de pings)
    lastPing = now;
    void (async () => {
      try {
        const { WebSocket } = await import("ws");
        const ws = new WebSocket(pushUrl);
        await new Promise<void>((res, rej) => {
          ws.on("open", () => res());
          ws.on("error", rej);
          setTimeout(() => rej(new Error("timeout")), 4000);
        });
        ws.send(JSON.stringify({ type: "host.ping", ticket, serverId }));
        ws.close();
      } catch {
        // push é best-effort — falha não afeta o fluxo
      }
    })();
  });
}

/** Baixa o snapshot do primary e substitui o arquivo local (antes do boot). */
async function syncSnapshotOnce(primaryUrl: string, dbPath: string): Promise<void> {
  const { WebSocket } = await import("ws");
  const { writeFileSync, existsSync } = await import("node:fs");
  try {
    console.log(`[janjanode] syncSnapshotOnce: conectando ${primaryUrl}`);
    const ws = new WebSocket(primaryUrl);
    await new Promise<void>((res, rej) => {
      ws.on("open", () => res());
      ws.on("error", (e) => rej(new Error(`ws error: ${(e as Error).message}`)));
      setTimeout(() => rej(new Error("timeout open")), 5000);
    });
    console.log("[janjanode] syncSnapshotOnce: conectado, hello…");
    const owner = process.env.JC_OWNER_IDENTITY ?? "";
    await new Promise<void>((res) => {
      ws.on("message", (raw) => {
        const f = JSON.parse(raw.toString()) as { event?: string };
        if (f.event === "result") res();
      });
      ws.send(JSON.stringify({ event: "hello", data: { identityId: owner } }));
      setTimeout(() => res(), 4000);
    });
    console.log("[janjanode] syncSnapshotOnce: enviando snapshot…");
    const snapshot = await new Promise<Buffer | null>((res) => {
      ws.on("message", (raw) => {
        console.log(`[janjanode] syncSnapshotOnce frame: ${raw.toString().slice(0, 80)}`);
        const frame = JSON.parse(raw.toString()) as { event?: string; data?: { ok?: boolean; data?: { dbB64?: string } } };
        if (frame.event === "result" && frame.data?.ok && frame.data.data?.dbB64) {
          res(Buffer.from(frame.data.data.dbB64, "base64"));
        } else {
          res(null);
        }
      });
      ws.send(JSON.stringify({ event: "command", data: { type: "replica.snapshot" } }));
      setTimeout(() => res(null), 5000);
    });
    ws.close();
    console.log(`[janjanode] syncSnapshotOnce: resposta=${snapshot ? snapshot.length + "B" : "null"}`);
    if (snapshot) {
      writeFileSync(dbPath, snapshot);
      console.log("[janjanode] snapshot inicial sincronizado do primary");
    } else {
      console.warn("[janjanode] primary não respondeu ao snapshot inicial — réplica pode divergir");
    }
  } catch (e) {
    console.warn(`[janjanode] falha no snapshot inicial: ${(e as Error).message}`);
  }
}

/**
 * Réplica autorizada (ADR-011): monitora o primary via ping (lease);
 * sincroniza o snapshot enquanto o primary está vivo; se o primary não responder
 * por REVOKE_AFTER_MS, PROMOVE automaticamente (epoch+1 — fencing).
 */
async function startReplicaLoop(svc: ServerService, primaryUrl: string, localPort: number): Promise<void> {
  const { WebSocket } = await import("ws");
  const { writeFileSync, readFileSync } = await import("node:fs");
  const intervalMs = Number(process.env.JC_LEASE_INTERVAL_MS ?? 5000);
  const revokeAfter = Number(process.env.JC_LEASE_REVOKE_MS ?? 15000);
  let failures = 0;
  let promoted = false;
  console.log(`[janjanode] modo réplica: primary=${primaryUrl} (lease ${revokeAfter}ms)`);

  const ping = (): Promise<boolean> =>
    new Promise((resolve) => {
      try {
        const ws = new WebSocket(primaryUrl);
        const timer = setTimeout(() => { ws.terminate(); resolve(false); }, 3000);
        ws.on("open", () => ws.send(JSON.stringify({ event: "command", data: { type: "replica.ping" } })));
        ws.on("message", (raw) => {
          clearTimeout(timer);
          ws.close();
          resolve(true);
        });
        ws.on("error", () => { clearTimeout(timer); resolve(false); });
      } catch {
        resolve(false);
      }
    });

  const syncSnapshot = (): Promise<void> =>
    new Promise((resolve) => {
      try {
        const ws = new WebSocket(primaryUrl);
        const timer = setTimeout(() => { ws.terminate(); resolve(); }, 5000);
        ws.on("open", () => ws.send(JSON.stringify({ event: "command", data: { type: "replica.snapshot" } })));
        ws.on("message", (raw) => {
          clearTimeout(timer);
          const frame = JSON.parse(raw.toString()) as { event?: string; data?: { ok?: boolean; data?: { dbB64?: string } } };
          if (frame.event === "result" && frame.data?.ok && frame.data.data?.dbB64) {
            const dbPath = process.env.JC_DB_PATH ?? "./janjanode-data/server.db";
            const snapshot = Buffer.from(frame.data.data.dbB64, "base64");
            const cur = readFileSync(dbPath);
            if (!cur.equals(snapshot)) {
              writeFileSync(dbPath, snapshot);
              console.log("[janjanode] snapshot sincronizado do primary");
            }
          }
          ws.close();
          resolve();
        });
        ws.on("error", () => { clearTimeout(timer); resolve(); });
      } catch {
        resolve();
      }
    });

  const promote = async (): Promise<void> => {
    // promoção automática: conecta no próprio host como owner e promove
    const ws = new WebSocket(`ws://127.0.0.1:${localPort}/signal`);
    await new Promise((res, rej) => { ws.on("open", res); ws.on("error", rej); setTimeout(() => rej(new Error("timeout")), 4000); });
    const owner = process.env.JC_OWNER_IDENTITY ?? "";
    ws.send(JSON.stringify({ event: "hello", data: { identityId: owner } }));
    await new Promise((r) => setTimeout(r, 300));
    const result = await new Promise<unknown>((res) => {
      ws.on("message", (raw) => {
        const f = JSON.parse(raw.toString());
        if (f.event === "result") res(f.data);
      });
      ws.send(JSON.stringify({ event: "command", data: { type: "replica.promote" } }));
      setTimeout(() => res(null), 4000);
    });
    ws.close();
    if ((result as { ok?: boolean })?.ok) console.log("[janjanode] PROMOVIDA automaticamente (lease expirado)");
  };

  setInterval(async () => {
    if (promoted) return;
    const alive = await ping();
    if (alive) {
      failures = 0;
      await syncSnapshot();
    } else {
      failures++;
      console.log(`[janjanode] primary sem resposta (${failures}x)`);
      if (failures * intervalMs >= revokeAfter) {
        promoted = true;
        try {
          await promote();
        } catch (e) {
          console.error(`[janjanode] falha na promoção: ${(e as Error).message}`);
        }
      }
    }
  }, intervalMs).unref();
}

bootstrap().catch((err) => {
  console.error("[janjanode] fatal:", err);
  process.exit(1);
});
