/**
 * Rendezvous — infra central mínima (ADR-003).
 * Bootstrap/discovery de hosts por serverId, com metadata efêmera (TTL curto),
 * rate limits por IP e NENHUM storage de conteúdo. Padrão: libp2p rendezvous
 * (REGISTER/DISCOVER, records assinados, sem contas).
 *
 * Protocolo (JSON sobre WebSocket):
 *   → { type: "register", serverId, endpoint }        (host anuncia; TTL renovável)
 *   → { type: "resolve", serverId }                    (cliente descobre endpoint)
 *   ← { ok: true, endpoint? } | { ok: false, error: { code, message } }
 */
import { WebSocketServer, WebSocket } from "ws";

const PORT = Number(process.env.JC_RENDEZVOUS_PORT ?? 8920);
const TTL_MS = Number(process.env.JC_RENDEZVOUS_TTL_MS ?? 2 * 3600_000); // 2h
const CLEANUP_MS = 60_000;
const RATE_LIMIT = { windowMs: 60_000, max: 120 }; // por IP

interface Record {
  serverId: string;
  endpoint: string;
  expiresAt: number;
}

const records = new Map<string, Record>();
const rateBuckets = new Map<string, { count: number; windowStart: number }>();

function rateLimited(ip: string): boolean {
  const now = Date.now();
  const bucket = rateBuckets.get(ip);
  if (!bucket || now - bucket.windowStart > RATE_LIMIT.windowMs) {
    rateBuckets.set(ip, { count: 1, windowStart: now });
    return false;
  }
  bucket.count++;
  return bucket.count > RATE_LIMIT.max;
}

function cleanup(): void {
  const now = Date.now();
  for (const [id, r] of records) if (r.expiresAt < now) records.delete(id);
  for (const [ip, b] of rateBuckets) if (now - b.windowStart > RATE_LIMIT.windowMs) rateBuckets.delete(ip);
}

function clientIp(ws: WebSocket): string {
  const addr = (ws as unknown as { _socket?: { remoteAddress?: string } })._socket?.remoteAddress ?? "unknown";
  return addr.replace(/^::ffff:/, "");
}

function reply(ws: WebSocket, data: unknown): void {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
}

export function startRendezvous(port = PORT): WebSocketServer {
  const wss = new WebSocketServer({ port, path: "/rendezvous" });
  wss.on("connection", (ws) => {
    ws.on("message", (raw) => {
      const ip = clientIp(ws);
      if (rateLimited(ip)) {
        reply(ws, { ok: false, error: { code: "rate_limited", message: "too many requests" } });
        return;
      }
      let frame: { type?: string; serverId?: string; endpoint?: string };
      try {
        frame = JSON.parse(raw.toString());
      } catch {
        reply(ws, { ok: false, error: { code: "invalid_input", message: "malformed frame" } });
        return;
      }
      switch (frame.type) {
        case "register": {
          if (!frame.serverId || !frame.endpoint) {
            reply(ws, { ok: false, error: { code: "invalid_input", message: "serverId and endpoint required" } });
            return;
          }
          records.set(frame.serverId, {
            serverId: frame.serverId,
            endpoint: frame.endpoint,
            expiresAt: Date.now() + TTL_MS,
          });
          reply(ws, { ok: true, data: { ttlMs: TTL_MS } });
          return;
        }
        case "resolve": {
          const rec = records.get(frame.serverId ?? "");
          if (!rec) {
            reply(ws, { ok: false, error: { code: "not_found", message: "host not registered (offline?)" } });
            return;
          }
          reply(ws, { ok: true, data: { endpoint: rec.endpoint } });
          return;
        }
        default:
          reply(ws, { ok: false, error: { code: "invalid_input", message: "unknown type" } });
      }
    });
  });
  setInterval(cleanup, CLEANUP_MS).unref();
  return wss;
}

if (process.argv[1]?.endsWith("main.js")) {
  startRendezvous();
  console.log(`[rendezvous] ouvindo em ws://127.0.0.1:${PORT}/rendezvous (TTL ${TTL_MS / 3600_000}h)`);
}
