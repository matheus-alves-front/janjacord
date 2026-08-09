/**
 * Push service (spec mobile/push; INTEGRATIONS §6) — infra central mínima.
 * - Payload 100% estático: "New activity on JanjaCord" (sem sender/server/channel/conteúdo).
 * - Tokens de device NUNCA expostos ao JanjaNode: o host dispara com um capability ticket,
 *   e o device registra com o MESMO ticket (acoplamento opaco pelo service).
 * - Provider: 'mock' (log) para teste sem credenciais; 'fcm'/'apns' exigem config (blocker externo).
 *
 * Protocolo (JSON sobre WebSocket):
 *   device.register { ticket, serverId, token, provider }
 *   host.ping       { ticket, serverId }     → dispara push estático para os devices do server
 */
import { WebSocketServer, WebSocket } from "ws";

const PORT = Number(process.env.JC_PUSH_PORT ?? 8980);
const STATIC_TEXT = process.env.JC_PUSH_TEXT ?? "New activity on JanjaCord";

interface Device {
  ticket: string;
  serverId: string;
  token: string;
  provider: "mock" | "fcm" | "apns";
}

const devices = new Map<string, Device>(); // token -> device

function reply(ws: WebSocket, data: unknown): void {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
}

/** Dispara push para um device. Provider mock = log (testável sem contas). */
async function dispatch(device: Device): Promise<void> {
  if (device.provider === "mock") {
    console.log(
      `[push] MOCK enviaria push → ${device.token} | payload: ${JSON.stringify({
        title: "JanjaCord",
        body: STATIC_TEXT,
        data: {},
      })} (sem conteúdo/sender/server/channel)`,
    );
    return;
  }
  // fcm/apns: requerem credenciais (JC_FCM_CREDENTIALS / JC_APNS_KEY) — blocker externo
  console.warn(`[push] provider ${device.provider} sem credenciais configuradas — push não disparado`);
}

export function startPushService(port = PORT): WebSocketServer {
  const wss = new WebSocketServer({ port, path: "/push" });
  wss.on("connection", (ws) => {
    ws.on("message", async (raw) => {
      let frame: { type?: string; ticket?: string; serverId?: string; token?: string; provider?: string };
      try {
        frame = JSON.parse(raw.toString());
      } catch {
        reply(ws, { ok: false, error: { code: "invalid_input", message: "malformed frame" } });
        return;
      }
      switch (frame.type) {
        case "device.register": {
          const provider = (frame.provider ?? "mock") as Device["provider"];
          if (!frame.ticket || !frame.serverId || !frame.token) {
            reply(ws, { ok: false, error: { code: "invalid_input", message: "ticket/serverId/token required" } });
            return;
          }
          devices.set(frame.token, { ticket: frame.ticket, serverId: frame.serverId, token: frame.token, provider });
          reply(ws, { ok: true, data: { registered: true } });
          return;
        }
        case "host.ping": {
          if (!frame.ticket || !frame.serverId) {
            reply(ws, { ok: false, error: { code: "invalid_input", message: "ticket/serverId required" } });
            return;
          }
          // dispara para todos os devices do server (payload estático; sem conteúdo)
          let dispatched = 0;
          for (const device of devices.values()) {
            if (device.serverId === frame.serverId && device.ticket === frame.ticket) {
              await dispatch(device);
              dispatched++;
            }
          }
          reply(ws, { ok: true, data: { dispatched, staticText: STATIC_TEXT } });
          return;
        }
        default:
          reply(ws, { ok: false, error: { code: "invalid_input", message: "unknown type" } });
      }
    });
  });
  return wss;
}

if (process.argv[1]?.endsWith("main.js")) {
  startPushService();
  console.log(`[push] service ativo em ws://127.0.0.1:${PORT}/push (payload estático: "${STATIC_TEXT}")`);
}
