import { WebSocket } from "ws";
import type { HostCommand, HostEvent, ErrorCode } from "@janjacord/schemas";

/**
 * Transport abstraction (ADR-006/013):
 * - HostTransport: WebSocket p/ o JanjaNode (spool, membership, signaling)
 * - DirectTransport: DataChannel P2P (mensagens realtime entre peers online)
 * - RelayTransport: TURN-only (policy relay, ADR-007)
 * Cada transport entrega frames {event, data} validados por Zod.
 */

export interface Transport {
  send(event: string, data: unknown): void;
  onEvent(handler: (event: HostEvent) => void): void;
  close(): void;
}

/** Cliente WebSocket do host (signaling `{event,data}`, path /signal). */
export class HostClient implements Transport {
  private ws: WebSocket;
  private handler: ((event: HostEvent) => void) | null = null;
  private queue: string[] = [];

  constructor(
    private readonly url: string,
    private readonly auth: { identityId: string; serverId?: string },
  ) {
    this.ws = new WebSocket(url);
    this.ws.on("open", () => {
      for (const m of this.queue) this.ws.send(m);
      this.queue = [];
    });
    this.ws.on("message", (raw) => {
      try {
        const frame = JSON.parse(raw.toString()) as { event: string; data: unknown };
        // entrega o HostEvent (payload de 'event'), não o envelope de transporte
        if (frame.event === "event") this.handler?.(frame.data as HostEvent);
      } catch {
        // ignora frames malformados (anti-abuso: log local)
      }
    });
  }

  /** Envia comando; resposta via evento ou promise curta. */
  command(cmd: HostCommand): void {
    const frame = JSON.stringify({ event: "command", data: cmd });
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(frame);
    else this.queue.push(frame);
  }

  send(event: string, data: unknown): void {
    const frame = JSON.stringify({ event, data });
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(frame);
    else this.queue.push(frame);
  }

  onEvent(handler: (event: HostEvent) => void): void {
    this.handler = handler;
  }

  /** Listener one-shot para um frame de resultado específico (event === 'result'). */
  onEventOnce(event: string, handler: (frame: { event: string; data: unknown }) => void): void {
    const h = (raw: unknown) => {
      try {
        const frame = JSON.parse(String(raw)) as { event: string; data: unknown };
        if (frame.event === event) {
          this.ws.off("message", h);
          handler(frame);
        }
      } catch {
        // ignora
      }
    };
    this.ws.on("message", h);
  }

  private pending: ((data: unknown) => void)[] = [];
  private resultBound = false;

  /**
   * Requisição serializada (fila FIFO): um comando por vez; respostas do host
   * chegam na mesma ordem. Um único listener 'result' distribui para o próximo
   * pending — garante que responses nunca cruzam, mesmo com chamadas concorrentes.
   */
  request(cmd: HostCommand, timeoutMs = 8000): Promise<unknown> {
    if (!this.resultBound) {
      this.resultBound = true;
      this.ws.on("message", (raw) => {
        try {
          const frame = JSON.parse(String(raw)) as { event?: string; data?: unknown };
          if (frame.event === "result") {
            const next = this.pending.shift();
            if (next) next(frame.data);
          }
        } catch {
          // frame malformado
        }
      });
    }
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        const idx = this.pending.indexOf(resolve);
        if (idx >= 0) this.pending.splice(idx, 1);
        resolve({ ok: false, error: { code: "timeout", message: "host timeout" } });
      }, timeoutMs);
      const wrapped = (data: unknown) => {
        clearTimeout(timer);
        resolve(data);
      };
      this.pending.push(wrapped);
      this.command(cmd);
    });
  }

  onOpen(handler: () => void): void {
    this.ws.on("open", handler);
  }

  onClose(handler: () => void): void {
    this.ws.on("close", handler);
  }

  close(): void {
    this.ws.close();
  }

  get ready(): boolean {
    return this.ws.readyState === WebSocket.OPEN;
  }
}

/** Resposta helper: ok(data) | err(code, message) — forma estável para o host responder. */
export type HostOk<T> = { ok: true; data: T };
export type HostErr = { ok: false; error: { code: ErrorCode; message: string } };
export type HostResult<T> = HostOk<T> | HostErr;

export function ok<T>(data: T): HostOk<T> {
  return { ok: true, data };
}

export function err(code: ErrorCode, message: string): HostErr {
  return { ok: false, error: { code, message } };
}
