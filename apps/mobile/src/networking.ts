/**
 * HostClient para React Native — usa o WebSocket nativo (sem a lib `ws` do Node).
 * Protocolo idêntico ao desktop: frames { event, data }; hello + commands com fila.
 */
export class HostClientRN {
  private ws: WebSocket | null = null;
  private pending: ((data: unknown) => void)[] = [];
  private handler: ((event: unknown) => void) | null = null;

  connect(url: string, identityId: string): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      this.ws = ws;
      ws.onopen = () => {
        ws.onmessage = (e) => this.onMessage(e.data);
        this.send("hello", { identityId });
        const timer = setTimeout(() => reject(new Error("hello timeout")), 8000);
        // resposta do hello = primeiro result
        const orig = this.pendingPush.bind(this);
        this.pendingPush = (d: unknown) => {
          clearTimeout(timer);
          resolve(d);
          this.pendingPush = orig;
        };
      };
      ws.onerror = () => reject(new Error("ws error"));
      ws.onclose = () => { this.handler?.({ type: "connection.closed" }); };
    });
  }

  private pendingPush(_d: unknown) {}

  private onMessage(raw: string) {
    let frame: { event?: string; data?: unknown };
    try { frame = JSON.parse(raw); } catch { return; }
    if (frame.event === "result") {
      const next = this.pending.shift();
      if (next) next(frame.data);
    } else if (frame.event === "event") {
      this.handler?.(frame.data);
    }
  }

  send(event: string, data: unknown) {
    this.ws?.send(JSON.stringify({ event, data }));
  }

  /** Fila serializada: um comando por vez (responses do host na mesma ordem). */
  request(cmd: unknown, timeoutMs = 8000): Promise<unknown> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve({ ok: false, error: { code: "timeout", message: "host timeout" } }), timeoutMs);
      const wrapped = (d: unknown) => { clearTimeout(timer); resolve(d); };
      this.pending.push(wrapped);
      this.send("command", cmd);
    });
  }

  onEvent(cb: (event: unknown) => void) { this.handler = cb; }
  close() { this.ws?.close(); }
}
