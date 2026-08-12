import { createServer } from "node:net";
import { describe, expect, it } from "vitest";
import {
  EXTERNAL_WEBSOCKET_HANDSHAKE_TIMEOUT_MS,
  EXTERNAL_WEBSOCKET_MAX_PAYLOAD_BYTES,
  REPLICA_TRANSFER_MAX_PAYLOAD_BYTES,
  createExternalWebSocket,
  externalWebSocketPolicy,
} from "./index.js";

describe("external WebSocket policy", () => {
  it("keeps the public protocol boundary at 64 KiB with compression disabled", () => {
    expect(externalWebSocketPolicy()).toEqual({
      maxPayload: 64 * 1024,
      perMessageDeflate: false,
      handshakeTimeout: 5_000,
    });
    expect(EXTERNAL_WEBSOCKET_MAX_PAYLOAD_BYTES).toBe(64 * 1024);
    expect(EXTERNAL_WEBSOCKET_HANDSHAKE_TIMEOUT_MS).toBe(5_000);
  });

  it("keeps full replica transfers on an explicit bounded policy", () => {
    expect(externalWebSocketPolicy("replica-transfer")).toEqual({
      maxPayload: 16 * 1024 * 1024,
      perMessageDeflate: false,
      handshakeTimeout: 5_000,
    });
    expect(REPLICA_TRANSFER_MAX_PAYLOAD_BYTES).toBe(16 * 1024 * 1024);
  });

  it("closes a stalled external HTTP upgrade at the handshake deadline", async () => {
    const sockets = new Set<import("node:net").Socket>();
    const server = createServer((socket) => {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
      // Accept TCP but deliberately never answer the WebSocket HTTP upgrade.
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("stalled upgrade server did not bind TCP");
    const startedAt = Date.now();
    const client = createExternalWebSocket(`ws://127.0.0.1:${address.port}/stalled`);
    try {
      const error = await new Promise<Error>((resolve, reject) => {
        const guard = setTimeout(() => reject(new Error("external handshake did not time out")), 7_000);
        client.once("error", (value) => {
          clearTimeout(guard);
          resolve(value);
        });
      });
      const elapsed = Date.now() - startedAt;
      expect(error.message).toMatch(/handshake.*timed out/i);
      expect(elapsed).toBeGreaterThanOrEqual(EXTERNAL_WEBSOCKET_HANDSHAKE_TIMEOUT_MS - 500);
      expect(elapsed).toBeLessThan(EXTERNAL_WEBSOCKET_HANDSHAKE_TIMEOUT_MS + 1_500);
      await new Promise<void>((resolve, reject) => {
        if (client.readyState === client.CLOSED) return resolve();
        const guard = setTimeout(() => reject(new Error("timed-out client did not close")), 1_000);
        client.once("close", () => { clearTimeout(guard); resolve(); });
      });
    } finally {
      if (client.readyState !== client.CLOSED) client.terminate();
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }, 8_000);
});
