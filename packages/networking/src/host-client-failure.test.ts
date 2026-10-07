import { createServer } from "node:net";
import { WebSocketServer } from "ws";
import { describe, expect, it } from "vitest";
import { HostClient } from "./index.js";

/**
 * O bug de campo: um erro de socket (TLS recusado, DNS, recusa) era descartado e o join só
 * descobria a falha ao esgotar o orçamento, reportando "a conexão demorou além do esperado".
 */
describe("HostClient transport failure reporting", () => {
  it("closes fast and preserves the real socket error for a refused route", async () => {
    // Reserva e libera a porta: garante recusa imediata sem depender de porta ocupada por acaso.
    const reservation = createServer();
    await new Promise<void>((resolve) => reservation.listen(0, "127.0.0.1", resolve));
    const address = reservation.address();
    if (!address || typeof address === "string") throw new Error("refused-port reservation did not bind TCP");
    await new Promise<void>((resolve, reject) => {
      reservation.close((error) => (error ? reject(error) : resolve()));
    });

    const client = new HostClient(`wss://127.0.0.1:${address.port}/signal`, { identityId: "identity-under-test" });
    try {
      const startedAt = Date.now();
      await new Promise<void>((resolve) => client.onClose(resolve));
      expect(Date.now() - startedAt).toBeLessThan(2_000);
      expect(client.connectionFailure()?.code).toBe("ECONNREFUSED");
      expect(client.connectionFailure()?.message).toMatch(/ECONNREFUSED/);
    } finally {
      client.close();
    }
  }, 10_000);

  it("leaves the failure channel empty when the session authenticates", async () => {
    const server = new WebSocketServer({ host: "127.0.0.1", port: 0 });
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("loopback ws server did not bind TCP");

    const client = new HostClient(`ws://127.0.0.1:${address.port}/signal`, { identityId: "identity-under-test" });
    try {
      const opened = await new Promise<boolean>((resolve) => client.onOpen(() => resolve(true)));
      expect(opened).toBe(true);
      expect(client.connectionFailure()).toBeNull();
    } finally {
      client.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }, 10_000);
});
