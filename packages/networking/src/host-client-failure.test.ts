import { createServer } from "node:net";
import { createSignedHostAuthChallenge } from "@janjacord/protocol";
import { ed25519PublicKey } from "@janjacord/crypto";
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

  it("reports which identity field was rejected instead of a bare host-authority error", async () => {
    // Host que responde por uma rota, mas assina o desafio com OUTRA chave — o caso em que a rota
    // publicada entrega outro processo (outra instância, túnel reapontado).
    const foreignSeed = Buffer.alloc(32, 42);
    const server = new WebSocketServer({ host: "127.0.0.1", port: 0 });
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("fake host did not bind TCP");
    server.on("connection", (socket) => {
      socket.on("message", () => {
        socket.send(JSON.stringify({
          event: "auth.challenge",
          data: createSignedHostAuthChallenge({
            version: 1,
            serverId: "11111111-1111-4111-8111-111111111111",
            authorityFingerprint: "00".repeat(32),
            hostId: "primary-host-de-outra-instancia",
            grantId: "22222222-2222-4222-8222-222222222222",
            challengeId: "33333333-3333-4333-8333-333333333333",
            nonce: Buffer.alloc(32, 7).toString("base64url"),
            issuedAt: Date.now(),
            expiresAt: Date.now() + 30_000,
          }, foreignSeed),
        }));
      });
    });

    const client = new HostClient(`ws://127.0.0.1:${address.port}/signal`, {
      identityId: "identity-under-test",
      deviceSeed: Buffer.alloc(32, 9),
      serverId: "11111111-1111-4111-8111-111111111111",
      expectedHostPublicKey: ed25519PublicKey(Buffer.alloc(32, 3)).toString("base64url"),
      expectedHostId: "primary-host-esperado",
    });
    try {
      await new Promise<void>((resolve) => client.onClose(resolve));
      const failure = client.connectionFailure();
      expect(failure?.code).toBe("closed_1008");
      expect(failure?.message).toMatch(/invalid host authority: host_public_key/);
    } finally {
      client.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
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
