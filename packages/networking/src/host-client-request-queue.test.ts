import { once } from "node:events";
import { afterEach, describe, expect, it } from "vitest";
import { ed25519Fingerprint, ed25519PublicKey } from "@janjacord/crypto";
import { createSignedHostAuthChallenge } from "@janjacord/protocol";
import { WebSocket, WebSocketServer } from "ws";
import { HostClient } from "./index.js";

const SERVER_ID = "11111111-1111-4111-8111-111111111111";
const GRANT_ID = "22222222-2222-4222-8222-222222222222";
const hostSeed = Buffer.alloc(32, 51);
const deviceSeed = Buffer.alloc(32, 52);
const hostPublicKey = ed25519PublicKey(hostSeed).toString("base64url");
const authorityFingerprint = ed25519Fingerprint(ed25519PublicKey(Buffer.alloc(32, 53)));
const servers: WebSocketServer[] = [];
const clients: HostClient[] = [];

afterEach(async () => {
  for (const client of clients.splice(0)) client.close();
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    for (const socket of server.clients) socket.terminate();
    server.close(() => resolve());
  })));
});

async function openServer(
  onApplicationFrame: (
    socket: WebSocket,
    commandNumber: number,
    frame: { event?: string; data?: unknown },
  ) => void,
): Promise<{ url: string; connections: () => number }> {
  const server = new WebSocketServer({ port: 0 });
  servers.push(server);
  if (!server.address()) await once(server, "listening");
  let commandNumber = 0;
  let connections = 0;
  server.on("connection", (socket: WebSocket) => {
    connections += 1;
    socket.on("message", (raw) => {
      const frame = JSON.parse(raw.toString()) as { event?: string; data?: unknown };
      if (frame.event === "auth.begin") {
        const now = Date.now();
        socket.send(JSON.stringify({
          event: "auth.challenge",
          data: createSignedHostAuthChallenge({
            version: 1,
            serverId: SERVER_ID,
            authorityFingerprint,
            hostId: "primary-host",
            grantId: GRANT_ID,
            challengeId: "33333333-3333-4333-8333-333333333333",
            nonce: Buffer.alloc(32, connections).toString("base64url"),
            issuedAt: now,
            expiresAt: now + 30_000,
          }, hostSeed),
        }));
      } else if (frame.event === "auth.prove") {
        socket.send(JSON.stringify({ event: "auth.ready", data: { ok: true } }));
      } else {
        if (frame.event === "command") commandNumber += 1;
        onApplicationFrame(socket, commandNumber, frame);
      }
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server did not bind");
  return {
    url: `ws://127.0.0.1:${address.port}`,
    connections: () => connections,
  };
}

function createClient(url: string): HostClient {
  const client = new HostClient(url, {
    identityId: "member",
    deviceSeed,
    serverId: SERVER_ID,
    authorityFingerprint,
    expectedHostPublicKey: hostPublicKey,
    expectedHostId: "primary-host",
    expectedGrantId: GRANT_ID,
  });
  clients.push(client);
  return client;
}

function waitUntilOpen(client: HostClient): Promise<void> {
  return Promise.race([
    new Promise<void>((resolve) => client.onOpen(resolve)),
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error("client open timeout")), 2_000)),
  ]);
}

describe("HostClient request queue", () => {
  it("rejects an oversized host frame without compression or FIFO displacement", async () => {
    let extensions: string | string[] | undefined;
    const server = new WebSocketServer({ port: 0, perMessageDeflate: true });
    servers.push(server);
    if (!server.address()) await once(server, "listening");
    server.on("connection", (socket, request) => {
      extensions = request.headers["sec-websocket-extensions"];
      socket.on("message", (raw) => {
        const frame = JSON.parse(raw.toString()) as { event?: string; data?: unknown };
        if (frame.event === "auth.begin") {
          const now = Date.now();
          socket.send(JSON.stringify({
            event: "auth.challenge",
            data: createSignedHostAuthChallenge({
              version: 1,
              serverId: SERVER_ID,
              authorityFingerprint,
              hostId: "primary-host",
              grantId: GRANT_ID,
              challengeId: "33333333-3333-4333-8333-333333333333",
              nonce: Buffer.alloc(32, 7).toString("base64url"),
              issuedAt: now,
              expiresAt: now + 30_000,
            }, hostSeed),
          }));
        } else if (frame.event === "auth.prove") {
          socket.send(JSON.stringify({ event: "auth.ready", data: { ok: true } }));
        } else if (frame.event === "command") {
          socket.send(JSON.stringify({ event: "result", data: { padding: "x".repeat(64 * 1024) } }));
        }
      });
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server did not bind");
    const client = createClient(`ws://127.0.0.1:${address.port}`);
    await waitUntilOpen(client);

    const oversized = client.request({ type: "server.state" }, 2_000);
    const queued = client.request({ type: "server.state" }, 2_000);

    await expect(Promise.all([oversized, queued])).resolves.toEqual([
      { ok: false, error: { code: "host_offline", message: "host connection closed" } },
      { ok: false, error: { code: "host_offline", message: "host connection closed" } },
    ]);
    expect(extensions).toBeUndefined();
  });

  it("uses a separate bounded inbound policy for full replica transfers and preserves the normal FIFO", async () => {
    const received: string[] = [];
    let normalRequests = 0;
    const negotiatedExtensions: Array<string | string[] | undefined> = [];
    const server = new WebSocketServer({ port: 0, perMessageDeflate: true });
    servers.push(server);
    if (!server.address()) await once(server, "listening");
    server.on("connection", (socket, request) => {
      negotiatedExtensions.push(request.headers["sec-websocket-extensions"]);
      socket.on("message", (raw) => {
        const frame = JSON.parse(raw.toString()) as { event?: string; data?: { type?: string } };
        if (frame.event === "auth.begin") {
          const now = Date.now();
          socket.send(JSON.stringify({
            event: "auth.challenge",
            data: createSignedHostAuthChallenge({
              version: 1,
              serverId: SERVER_ID,
              authorityFingerprint,
              hostId: "primary-host",
              grantId: GRANT_ID,
              challengeId: "33333333-3333-4333-8333-333333333333",
              nonce: Buffer.alloc(32, negotiatedExtensions.length).toString("base64url"),
              issuedAt: now,
              expiresAt: now + 30_000,
            }, hostSeed),
          }));
        } else if (frame.event === "auth.prove") {
          socket.send(JSON.stringify({ event: "auth.ready", data: { ok: true } }));
        } else if (frame.event === "command") {
          received.push(frame.data?.type ?? "");
          if (frame.data?.type !== "replica.snapshot") normalRequests += 1;
          socket.send(JSON.stringify({
            event: "result",
            data: frame.data?.type === "replica.snapshot"
              ? { ok: true, data: { dbB64: "x".repeat(80 * 1024) } }
              : normalRequests === 1
                ? { ok: true, data: "normal-result" }
                : { padding: "x".repeat(80 * 1024) },
          }));
        }
      });
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server did not bind");
    const client = createClient(`ws://127.0.0.1:${address.port}`);
    await waitUntilOpen(client);

    await expect(client.request({ type: "replica.snapshot", grantId: GRANT_ID, serverId: SERVER_ID }, 2_000))
      .resolves.toMatchObject({ ok: true, data: { dbB64: expect.any(String) } });
    await expect(client.request({ type: "server.state" }, 2_000)).resolves.toEqual({ ok: true, data: "normal-result" });
    await expect(client.request({ type: "server.state" }, 2_000)).resolves.toEqual({
      ok: false,
      error: { code: "host_offline", message: "host connection closed" },
    });

    expect(received).toEqual(["replica.snapshot", "server.state", "server.state"]);
    expect(negotiatedExtensions).toEqual([undefined]);
  });

  it("keeps delayed hello and ignored send results ahead of request results", async () => {
    const receivedEvents: string[] = [];
    const server = await openServer((socket, commandNumber, frame) => {
      receivedEvents.push(frame.event ?? "");
      if (frame.event === "hello") {
        setTimeout(() => {
          socket.send(JSON.stringify({ event: "result", data: { ok: true, data: "hello-result" } }));
        }, 80);
      } else if (frame.event === "event.fire-and-forget") {
        // send() is fire-and-forget to its caller, but the real gateway still emits a FIFO result.
        socket.send(JSON.stringify({ event: "result", data: { ok: false, error: { code: "invalid_input" } } }));
      } else if (frame.event === "command" && commandNumber === 1) {
        socket.send(JSON.stringify({ event: "result", data: { ok: true, data: "send-result" } }));
      } else if (frame.event === "command" && commandNumber === 2) {
        socket.send(JSON.stringify({ event: "result", data: { ok: true, data: "request-result" } }));
      }
    });
    const client = createClient(server.url);
    await waitUntilOpen(client);

    client.send("hello", { identityId: "member" });
    client.send("event.fire-and-forget", { sequence: 1 });
    client.send("command", { type: "server.state" });
    const result = client.request({ type: "server.state" }, 1_000);

    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(receivedEvents).toEqual(["hello"]);
    await expect(result).resolves.toEqual({ ok: true, data: "request-result" });
    expect(receivedEvents).toEqual(["hello", "event.fire-and-forget", "command", "command"]);
  });

  it("does not let an unknown-event result displace the following request", async () => {
    const receivedEvents: string[] = [];
    const pushedEvents: unknown[] = [];
    const server = await openServer((socket, _commandNumber, frame) => {
      receivedEvents.push(frame.event ?? "");
      if (frame.event === "application.unknown") {
        socket.send(JSON.stringify({ event: "event", data: { type: "server.stateChanged" } }));
        socket.send(JSON.stringify({
          event: "result",
          data: { ok: false, error: { code: "invalid_input", message: "unknown event" } },
        }));
      } else if (frame.event === "command") {
        socket.send(JSON.stringify({ event: "result", data: { ok: true, data: "request-result" } }));
      }
    });
    const client = createClient(server.url);
    await waitUntilOpen(client);
    client.onEvent((event) => pushedEvents.push(event));

    client.send("application.unknown", { sequence: 1 });
    await expect(client.request({ type: "server.state" }, 1_000)).resolves.toEqual({
      ok: true,
      data: "request-result",
    });
    expect(receivedEvents).toEqual(["application.unknown", "command"]);
    expect(pushedEvents).toEqual([{ type: "server.stateChanged" }]);
  });

  it("does not let a lost first ACK consume the following request result", async () => {
    const server = await openServer((socket, commandNumber) => {
      if (commandNumber === 2) {
        socket.send(JSON.stringify({ event: "result", data: { ok: true, data: "second" } }));
      }
    });
    const client = createClient(server.url);
    await waitUntilOpen(client);

    await expect(client.request({ type: "server.state" }, 40)).resolves.toMatchObject({
      ok: false,
      error: { code: "timeout" },
    });
    await expect(client.request({ type: "server.state" }, 1_000)).resolves.toEqual({
      ok: true,
      data: "second",
    });
    expect(server.connections()).toBe(2);
  });

  it("fences a late result on the timed-out socket before dispatching the next request", async () => {
    let lateResultAttempted = false;
    const server = await openServer((socket, commandNumber) => {
      if (commandNumber === 1) {
        setTimeout(() => {
          lateResultAttempted = true;
          if (socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ event: "result", data: { ok: true, data: "late-first" } }));
          }
        }, 80);
      } else {
        setTimeout(() => {
          socket.send(JSON.stringify({ event: "result", data: { ok: true, data: "second" } }));
        }, 100);
      }
    });
    const client = createClient(server.url);
    await waitUntilOpen(client);

    await client.request({ type: "server.state" }, 40);
    await expect(client.request({ type: "server.state" }, 1_000)).resolves.toEqual({
      ok: true,
      data: "second",
    });
    expect(lateResultAttempted).toBe(true);
  });

  it("settles in-flight and queued requests immediately when closed", async () => {
    const server = await openServer(() => undefined);
    const client = createClient(server.url);
    await waitUntilOpen(client);

    const inFlight = client.request({ type: "server.state" }, 60_000);
    const queued = client.request({ type: "server.state" }, 60_000);
    client.close();

    await expect(Promise.all([inFlight, queued])).resolves.toEqual([
      { ok: false, error: { code: "host_offline", message: "transport closed" } },
      { ok: false, error: { code: "host_offline", message: "transport closed" } },
    ]);
    await expect(client.request({ type: "server.state" }, 60_000)).resolves.toEqual(
      { ok: false, error: { code: "host_offline", message: "transport closed" } },
    );
    expect(() => client.command({ type: "server.state" })).toThrow(/closed/);
  });
});
