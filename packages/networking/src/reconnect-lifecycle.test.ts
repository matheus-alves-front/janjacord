import { once } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ed25519Fingerprint, ed25519PublicKey } from "@janjacord/crypto";
import { createSignedHostAuthChallenge, createSignedHostGrant, createSignedHostRecord } from "@janjacord/protocol";
import { WebSocketServer, type WebSocket } from "ws";

interface ControlledPeer {
  fail(): void;
  receive(frame: unknown): void;
  sentFrames(): unknown[];
  remoteDescriptions(): { sdp: string; type: string }[];
  remoteCandidates(): { candidate: string; mid: string }[];
}

const rtc = vi.hoisted(() => ({ peers: [] as ControlledPeer[] }));

vi.mock("node-datachannel", () => {
  class ControlledDataChannel {
    private open = true;
    private closedHandler: (() => void) | null = null;
    private messageHandler: ((message: string) => void) | null = null;
    private readonly sent: unknown[] = [];

    isOpen(): boolean {
      return this.open;
    }

    sendMessage(message: string): boolean {
      this.sent.push(JSON.parse(message));
      return this.open;
    }

    onOpen(handler: () => void): void {
      queueMicrotask(handler);
    }

    onMessage(handler: (message: string) => void): void {
      this.messageHandler = handler;
    }

    onClosed(handler: () => void): void {
      this.closedHandler = handler;
    }

    onError(): void {}

    close(): void {
      if (!this.open) return;
      this.open = false;
      // libdatachannel may report closure while the transport is still tearing down.
      this.closedHandler?.();
    }

    receive(frame: unknown): void {
      this.messageHandler?.(JSON.stringify(frame));
    }

    sentFrames(): unknown[] {
      return [...this.sent];
    }
  }

  class ControlledPeerConnection implements ControlledPeer {
    private readonly channel = new ControlledDataChannel();
    private stateHandler: ((state: string) => void) | null = null;
    private readonly descriptions: { sdp: string; type: string }[] = [];
    private readonly candidates: { candidate: string; mid: string }[] = [];

    constructor() {
      rtc.peers.push(this);
    }

    onLocalDescription(): void {}

    onLocalCandidate(): void {}

    onStateChange(handler: (state: string) => void): void {
      this.stateHandler = handler;
    }

    createDataChannel(): ControlledDataChannel {
      return this.channel;
    }

    setLocalDescription(): void {}

    setRemoteDescription(sdp: string, type: string): void {
      this.descriptions.push({ sdp, type });
    }

    addRemoteCandidate(candidate: string, mid: string): void {
      this.candidates.push({ candidate, mid });
    }

    close(): void {}

    state(): string {
      return "connected";
    }

    getSelectedCandidatePair(): null {
      return null;
    }

    fail(): void {
      this.stateHandler?.("failed");
    }

    receive(frame: unknown): void {
      this.channel.receive(frame);
    }

    sentFrames(): unknown[] {
      return this.channel.sentFrames();
    }

    remoteDescriptions(): { sdp: string; type: string }[] {
      return [...this.descriptions];
    }

    remoteCandidates(): { candidate: string; mid: string }[] {
      return [...this.candidates];
    }
  }

  return { default: { PeerConnection: ControlledPeerConnection } };
});

import { IceHostTransport } from "./index.js";

const SERVER_ID = "11111111-1111-4111-8111-111111111111";
const GRANT_ID = "22222222-2222-4222-8222-222222222222";
const authoritySeed = Buffer.alloc(32, 41);
const hostSeed = Buffer.alloc(32, 42);
const deviceSeed = Buffer.alloc(32, 43);

function hostRegistration(now = Date.now()) {
  const authorityPublicKey = ed25519PublicKey(authoritySeed).toString("base64url");
  const hostPublicKey = ed25519PublicKey(hostSeed).toString("base64url");
  const grant = createSignedHostGrant({
    version: 1,
    grantId: GRANT_ID,
    serverId: SERVER_ID,
    issuerIdentityId: "owner",
    subjectIdentityId: "owner",
    subjectAuthPublicKey: ed25519PublicKey(deviceSeed).toString("base64url"),
    devicePublicKey: hostPublicKey,
    hostId: "primary-host",
    capabilities: ["register", "replicate", "promote"],
    generation: 1,
    issuedAt: now - 1_000,
    expiresAt: now + 120_000,
  }, authoritySeed);
  const record = createSignedHostRecord({
    version: 1,
    serverId: SERVER_ID,
    grantId: GRANT_ID,
    hostId: "primary-host",
    role: "primary",
    epoch: 1,
    recordSeq: 1,
    previousRecordHash: null,
    endpoints: ["wss://host.example/signal"],
    candidates: [],
    issuedAt: now,
    ttlMs: 60_000,
    expiresAt: now + 60_000,
  }, hostSeed);
  return {
    registration: { authorityPublicKey, grant, record },
    authorityFingerprint: ed25519Fingerprint(Buffer.from(authorityPublicKey, "base64url")),
  };
}

async function waitFor(check: () => boolean, message: string): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (!check()) {
    if (Date.now() >= deadline) throw new Error(message);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function authenticate(peer: ControlledPeer, trust: ReturnType<typeof hostRegistration>): void {
  const now = Date.now();
  peer.receive({
    event: "auth.challenge",
    data: createSignedHostAuthChallenge({
      version: 1,
      serverId: SERVER_ID,
      authorityFingerprint: trust.authorityFingerprint,
      hostId: "primary-host",
      grantId: GRANT_ID,
      challengeId: "33333333-3333-4333-8333-333333333333",
      nonce: Buffer.alloc(32, 9).toString("base64url"),
      issuedAt: now,
      expiresAt: now + 30_000,
    }, hostSeed),
  });
  peer.receive({ event: "auth.ready", data: { ok: true } });
}

async function connectedTransport(): Promise<{
  transport: IceHostTransport;
  trust: ReturnType<typeof hostRegistration>;
  relay(payload: unknown): void;
  relayRaw(raw: string): void;
  bridgeExtensions(): string | string[] | undefined;
}> {
  const server = new WebSocketServer({ port: 0 });
  servers.push(server);
  if (!server.address()) await once(server, "listening");
  let activeSocket: WebSocket | null = null;
  let activeSessionId = "";
  let extensions: string | string[] | undefined;
  server.on("connection", (socket: WebSocket, request) => {
    activeSocket = socket;
    extensions = request.headers["sec-websocket-extensions"];
    socket.on("message", (raw) => {
      const frame = JSON.parse(raw.toString()) as {
        type?: string;
        sessionId?: string;
        payload?: { type?: string };
      };
      if (frame.type === "signal.open" && frame.payload?.type === "ice.request") {
        activeSessionId = frame.sessionId ?? "";
        socket.send(JSON.stringify({
          type: "signal.relay",
          sessionId: frame.sessionId,
          payload: { type: "ice.config", networkPrivacy: "direct", credentials: null },
        }));
      }
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test bridge did not bind");
  const trust = hostRegistration();
  const transport = new IceHostTransport({
    bridgeUrl: `ws://127.0.0.1:${address.port}`,
    serverId: SERVER_ID,
    hostId: "primary-host",
    identityId: "member",
    authorityFingerprint: trust.authorityFingerprint,
    hostRegistration: trust.registration,
    deviceSeed,
    iceServers: ["stun:127.0.0.1:3478"],
    reconnectBaseDelayMs: 20,
    reconnectMaxDelayMs: 100,
    connectionTimeoutMs: 1_000,
  });
  transports.push(transport);
  await waitFor(() => rtc.peers.length === 1, "transport did not create a peer");
  authenticate(rtc.peers[0]!, trust);
  await waitFor(() => transport.ready, "transport did not authenticate");
  return {
    transport,
    trust,
    relay(payload: unknown) {
      if (!activeSocket || !activeSessionId) throw new Error("bridge session is not ready");
      activeSocket.send(JSON.stringify({ type: "signal.relay", sessionId: activeSessionId, payload }));
    },
    relayRaw(raw: string) {
      if (!activeSocket) throw new Error("bridge socket is not ready");
      activeSocket.send(raw);
    },
    bridgeExtensions: () => extensions,
  };
}

const servers: WebSocketServer[] = [];
const transports: IceHostTransport[] = [];

afterEach(async () => {
  for (const transport of transports.splice(0)) transport.close();
  rtc.peers.splice(0);
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    for (const client of server.clients) client.terminate();
    server.close(() => resolve());
  })));
});

describe("IceHostTransport reconnect lifecycle", () => {
  it("keeps delayed hello and mixed send(command) result slots ahead of request results", async () => {
    const { transport } = await connectedTransport();
    const peer = rtc.peers[0]!;

    transport.send("hello", { identityId: "member" });
    transport.send("event.fire-and-forget", { sequence: 1 });
    transport.send("command", { type: "server.state" });
    let settled = false;
    const result = transport.request({ type: "server.state" }, 1_000).finally(() => {
      settled = true;
    });

    await waitFor(() => peer.sentFrames().filter((frame) => (
      ["hello", "event.fire-and-forget", "command"].includes((frame as { event?: string }).event ?? "")
    )).length === 4, "mixed application frames were not sent");
    expect(peer.sentFrames().slice(-4).map((frame) => (frame as { event?: string }).event)).toEqual([
      "hello",
      "event.fire-and-forget",
      "command",
      "command",
    ]);

    await new Promise((resolve) => setTimeout(resolve, 50));
    peer.receive({ event: "result", data: { ok: true, data: "hello-result" } });
    peer.receive({ event: "result", data: { ok: false, error: { code: "invalid_input", message: "unknown event" } } });
    peer.receive({ event: "result", data: { ok: true, data: "send-result" } });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(settled).toBe(false);
    peer.receive({ event: "result", data: { ok: true, data: "request-result" } });

    await expect(result).resolves.toEqual({ ok: true, data: "request-result" });
  });

  it("does not let an unknown-event result displace the following request", async () => {
    const { transport } = await connectedTransport();
    const peer = rtc.peers[0]!;
    const pushedEvents: unknown[] = [];
    transport.onEvent((event) => pushedEvents.push(event));

    transport.send("application.unknown", { sequence: 1 });
    let settled = false;
    const result = transport.request({ type: "server.state" }, 1_000).finally(() => {
      settled = true;
    });
    await waitFor(
      () => peer.sentFrames().filter((frame) => ["application.unknown", "command"].includes((frame as { event?: string }).event ?? "")).length === 2,
      "unknown event and request were not sent",
    );

    peer.receive({ event: "event", data: { type: "server.stateChanged" } });
    peer.receive({ event: "result", data: { ok: false, error: { code: "invalid_input", message: "unknown event" } } });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(settled).toBe(false);
    peer.receive({ event: "result", data: { ok: true, data: "request-result" } });

    await expect(result).resolves.toEqual({ ok: true, data: "request-result" });
    expect(pushedEvents).toEqual([{ type: "server.stateChanged" }]);
  });

  it("rejects malformed bridge answers and candidates before native RTC", async () => {
    const { relay } = await connectedTransport();
    const peer = rtc.peers[0]!;
    const validSdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
    const validCandidate = "candidate:1 1 udp 2122260223 192.0.2.1 54321 typ host";

    relay({ type: "answer", sdp: "not-sdp" });
    relay({ type: "answer", sdp: `v=0\r\n${"s".repeat(48 * 1024)}` });
    relay({ type: "offer", sdp: validSdp });
    relay({ type: "candidate", candidate: "not-a-candidate", mid: "0" });
    relay({ type: "candidate", candidate: `candidate:${"c".repeat(4 * 1024)}`, mid: "0" });
    relay({ type: "candidate", candidate: validCandidate, mid: "m".repeat(65) });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(peer.remoteDescriptions()).toEqual([]);
    expect(peer.remoteCandidates()).toEqual([]);

    relay({ type: "answer", sdp: validSdp });
    relay({ type: "candidate", candidate: validCandidate, mid: "0" });
    await waitFor(
      () => peer.remoteDescriptions().length === 1 && peer.remoteCandidates().length === 1,
      "valid answer and candidate did not reach native RTC",
    );
    expect(peer.remoteDescriptions()).toEqual([{ sdp: validSdp, type: "answer" }]);
    expect(peer.remoteCandidates()).toEqual([{ candidate: validCandidate, mid: "0" }]);
  });

  it("bounds bridge WebSocket payloads and disables compression negotiation", async () => {
    const { relayRaw, bridgeExtensions } = await connectedTransport();
    expect(bridgeExtensions()).toBeUndefined();

    relayRaw(JSON.stringify({ padding: "x".repeat(64 * 1024) }));
    await waitFor(() => rtc.peers.length === 2, "oversized bridge frame did not fence and reconnect the transport");
  });

  it("fences a timed-out generation so a late result cannot consume the next attempt", async () => {
    const { transport, trust } = await connectedTransport();
    const firstPeer = rtc.peers[0]!;
    const first = transport.request({ type: "server.state" }, 40);
    await waitFor(
      () => firstPeer.sentFrames().some((frame) => (frame as { event?: string }).event === "command"),
      "first command was not sent",
    );
    await expect(first).resolves.toMatchObject({ ok: false, error: { code: "timeout" } });

    // The old channel can still invoke a queued native callback after teardown. Its generation
    // must already be invalid, otherwise this frame could settle a request on the new channel.
    firstPeer.receive({ event: "result", data: { ok: true, data: "late-first" } });
    await waitFor(() => rtc.peers.length === 2, "transport did not reconnect after request timeout");
    const secondPeer = rtc.peers[1]!;
    authenticate(secondPeer, trust);
    await waitFor(() => transport.ready, "transport did not reauthenticate after timeout");

    const second = transport.request({ type: "server.state" }, 1_000);
    await waitFor(
      () => secondPeer.sentFrames().some((frame) => (frame as { event?: string }).event === "command"),
      "second command was not sent",
    );
    secondPeer.receive({ event: "result", data: { ok: true, data: "second" } });
    await expect(second).resolves.toEqual({ ok: true, data: "second" });
  });

  it("settles every request and leaves no reconnect behind after close", async () => {
    const { transport } = await connectedTransport();
    const first = transport.request({ type: "server.state" }, 60_000);
    const second = transport.request({ type: "server.state" }, 60_000);
    transport.close();

    await expect(Promise.all([first, second])).resolves.toEqual([
      { ok: false, error: { code: "host_offline", message: "transport closed" } },
      { ok: false, error: { code: "host_offline", message: "transport closed" } },
    ]);
    await expect(transport.request({ type: "server.state" }, 60_000)).resolves.toEqual(
      { ok: false, error: { code: "host_offline", message: "transport closed" } },
    );
    expect(() => transport.command({ type: "server.state" })).toThrow(/closed/);
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(rtc.peers).toHaveLength(1);
  });

  it("invalidates teardown callbacks before backoff so they cannot replace the new session", async () => {
    const server = new WebSocketServer({ port: 0 });
    servers.push(server);
    if (!server.address()) await once(server, "listening");
    let bridgeConnections = 0;
    server.on("connection", (socket: WebSocket) => {
      bridgeConnections += 1;
      socket.on("message", (raw) => {
        const frame = JSON.parse(raw.toString()) as {
          type?: string;
          sessionId?: string;
          payload?: { type?: string };
        };
        if (frame.type === "signal.open" && frame.payload?.type === "ice.request") {
          socket.send(JSON.stringify({
            type: "signal.relay",
            sessionId: frame.sessionId,
            payload: { type: "ice.config", networkPrivacy: "direct", credentials: null },
          }));
        }
      });
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test bridge did not bind");
    const trust = hostRegistration();
    const transport = new IceHostTransport({
      bridgeUrl: `ws://127.0.0.1:${address.port}`,
      serverId: SERVER_ID,
      hostId: "primary-host",
      identityId: "member",
      authorityFingerprint: trust.authorityFingerprint,
      hostRegistration: trust.registration,
      deviceSeed,
      iceServers: ["stun:127.0.0.1:3478"],
      reconnectBaseDelayMs: 20,
      reconnectMaxDelayMs: 100,
      connectionTimeoutMs: 1_000,
    });
    transports.push(transport);

    await waitFor(() => rtc.peers.length === 1, "initial transport attempt did not create a peer");
    rtc.peers[0]!.fail();
    await waitFor(() => rtc.peers.length >= 2, "transport did not reconnect");
    await new Promise((resolve) => setTimeout(resolve, 120));

    expect(rtc.peers).toHaveLength(2);
    expect(bridgeConnections).toBe(2);
  });

  it("emits one persistent, monotonic signal for each authenticated connection", async () => {
    const server = new WebSocketServer({ port: 0 });
    servers.push(server);
    if (!server.address()) await once(server, "listening");
    server.on("connection", (socket: WebSocket) => {
      socket.on("message", (raw) => {
        const frame = JSON.parse(raw.toString()) as {
          type?: string;
          sessionId?: string;
          payload?: { type?: string };
        };
        if (frame.type === "signal.open" && frame.payload?.type === "ice.request") {
          socket.send(JSON.stringify({
            type: "signal.relay",
            sessionId: frame.sessionId,
            payload: { type: "ice.config", networkPrivacy: "direct", credentials: null },
          }));
        }
      });
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test bridge did not bind");
    const trust = hostRegistration();
    const transport = new IceHostTransport({
      bridgeUrl: `ws://127.0.0.1:${address.port}`,
      serverId: SERVER_ID,
      hostId: "primary-host",
      identityId: "member",
      authorityFingerprint: trust.authorityFingerprint,
      hostRegistration: trust.registration,
      deviceSeed,
      iceServers: ["stun:127.0.0.1:3478"],
      reconnectBaseDelayMs: 20,
      reconnectMaxDelayMs: 100,
      connectionTimeoutMs: 1_000,
    });
    transports.push(transport);
    const openings: { generation: number; reconnected: boolean }[] = [];
    transport.onAuthenticatedOpen((event) => openings.push(event));

    await waitFor(() => rtc.peers.length === 1, "initial transport attempt did not create a peer");
    // Use the same production helper/host key as JanjaNode for a valid challenge.
    const authenticateValid = (peer: ControlledPeer) => {
      const now = Date.now();
      peer.receive({
        event: "auth.challenge",
        data: createSignedHostAuthChallenge({
          version: 1,
          serverId: SERVER_ID,
          authorityFingerprint: trust.authorityFingerprint,
          hostId: "primary-host",
          grantId: GRANT_ID,
          challengeId: "33333333-3333-4333-8333-333333333333",
          nonce: Buffer.alloc(32, 9).toString("base64url"),
          issuedAt: now,
          expiresAt: now + 30_000,
        }, hostSeed),
      });
      peer.receive({ event: "auth.ready", data: { ok: true } });
    };
    authenticateValid(rtc.peers[0]!);
    await waitFor(() => openings.length === 1, "initial authenticated lifecycle signal missing");
    rtc.peers[0]!.receive({ event: "auth.ready", data: { ok: true } });
    expect(openings).toEqual([{ generation: 1, reconnected: false }]);

    rtc.peers[0]!.fail();
    await waitFor(() => rtc.peers.length === 2, "transport did not reconnect");
    authenticateValid(rtc.peers[1]!);
    await waitFor(() => openings.length === 2, "authenticated reconnect lifecycle signal missing");
    expect(openings).toEqual([
      { generation: 1, reconnected: false },
      { generation: 2, reconnected: true },
    ]);
  });
});
