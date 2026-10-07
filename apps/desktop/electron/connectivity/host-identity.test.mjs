import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";
import { createSignedHostAuthChallenge } from "@janjacord/protocol";
import { ed25519PublicKey } from "@janjacord/crypto";
import { probePublishedHostIdentity } from "./host-identity.mjs";

const SERVER_ID = "11111111-1111-4111-8111-111111111111";
const hostSeed = Buffer.alloc(32, 2);
const otherSeed = Buffer.alloc(32, 7);

function challengeFrom(seed, overrides = {}) {
  const now = Date.now();
  return createSignedHostAuthChallenge({
    version: 1,
    serverId: SERVER_ID,
    authorityFingerprint: "11".repeat(32),
    hostId: "primary-host-esperado",
    grantId: "22222222-2222-4222-8222-222222222222",
    challengeId: "33333333-3333-4333-8333-333333333333",
    nonce: Buffer.alloc(32, 7).toString("base64url"),
    issuedAt: now,
    expiresAt: now + 30_000,
    ...overrides,
  }, seed);
}

class FakeSocket extends EventEmitter {
  sent = [];
  closed = false;
  send(payload) {
    this.sent.push(JSON.parse(payload));
  }
  close() {
    this.closed = true;
  }
}

const probe = (socket, overrides = {}) => probePublishedHostIdentity({
  endpoint: "wss://rota.example/signal",
  openSocket: () => socket,
  probeIdentityId: "identity-de-diagnostico",
  probePublicKey: ed25519PublicKey(Buffer.alloc(32, 9)).toString("base64url"),
  expectedHostPublicKey: ed25519PublicKey(hostSeed).toString("base64url"),
  expectedHostId: "primary-host-esperado",
  timeoutMs: 50,
  ...overrides,
});

describe("published host identity probe", () => {
  it("confirms the host that answers for the published route", async () => {
    const socket = new FakeSocket();
    const result = probe(socket);
    socket.emit("open");
    expect(socket.sent[0]).toMatchObject({ event: "auth.begin", data: { identityId: "identity-de-diagnostico" } });
    socket.emit("message", JSON.stringify({ event: "auth.challenge", data: challengeFrom(hostSeed) }));
    await expect(result).resolves.toMatchObject({ ok: true, reason: null, identityMismatch: false, hostId: "primary-host-esperado" });
    expect(socket.closed).toBe(true);
  });

  it("flags the route as delivering another host when the key differs", async () => {
    const socket = new FakeSocket();
    const result = probe(socket);
    socket.emit("open");
    socket.emit("message", JSON.stringify({ event: "auth.challenge", data: challengeFrom(otherSeed) }));
    await expect(result).resolves.toMatchObject({ ok: false, reason: "host_public_key", identityMismatch: true });
  });

  it("flags a different community even when the answering host is well-formed", async () => {
    const socket = new FakeSocket();
    const result = probe(socket, {
      expectedHostPublicKey: ed25519PublicKey(hostSeed).toString("base64url"),
      expectedHostId: "primary-host-esperado",
    });
    socket.emit("open");
    socket.emit("message", JSON.stringify({ event: "auth.challenge", data: challengeFrom(otherSeed, { hostId: "primary-host-esperado" }) }));
    await expect(result).resolves.toMatchObject({ ok: false, identityMismatch: true });
  });

  it("ignores noise before the challenge instead of settling on the first frame", async () => {
    const socket = new FakeSocket();
    const result = probe(socket);
    socket.emit("open");
    socket.emit("message", "não é json");
    socket.emit("message", JSON.stringify({ event: "event", data: { type: "message" } }));
    socket.emit("message", JSON.stringify({ event: "auth.challenge", data: challengeFrom(hostSeed) }));
    await expect(result).resolves.toMatchObject({ ok: true });
  });

  it("reports a silent route as a network reason, not as an identity mismatch", async () => {
    const socket = new FakeSocket();
    const result = probe(socket, { timeoutMs: 20 });
    socket.emit("open");
    await expect(result).resolves.toMatchObject({ ok: false, reason: "timeout", identityMismatch: false });
  });
});
