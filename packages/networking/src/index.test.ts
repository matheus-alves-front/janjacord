import { afterEach, describe, expect, it } from "vitest";
import { once } from "node:events";
import { ed25519Fingerprint, ed25519PublicKey } from "@janjacord/crypto";
import {
  createSignedHostAuthChallenge,
  createSignedHostGrant,
  createSignedHostRecord,
  hostRegistrationRecordHash,
} from "@janjacord/protocol";
import { WebSocketServer, type WebSocket } from "ws";
import {
  HostClient,
  browserRtcIceConfiguration,
  createSignedIceAccessProof,
  deserializeHostRegistrationHighWater,
  iceServerConfiguration,
  issueLegacyHostConfirmation,
  isRelayOnlyCandidatePair,
  reconnectBackoffDelay,
  settleTransportGenerationRequests,
  selectHostRegistrations,
  serializeHostRegistrationHighWater,
  temporaryTurnIceServers,
  validateLegacyHostConfirmation,
} from "./index.js";

const SERVER_ID = "11111111-1111-4111-8111-111111111111";
const GRANT_ID = "22222222-2222-4222-8222-222222222222";
const authoritySeed = Buffer.alloc(32, 31);
const hostSeed = Buffer.alloc(32, 32);
const deviceSeed = Buffer.alloc(32, 33);
const authorityPublicKey = ed25519PublicKey(authoritySeed).toString("base64url");
const authorityFingerprint = ed25519Fingerprint(Buffer.from(authorityPublicKey, "base64url"));

describe("ICE request generation fencing", () => {
  it("fails every in-flight request exactly once before a reconnect generation can answer", () => {
    const resolved: unknown[] = [];
    const requests = [1, 2].map(() => ({
      resolve: (value: unknown) => resolved.push(value),
      timer: setTimeout(() => undefined, 60_000),
      settled: false,
    }));
    settleTransportGenerationRequests(requests, { ok: false, error: { code: "host_offline" } });
    expect(requests).toHaveLength(0);
    expect(resolved).toEqual([
      { ok: false, error: { code: "host_offline" } },
      { ok: false, error: { code: "host_offline" } },
    ]);
    settleTransportGenerationRequests(requests, { ok: true });
    expect(resolved).toHaveLength(2);
  });
});

describe("ICE access authorization proof", () => {
  it("binds a short-lived invite capability hash to the exact session and device", () => {
    const proof = createSignedIceAccessProof({
      serverId: SERVER_ID,
      hostId: "primary-host",
      identityId: "new-member",
      deviceSeed,
      inviteAccessHash: "ab".repeat(32),
    }, "S".repeat(32), 10_000);
    expect(proof.payload).toMatchObject({
      sessionId: "S".repeat(32),
      inviteAccessHash: "ab".repeat(32),
      issuedAt: 10_000,
      expiresAt: 40_000,
    });
    expect(proof.signature).toHaveLength(86);
  });
});

function registration(options: {
  now: number;
  recordSeq: number;
  epoch?: number;
  generation?: number;
  grantId?: string;
  previousRecordHash?: string | null;
  endpoint?: string;
}) {
  const grantId = options.grantId ?? GRANT_ID;
  const grant = createSignedHostGrant({
    version: 1,
    grantId,
    serverId: SERVER_ID,
    issuerIdentityId: "owner",
    subjectIdentityId: "owner",
    subjectAuthPublicKey: ed25519PublicKey(deviceSeed).toString("base64url"),
    devicePublicKey: ed25519PublicKey(hostSeed).toString("base64url"),
    hostId: "primary-host",
    capabilities: ["register", "replicate", "promote"],
    generation: options.generation ?? 1,
    issuedAt: options.now - 1_000,
    expiresAt: options.now + 120_000,
  }, authoritySeed);
  const record = createSignedHostRecord({
    version: 1,
    serverId: SERVER_ID,
    grantId,
    hostId: "primary-host",
    role: "primary",
    epoch: options.epoch ?? 1,
    recordSeq: options.recordSeq,
    previousRecordHash: options.previousRecordHash ?? null,
    endpoints: [options.endpoint ?? "wss://host.example/signal"],
    candidates: [],
    issuedAt: options.now,
    ttlMs: 60_000,
    expiresAt: options.now + 60_000,
  }, hostSeed);
  return { authorityPublicKey, grant, record };
}

describe("client-side signed host high-water", () => {
  it("selects the unique monotonic maximum without trusting bridge order", () => {
    const now = 50_000;
    const first = registration({ now, recordSeq: 1 });
    const second = registration({ now: now + 1, recordSeq: 2, previousRecordHash: hostRegistrationRecordHash(first.record) });
    const third = registration({ now: now + 2, recordSeq: 3, previousRecordHash: hostRegistrationRecordHash(second.record) });

    const a = selectHostRegistrations([first, third, second], { serverId: SERVER_ID, authorityFingerprint, now: now + 3 });
    const b = selectHostRegistrations([second, first, third], { serverId: SERVER_ID, authorityFingerprint, now: now + 3 });
    expect(a.registrations).toHaveLength(1);
    expect(a.registrations[0]?.record.payload.recordSeq).toBe(3);
    expect(a.registrations[0]?.recordHash).toBe(b.registrations[0]?.recordHash);
    expect(a.highWater.marks[0]).toMatchObject({ grantGeneration: 1, epoch: 1, recordSeq: 3 });
  });

  it("serializes strict state and rejects downgrade, exact replay and equal-sequence conflict", () => {
    const now = 80_000;
    const current = registration({ now, recordSeq: 5, epoch: 4 });
    const selected = selectHostRegistrations([current], { serverId: SERVER_ID, authorityFingerprint, now: now + 1 });
    const persisted = deserializeHostRegistrationHighWater(serializeHostRegistrationHighWater(selected.highWater));
    const stale = registration({ now: now + 1, recordSeq: 4, epoch: 4 });
    const conflict = registration({ now: now + 2, recordSeq: 5, epoch: 4, endpoint: "wss://other.example/signal" });
    const result = selectHostRegistrations([stale, current, conflict], {
      serverId: SERVER_ID,
      authorityFingerprint,
      highWater: persisted,
      now: now + 3,
    });
    expect(result.registrations).toHaveLength(0);
    expect(result.rejected).toEqual([
      expect.objectContaining({ index: 0, reason: "downgrade" }),
      expect.objectContaining({ index: 1, reason: "replay" }),
      expect.objectContaining({ index: 2, reason: "conflict" }),
    ]);
    expect(() => deserializeHostRegistrationHighWater('{"version":1,"marks":[{}]}')).toThrow(/high-water/);
  });

  it("requires the next signed record to be exactly contiguous and linked to the prior hash", () => {
    const now = 95_000;
    const first = registration({ now, recordSeq: 1 });
    const accepted = selectHostRegistrations([first], { serverId: SERVER_ID, authorityFingerprint, now: now + 1 });
    expect(accepted.registrations).toHaveLength(1);
    const jumped = registration({
      now: now + 2,
      recordSeq: 3,
      previousRecordHash: accepted.registrations[0]!.recordHash,
    });
    const result = selectHostRegistrations([jumped], {
      serverId: SERVER_ID,
      authorityFingerprint,
      highWater: accepted.highWater,
      now: now + 3,
    });
    expect(result.registrations).toHaveLength(0);
    expect(result.rejected).toEqual([expect.objectContaining({ reason: "conflict" })]);
    const wrongLink = registration({ now: now + 4, recordSeq: 2, previousRecordHash: "ff".repeat(32) });
    const wrongLinkResult = selectHostRegistrations([wrongLink], {
      serverId: SERVER_ID,
      authorityFingerprint,
      highWater: accepted.highWater,
      now: now + 5,
    });
    expect(wrongLinkResult.registrations).toHaveLength(0);
    expect(wrongLinkResult.rejected).toEqual([expect.objectContaining({ reason: "conflict" })]);
  });

  it("never accepts a known revoked grant and rejects incomparable maxima", () => {
    const now = 110_000;
    const revoked = registration({ now, recordSeq: 10, generation: 4 });
    expect(selectHostRegistrations([revoked], {
      serverId: SERVER_ID,
      authorityFingerprint,
      verifiedRevokedGrantIds: new Set([GRANT_ID]),
      now: now + 1,
    })).toMatchObject({ registrations: [], rejected: [{ reason: "revoked" }] });

    const higherGrant = registration({ now: now + 2, recordSeq: 3, epoch: 1, generation: 2 });
    const higherEpoch = registration({ now: now + 3, recordSeq: 4, epoch: 2, generation: 1 });
    const ambiguous = selectHostRegistrations([higherGrant, higherEpoch], {
      serverId: SERVER_ID,
      authorityFingerprint,
      now: now + 4,
    });
    expect(ambiguous.registrations).toHaveLength(0);
    expect(ambiguous.rejected.every((entry) => entry.reason === "ambiguous")).toBe(true);
  });

  it("enforces the highest authority-verified generation floor per host", () => {
    const now = 140_000;
    const stale = registration({ now, recordSeq: 1, generation: 4 });
    expect(selectHostRegistrations([stale], {
      serverId: SERVER_ID,
      authorityFingerprint,
      verifiedGenerationFloors: new Map([["primary-host", 4]]),
      now: now + 1,
    })).toMatchObject({ registrations: [], rejected: [{ reason: "revoked" }] });

    const rotated = registration({ now: now + 2, recordSeq: 1, generation: 5 });
    expect(selectHostRegistrations([rotated], {
      serverId: SERVER_ID,
      authorityFingerprint,
      verifiedGenerationFloors: new Map([["primary-host", 4]]),
      now: now + 3,
    }).registrations).toHaveLength(1);
  });
});

describe("JC2 exact-key confirmation", () => {
  it("binds a short-lived one-time presentation to the exact observed host key", () => {
    const token = "tofu-confirmation-token";
    const candidate = {
      hostPublicKey: ed25519PublicKey(hostSeed).toString("base64url"),
      hostKeyFingerprint: ed25519Fingerprint(ed25519PublicKey(hostSeed)),
      serverId: SERVER_ID,
      authorityFingerprint,
      hostId: "primary-host",
      grantId: GRANT_ID,
    };
    const issued = issueLegacyHostConfirmation(candidate, 1_000, token);
    const exact = { confirmationToken: token, hostPublicKey: candidate.hostPublicKey, fingerprint: candidate.hostKeyFingerprint };
    expect(validateLegacyHostConfirmation(issued.pending, exact, 2_000)).toBe(true);
    expect(validateLegacyHostConfirmation(issued.pending, { ...exact, confirmationToken: "wrong" }, 2_000)).toBe(false);
    expect(validateLegacyHostConfirmation(issued.pending, { ...exact, fingerprint: "changed" }, 2_000)).toBe(false);
    expect(validateLegacyHostConfirmation(issued.pending, exact, issued.pending.expiresAt + 1)).toBe(false);
  });
});

describe("shared data/call ICE configuration", () => {
  const credentials = {
    urls: ["stun:relay.example:3478", "turn:relay.example:3478?transport=udp", "turns:relay.example:5349?transport=tcp"],
    username: "9999999999:opaque",
    credential: "short-lived-password",
    credentialType: "password" as const,
    expiresAt: 500_000,
  };

  it("maps temporary credentials to native and browser configurations without a shared secret", () => {
    expect(temporaryTurnIceServers(credentials, 100_000)).toEqual([
      expect.objectContaining({ hostname: "relay.example", port: 3478, relayType: "TurnUdp", username: credentials.username }),
      expect.objectContaining({ hostname: "relay.example", port: 5349, relayType: "TurnTls", username: credentials.username }),
    ]);
    const browser = browserRtcIceConfiguration(["stun:stun.example:3478"], credentials, "direct", 100_000);
    expect(browser).toEqual({
      iceServers: [
        { urls: "stun:stun.example:3478" },
        { urls: "stun:relay.example:3478" },
        { urls: credentials.urls.slice(1), username: credentials.username, credential: credentials.credential, credentialType: "password" },
      ],
      iceTransportPolicy: "all",
      expiresAt: credentials.expiresAt,
    });
    expect(JSON.stringify(browser)).not.toContain("shared-secret");
  });

  it("fails relay-only closed and excludes STUN from relay-only calls", () => {
    expect(() => iceServerConfiguration(["stun:stun.example:3478"], null, "relay", 100_000)).toThrow(/temporary TURN/);
    const native = iceServerConfiguration(["stun:stun.example:3478"], credentials, "relay", 100_000);
    expect(native).toEqual({
      iceServers: [
        expect.objectContaining({ hostname: "relay.example", relayType: "TurnUdp", username: credentials.username }),
        expect.objectContaining({ hostname: "relay.example", relayType: "TurnTls", username: credentials.username }),
      ],
      iceTransportPolicy: "relay",
    });
    expect(native.iceServers.every((server) => typeof server !== "string" && Boolean(server.relayType))).toBe(true);
    expect(browserRtcIceConfiguration(["stun:stun.example:3478"], credentials, "relay", 100_000)).toMatchObject({
      iceServers: [{ urls: credentials.urls.slice(1) }],
      iceTransportPolicy: "relay",
    });
    expect(reconnectBackoffDelay(3, 100, 1_000, () => 0)).toBe(800);
    expect(isRelayOnlyCandidatePair(null)).toBe(false);
    expect(isRelayOnlyCandidatePair({ local: { type: "host" }, remote: { type: "prflx" } })).toBe(false);
    expect(isRelayOnlyCandidatePair({ local: { type: "RELAY" }, remote: { type: "relay" } })).toBe(true);
  });
});

const servers: WebSocketServer[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    for (const client of server.clients) client.terminate();
    server.close(() => resolve());
  })));
});

async function tofuServer(): Promise<{ url: string; proof: Promise<unknown> }> {
  const server = new WebSocketServer({ port: 0 });
  servers.push(server);
  if (!server.address()) await once(server, "listening");
  const proof = new Promise<unknown>((resolve) => {
    server.on("connection", (socket: WebSocket) => {
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
              hostId: "legacy-host",
              grantId: GRANT_ID,
              challengeId: "33333333-3333-4333-8333-333333333333",
              nonce: Buffer.alloc(32, 9).toString("base64url"),
              issuedAt: now,
              expiresAt: now + 30_000,
            }, hostSeed),
          }));
        } else if (frame.event === "auth.prove") {
          resolve(frame.data);
          socket.send(JSON.stringify({ event: "auth.ready", data: {} }));
        }
      });
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server did not bind");
  return { url: `ws://127.0.0.1:${address.port}`, proof };
}

describe("JC2 explicit TOFU", () => {
  it("does not let the legacy flag silently trust an unpinned challenge", async () => {
    const server = await tofuServer();
    const client = new HostClient(server.url, {
      identityId: "legacy-user",
      deviceSeed,
      serverId: SERVER_ID,
      authorityFingerprint,
      allowUnverifiedLegacyHost: true,
    });
    await new Promise<void>((resolve, reject) => {
      client.onClose(resolve);
      setTimeout(() => reject(new Error("expected explicit TOFU close")), 2_000);
    });
  });

  it("exposes the signed challenge key and opens only after explicit confirmation", async () => {
    const server = await tofuServer();
    let candidate: { hostPublicKey: string; hostKeyFingerprint: string } | undefined;
    const client = new HostClient(server.url, {
      identityId: "legacy-user",
      deviceSeed,
      serverId: SERVER_ID,
      authorityFingerprint,
      onLegacyHostFirstUse: (value) => {
        candidate = value;
        return true;
      },
    });
    await Promise.race([
      new Promise<void>((resolve) => client.onOpen(resolve)),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("TOFU auth timeout")), 2_000)),
    ]);
    await server.proof;
    client.close();
    expect(candidate).toMatchObject({
      hostPublicKey: ed25519PublicKey(hostSeed).toString("base64url"),
      hostKeyFingerprint: ed25519Fingerprint(ed25519PublicKey(hostSeed)),
    });
  });
});
