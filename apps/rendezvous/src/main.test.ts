import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHash, createHmac, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  canonicalJson,
  ed25519Fingerprint,
  ed25519PublicKey,
  sha256Hex,
  signCanonicalPayload,
} from "@janjacord/crypto";
import {
  createSignedHostGrant,
  createSignedHostGrantRevocation,
  createSignedHostRecord,
} from "@janjacord/protocol";
import { WebSocket, type WebSocketServer } from "ws";
import {
  handleRendezvousFrame,
  isBoundedFrameStructure,
  cleanupExpiredSignalingSessions,
  MAX_RENDEZVOUS_FRAME_BYTES,
  SIGNAL_SESSION_TTL_MS,
  issueTurnCredentials,
  isValidSignalingPayload,
  isSignalingSessionContinuation,
  loadRendezvousState,
  resetRendezvousState,
  resolveClientIp,
  signalingAdmissionReason,
  startRendezvous,
} from "./main.js";

const SERVER_ID = "11111111-1111-4111-8111-111111111111";
const GRANT_ID = "22222222-2222-4222-8222-222222222222";
const PROOF_DOMAIN = "janjacord.bridge-registration-proof.v1";
const authoritySeed = Buffer.alloc(32, 4);
const deviceSeed = Buffer.alloc(32, 5);
const authorityPublicKey = ed25519PublicKey(authoritySeed).toString("base64url");
const authorityFingerprint = ed25519Fingerprint(Buffer.from(authorityPublicKey, "base64url"));
let testBridgeIdentity: { descriptor: Record<string, any>; adminKey: string } | undefined;

type RegistrationOptions = {
  now?: number;
  epoch?: number;
  recordSeq?: number;
  previousRecordHash?: string | null;
  generation?: number;
  authoritySeed?: Buffer;
  deviceSeed?: Buffer;
  grantId?: string;
  hostId?: string;
};

function registration(options: RegistrationOptions = {}) {
  const now = options.now ?? Date.now();
  const registrationAuthoritySeed = options.authoritySeed ?? authoritySeed;
  const registrationDeviceSeed = options.deviceSeed ?? deviceSeed;
  const grantId = options.grantId ?? GRANT_ID;
  const hostId = options.hostId ?? "member-host";
  const registrationAuthorityKey = ed25519PublicKey(registrationAuthoritySeed).toString("base64url");
  const registrationDeviceKey = ed25519PublicKey(registrationDeviceSeed).toString("base64url");
  const grant = createSignedHostGrant({
    version: 1,
    grantId,
    serverId: SERVER_ID,
    issuerIdentityId: "owner",
    subjectIdentityId: "member",
    subjectAuthPublicKey: registrationDeviceKey,
    devicePublicKey: registrationDeviceKey,
    hostId,
    capabilities: ["register", "replicate", "promote"],
    generation: options.generation ?? 1,
    issuedAt: now - 1_000,
    expiresAt: now + 120_000,
  }, registrationAuthoritySeed);
  const record = createSignedHostRecord({
    version: 1,
    serverId: SERVER_ID,
    grantId,
    hostId,
    role: "primary",
    epoch: options.epoch ?? 1,
    recordSeq: options.recordSeq ?? 1,
    previousRecordHash: options.previousRecordHash ?? null,
    endpoints: ["wss://host.example/signal"],
    candidates: [],
    issuedAt: now,
    ttlMs: 60_000,
    expiresAt: now + 60_000,
  }, registrationDeviceSeed);
  return {
    authorityPublicKey: registrationAuthorityKey,
    authoritySeed: registrationAuthoritySeed,
    deviceSeed: registrationDeviceSeed,
    grant,
    record,
  };
}

function accessFrame(
  value: ReturnType<typeof registration>,
  pairingToken?: string | null,
  bridgeId?: string,
  slot: "registration" | "witness" = "registration",
) {
  const resolvedBridgeId = bridgeId ?? testBridgeIdentity?.descriptor.payload.bridgeId ?? "test-bridge";
  const resolvedPairing = pairingToken === null ? undefined : pairingToken
    ?? (testBridgeIdentity ? mintPairingToken(resolvedBridgeId, testBridgeIdentity.adminKey) : undefined);
  const issuedAt = Date.now();
  const payload = {
    version: 1,
    bridgeId: resolvedBridgeId,
    serverId: value.grant.payload.serverId,
    hostId: value.grant.payload.hostId,
    grantId: value.grant.payload.grantId,
    slot,
    proofId: randomUUID(),
    issuedAt,
    expiresAt: issuedAt + 30_000,
  };
  return {
    type: "access.issue",
    requestId: randomUUID(),
    ...(resolvedPairing ? { pairingToken: resolvedPairing } : {}),
    authorityPublicKey: value.authorityPublicKey,
    grant: value.grant,
    proof: {
      payload,
      publicKey: value.grant.payload.devicePublicKey,
      signature: signCanonicalPayload(value.deviceSeed, "janjacord.bridge-access.v1", payload).toString("base64url"),
    },
  };
}

function beginFrame(value: ReturnType<typeof registration>, requestId = randomUUID(), accessToken?: string) {
  return {
    type: "register.begin",
    requestId,
    authorityPublicKey: value.authorityPublicKey,
    grant: value.grant,
    record: value.record,
    ...(accessToken ? { accessToken } : {}),
  };
}

function proofFrame(
  value: ReturnType<typeof registration>,
  challenge: Record<string, unknown>,
  signingSeed = value.deviceSeed,
) {
  const now = Date.now();
  const payload = {
    version: 1,
    serverId: value.record.payload.serverId,
    hostId: value.record.payload.hostId,
    grantId: value.grant.payload.grantId,
    recordHash: challenge.recordHash,
    challengeId: challenge.challengeId,
    nonce: challenge.nonce,
    issuedAt: now,
    expiresAt: Math.min(Number(challenge.expiresAt), now + 10_000),
  };
  return {
    type: "register.prove",
    requestId: challenge.requestId,
    challengeId: challenge.challengeId,
    proof: {
      payload,
      publicKey: ed25519PublicKey(signingSeed).toString("base64url"),
      signature: signCanonicalPayload(signingSeed, PROOF_DOMAIN, payload).toString("base64url"),
    },
  };
}

function witnessFrame(value: ReturnType<typeof registration>, primaryHostId: string, accessToken: string) {
  const issuedAt = Date.now();
  const payload = {
    version: 1,
    serverId: SERVER_ID,
    primaryHostId,
    replicaHostId: value.grant.payload.hostId,
    grantId: value.grant.payload.grantId,
    nonce: randomUUID(),
    issuedAt,
    expiresAt: issuedAt + 15_000,
  };
  return {
    type: "witness.primary",
    requestId: randomUUID(),
    accessToken,
    authorityPublicKey: value.authorityPublicKey,
    grant: value.grant,
    proof: {
      payload,
      publicKey: value.grant.payload.devicePublicKey,
      signature: signCanonicalPayload(value.deviceSeed, "janjacord.replica-witness.v1", payload).toString("base64url"),
    },
  };
}

function promotionClaimFrame(witness: unknown) {
  return {
    type: "promotion.claim",
    requestId: randomUUID(),
    authorityFingerprint,
    witness,
  };
}

const servers: WebSocketServer[] = [];
const sockets: WebSocket[] = [];
let tempDir: string | undefined;

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value as object).sort().map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}`;
}

function configureBridgeIdentity(): { descriptor: Record<string, any>; adminKey: string } {
  if (!tempDir) tempDir = mkdtempSync(join(tmpdir(), "janjabridge-identity-"));
  const pair = generateKeyPairSync("ed25519");
  const publicJwk = pair.publicKey.export({ format: "jwk" });
  const publicKey = String(publicJwk.x);
  const fingerprint = createHash("sha256").update(Buffer.from(publicKey, "base64url")).digest("hex");
  const payload = {
    version: 1,
    bridgeId: `ed25519:${fingerprint}`,
    endpoints: ["wss://bridge.example/rendezvous"],
    issuedAt: Date.now() - 1_000,
    expiresAt: Date.now() + 60_000,
  };
  const descriptor = {
    payload,
    publicKey,
    signature: sign(null, Buffer.concat([
      Buffer.from("janjacord.bridge-descriptor.v1\0"),
      Buffer.from(canonical(payload)),
    ]), pair.privateKey).toString("base64url"),
  };
  process.env.JC_BRIDGE_DESCRIPTOR_FILE = join(tempDir, "descriptor.json");
  process.env.JC_BRIDGE_SIGNING_KEY_FILE = join(tempDir, "bridge-key.pem");
  process.env.JC_BRIDGE_PAIRING_ADMIN_KEY_FILE = join(tempDir, "pairing-admin-key");
  const adminKey = "pairing-admin-key-that-never-leaves-the-bridge";
  writeFileSync(process.env.JC_BRIDGE_DESCRIPTOR_FILE, JSON.stringify(descriptor), { mode: 0o600 });
  writeFileSync(process.env.JC_BRIDGE_SIGNING_KEY_FILE, pair.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  writeFileSync(process.env.JC_BRIDGE_PAIRING_ADMIN_KEY_FILE, adminKey, { mode: 0o600 });
  return { descriptor, adminKey };
}

function mintPairingToken(bridgeId: string, adminKey: string, now = Date.now()): string {
  const payload = { version: 1, bridgeId, tokenId: randomUUID(), issuedAt: now, expiresAt: now + 60_000 };
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const prefix = `JCP1.${encoded}`;
  return `${prefix}.${createHmac("sha256", adminKey).update(prefix).digest("base64url")}`;
}

async function startBridge(): Promise<string> {
  const server = startRendezvous(0);
  servers.push(server);
  if (!server.address()) await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("bridge did not bind a TCP port");
  return `ws://127.0.0.1:${address.port}/rendezvous`;
}

async function connect(url: string): Promise<WebSocket> {
  const ws = new WebSocket(url);
  sockets.push(ws);
  await once(ws, "open");
  return ws;
}

async function exchange(ws: WebSocket, frame: unknown): Promise<Record<string, any>> {
  const response = once(ws, "message");
  ws.send(JSON.stringify(frame));
  const [raw] = await response;
  return JSON.parse(raw.toString()) as Record<string, any>;
}

async function nextFrame(ws: WebSocket): Promise<Record<string, any>> {
  const [raw] = await once(ws, "message");
  return JSON.parse(raw.toString()) as Record<string, any>;
}

function signalOpenFrame(sessionId: string, payload: Record<string, unknown>) {
  return {
    type: "signal.open",
    sessionId,
    serverId: SERVER_ID,
    authorityFingerprint,
    hostId: "member-host",
    payload,
  };
}

async function registerHost(ws: WebSocket, value: ReturnType<typeof registration>, pairingToken?: string) {
  const access = await exchange(ws, accessFrame(value, pairingToken));
  expect(access).toMatchObject({ type: "access.result", ok: true });
  const challenge = await exchange(ws, beginFrame(value, randomUUID(), access.data.accessToken));
  expect(challenge).toMatchObject({ type: "register.challenge", recordHash: sha256Hex(canonicalJson(value.record)) });
  const result = await exchange(ws, proofFrame(value, challenge));
  expect(result).toMatchObject({ type: "register.result", requestId: challenge.requestId, ok: true });
  return { challenge, result };
}

async function beginAuthorized(ws: WebSocket, value: ReturnType<typeof registration>) {
  const access = await exchange(ws, accessFrame(value));
  expect(access).toMatchObject({ type: "access.result", ok: true });
  return exchange(ws, beginFrame(value, randomUUID(), access.data.accessToken));
}

beforeEach(() => {
  resetRendezvousState();
  delete process.env.JC_RENDEZVOUS_STATE_FILE;
  delete process.env.JC_TURN_SHARED_SECRET_FILE;
  delete process.env.JC_BRIDGE_PAIRING_SECRET_FILE;
  delete process.env.JC_BRIDGE_PAIRING_ADMIN_KEY_FILE;
  delete process.env.JC_BRIDGE_DESCRIPTOR_FILE;
  delete process.env.JC_BRIDGE_SIGNING_KEY_FILE;
  delete process.env.JC_WITNESS_ABSENCE_GRACE_MS;
  delete process.env.JC_RENDEZVOUS_COMPACT_BYTES;
  testBridgeIdentity = configureBridgeIdentity();
});

afterEach(async () => {
  for (const ws of sockets.splice(0)) ws.terminate();
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  resetRendezvousState();
  delete process.env.JC_RENDEZVOUS_STATE_FILE;
  delete process.env.JC_TURN_SHARED_SECRET_FILE;
  delete process.env.JC_BRIDGE_PAIRING_SECRET_FILE;
  delete process.env.JC_BRIDGE_PAIRING_ADMIN_KEY_FILE;
  delete process.env.JC_BRIDGE_DESCRIPTOR_FILE;
  delete process.env.JC_BRIDGE_SIGNING_KEY_FILE;
  delete process.env.JC_RENDEZVOUS_COMPACT_BYTES;
  if (tempDir) rmSync(tempDir, { recursive: true, force: true });
  tempDir = undefined;
  testBridgeIdentity = undefined;
});

describe("hardened signed rendezvous", () => {
  it("rejects binary, oversized and over-deep frames at the WebSocket boundary", async () => {
    expect(isBoundedFrameStructure({ nested: { ok: true } })).toBe(true);
    let deep: Record<string, unknown> = { leaf: true };
    for (let index = 0; index < 9; index++) deep = { nested: deep };
    expect(isBoundedFrameStructure(deep)).toBe(false);

    const url = await startBridge();
    const binary = await connect(url);
    const binaryClosed = once(binary, "close");
    binary.send(Buffer.from("{}"));
    expect((await binaryClosed)[0]).toBe(1003);

    const oversized = await connect(url);
    const oversizedClosed = once(oversized, "close");
    oversized.send(JSON.stringify({ type: "health.ready", requestId: "x", padding: "x".repeat(MAX_RENDEZVOUS_FRAME_BYTES) }));
    expect((await oversizedClosed)[0]).toBe(1009);
  });

  it("reports exact backend readiness only for the dedicated health frame", async () => {
    const ws = await connect(await startBridge());
    const requestId = randomUUID();
    expect(await exchange(ws, { type: "health.ready", requestId })).toEqual({
      type: "health.ready.result",
      requestId,
      ok: true,
      data: { ready: true, stateLoaded: true },
    });
    expect(await exchange(ws, { type: "health.ready" })).toMatchObject({
      type: "health.ready.result",
      ok: false,
      error: { code: "invalid_input" },
    });
  });

  it("uses one canonical forwarded client IP only from an explicitly trusted proxy", () => {
    expect(resolveClientIp("172.30.0.10", "203.0.113.7", "172.30.0.10")).toBe("203.0.113.7");
    expect(resolveClientIp("198.51.100.9", "203.0.113.7", "172.30.0.10")).toBe("198.51.100.9");
    expect(resolveClientIp("172.30.0.10", "203.0.113.7, 198.51.100.4", "172.30.0.10")).toBe("172.30.0.10");
    expect(resolveClientIp("172.30.0.10", " 203.0.113.7", "172.30.0.10")).toBe("172.30.0.10");
  });

  it("bounds signaling sessions globally and by host and client", () => {
    const hostA = {};
    const hostB = {};
    const clientA = {};
    const clientB = {};
    const limits = { total: 3, perHost: 2, perClient: 2 };
    expect(signalingAdmissionReason([], hostA, clientA, limits)).toBeNull();
    expect(signalingAdmissionReason([
      { host: hostA, client: clientA },
      { host: hostA, client: clientB },
    ], hostA, {}, limits)).toBe("host_capacity");
    expect(signalingAdmissionReason([
      { host: hostA, client: clientA },
      { host: hostB, client: clientA },
    ], {}, clientA, limits)).toBe("client_capacity");
    expect(signalingAdmissionReason([
      { host: hostA, client: clientA },
      { host: hostB, client: clientB },
      { host: {}, client: {} },
    ], {}, {}, limits)).toBe("global_capacity");
  });

  it("allows only the owning client to continue an existing signaling session", () => {
    const host = {};
    const client = {};
    const session = { host, client };
    expect(isSignalingSessionContinuation(session, host, client)).toBe(true);
    expect(isSignalingSessionContinuation(session, host, {})).toBe(false);
    expect(isSignalingSessionContinuation(session, {}, client)).toBe(false);
    expect(isSignalingSessionContinuation(undefined, host, client)).toBe(false);
  });

  it("enforces strict SDP and candidate bounds before forwarding signaling", () => {
    const offer = { type: "offer", sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n" };
    const candidate = { type: "candidate", candidate: "candidate:1 1 UDP 1 192.0.2.1 5000 typ host", mid: "0" };
    expect(isValidSignalingPayload("signal.open", offer)).toBe(true);
    expect(isValidSignalingPayload("signal.relay", candidate)).toBe(true);
    expect(isValidSignalingPayload("signal.open", { ...offer, sdp: `v=0\r\n${"x".repeat(49 * 1024)}` })).toBe(false);
    expect(isValidSignalingPayload("signal.relay", { ...candidate, candidate: `candidate:${"x".repeat(4 * 1024)}` })).toBe(false);
    expect(isValidSignalingPayload("signal.relay", { ...candidate, mid: "invalid mid" })).toBe(false);
  });

  it("requires host-confirmed ice.request before offer/candidate/refresh and forwards close as a recognized type", async () => {
    const url = await startBridge();
    const host = await connect(url);
    await registerHost(host, registration());
    const client = await connect(url);
    const sessionId = "signal-session-authenticated-001";
    const offer = { type: "offer", sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n" };
    const candidate = { type: "candidate", candidate: "candidate:1 1 UDP 1 192.0.2.1 5000 typ host", mid: "0" };

    expect(await exchange(client, signalOpenFrame(sessionId, offer))).toMatchObject({
      ok: false,
      error: { code: "unauthorized" },
    });
    expect(await exchange(client, signalOpenFrame(sessionId, {
      type: "ice.request",
      serverId: SERVER_ID,
      hostId: "different-host",
      accessProof: { signed: true },
    }))).toMatchObject({ ok: false, error: { code: "invalid_input" } });

    const hostRequest = nextFrame(host);
    expect(await exchange(client, signalOpenFrame(sessionId, {
      type: "ice.request",
      serverId: SERVER_ID,
      hostId: "member-host",
      accessProof: { signed: true },
    }))).toMatchObject({ ok: true, data: { sessionId } });
    expect(await hostRequest).toMatchObject({ type: "signal.open", sessionId, payload: { type: "ice.request" } });

    expect(await exchange(client, { type: "signal.relay", sessionId, payload: candidate })).toMatchObject({
      ok: false,
      error: { code: "unauthorized" },
    });
    expect(await exchange(client, {
      type: "signal.relay",
      sessionId,
      payload: { type: "ice.refresh", serverId: SERVER_ID, hostId: "member-host" },
    })).toMatchObject({ ok: false, error: { code: "unauthorized" } });
    expect(await exchange(client, signalOpenFrame(sessionId, offer))).toMatchObject({
      ok: false,
      error: { code: "unauthorized" },
    });

    const clientConfig = nextFrame(client);
    expect(await exchange(host, {
      type: "signal.relay",
      sessionId,
      payload: { type: "ice.config", networkPrivacy: "direct", credentials: null },
    })).toMatchObject({ ok: true });
    expect(await clientConfig).toMatchObject({ type: "signal.relay", sessionId, payload: { type: "ice.config" } });

    const hostOffer = nextFrame(host);
    expect(await exchange(client, signalOpenFrame(sessionId, offer))).toMatchObject({ ok: true });
    expect(await hostOffer).toMatchObject({ type: "signal.open", sessionId, payload: offer });

    const hostCandidate = nextFrame(host);
    expect(await exchange(client, { type: "signal.relay", sessionId, payload: candidate })).toMatchObject({ ok: true });
    expect(await hostCandidate).toMatchObject({ type: "signal.relay", sessionId, payload: candidate });

    const hostClose = nextFrame(host);
    expect(await exchange(client, { type: "signal.close", sessionId })).toMatchObject({ ok: true });
    expect(await hostClose).toEqual({ type: "signal.close", sessionId, payload: { reason: "closed" } });
  });

  it("notifies signal.close and releases session state on disconnect and timeout churn", async () => {
    const url = await startBridge();
    const host = await connect(url);
    await registerHost(host, registration());

    const disconnectedClient = await connect(url);
    const disconnectedSession = "signal-session-disconnect-001";
    const firstHostRequest = nextFrame(host);
    expect(await exchange(disconnectedClient, signalOpenFrame(disconnectedSession, {
      type: "ice.request", serverId: SERVER_ID, hostId: "member-host", accessProof: { signed: true },
    }))).toMatchObject({ ok: true });
    await firstHostRequest;
    const disconnectClose = nextFrame(host);
    disconnectedClient.terminate();
    expect(await disconnectClose).toEqual({
      type: "signal.close",
      sessionId: disconnectedSession,
      payload: { reason: "disconnect" },
    });

    const timeoutClient = await connect(url);
    const timeoutSession = "signal-session-timeout-00001";
    const timeoutHostRequest = nextFrame(host);
    expect(await exchange(timeoutClient, signalOpenFrame(timeoutSession, {
      type: "ice.request", serverId: SERVER_ID, hostId: "member-host", accessProof: { signed: true },
    }))).toMatchObject({ ok: true });
    await timeoutHostRequest;
    const timeoutHostClose = nextFrame(host);
    const timeoutClientClose = nextFrame(timeoutClient);
    expect(cleanupExpiredSignalingSessions(Date.now() + SIGNAL_SESSION_TTL_MS + 1)).toBe(1);
    expect(await timeoutHostClose).toEqual({ type: "signal.close", sessionId: timeoutSession, payload: { reason: "timeout" } });
    expect(await timeoutClientClose).toEqual({ type: "signal.close", sessionId: timeoutSession, payload: { reason: "timeout" } });

    const replacement = await connect(url);
    const replacementHostRequest = nextFrame(host);
    expect(await exchange(replacement, signalOpenFrame(timeoutSession, {
      type: "ice.request", serverId: SERVER_ID, hostId: "member-host", accessProof: { signed: true },
    }))).toMatchObject({ ok: true });
    expect(await replacementHostRequest).toMatchObject({ type: "signal.open", sessionId: timeoutSession });
  });

  it("rejects oversized SDP/candidates without forwarding them after authorization", async () => {
    const url = await startBridge();
    const host = await connect(url);
    await registerHost(host, registration());
    const client = await connect(url);
    const sessionId = "signal-session-bounds-0000001";
    const hostRequest = nextFrame(host);
    await exchange(client, signalOpenFrame(sessionId, {
      type: "ice.request", serverId: SERVER_ID, hostId: "member-host", accessProof: { signed: true },
    }));
    await hostRequest;
    const clientConfig = nextFrame(client);
    await exchange(host, {
      type: "signal.relay", sessionId, payload: { type: "ice.config", networkPrivacy: "direct", credentials: null },
    });
    await clientConfig;

    expect(await exchange(client, signalOpenFrame(sessionId, {
      type: "offer", sdp: `v=0\r\n${"x".repeat(49 * 1024)}`,
    }))).toMatchObject({ ok: false, error: { code: "invalid_input" } });
    expect(await exchange(client, {
      type: "signal.relay",
      sessionId,
      payload: { type: "candidate", candidate: `candidate:${"x".repeat(4 * 1024)}`, mid: "0" },
    })).toMatchObject({ ok: false, error: { code: "invalid_input" } });
  });
  it("requires correct pairing before issuing a host challenge", async () => {
    const { descriptor, adminKey } = configureBridgeIdentity();
    const secret = mintPairingToken(descriptor.payload.bridgeId, adminKey);
    const url = await startBridge();
    const value = registration();
    expect(await exchange(await connect(url), accessFrame(value, null, descriptor.payload.bridgeId))).toMatchObject({
      type: "access.result", ok: false, error: { code: "pairing_required" },
    });
    expect(await exchange(await connect(url), accessFrame(value, "wrong-pairing-secret-that-is-long-enough"))).toMatchObject({
      type: "access.result", ok: false, error: { code: "pairing_required" },
    });
    const host = await connect(url);
    const accessRequest = accessFrame(value, secret, descriptor.payload.bridgeId);
    const access = await exchange(host, accessRequest);
    expect(access).toMatchObject({ type: "access.result", ok: true });
    expect(await exchange(await connect(url), accessRequest)).toMatchObject({
      type: "access.result", ok: false, error: { code: "unauthorized" },
    });
    const challenge = await exchange(host, beginFrame(value, randomUUID(), access.data.accessToken));
    expect(challenge).toMatchObject({ type: "register.challenge" });
    expect(await exchange(host, proofFrame(value, challenge))).toMatchObject({ type: "register.result", ok: true });
    expect(JSON.stringify(challenge)).not.toContain(secret);
  });

  it("keeps registration access valid when the same host issues witness access", async () => {
    const descriptor = testBridgeIdentity!.descriptor;
    const url = await startBridge();
    const ws = await connect(url);
    const value = registration();
    const registrationAccess = await exchange(ws, accessFrame(value, undefined, descriptor.payload.bridgeId, "registration"));
    expect(registrationAccess).toMatchObject({ type: "access.result", ok: true });
    expect(await exchange(ws, accessFrame(value, undefined, descriptor.payload.bridgeId, "witness"))).toMatchObject({
      type: "access.result",
      ok: true,
    });
    expect(await exchange(ws, beginFrame(value, randomUUID(), registrationAccess.data.accessToken))).toMatchObject({
      type: "register.challenge",
    });
  });

  it("witnesses only live authenticated primary bindings and rejects revoked promote grants", async () => {
    const { descriptor, adminKey } = configureBridgeIdentity();
    const secret = mintPairingToken(descriptor.payload.bridgeId, adminKey);
    const url = await startBridge();
    const primarySocket = await connect(url);
    const primary = registration({ hostId: "primary-host" });
    const primaryAccess = await exchange(primarySocket, accessFrame(primary, secret, descriptor.payload.bridgeId));
    const primaryChallenge = await exchange(primarySocket, beginFrame(primary, randomUUID(), primaryAccess.data.accessToken));
    expect(await exchange(primarySocket, proofFrame(primary, primaryChallenge))).toMatchObject({ ok: true });
    const replica = registration({
      hostId: "replica-host",
      grantId: "77777777-7777-4777-8777-777777777777",
      deviceSeed: Buffer.alloc(32, 44),
    });
    const observer = await connect(url);
    const replicaAccessFrame = accessFrame(replica, undefined, descriptor.payload.bridgeId, "witness");
    const replicaAccess = await exchange(observer, replicaAccessFrame);
    expect(replicaAccess).toMatchObject({ ok: true });
    expect(await exchange(observer, witnessFrame(replica, "caller-chosen-host", replicaAccess.data.accessToken))).toMatchObject({
      type: "witness.primary.result", ok: false, error: { code: "unauthorized" },
    });
    const online = await exchange(observer, witnessFrame(replica, "primary-host", replicaAccess.data.accessToken));
    expect(online).toMatchObject({ type: "witness.primary.result", ok: true, data: { witness: { payload: {
      bridgeId: descriptor.payload.bridgeId, requestId: expect.any(String), primaryHostId: "primary-host", primaryOnline: true,
    } } } });
    primarySocket.terminate();
    await once(primarySocket, "close");
    expect(await exchange(observer, witnessFrame(replica, "primary-host", replicaAccess.data.accessToken))).toMatchObject({
      type: "witness.primary.result", ok: true, data: { witness: { payload: { primaryOnline: true } } },
    });
    process.env.JC_WITNESS_ABSENCE_GRACE_MS = "10";
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(await exchange(observer, witnessFrame(replica, "primary-host", replicaAccess.data.accessToken))).toMatchObject({
      type: "witness.primary.result", ok: true, data: { witness: { payload: { primaryOnline: false } } },
    });
    const revocation = createSignedHostGrantRevocation({
      version: 1,
      serverId: SERVER_ID,
      grantId: replica.grant.payload.grantId,
      hostId: replica.grant.payload.hostId,
      issuerIdentityId: "owner",
      revokedAt: Date.now(),
      generation: 2,
    }, authoritySeed);
    expect(await exchange(observer, { type: "revoke", authorityPublicKey, revocation })).toMatchObject({ ok: true });
    expect(await exchange(observer, witnessFrame(replica, "primary-host", replicaAccess.data.accessToken))).toMatchObject({
      type: "witness.primary.result", ok: false, error: { code: "unauthorized" },
    });
  });

  it("persists one promotion vote per epoch and rejects a concurrent candidate", async () => {
    if (!tempDir) throw new Error("bridge fixture directory missing");
    process.env.JC_RENDEZVOUS_STATE_FILE = join(tempDir, "state.jsonl");
    process.env.JC_RENDEZVOUS_COMPACT_BYTES = "1";
    process.env.JC_WITNESS_ABSENCE_GRACE_MS = "10";
    const descriptor = testBridgeIdentity!.descriptor;
    const url = await startBridge();
    const primarySocket = await connect(url);
    const primary = registration({ hostId: "primary-host" });
    await registerHost(primarySocket, primary);

    const candidateA = registration({
      hostId: "replica-a",
      grantId: "77777777-7777-4777-8777-777777777777",
      deviceSeed: Buffer.alloc(32, 71),
    });
    const candidateB = registration({
      hostId: "replica-b",
      grantId: "88888888-8888-4888-8888-888888888888",
      deviceSeed: Buffer.alloc(32, 72),
    });
    const observerA = await connect(url);
    const observerB = await connect(url);
    const accessA = await exchange(observerA, accessFrame(candidateA, undefined, descriptor.payload.bridgeId, "witness"));
    const accessB = await exchange(observerB, accessFrame(candidateB, undefined, descriptor.payload.bridgeId, "witness"));
    expect(accessA.ok).toBe(true);
    expect(accessB.ok).toBe(true);

    primarySocket.terminate();
    await once(primarySocket, "close");
    await new Promise((resolve) => setTimeout(resolve, 20));
    const witnessA = await exchange(observerA, witnessFrame(candidateA, "primary-host", accessA.data.accessToken));
    const witnessB = await exchange(observerB, witnessFrame(candidateB, "primary-host", accessB.data.accessToken));
    expect(witnessA).toMatchObject({ ok: true, data: { witness: { payload: { primaryOnline: false, replicaHostId: "replica-a" } } } });
    expect(witnessB).toMatchObject({ ok: true, data: { witness: { payload: { primaryOnline: false, replicaHostId: "replica-b" } } } });

    expect(await exchange(observerA, promotionClaimFrame(witnessA.data.witness))).toMatchObject({
      type: "promotion.claim.result",
      ok: true,
      data: { receipt: { payload: { candidateHostId: "replica-a", electionEpoch: 2 } } },
    });
    expect(await exchange(observerB, promotionClaimFrame(witnessB.data.witness))).toMatchObject({
      type: "promotion.claim.result",
      ok: false,
      error: { code: "conflict" },
    });

    resetRendezvousState();
    expect(() => loadRendezvousState()).not.toThrow();
    expect(await exchange(observerB, promotionClaimFrame(witnessB.data.witness))).toMatchObject({
      type: "promotion.claim.result",
      ok: false,
      error: { code: "conflict" },
    });
  });

  it("requires durable control state in production", () => {
    const previous = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      expect(() => startRendezvous(0)).toThrow("JC_RENDEZVOUS_STATE_FILE is required in production");
    } finally {
      if (previous === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previous;
    }
  });

  it("keeps authorities isolated and resolves complete verifiable chains", async () => {
    const url = await startBridge();
    const host = await connect(url);
    const resolver = await connect(url);
    const accepted = registration();
    await registerHost(host, accepted);

    expect(await exchange(resolver, { type: "resolve", serverId: SERVER_ID, authorityFingerprint })).toMatchObject({
      ok: true,
      data: {
        records: [{
          record: { payload: { hostId: "member-host", epoch: 1 } },
          grant: { payload: { grantId: GRANT_ID, generation: 1 } },
          authorityPublicKey,
        }],
      },
    });
    expect(await exchange(resolver, {
      type: "resolve",
      serverId: SERVER_ID,
      authorityFingerprint: "00".repeat(32),
    })).toMatchObject({ ok: false, error: { code: "not_found" } });

    const attackerSeed = Buffer.alloc(32, 8);
    const attackerDeviceSeed = Buffer.alloc(32, 9);
    const attacker = registration({
      authoritySeed: attackerSeed,
      deviceSeed: attackerDeviceSeed,
      grantId: "44444444-4444-4444-8444-444444444444",
      hostId: "attacker-host",
      epoch: 1,
    });
    await registerHost(await connect(url), attacker);
    const forgedRevocation = createSignedHostGrantRevocation({
      version: 1,
      serverId: SERVER_ID,
      grantId: GRANT_ID,
      hostId: "member-host",
      issuerIdentityId: "attacker",
      revokedAt: Date.now(),
      generation: 2,
    }, attackerSeed);
    expect(await exchange(resolver, {
      type: "revoke",
      authorityPublicKey: attacker.authorityPublicKey,
      revocation: forgedRevocation,
    })).toMatchObject({ ok: true });
    expect(await exchange(resolver, { type: "resolve", serverId: SERVER_ID, authorityFingerprint })).toMatchObject({
      ok: true,
      data: { records: [{ record: { payload: { hostId: "member-host" } } }] },
    });
  });

  it("persists revocations and high-water marks across reset and reload", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "janjabridge-state-"));
    process.env.JC_RENDEZVOUS_STATE_FILE = join(tempDir, "state.jsonl");
    const url = await startBridge();
    const firstSocket = await connect(url);
    const first = registration({ epoch: 1, recordSeq: 1, generation: 2 });
    await registerHost(firstSocket, first);

    resetRendezvousState();
    loadRendezvousState();
    // Exact same hash/seq is an idempotent reconnect, not a rollback.
    await registerHost(await connect(url), first);

    const revocation = createSignedHostGrantRevocation({
      version: 1,
      serverId: SERVER_ID,
      grantId: GRANT_ID,
      hostId: "member-host",
      issuerIdentityId: "owner",
      revokedAt: Date.now(),
      generation: 3,
    }, authoritySeed);
    expect(await exchange(firstSocket, { type: "revoke", authorityPublicKey, revocation })).toMatchObject({ ok: true });

    resetRendezvousState();
    loadRendezvousState();
    const replay = registration({
      epoch: 1,
      recordSeq: 2,
      previousRecordHash: sha256Hex(canonicalJson(first.record)),
      generation: 2,
    });
    expect(await exchange(await connect(url), accessFrame(replay))).toMatchObject({
      type: "access.result",
      ok: false,
      error: { code: "unauthorized" },
    });
    const revokedGeneration = registration({
      epoch: 1,
      recordSeq: 2,
      previousRecordHash: sha256Hex(canonicalJson(first.record)),
      generation: 3,
    });
    expect(await exchange(await connect(url), accessFrame(revokedGeneration))).toMatchObject({ ok: false });

    const rotated = registration({
      epoch: 1,
      recordSeq: 2,
      previousRecordHash: sha256Hex(canonicalJson(first.record)),
      generation: 4,
    });
    await registerHost(await connect(url), rotated);
  });

  it("keeps pairing consumption one-shot across compact and restart", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "janjabridge-pairing-restart-"));
    process.env.JC_RENDEZVOUS_STATE_FILE = join(tempDir, "state.jsonl");
    process.env.JC_RENDEZVOUS_COMPACT_BYTES = "1";
    const { descriptor, adminKey } = configureBridgeIdentity();
    const token = mintPairingToken(descriptor.payload.bridgeId, adminKey);
    const url = await startBridge();
    const value = registration();
    expect(await exchange(await connect(url), accessFrame(value, token, descriptor.payload.bridgeId))).toMatchObject({ ok: true });
    resetRendezvousState();
    loadRendezvousState();
    const secondAuthority = registration({ authoritySeed: Buffer.alloc(32, 88), deviceSeed: Buffer.alloc(32, 89) });
    expect(await exchange(await connect(url), accessFrame(secondAuthority, token, descriptor.payload.bridgeId))).toMatchObject({
      ok: false,
      error: { code: "pairing_required" },
    });
  });

  it("replays revoke-then-compact checkpoints idempotently after restart", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "janjabridge-revoke-compact-"));
    process.env.JC_RENDEZVOUS_STATE_FILE = join(tempDir, "state.jsonl");
    const url = await startBridge();
    const accepted = registration({ generation: 1 });
    const socket = await connect(url);
    await registerHost(socket, accepted);
    process.env.JC_RENDEZVOUS_COMPACT_BYTES = "1";
    const revocation = createSignedHostGrantRevocation({
      version: 1,
      serverId: SERVER_ID,
      grantId: GRANT_ID,
      hostId: "member-host",
      issuerIdentityId: "owner",
      revokedAt: Date.now(),
      generation: 2,
    }, authoritySeed);
    expect(await exchange(socket, { type: "revoke", authorityPublicKey, revocation })).toMatchObject({ ok: true });
    resetRendezvousState();
    expect(() => loadRendezvousState()).not.toThrow();
    resetRendezvousState();
    expect(() => loadRendezvousState()).not.toThrow();
  });

  it("compacts durable host access and ledger state into a bounded valid checkpoint", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "janjabridge-compaction-"));
    const stateFile = join(tempDir, "state.jsonl");
    process.env.JC_RENDEZVOUS_STATE_FILE = stateFile;
    process.env.JC_RENDEZVOUS_COMPACT_BYTES = "1";
    const url = await startBridge();
    const first = registration({ recordSeq: 1 });
    await registerHost(await connect(url), first);
    const second = registration({
      recordSeq: 2,
      previousRecordHash: sha256Hex(canonicalJson(first.record)),
    });
    await registerHost(await connect(url), second);
    // One pairing-consumption event, one tenant access credential and one high-water mark.
    expect(readFileSync(stateFile, "utf8").trim().split("\n").length).toBeLessThanOrEqual(3);

    resetRendezvousState();
    expect(() => loadRendezvousState()).not.toThrow();
    const third = registration({
      recordSeq: 3,
      previousRecordHash: sha256Hex(canonicalJson(second.record)),
    });
    await registerHost(await connect(url), third);
  });

  it("rejects epoch, sequence, and grant-generation downgrade", async () => {
    const url = await startBridge();
    const first = registration({ epoch: 1, recordSeq: 1, generation: 2 });
    await registerHost(await connect(url), first);
    const previousRecordHash = sha256Hex(canonicalJson(first.record));

    expect(await beginAuthorized(await connect(url), registration({
      epoch: 0,
      recordSeq: 2,
      previousRecordHash,
      generation: 2,
    }))).toMatchObject({
      ok: false,
      error: { code: "conflict", message: "stale host epoch" },
      higherRegistration: { record: { payload: { epoch: 1, role: "primary" } } },
    });
    expect(await beginAuthorized(await connect(url), registration({
      epoch: 2,
      recordSeq: 1,
      previousRecordHash,
      generation: 2,
    }))).toMatchObject({ ok: false, error: { code: "conflict" } });
    expect(await beginAuthorized(await connect(url), registration({
      epoch: 2,
      recordSeq: 2,
      previousRecordHash,
      generation: 2,
    }))).toMatchObject({
      ok: false,
      error: { code: "unauthorized", message: "higher primary epoch requires a strict bridge promotion certificate" },
    });
    expect(await exchange(await connect(url), accessFrame(registration({
      epoch: 2,
      recordSeq: 2,
      previousRecordHash,
      generation: 1,
    })))).toMatchObject({ ok: false, error: { code: "unauthorized" } });
    expect(await beginAuthorized(await connect(url), registration({
      epoch: 2,
      recordSeq: 2,
      previousRecordHash: "00".repeat(32),
      generation: 2,
    }))).toMatchObject({ ok: false, error: { code: "conflict", message: "host record sequence must be exactly contiguous" } });
    expect(await beginAuthorized(await connect(url), registration({
      epoch: 99,
      recordSeq: 2,
      previousRecordHash,
      generation: 2,
    }))).toMatchObject({ ok: false, error: { code: "conflict", message: "host epoch transition is not contiguous" } });
    expect(await beginAuthorized(await connect(url), registration({
      epoch: 2,
      recordSeq: 3,
      previousRecordHash,
      generation: 2,
    }))).toMatchObject({ ok: false, error: { code: "conflict", message: "host record sequence must be exactly contiguous" } });
  });

  it("lets a delayed independent bridge bootstrap by replaying seq1 then seq2", async () => {
    const first = registration({ epoch: 1, recordSeq: 1 });
    const second = registration({
      epoch: 1,
      recordSeq: 2,
      previousRecordHash: sha256Hex(canonicalJson(first.record)),
    });
    const bridgeA = await startBridge();
    await registerHost(await connect(bridgeA), first);
    await registerHost(await connect(bridgeA), second);

    resetRendezvousState();
    const bridgeB = await startBridge();
    await registerHost(await connect(bridgeB), first);
    await registerHost(await connect(bridgeB), second);
    expect(await exchange(await connect(bridgeB), {
      type: "resolve", serverId: SERVER_ID, authorityFingerprint,
    })).toMatchObject({ ok: true, data: { records: [{ record: { payload: { recordSeq: 2 } } }] } });
  });

  it("fails closed on durable non-tail corruption and tolerates only a torn final append", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "janjabridge-corruption-"));
    const stateFile = join(tempDir, "state.jsonl");
    process.env.JC_RENDEZVOUS_STATE_FILE = stateFile;
    const url = await startBridge();
    await registerHost(await connect(url), registration());
    const valid = readFileSync(stateFile, "utf8");
    writeFileSync(stateFile, `not-json\n${valid}`, { mode: 0o600 });
    resetRendezvousState();
    expect(() => loadRendezvousState()).toThrow(/corruption at record 1/);

    writeFileSync(stateFile, `${valid}{"version":1`, { mode: 0o600 });
    resetRendezvousState();
    expect(() => loadRendezvousState()).not.toThrow();
  });

  it("binds challenges to one socket and consumes proof one-shot", async () => {
    const url = await startBridge();
    const firstSocket = await connect(url);
    const secondSocket = await connect(url);
    const value = registration();
    const access = await exchange(firstSocket, accessFrame(value));
    const begin = beginFrame(value, randomUUID(), access.data.accessToken);
    const challenge = await exchange(firstSocket, begin);
    const proof = proofFrame(value, challenge);

    expect(await exchange(secondSocket, begin)).toMatchObject({ ok: false, error: { code: "conflict" } });
    expect(await exchange(secondSocket, proof)).toMatchObject({ ok: false, error: { code: "unauthorized" } });
    expect(await exchange(firstSocket, proof)).toMatchObject({ type: "register.result", ok: true });
    expect(await exchange(firstSocket, proof)).toMatchObject({ ok: false, error: { code: "unauthorized" } });
    const reconnectChallenge = await exchange(secondSocket, begin);
    expect(reconnectChallenge).toMatchObject({ type: "register.challenge" });
    expect(await exchange(secondSocket, proofFrame(value, reconnectChallenge))).toMatchObject({ ok: true });
  });

  it("rejects a bad live proof and does not allow a corrected replay", async () => {
    const url = await startBridge();
    const ws = await connect(url);
    const value = registration();
    const challenge = await beginAuthorized(ws, value);
    expect(await exchange(ws, proofFrame(value, challenge, Buffer.alloc(32, 7)))).toMatchObject({
      ok: false,
      error: { code: "unauthorized" },
    });
    expect(await exchange(ws, proofFrame(value, challenge))).toMatchObject({
      ok: false,
      error: { code: "unauthorized" },
    });
  });

  it("does not issue TURN before proof and revocation unbinds an accepted socket", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "janjabridge-turn-"));
    const turnSecret = "s".repeat(64);
    process.env.JC_TURN_SHARED_SECRET_FILE = join(tempDir, "turn-secret");
    writeFileSync(process.env.JC_TURN_SHARED_SECRET_FILE, turnSecret, { mode: 0o600 });
    const url = await startBridge();
    const ws = await connect(url);
    const value = registration();
    const turnRequest = { type: "turn.issue", serverId: SERVER_ID, hostId: "member-host", subject: "session" };

    expect(await exchange(ws, turnRequest)).toMatchObject({ ok: false, error: { code: "unauthorized" } });
    const challenge = await beginAuthorized(ws, value);
    expect(await exchange(ws, turnRequest)).toMatchObject({ ok: false, error: { code: "unauthorized" } });
    expect(await exchange(ws, proofFrame(value, challenge))).toMatchObject({ ok: true });
    const issued = await exchange(ws, turnRequest);
    expect(issued).toMatchObject({ ok: true, data: { credentialType: "password" } });
    expect(JSON.stringify(issued)).not.toContain(turnSecret);

    const revocation = createSignedHostGrantRevocation({
      version: 1,
      serverId: SERVER_ID,
      grantId: GRANT_ID,
      hostId: "member-host",
      issuerIdentityId: "owner",
      revokedAt: Date.now(),
      generation: 2,
    }, authoritySeed);
    expect(await exchange(ws, { type: "revoke", authorityPublicKey, revocation })).toMatchObject({ ok: true });
    expect(await exchange(ws, turnRequest)).toMatchObject({ ok: false, error: { code: "unauthorized" } });
    expect(await exchange(await connect(url), {
      type: "resolve",
      serverId: SERVER_ID,
      authorityFingerprint,
    })).toMatchObject({
      ok: true,
      data: {
        records: [],
        revocations: [{ authorityPublicKey, revocation: { payload: { grantId: GRANT_ID, generation: 2 } } }],
      },
    });
  });

  it("issues bounded coturn REST credentials without exposing the shared secret", () => {
    const secret = "s".repeat(64);
    const result = issueTurnCredentials({ serverId: SERVER_ID, hostId: "member-host", subject: "session", ttlSeconds: 9999 }, 1_000_000, secret) as {
      ok: true;
      data: { username: string; credential: string; expiresAt: number };
    };
    expect(result.ok).toBe(true);
    expect(result.data.expiresAt).toBe(1_600_000);
    expect(result.data.credential).toBe(createHmac("sha1", secret).update(result.data.username).digest("base64"));
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("keeps direct frame registration disabled", () => {
    expect(handleRendezvousFrame({ type: "register", ...registration() })).toMatchObject({
      ok: false,
      error: { code: "invalid_input" },
    });
  });
});
