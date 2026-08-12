import { createHash, createHmac, createPrivateKey, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, statSync, truncateSync, writeFileSync, writeSync } from "node:fs";
import { dirname } from "node:path";
import {
  canonicalJson,
  ed25519Fingerprint,
  sha256Hex,
  signCanonicalPayload,
  verifyCanonicalPayload,
} from "@janjacord/crypto";
import {
  verifyHostRegistration,
  createSignedBridgeWitness,
  verifySignedBridgeDescriptor,
  verifySignedBridgeWitness,
  verifySignedHostGrant,
  verifySignedHostGrantRevocation,
} from "@janjacord/protocol";
import {
  AuthorityFingerprintSchema,
  PublicKeySchema,
  SignedHostGrantSchema,
  SignedHostRecordSchema,
  type SignedHostGrant,
  type SignedHostGrantRevocation,
  type SignedHostRecord,
  type SignedBridgeDescriptor,
} from "@janjacord/schemas";
import { WebSocketServer, WebSocket } from "ws";
import { isIP } from "node:net";

const PORT = Number(process.env.JC_RENDEZVOUS_PORT ?? 8920);
const MAX_TTL_MS = Number(process.env.JC_RENDEZVOUS_MAX_TTL_MS ?? 2 * 3600_000);
const CLEANUP_MS = 60_000;
const RATE_LIMIT = { windowMs: 60_000, max: Number(process.env.JC_RENDEZVOUS_RATE_LIMIT ?? 120) };
const MAX_RECORDS_PER_SERVER = 16;
const MAX_SIGNAL_FRAME_BYTES = 56 * 1024;
const MAX_SIGNAL_SDP_BYTES = 48 * 1024;
const MAX_SIGNAL_CANDIDATE_BYTES = 4 * 1024;
const MAX_SIGNAL_MID_BYTES = 64;
export const SIGNAL_SESSION_TTL_MS = 10 * 60_000;
function positiveIntegerSetting(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? fallback);
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}
const MAX_SIGNAL_SESSIONS = positiveIntegerSetting("JC_MAX_SIGNAL_SESSIONS", 1_024);
const MAX_SIGNAL_SESSIONS_PER_HOST = positiveIntegerSetting("JC_MAX_SIGNAL_SESSIONS_PER_HOST", 128);
const MAX_SIGNAL_SESSIONS_PER_CLIENT = positiveIntegerSetting("JC_MAX_SIGNAL_SESSIONS_PER_CLIENT", 8);
const MAX_TURN_TTL_SECONDS = 600;
const REGISTRATION_CHALLENGE_TTL_MS = 30_000;
const REGISTRATION_PROOF_CLOCK_SKEW_MS = 5_000;
const REGISTRATION_PROOF_DOMAIN = "janjacord.bridge-registration-proof.v1";
const REPLICA_WITNESS_DOMAIN = "janjacord.replica-witness.v1";
const PROMOTION_VOTE_DOMAIN = "janjacord.promotion-vote.v1";
const BRIDGE_ACCESS_DOMAIN = "janjacord.bridge-access.v1";
const MAX_DURABLE_ENTRIES = 16_384;
export const MAX_RENDEZVOUS_FRAME_BYTES = 64 * 1024;
const MAX_FRAME_DEPTH = 8;
const MAX_FRAME_NODES = 512;
const MAX_OBJECT_KEYS = 64;
type HostAccessSlot = "registration" | "witness";

interface StoredRecord {
  record: SignedHostRecord;
  grant: SignedHostGrant;
  authorityPublicKey: string;
  authorityFingerprint: string;
  expiresAt: number;
  promotionCertificate?: unknown;
}

interface HighWaterMark {
  authorityFingerprint: string;
  serverId: string;
  hostId: string;
  epoch: number;
  recordSeq: number;
  recordHash: string;
  grantId: string;
  grantGeneration: number;
  role?: "primary" | "replica";
}

interface RevocationMark {
  revokedAt: number;
  generation: number;
  authorityPublicKey: string;
  revocation: SignedHostGrantRevocation;
}

interface PairingConsumption {
  tokenHash: string;
  bridgeId: string;
  authorityFingerprint: string;
  serverId: string;
  hostId: string;
  consumedAt: number;
  expiresAt: number;
}

interface PromotionVote {
  authorityFingerprint: string;
  serverId: string;
  electionEpoch: number;
  candidateHostId: string;
  primaryHostId: string;
  primaryRecordHash: string;
  grantedAt: number;
}

interface PendingRegistration {
  requestId: string;
  challengeId: string;
  nonce: string;
  recordHash: string;
  createdAt: number;
  expiresAt: number;
  claimKey: string;
  authorityFingerprint: string;
  authorityPublicKey: string;
  record: SignedHostRecord;
  grant: SignedHostGrant;
  promotionCertificate?: unknown;
}

function authorityScope(authorityFingerprint: string, serverId: string): string {
  return `${authorityFingerprint.toLowerCase()}:${serverId}`;
}

function promotionVoteKey(authorityFingerprint: string, serverId: string, electionEpoch: number): string {
  return `${authorityScope(authorityFingerprint, serverId)}:${electionEpoch}`;
}

const records = new Map<string, Map<string, StoredRecord>>();
const revokedGrants = new Map<string, Map<string, RevocationMark>>();
const highWaterMarks = new Map<string, Map<string, HighWaterMark>>();
const rateBuckets = new Map<string, { count: number; windowStart: number }>();
const hostSockets = new Map<string, WebSocket>();
type SignalingSession = {
  host: WebSocket;
  client: WebSocket;
  expiresAt: number;
  authorized: boolean;
};
const signalingSessions = new Map<string, SignalingSession>();
const socketHosts = new Map<WebSocket, {
  authorityFingerprint: string;
  serverId: string;
  hostId: string;
  grantId: string;
  grantGeneration: number;
  authorizationExpiresAt: number;
}>();
const pendingRegistrations = new Map<WebSocket, PendingRegistration>();
const pendingRegistrationClaims = new Map<string, WebSocket>();
const hostAccess = new Map<string, { tokenHash: string; grantId: string; generation: number; expiresAt: number; proofId: string }>();
const consumedAccessProofs = new Map<string, number>();
const hostDisconnectedAt = new Map<string, number>();
const consumedWitnessNonces = new Set<string>();
const consumedPairingTokens = new Map<string, PairingConsumption>();
const promotionVotes = new Map<string, PromotionVote>();
const socketClientIps = new Map<WebSocket, string>();
let durableStateSeq = 0;
let durableStateHash: string | null = null;
let bridgeSigningMaterial: { descriptor: SignedBridgeDescriptor; seed: Buffer } | null = null;

export function signalingAdmissionReason(
  sessions: Iterable<{ host: unknown; client: unknown }>,
  host: unknown,
  client: unknown,
  limits = {
    total: MAX_SIGNAL_SESSIONS,
    perHost: MAX_SIGNAL_SESSIONS_PER_HOST,
    perClient: MAX_SIGNAL_SESSIONS_PER_CLIENT,
  },
): "global_capacity" | "host_capacity" | "client_capacity" | null {
  let total = 0;
  let hostCount = 0;
  let clientCount = 0;
  for (const session of sessions) {
    total += 1;
    if (session.host === host) hostCount += 1;
    if (session.client === client) clientCount += 1;
  }
  if (total >= limits.total) return "global_capacity";
  if (hostCount >= limits.perHost) return "host_capacity";
  if (clientCount >= limits.perClient) return "client_capacity";
  return null;
}

export function isSignalingSessionContinuation(
  session: { host: unknown; client: unknown } | undefined,
  host: unknown,
  client: unknown,
): boolean {
  return Boolean(session && session.host === host && session.client === client);
}

export function isBoundedFrameStructure(value: unknown): boolean {
  let nodes = 0;
  const visit = (item: unknown, depth: number): boolean => {
    if (++nodes > MAX_FRAME_NODES || depth > MAX_FRAME_DEPTH) return false;
    if (item === null || typeof item === "boolean" || typeof item === "number") return true;
    if (typeof item === "string") return item.length <= MAX_RENDEZVOUS_FRAME_BYTES;
    if (Array.isArray(item)) return item.length <= MAX_OBJECT_KEYS && item.every((entry) => visit(entry, depth + 1));
    if (!item || typeof item !== "object") return false;
    const entries = Object.entries(item as Record<string, unknown>);
    return entries.length <= MAX_OBJECT_KEYS
      && entries.every(([key, entry]) => key.length <= 128 && visit(entry, depth + 1));
  };
  return visit(value, 0);
}

function loadBridgeSigningMaterial(): { descriptor: SignedBridgeDescriptor; seed: Buffer } | null {
  const descriptorFile = process.env.JC_BRIDGE_DESCRIPTOR_FILE;
  const signingKeyFile = process.env.JC_BRIDGE_SIGNING_KEY_FILE;
  if (!descriptorFile || !signingKeyFile) return null;
  const descriptor = verifySignedBridgeDescriptor(JSON.parse(readFileSync(descriptorFile, "utf8")));
  if (!descriptor) throw new Error("invalid or expired bridge descriptor");
  const canonicalBridgeId = `ed25519:${ed25519Fingerprint(Buffer.from(descriptor.publicKey, "base64url"))}`;
  if (descriptor.payload.bridgeId !== canonicalBridgeId) {
    throw new Error("bridge signing descriptor requires canonical ed25519 bridge id");
  }
  const jwk = createPrivateKey(readFileSync(signingKeyFile)).export({ format: "jwk" });
  if (typeof jwk.d !== "string" || typeof jwk.x !== "string" || jwk.x !== descriptor.publicKey) {
    throw new Error("bridge signing key does not match descriptor");
  }
  const seed = Buffer.from(jwk.d, "base64url");
  if (seed.length !== 32) throw new Error("invalid Ed25519 bridge signing seed");
  return { descriptor, seed };
}

function rateLimited(ip: string): boolean {
  const now = Date.now();
  const bucket = rateBuckets.get(ip);
  if (!bucket || now - bucket.windowStart > RATE_LIMIT.windowMs) {
    rateBuckets.set(ip, { count: 1, windowStart: now });
    return false;
  }
  bucket.count++;
  return bucket.count > RATE_LIMIT.max;
}

function cleanup(now = Date.now()): void {
  for (const [serverId, hosts] of records) {
    for (const [hostId, entry] of hosts) if (entry.expiresAt <= now) hosts.delete(hostId);
    if (hosts.size === 0) records.delete(serverId);
  }
  for (const [ip, bucket] of rateBuckets) {
    if (now - bucket.windowStart > RATE_LIMIT.windowMs) rateBuckets.delete(ip);
  }
  cleanupExpiredSignalingSessions(now);
  for (const [ws, binding] of socketHosts) {
    if (binding.authorizationExpiresAt <= now) unbindSocket(ws);
  }
  for (const [ws, pending] of pendingRegistrations) {
    if (pending.expiresAt <= now) clearPendingRegistration(ws);
  }
  for (const [key, access] of hostAccess) if (access.expiresAt <= now) hostAccess.delete(key);
  for (const [proofId, expiresAt] of consumedAccessProofs) if (expiresAt <= now) consumedAccessProofs.delete(proofId);
}

function clientIp(ws: WebSocket): string {
  return socketClientIps.get(ws) ?? "unknown";
}

export function resolveClientIp(remoteAddress: string | undefined, forwardedFor: string | string[] | undefined, trustedProxyList: string): string {
  const remote = (remoteAddress ?? "unknown").replace(/^::ffff:/, "");
  const trusted = new Set(trustedProxyList.split(",").map((entry) => entry.trim()).filter((entry) => isIP(entry) !== 0));
  if (!trusted.has(remote) || typeof forwardedFor !== "string") return remote;
  // The edge proxy must overwrite (not append) X-Forwarded-For. Lists and non-canonical
  // representations are ignored so an external client cannot select its own rate bucket.
  const candidate = forwardedFor.trim();
  if (candidate !== forwardedFor || candidate.includes(",") || isIP(candidate) === 0) return remote;
  return candidate;
}

function reply(ws: WebSocket, data: unknown): void {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
}

function closeSignalingSession(
  sessionId: string,
  source: WebSocket | null,
  reason: "closed" | "disconnect" | "timeout",
): boolean {
  const session = signalingSessions.get(sessionId);
  if (!session) return false;
  signalingSessions.delete(sessionId);
  const frame = { type: "signal.close", sessionId, payload: { reason } };
  if (session.host !== source) reply(session.host, frame);
  if (session.client !== source) reply(session.client, frame);
  return true;
}

export function cleanupExpiredSignalingSessions(now = Date.now()): number {
  let closed = 0;
  for (const [sessionId, session] of signalingSessions) {
    if (session.expiresAt <= now && closeSignalingSession(sessionId, null, "timeout")) closed += 1;
  }
  return closed;
}

function publicKeyFingerprint(publicKey: string): string | null {
  try {
    return ed25519Fingerprint(Buffer.from(PublicKeySchema.parse(publicKey), "base64url"));
  } catch {
    return null;
  }
}

function hostBindingKey(authorityFingerprint: string, serverId: string, hostId: string): string {
  return `${authorityScope(authorityFingerprint, serverId)}:${hostId}`;
}

function hostAccessKey(authorityFingerprint: string, serverId: string, hostId: string, slot: HostAccessSlot): string {
  return `${hostBindingKey(authorityFingerprint, serverId, hostId)}:${slot}`;
}

function clearPendingRegistration(ws: WebSocket): PendingRegistration | undefined {
  const pending = pendingRegistrations.get(ws);
  if (!pending) return undefined;
  pendingRegistrations.delete(ws);
  if (pendingRegistrationClaims.get(pending.claimKey) === ws) pendingRegistrationClaims.delete(pending.claimKey);
  return pending;
}

function unbindSocket(ws: WebSocket): void {
  const binding = socketHosts.get(ws);
  if (binding) {
    const key = hostBindingKey(binding.authorityFingerprint, binding.serverId, binding.hostId);
    if (hostSockets.get(key) === ws) hostSockets.delete(key);
    hostDisconnectedAt.set(key, Date.now());
  }
  socketHosts.delete(ws);
  for (const [sessionId, session] of signalingSessions) {
    if (session.host === ws || session.client === ws) closeSignalingSession(sessionId, ws, "disconnect");
  }
}

type RendezvousError = { ok: false; error: { code: string; message: string } };

type RegisterBeginFrame = {
  type: "register.begin";
  requestId: string;
  authorityPublicKey: string;
  grant: unknown;
  record: unknown;
  accessToken?: unknown;
  promotionCertificate?: unknown;
};

function pairingAdminKey(): string | null {
  return readSecret(process.env.JC_BRIDGE_PAIRING_ADMIN_KEY_FILE ?? process.env.JC_BRIDGE_PAIRING_SECRET_FILE);
}

function pairingTokenPayload(value: unknown, now: number): { tokenHash: string; bridgeId: string; expiresAt: number } | null {
  const adminKey = pairingAdminKey();
  if (!adminKey) return null;
  if (typeof value !== "string" || value.length > 512) return null;
  const match = /^JCP1\.([A-Za-z0-9_-]{32,384})\.([A-Za-z0-9_-]{43})$/.exec(value);
  if (!match) return null;
  const actual = Buffer.from(match[2]!, "base64url");
  const expected = createHmac("sha256", adminKey).update(`JCP1.${match[1]}`).digest();
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(match[1]!, "base64url").toString("utf8")) as Record<string, unknown>;
    if (Object.keys(payload).sort().join("\0") !== ["bridgeId", "expiresAt", "issuedAt", "tokenId", "version"].sort().join("\0")
      || payload.version !== 1 || typeof payload.bridgeId !== "string"
      || typeof payload.tokenId !== "string" || !/^[0-9a-f-]{36}$/i.test(payload.tokenId)
      || !Number.isSafeInteger(payload.issuedAt) || !Number.isSafeInteger(payload.expiresAt)
      || Number(payload.issuedAt) > now + 5_000 || Number(payload.expiresAt) <= now
      || Number(payload.expiresAt) > Number(payload.issuedAt) + 30 * 24 * 3600_000) return null;
    return {
      tokenHash: createHash("sha256").update(value).digest("hex"),
      bridgeId: payload.bridgeId,
      expiresAt: Number(payload.expiresAt),
    };
  } catch {
    return null;
  }
}

function consumePairingToken(
  value: unknown,
  binding: Omit<PairingConsumption, "tokenHash" | "consumedAt" | "expiresAt">,
  now: number,
): boolean {
  const token = pairingTokenPayload(value, now);
  const expectedBridgeId = bridgeSigningMaterial?.descriptor.payload.bridgeId;
  if (!token || consumedPairingTokens.has(token.tokenHash)
    || token.bridgeId !== binding.bridgeId
    || (expectedBridgeId && token.bridgeId !== expectedBridgeId)) return false;
  const consumed: PairingConsumption = {
    ...binding,
    tokenHash: token.tokenHash,
    consumedAt: now,
    expiresAt: token.expiresAt,
  };
  // Persist before issuing any reusable community credential. A crash can burn a token but can
  // never make one reusable or bind it to two communities.
  appendStateEvent({ type: "pairingConsumed", ...consumed });
  consumedPairingTokens.set(consumed.tokenHash, consumed);
  return true;
}

function validHostAccessToken(value: unknown, checked: VerifiedRegistration, now: number): boolean {
  if (typeof value !== "string" || value.length < 32 || value.length > 512) return false;
  const entry = hostAccess.get(hostBindingKey(
    checked.authorityFingerprint,
    checked.record.payload.serverId,
    checked.record.payload.hostId,
  ) + ":registration");
  if (!entry || entry.expiresAt <= now || entry.grantId !== checked.grant.payload.grantId
    || entry.generation !== checked.grant.payload.generation) return false;
  const actual = createHash("sha256").update(value).digest();
  const expected = Buffer.from(entry.tokenHash, "hex");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function registrationCursor(frame: Record<string, unknown>, now = Date.now()): unknown {
  const requestId = typeof frame.requestId === "string" ? frame.requestId : "";
  const authorityFingerprint = typeof frame.authorityFingerprint === "string" ? frame.authorityFingerprint.toLowerCase() : "";
  const serverId = typeof frame.serverId === "string" ? frame.serverId : "";
  const hostId = typeof frame.hostId === "string" ? frame.hostId : "";
  const access = hostAccess.get(hostAccessKey(authorityFingerprint, serverId, hostId, "registration"));
  const supplied = typeof frame.accessToken === "string"
    ? createHash("sha256").update(frame.accessToken).digest("hex") : "";
  if (!requestId || !AuthorityFingerprintSchema.safeParse(authorityFingerprint).success
    || !access || access.expiresAt <= now || access.tokenHash !== supplied) {
    return { type: "register.cursor.result", requestId, ok: false, error: { code: "unauthorized", message: "valid host access required" } };
  }
  const scope = authorityScope(authorityFingerprint, serverId);
  const head = highWaterMarks.get(scope)?.get(hostId);
  return {
    type: "register.cursor.result",
    requestId,
    ok: true,
    data: { nextRecordSeq: (head?.recordSeq ?? 0) + 1, previousRecordHash: head?.recordHash ?? null },
  };
}

function issueHostAccess(frame: Record<string, unknown>, now = Date.now()): unknown {
  const requestId = typeof frame.requestId === "string" ? frame.requestId : "";
  const denied = (message = "valid host access proof required") => ({
    type: "access.result", requestId, ok: false, error: { code: "unauthorized", message },
  });
  const authorityPublicKey = typeof frame.authorityPublicKey === "string" ? frame.authorityPublicKey : "";
  const grant = verifySignedHostGrant(frame.grant, authorityPublicKey, now);
  const authorityFingerprint = publicKeyFingerprint(authorityPublicKey);
  const signed = frame.proof as { payload?: Record<string, unknown>; publicKey?: unknown; signature?: unknown } | undefined;
  if (!requestId || !grant || !authorityFingerprint || !grant.payload.capabilities.includes("register") || !signed?.payload) return denied();
  const payload = signed.payload;
  const expectedKeys = ["bridgeId", "expiresAt", "grantId", "hostId", "issuedAt", "proofId", "serverId", "slot", "version"];
  const publicKey = decodeCanonicalBase64Url(signed.publicKey, 32);
  const signature = decodeCanonicalBase64Url(signed.signature, 64);
  const proofId = typeof payload.proofId === "string" ? payload.proofId : "";
  const scope = authorityScope(authorityFingerprint, grant.payload.serverId);
  const tenantPrefix = `${scope}:`;
  const scopeEstablished = (highWaterMarks.get(scope)?.size ?? 0) > 0
    || [...hostAccess.keys()].some((entry) => entry.startsWith(tenantPrefix));
  const revocation = revokedGrants.get(scope)?.get(grant.payload.grantId);
  const hostFloor = highWaterMarks.get(scope)?.get(grant.payload.hostId)?.grantGeneration ?? 0;
  if (!publicKey || !signature || signed.publicKey !== grant.payload.devicePublicKey
    || Object.keys(payload).sort().join("\0") !== expectedKeys.sort().join("\0")
    || payload.version !== 1 || payload.serverId !== grant.payload.serverId
    || payload.hostId !== grant.payload.hostId || payload.grantId !== grant.payload.grantId
    || !["registration", "witness"].includes(String(payload.slot))
    || typeof payload.bridgeId !== "string" || payload.bridgeId.length < 1
    || !/^[0-9a-f-]{36}$/i.test(proofId) || consumedAccessProofs.has(proofId)
    || typeof payload.issuedAt !== "number" || !Number.isSafeInteger(payload.issuedAt)
    || typeof payload.expiresAt !== "number" || !Number.isSafeInteger(payload.expiresAt)
    || payload.issuedAt < now - 10_000 || payload.issuedAt > now + REGISTRATION_PROOF_CLOCK_SKEW_MS
    || payload.expiresAt <= now || payload.expiresAt > payload.issuedAt + 30_000
    || (revocation && grant.payload.generation <= revocation.generation)
    || grant.payload.generation < hostFloor
    || !verifyCanonicalPayload(publicKey, BRIDGE_ACCESS_DOMAIN, payload, signature)) return denied();
  if (!scopeEstablished) {
    try {
      if (!consumePairingToken(frame.pairingToken, {
        bridgeId: String(payload.bridgeId),
        authorityFingerprint,
        serverId: grant.payload.serverId,
        hostId: grant.payload.hostId,
      }, now)) {
        return { type: "access.result", requestId, ok: false, error: { code: "pairing_required", message: "unused one-time community pairing required" } };
      }
    } catch {
      return { type: "access.result", requestId, ok: false, error: { code: "unavailable", message: "pairing consumption could not be persisted" } };
    }
  }
  const accessToken = randomBytes(48).toString("base64url");
  const access = {
    tokenHash: createHash("sha256").update(accessToken).digest("hex"),
    grantId: grant.payload.grantId,
    generation: grant.payload.generation,
    expiresAt: Math.min(grant.payload.expiresAt, now + 24 * 3600_000),
    proofId,
  };
  const slot = payload.slot as HostAccessSlot;
  const hostKey = hostBindingKey(authorityFingerprint, grant.payload.serverId, grant.payload.hostId);
  const key = `${hostKey}:${slot}`;
  const tenantAccessCount = new Set(
    [...hostAccess.keys()]
      .filter((entry) => entry.startsWith(tenantPrefix))
      .map((entry) => entry.replace(/:(?:registration|witness)$/, "")),
  ).size;
  const tenantQuota = Math.max(1, Math.min(256, Number(process.env.JC_BRIDGE_HOSTS_PER_COMMUNITY ?? 32)));
  if (![...hostAccess.keys()].some((entry) => entry.startsWith(`${hostKey}:`)) && tenantAccessCount >= tenantQuota) {
    return denied("community host credential quota reached");
  }
  if (!hostAccess.has(key) && hostAccess.size >= MAX_DURABLE_ENTRIES) return denied("bridge host access capacity reached");
  try {
    appendStateEvent({ type: "hostAccess", key, ...access });
  } catch {
    return { type: "access.result", requestId, ok: false, error: { code: "unavailable", message: "host access state could not be persisted" } };
  }
  consumedAccessProofs.set(proofId, Number(payload.expiresAt));
  hostAccess.set(key, access);
  maybeCompactState();
  return { type: "access.result", requestId, ok: true, data: { accessToken, expiresAt: access.expiresAt } };
}

type VerifiedRegistration = {
  authorityFingerprint: string;
  authorityPublicKey: string;
  grant: SignedHostGrant;
  record: SignedHostRecord;
  recordHash: string;
  promotionCertificate?: unknown;
};

function validateRegistration(frame: Pick<RegisterBeginFrame, "authorityPublicKey" | "grant" | "record" | "promotionCertificate">, now: number):
  | { ok: true; data: VerifiedRegistration }
  | RendezvousError {
  const authorityFingerprint = publicKeyFingerprint(frame.authorityPublicKey);
  if (!authorityFingerprint) return { ok: false, error: { code: "invalid_input", message: "invalid authority key" } };
  const parsedGrant = SignedHostGrantSchema.safeParse(frame.grant);
  const parsedRecord = SignedHostRecordSchema.safeParse(frame.record);
  if (!parsedGrant.success || !parsedRecord.success) {
    return { ok: false, error: { code: "invalid_input", message: "malformed signed registration" } };
  }
  const serverId = parsedRecord.data.payload.serverId;
  const scope = authorityScope(authorityFingerprint, serverId);
  const revocation = revokedGrants.get(scope)?.get(parsedGrant.data.payload.grantId);
  const revoked = new Set<string>();
  if (revocation && parsedGrant.data.payload.generation <= revocation.generation) {
    revoked.add(parsedGrant.data.payload.grantId);
  }
  const verified = verifyHostRegistration({
    record: parsedRecord.data,
    grant: parsedGrant.data,
    authorityPublicKey: frame.authorityPublicKey,
    revokedGrantIds: revoked,
    now,
  });
  if (!verified) return { ok: false, error: { code: "unauthorized", message: "invalid or revoked host registration" } };

  const scopeHighWater = highWaterMarks.get(scope);
  const highestEpoch = Math.max(0, ...[...(scopeHighWater?.values() ?? [])].map((mark) => mark.epoch));
  if ((!scopeHighWater || scopeHighWater.size === 0) && (
    verified.record.payload.epoch > 1 || verified.record.payload.recordSeq !== 1
  )) {
    return { ok: false, error: { code: "conflict", message: "host record requires an initial checkpoint" } };
  }
  if (verified.record.payload.epoch < highestEpoch) {
    return { ok: false, error: { code: "conflict", message: "stale host epoch" } };
  }
  if (scopeHighWater && scopeHighWater.size > 0 && verified.record.payload.epoch > highestEpoch + 1) {
    return { ok: false, error: { code: "conflict", message: "host epoch transition is not contiguous" } };
  }
  const previous = scopeHighWater?.get(verified.record.payload.hostId);
  if (previous) {
    if (verified.grant.payload.generation < previous.grantGeneration) {
      return { ok: false, error: { code: "conflict", message: "stale host grant generation" } };
    }
    if (
      verified.grant.payload.generation === previous.grantGeneration &&
      verified.grant.payload.grantId !== previous.grantId
    ) {
      return { ok: false, error: { code: "conflict", message: "host grant generation already bound" } };
    }
    if (verified.record.payload.epoch < previous.epoch) {
      return { ok: false, error: { code: "conflict", message: "stale host epoch" } };
    }
    const idempotent = verified.record.payload.recordSeq === previous.recordSeq
      && verified.record.payload.epoch === previous.epoch
      && verified.record.payload.grantId === previous.grantId
      && sha256Hex(canonicalJson(verified.record)) === previous.recordHash;
    if (verified.record.payload.recordSeq < previous.recordSeq || (verified.record.payload.recordSeq === previous.recordSeq && !idempotent)) {
      return { ok: false, error: { code: "conflict", message: "stale host record sequence" } };
    }
    if (!idempotent && (verified.record.payload.recordSeq !== previous.recordSeq + 1
      || verified.record.payload.previousRecordHash !== previous.recordHash)) {
      return { ok: false, error: { code: "conflict", message: "host record sequence must be exactly contiguous" } };
    }
  } else if (verified.record.payload.recordSeq !== 1 || verified.record.payload.previousRecordHash !== null) {
    return { ok: false, error: { code: "conflict", message: "host record requires an initial checkpoint" } };
  }
  if (scopeHighWater && scopeHighWater.size > 0
    && verified.record.payload.role === "primary" && verified.record.payload.epoch > highestEpoch) {
    const certificate = frame.promotionCertificate;
    if (!validPromotionCertificate(certificate, verified, scopeHighWater, highestEpoch, now)) {
      return { ok: false, error: { code: "unauthorized", message: "higher primary epoch requires a strict bridge promotion certificate" } };
    }
  }
  const hosts = records.get(scope) ?? new Map<string, StoredRecord>();
  if (!hosts.has(verified.record.payload.hostId) && hosts.size >= MAX_RECORDS_PER_SERVER) {
    return { ok: false, error: { code: "rate_limited", message: "host record quota reached" } };
  }
  return {
    ok: true,
    data: {
      ...verified,
      authorityPublicKey: frame.authorityPublicKey,
      authorityFingerprint,
      recordHash: sha256Hex(canonicalJson(verified.record)),
      ...(frame.promotionCertificate ? { promotionCertificate: frame.promotionCertificate } : {}),
    },
  };
}

function validPromotionCertificate(
  value: unknown,
  registration: { record: SignedHostRecord; grant: SignedHostGrant },
  marks: Map<string, HighWaterMark>,
  highestEpoch: number,
  now: number,
): boolean {
  if (!Array.isArray(value) || value.length < 2 || value.length > 3) return false;
  const authorityApprovedBridges = new Set(registration.grant.payload.witnessBridgeIds ?? []);
  if (authorityApprovedBridges.size < 2) return false;
  const primary = [...marks.values()]
    .filter((mark) => mark.role === "primary" && mark.epoch === highestEpoch)
    .sort((left, right) => right.recordSeq - left.recordSeq)[0];
  if (!primary) return false;
  const bridgeIds = new Set<string>();
  const requestIds = new Set<string>();
  const signing = bridgeSigningMaterial ?? loadBridgeSigningMaterial();
  if (!signing) return false;
  bridgeSigningMaterial = signing;
  let includesDurableLocalVote = false;
  for (const item of value) {
    if (!item || typeof item !== "object") return false;
    const receipt = item as { payload?: Record<string, unknown>; publicKey?: unknown; signature?: unknown };
    const payload = receipt.payload;
    const expectedKeys = [
      "bridgeId", "candidateHostId", "electionEpoch", "expiresAt", "issuedAt", "primaryEpoch",
      "primaryHostId", "primaryRecordHash", "requestId", "serverId", "version", "voteGrantedAt",
    ];
    if (!payload || Object.keys(payload).sort().join("\0") !== expectedKeys.sort().join("\0")
      || typeof receipt.publicKey !== "string" || !PublicKeySchema.safeParse(receipt.publicKey).success
      || typeof receipt.signature !== "string") return false;
    const publicKey = Buffer.from(receipt.publicKey, "base64url");
    const signature = Buffer.from(receipt.signature, "base64url");
    const bridgeId = String(payload.bridgeId ?? "");
    const requestId = String(payload.requestId ?? "");
    if (payload.version !== 1 || !authorityApprovedBridges.has(bridgeId)
      || bridgeId !== `ed25519:${ed25519Fingerprint(publicKey)}`
      || requestId.length < 1 || requestId.length > 128
      || payload.serverId !== registration.record.payload.serverId
      || payload.candidateHostId !== registration.record.payload.hostId
      || payload.primaryHostId !== primary.hostId
      || payload.primaryRecordHash !== primary.recordHash
      || payload.primaryEpoch !== highestEpoch
      || payload.electionEpoch !== registration.record.payload.epoch
      || !Number.isSafeInteger(payload.voteGrantedAt)
      || !Number.isSafeInteger(payload.issuedAt)
      || !Number.isSafeInteger(payload.expiresAt)
      || Number(payload.voteGrantedAt) > Number(payload.issuedAt)
      || Number(payload.issuedAt) > now + 5_000
      || Number(payload.expiresAt) <= now
      || Number(payload.expiresAt) > Number(payload.issuedAt) + 24 * 3600_000
      || signature.length !== 64 || signature.toString("base64url") !== receipt.signature
      || !verifyCanonicalPayload(publicKey, PROMOTION_VOTE_DOMAIN, payload, signature)
      || bridgeIds.has(bridgeId) || requestIds.has(requestId)) return false;
    if (bridgeId === signing.descriptor.payload.bridgeId) {
      if (receipt.publicKey !== signing.descriptor.publicKey) return false;
      const durableVote = promotionVotes.get(promotionVoteKey(
        primary.authorityFingerprint,
        registration.record.payload.serverId,
        registration.record.payload.epoch,
      ));
      if (!durableVote || durableVote.candidateHostId !== registration.record.payload.hostId
        || durableVote.primaryHostId !== primary.hostId
        || durableVote.primaryRecordHash !== primary.recordHash
        || durableVote.electionEpoch !== registration.record.payload.epoch
        || durableVote.grantedAt !== payload.voteGrantedAt) return false;
      includesDurableLocalVote = true;
    }
    bridgeIds.add(bridgeId);
    requestIds.add(requestId);
  }
  return bridgeIds.size >= 2 && includesDurableLocalVote;
}

function beginRegistration(ws: WebSocket, frame: RegisterBeginFrame, now = Date.now()): unknown {
  cleanup(now);
  if (typeof frame.requestId !== "string" || frame.requestId.length < 1 || frame.requestId.length > 128) {
    return { type: "register.result", requestId: frame.requestId, ok: false, error: { code: "invalid_input", message: "invalid requestId" } };
  }
  if (pendingRegistrations.has(ws)) {
    return { type: "register.result", requestId: frame.requestId, ok: false, error: { code: "conflict", message: "registration proof already pending" } };
  }
  const checked = validateRegistration(frame, now);
  if (!checked.ok) {
    let higherRegistration: {
      authorityPublicKey: string;
      grant: SignedHostGrant;
      record: SignedHostRecord;
      promotionCertificate?: unknown;
    } | undefined;
    if (checked.error.message === "stale host epoch") {
      const authorityFingerprint = publicKeyFingerprint(frame.authorityPublicKey);
      const parsedRecord = SignedHostRecordSchema.safeParse(frame.record);
      if (authorityFingerprint && parsedRecord.success) {
        const scope = authorityScope(authorityFingerprint, parsedRecord.data.payload.serverId);
        const higher = [...(records.get(scope)?.values() ?? [])]
          .filter((entry) => entry.record.payload.role === "primary"
            && entry.record.payload.epoch > parsedRecord.data.payload.epoch)
          .sort((left, right) => right.record.payload.epoch - left.record.payload.epoch
            || right.record.payload.recordSeq - left.record.payload.recordSeq)[0];
        if (higher) higherRegistration = {
          authorityPublicKey: higher.authorityPublicKey,
          grant: higher.grant,
          record: higher.record,
          ...(higher.promotionCertificate ? { promotionCertificate: higher.promotionCertificate } : {}),
        };
      }
    }
    return {
      type: "register.result",
      requestId: frame.requestId,
      ...checked,
      ...(higherRegistration ? { higherRegistration } : {}),
    };
  }
  if (!validHostAccessToken(frame.accessToken, checked.data, now)) {
    return { type: "register.result", requestId: frame.requestId, ok: false, error: { code: "unauthorized", message: "valid host access credential required" } };
  }
  const { authorityFingerprint, authorityPublicKey, grant, record, recordHash } = checked.data;
  const claimKey = hostBindingKey(authorityFingerprint, record.payload.serverId, record.payload.hostId);
  if (pendingRegistrationClaims.has(claimKey)) {
    return { type: "register.result", requestId: frame.requestId, ok: false, error: { code: "conflict", message: "host registration already pending" } };
  }
  const pending: PendingRegistration = {
    requestId: frame.requestId,
    challengeId: randomUUID(),
    nonce: randomBytes(32).toString("base64url"),
    recordHash,
    createdAt: now,
    expiresAt: now + REGISTRATION_CHALLENGE_TTL_MS,
    claimKey,
    authorityFingerprint,
    authorityPublicKey,
    record,
    grant,
    ...(frame.promotionCertificate ? { promotionCertificate: frame.promotionCertificate } : {}),
  };
  pendingRegistrations.set(ws, pending);
  pendingRegistrationClaims.set(claimKey, ws);
  return {
    type: "register.challenge",
    requestId: pending.requestId,
    challengeId: pending.challengeId,
    nonce: pending.nonce,
    recordHash: pending.recordHash,
    expiresAt: pending.expiresAt,
  };
}

type RegisterProofFrame = {
  type: "register.prove";
  requestId: string;
  challengeId: string;
  proof: unknown;
};

function decodeCanonicalBase64Url(value: unknown, expectedBytes: number): Buffer | null {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== expectedBytes || decoded.toString("base64url") !== value) return null;
  return decoded;
}

function validRegistrationProof(pending: PendingRegistration, proof: unknown, now: number): boolean {
  if (!proof || typeof proof !== "object" || Array.isArray(proof)) return false;
  const signed = proof as { payload?: unknown; publicKey?: unknown; signature?: unknown };
  if (signed.publicKey !== pending.grant.payload.devicePublicKey) return false;
  const publicKey = decodeCanonicalBase64Url(signed.publicKey, 32);
  const signature = decodeCanonicalBase64Url(signed.signature, 64);
  if (!publicKey || !signature || !signed.payload || typeof signed.payload !== "object" || Array.isArray(signed.payload)) return false;
  const payload = signed.payload as Record<string, unknown>;
  const expectedKeys = [
    "challengeId",
    "expiresAt",
    "grantId",
    "hostId",
    "issuedAt",
    "nonce",
    "recordHash",
    "serverId",
    "version",
  ];
  if (Object.keys(payload).sort().join("\0") !== expectedKeys.sort().join("\0")) return false;
  if (
    payload.version !== 1 ||
    payload.serverId !== pending.record.payload.serverId ||
    payload.hostId !== pending.record.payload.hostId ||
    payload.grantId !== pending.grant.payload.grantId ||
    payload.recordHash !== pending.recordHash ||
    payload.challengeId !== pending.challengeId ||
    payload.nonce !== pending.nonce ||
    typeof payload.issuedAt !== "number" ||
    !Number.isSafeInteger(payload.issuedAt) ||
    typeof payload.expiresAt !== "number" ||
    !Number.isSafeInteger(payload.expiresAt) ||
    payload.issuedAt < pending.createdAt - REGISTRATION_PROOF_CLOCK_SKEW_MS ||
    payload.issuedAt > now + REGISTRATION_PROOF_CLOCK_SKEW_MS ||
    payload.expiresAt <= payload.issuedAt ||
    payload.expiresAt > pending.expiresAt ||
    payload.expiresAt <= now
  ) return false;
  return verifyCanonicalPayload(publicKey, REGISTRATION_PROOF_DOMAIN, payload, signature);
}

function appendStateEvent(event: unknown): void {
  const stateFile = process.env.JC_RENDEZVOUS_STATE_FILE;
  if (!stateFile) {
    if (process.env.NODE_ENV === "production") throw new Error("durable rendezvous state is required in production");
    return;
  }
  if (existsSync(stateFile)) assertSecureStateFile(stateFile);
  const body = { version: 1, seq: durableStateSeq + 1, previousHash: durableStateHash, event };
  const envelope = { ...body, hash: sha256Hex(canonicalJson(body)) };
  const fd = openSync(stateFile, "a", 0o600);
  try {
    writeSync(fd, `${JSON.stringify(envelope)}\n`);
    fsyncSync(fd);
    durableStateSeq = body.seq;
    durableStateHash = envelope.hash;
  } finally {
    closeSync(fd);
  }
}

function maybeCompactState(): void {
  const stateFile = process.env.JC_RENDEZVOUS_STATE_FILE;
  if (!stateFile || !existsSync(stateFile)) return;
  const threshold = Math.max(1, Number(process.env.JC_RENDEZVOUS_COMPACT_BYTES ?? 4 * 1024 * 1024));
  if (statSync(stateFile).size < threshold && durableStateSeq < 10_000) return;
  const now = Date.now();
  cleanup(now);
  const events: unknown[] = [];
  // Revocations must be replayed before their generation-floored high-water marks. Reversing
  // this order makes a valid revoke->compact checkpoint reject itself after restart.
  for (const revocations of revokedGrants.values()) for (const value of revocations.values()) {
    events.push({ type: "revocation", authorityPublicKey: value.authorityPublicKey, revocation: value.revocation });
  }
  for (const consumed of consumedPairingTokens.values()) events.push({ type: "pairingConsumed", ...consumed });
  for (const marks of highWaterMarks.values()) for (const mark of marks.values()) events.push({ type: "highWater", ...mark });
  for (const vote of promotionVotes.values()) events.push({ type: "promotionVote", ...vote });
  for (const [key, access] of hostAccess) if (access.expiresAt > now) events.push({ type: "hostAccess", key, ...access });
  const lines: string[] = [];
  let seq = 0;
  let previousHash: string | null = null;
  for (const event of events) {
    const body = { version: 1, seq: ++seq, previousHash, event };
    const hash = sha256Hex(canonicalJson(body));
    lines.push(JSON.stringify({ ...body, hash }));
    previousHash = hash;
  }
  const temporary = `${stateFile}.${process.pid}.compact`;
  writeFileSync(temporary, lines.length > 0 ? `${lines.join("\n")}\n` : "", { mode: 0o600 });
  const fd = openSync(temporary, "r");
  try { fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(temporary, stateFile);
  const directory = openSync(dirname(stateFile), "r");
  try { fsyncSync(directory); } finally { closeSync(directory); }
  durableStateSeq = seq;
  durableStateHash = previousHash;
}

function assertSecureStateFile(path: string): void {
  if (process.platform === "win32") return;
  const stat = statSync(path);
  if ((stat.mode & 0o077) !== 0) throw new Error("rendezvous state file must not be accessible by group/others");
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new Error("rendezvous state file must be owned by the bridge process user");
  }
}

function applyHighWaterMark(mark: HighWaterMark): boolean {
  const scope = authorityScope(mark.authorityFingerprint, mark.serverId);
  const scopeMarks = highWaterMarks.get(scope) ?? new Map<string, HighWaterMark>();
  const current = scopeMarks.get(mark.hostId);
  if (current) {
    if (mark.grantGeneration < current.grantGeneration) return false;
    if (mark.grantGeneration === current.grantGeneration && mark.grantId !== current.grantId) return false;
    if (mark.epoch < current.epoch || mark.recordSeq <= current.recordSeq) return false;
  }
  scopeMarks.set(mark.hostId, mark);
  highWaterMarks.set(scope, scopeMarks);
  return true;
}

function applyPromotionVote(vote: PromotionVote): boolean {
  const key = promotionVoteKey(vote.authorityFingerprint, vote.serverId, vote.electionEpoch);
  const current = promotionVotes.get(key);
  if (current) {
    return current.candidateHostId === vote.candidateHostId
      && current.primaryHostId === vote.primaryHostId
      && current.primaryRecordHash === vote.primaryRecordHash;
  }
  promotionVotes.set(key, vote);
  return true;
}

function durableEntryCount(): number {
  return promotionVotes.size
    + consumedPairingTokens.size
    + hostAccess.size
    + [...highWaterMarks.values()].reduce((sum, entries) => sum + entries.size, 0)
    + [...revokedGrants.values()].reduce((sum, entries) => sum + entries.size, 0);
}

function commitRegistration(ws: WebSocket, candidate: VerifiedRegistration, now: number):
  | { ok: true; data: { ttlMs: number; expiresAt: number; recordHash: string; epoch: number; role: "primary" | "replica" } }
  | RendezvousError {
  const { authorityFingerprint, authorityPublicKey, grant, record, recordHash } = candidate;
  const mark: HighWaterMark = {
    authorityFingerprint,
    serverId: record.payload.serverId,
    hostId: record.payload.hostId,
    epoch: record.payload.epoch,
    recordSeq: record.payload.recordSeq,
    recordHash,
    grantId: grant.payload.grantId,
    grantGeneration: grant.payload.generation,
    role: record.payload.role,
  };
  const current = highWaterMarks.get(authorityScope(mark.authorityFingerprint, mark.serverId))?.get(mark.hostId);
  const idempotent = current?.recordHash === mark.recordHash
    && current.recordSeq === mark.recordSeq
    && current.epoch === mark.epoch
    && current.grantId === mark.grantId;
  if (!idempotent) {
    const totalMarks = [...highWaterMarks.values()].reduce((sum, entries) => sum + entries.size, 0);
    if (!current && totalMarks >= MAX_DURABLE_ENTRIES) {
      return { ok: false, error: { code: "unavailable", message: "host ledger capacity reached" } };
    }
    try {
      appendStateEvent({ type: "highWater", ...mark });
    } catch {
      return { ok: false, error: { code: "unavailable", message: "registration state could not be persisted" } };
    }
    if (!applyHighWaterMark(mark)) {
      return { ok: false, error: { code: "conflict", message: "registration high-water mark changed" } };
    }
    maybeCompactState();
  }
  const scope = authorityScope(authorityFingerprint, record.payload.serverId);
  const hosts = records.get(scope) ?? new Map<string, StoredRecord>();
  const expiresAt = Math.min(record.payload.expiresAt, now + MAX_TTL_MS);
  hosts.set(record.payload.hostId, {
    record,
    grant,
    authorityPublicKey,
    authorityFingerprint,
    expiresAt,
    ...(candidate.promotionCertificate ? { promotionCertificate: candidate.promotionCertificate } : {}),
  });
  records.set(scope, hosts);

  const bindingKey = hostBindingKey(authorityFingerprint, record.payload.serverId, record.payload.hostId);
  unbindSocket(ws);
  const previousSocket = hostSockets.get(bindingKey);
  if (previousSocket && previousSocket !== ws) unbindSocket(previousSocket);
  const binding = {
    authorityFingerprint,
    serverId: record.payload.serverId,
    hostId: record.payload.hostId,
    grantId: grant.payload.grantId,
    grantGeneration: grant.payload.generation,
    authorizationExpiresAt: Math.min(expiresAt, grant.payload.expiresAt),
  };
  socketHosts.set(ws, binding);
  hostSockets.set(bindingKey, ws);
  hostDisconnectedAt.delete(bindingKey);
  if (record.payload.role === "primary") {
    for (const [peer, peerBinding] of socketHosts) {
      if (peer !== ws && peer.readyState === WebSocket.OPEN
        && peerBinding.authorityFingerprint === authorityFingerprint
        && peerBinding.serverId === record.payload.serverId) {
        reply(peer, {
          type: "host.epoch",
          registration: {
            authorityPublicKey,
            grant,
            record,
            ...(candidate.promotionCertificate ? { promotionCertificate: candidate.promotionCertificate } : {}),
          },
        });
      }
    }
  }
  return {
    ok: true,
    data: {
      ttlMs: expiresAt - now,
      expiresAt,
      recordHash,
      epoch: record.payload.epoch,
      role: record.payload.role,
    },
  };
}

function proveRegistration(ws: WebSocket, frame: RegisterProofFrame, now = Date.now()): unknown {
  const pending = pendingRegistrations.get(ws);
  if (!pending) {
    return { type: "register.result", requestId: frame.requestId, ok: false, error: { code: "unauthorized", message: "registration challenge required" } };
  }
  clearPendingRegistration(ws);
  if (frame.requestId !== pending.requestId || frame.challengeId !== pending.challengeId) {
    return { type: "register.result", requestId: frame.requestId, ok: false, error: { code: "unauthorized", message: "registration challenge mismatch" } };
  }
  if (pending.expiresAt <= now || !validRegistrationProof(pending, frame.proof, now)) {
    return { type: "register.result", requestId: frame.requestId, ok: false, error: { code: "unauthorized", message: "invalid or expired registration proof" } };
  }
  const checked = validateRegistration({
    authorityPublicKey: pending.authorityPublicKey,
    grant: pending.grant,
    record: pending.record,
    promotionCertificate: pending.promotionCertificate,
  }, now);
  if (!checked.ok) return { type: "register.result", requestId: frame.requestId, ...checked };
  if (checked.data.recordHash !== pending.recordHash) {
    return { type: "register.result", requestId: frame.requestId, ok: false, error: { code: "unauthorized", message: "registration transcript mismatch" } };
  }
  return { type: "register.result", requestId: frame.requestId, ...commitRegistration(ws, checked.data, now) };
}

type RevokeFrame = {
  type: "revoke";
  authorityPublicKey: string;
  revocation: unknown;
};

function applyRevocation(
  authorityFingerprint: string,
  authorityPublicKey: string,
  revocation: SignedHostGrantRevocation,
): void {
  const { serverId, grantId, revokedAt, generation } = revocation.payload;
  const scope = authorityScope(authorityFingerprint, serverId);
  const serverRevocations = revokedGrants.get(scope) ?? new Map<string, RevocationMark>();
  serverRevocations.set(grantId, { revokedAt, generation, authorityPublicKey, revocation });
  revokedGrants.set(scope, serverRevocations);

  const hosts = records.get(scope);
  if (hosts) {
    for (const [hostId, entry] of hosts) {
      if (entry.grant.payload.grantId === grantId && entry.grant.payload.generation <= generation) hosts.delete(hostId);
    }
  }
  const scopeMarks = highWaterMarks.get(scope);
  if (scopeMarks) {
    for (const [hostId, mark] of scopeMarks) {
      if (mark.grantId === grantId && mark.grantGeneration < generation) {
        scopeMarks.set(hostId, { ...mark, grantGeneration: generation });
      }
    }
  }
  for (const [ws, binding] of socketHosts) {
    if (
      binding.authorityFingerprint === authorityFingerprint &&
      binding.serverId === serverId &&
      binding.grantId === grantId &&
      binding.grantGeneration <= generation
    ) unbindSocket(ws);
  }
}

function revoke(frame: RevokeFrame, persist = true): unknown {
  const parsed = verifySignedHostGrantRevocation(frame.revocation, frame.authorityPublicKey);
  if (!parsed) {
    return { ok: false, error: { code: "unauthorized", message: "invalid grant revocation" } };
  }
  const { serverId, grantId, revokedAt, generation } = parsed.payload;
  const fingerprint = publicKeyFingerprint(frame.authorityPublicKey);
  if (!fingerprint) return { ok: false, error: { code: "invalid_input", message: "invalid authority key" } };
  const scope = authorityScope(fingerprint, serverId);
  const previous = revokedGrants.get(scope)?.get(grantId);
  if (previous && generation === previous.generation && revokedAt === previous.revokedAt
    && previous.authorityPublicKey === frame.authorityPublicKey
    && canonicalJson(previous.revocation) === canonicalJson(parsed)) {
    return { ok: true, data: { grantId, revokedAt, generation } };
  }
  if (previous && (generation < previous.generation || (generation === previous.generation && revokedAt <= previous.revokedAt))) {
    return { ok: false, error: { code: "conflict", message: "stale revocation" } };
  }
  const acceptedGeneration = Math.max(
    0,
    ...[...(highWaterMarks.get(scope)?.values() ?? [])]
      .filter((mark) => mark.grantId === grantId)
      .map((mark) => mark.grantGeneration),
  );
  if (generation <= acceptedGeneration) {
    return { ok: false, error: { code: "conflict", message: "stale revocation generation" } };
  }
  if (persist) {
    const totalRevocations = [...revokedGrants.values()].reduce((sum, entries) => sum + entries.size, 0);
    if (!previous && totalRevocations >= MAX_DURABLE_ENTRIES) {
      return { ok: false, error: { code: "unavailable", message: "revocation ledger capacity reached" } };
    }
    try {
      appendStateEvent({ type: "revocation", authorityPublicKey: frame.authorityPublicKey, revocation: parsed });
    } catch {
      return { ok: false, error: { code: "unavailable", message: "revocation state could not be persisted" } };
    }
  }
  applyRevocation(fingerprint, frame.authorityPublicKey, parsed);
  if (persist) maybeCompactState();
  return { ok: true, data: { grantId, revokedAt, generation } };
}

function persistedHighWater(value: unknown): HighWaterMark | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const mark = value as Partial<HighWaterMark>;
  if (
    typeof mark.authorityFingerprint !== "string" ||
    !AuthorityFingerprintSchema.safeParse(mark.authorityFingerprint).success ||
    typeof mark.serverId !== "string" ||
    typeof mark.hostId !== "string" ||
    mark.hostId.length < 1 ||
    mark.hostId.length > 128 ||
    typeof mark.epoch !== "number" ||
    !Number.isSafeInteger(mark.epoch) ||
    mark.epoch < 0 ||
    typeof mark.recordSeq !== "number" ||
    !Number.isSafeInteger(mark.recordSeq) ||
    mark.recordSeq < 1 ||
    typeof mark.recordHash !== "string" ||
    !/^[0-9a-f]{64}$/.test(mark.recordHash) ||
    typeof mark.grantId !== "string" ||
    typeof mark.grantGeneration !== "number" ||
    !Number.isSafeInteger(mark.grantGeneration) ||
    mark.grantGeneration < 1
  ) return null;
  return mark as HighWaterMark;
}

function persistedPromotionVote(value: unknown): PromotionVote | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const vote = value as Partial<PromotionVote>;
  if (
    typeof vote.authorityFingerprint !== "string" ||
    !AuthorityFingerprintSchema.safeParse(vote.authorityFingerprint).success ||
    typeof vote.serverId !== "string" ||
    vote.serverId.length < 1 || vote.serverId.length > 128 ||
    typeof vote.electionEpoch !== "number" ||
    !Number.isSafeInteger(vote.electionEpoch) || vote.electionEpoch < 1 ||
    typeof vote.candidateHostId !== "string" ||
    vote.candidateHostId.length < 1 || vote.candidateHostId.length > 128 ||
    typeof vote.primaryHostId !== "string" ||
    vote.primaryHostId.length < 1 || vote.primaryHostId.length > 128 ||
    typeof vote.primaryRecordHash !== "string" ||
    !/^[0-9a-f]{64}$/.test(vote.primaryRecordHash) ||
    typeof vote.grantedAt !== "number" ||
    !Number.isSafeInteger(vote.grantedAt) || vote.grantedAt < 1
  ) return null;
  return vote as PromotionVote;
}

export function loadRendezvousState(): void {
  const stateFile = process.env.JC_RENDEZVOUS_STATE_FILE;
  if (!stateFile || !existsSync(stateFile)) return;
  assertSecureStateFile(stateFile);
  const raw = readFileSync(stateFile, "utf8");
  const lines = raw.split("\n");
  // A torn final append is recoverable; corruption anywhere before the tail is fatal.
  if (!raw.endsWith("\n")) {
    lines.pop();
    truncateSync(stateFile, Math.max(0, raw.lastIndexOf("\n") + 1));
  }
  durableStateSeq = 0;
  durableStateHash = null;
  for (const [index, line] of lines.entries()) {
    if (!line.trim()) continue;
    try {
      const envelope = JSON.parse(line) as Record<string, unknown>;
      const body = {
        version: envelope.version,
        seq: envelope.seq,
        previousHash: envelope.previousHash,
        event: envelope.event,
      };
      if (body.version !== 1 || body.seq !== durableStateSeq + 1
        || body.previousHash !== durableStateHash || envelope.hash !== sha256Hex(canonicalJson(body))
        || !body.event || typeof body.event !== "object" || Array.isArray(body.event)) {
        throw new Error("invalid durable state hash chain");
      }
      const stored = body.event as Record<string, unknown>;
      if (stored.type === "highWater") {
        const mark = persistedHighWater(stored);
        if (!mark || !applyHighWaterMark(mark)) throw new Error("invalid persisted high-water mark");
      } else if (stored.type === "promotionVote") {
        const vote = persistedPromotionVote(stored);
        if (!vote || !applyPromotionVote(vote)) throw new Error("invalid persisted promotion vote");
      } else if (stored.type === "revocation" || (stored.authorityPublicKey && stored.revocation)) {
        const applied = revoke({
          type: "revoke",
          authorityPublicKey: String(stored.authorityPublicKey ?? ""),
          revocation: stored.revocation,
        }, false) as { ok?: boolean };
        if (!applied.ok) throw new Error("invalid persisted revocation");
      } else if (stored.type === "hostAccess") {
        if (typeof stored.key !== "string" || typeof stored.proofId !== "string"
          || typeof stored.tokenHash !== "string" || !/^[0-9a-f]{64}$/.test(stored.tokenHash)
          || typeof stored.grantId !== "string" || typeof stored.generation !== "number"
          || !Number.isSafeInteger(stored.generation) || typeof stored.expiresAt !== "number"
          || !Number.isSafeInteger(stored.expiresAt)) throw new Error("malformed persisted host access");
        consumedAccessProofs.set(stored.proofId, stored.expiresAt);
        const storedKey = /:(?:registration|witness)$/.test(stored.key)
          ? stored.key
          : `${stored.key}:registration`;
        hostAccess.set(storedKey, {
          tokenHash: stored.tokenHash,
          grantId: stored.grantId,
          generation: stored.generation,
          expiresAt: stored.expiresAt,
          proofId: stored.proofId,
        });
      } else if (stored.type === "pairingConsumed") {
        if (typeof stored.tokenHash !== "string" || !/^[0-9a-f]{64}$/.test(stored.tokenHash)
          || typeof stored.bridgeId !== "string" || typeof stored.authorityFingerprint !== "string"
          || !AuthorityFingerprintSchema.safeParse(stored.authorityFingerprint).success
          || typeof stored.serverId !== "string" || typeof stored.hostId !== "string"
          || !Number.isSafeInteger(stored.consumedAt) || !Number.isSafeInteger(stored.expiresAt)) {
          throw new Error("malformed persisted pairing consumption");
        }
        consumedPairingTokens.set(stored.tokenHash, stored as unknown as PairingConsumption);
      } else {
        throw new Error("unknown persisted state event");
      }
      durableStateSeq = body.seq as number;
      durableStateHash = envelope.hash as string;
    } catch (error) {
      throw new Error(`rendezvous durable state corruption at record ${index + 1}: ${(error as Error).message}`);
    }
  }
}

type ResolveFrame = {
  type: "resolve";
  serverId: string;
  authorityFingerprint: string;
};

function resolve(frame: ResolveFrame, now = Date.now()): unknown {
  if (!AuthorityFingerprintSchema.safeParse(frame.authorityFingerprint).success) {
    return { ok: false, error: { code: "invalid_input", message: "authorityFingerprint required" } };
  }
  cleanup(now);
  const scope = authorityScope(frame.authorityFingerprint, frame.serverId);
  const hosts = [...(records.get(scope)?.values() ?? [])]
    .filter((entry) => entry.authorityFingerprint === frame.authorityFingerprint.toLowerCase() && entry.expiresAt > now)
    .sort((a, b) => b.record.payload.epoch - a.record.payload.epoch || Number(a.record.payload.role !== "primary") - Number(b.record.payload.role !== "primary"));
  const revocations = [...(revokedGrants.get(scope)?.values() ?? [])]
    .sort((a, b) => b.generation - a.generation || b.revokedAt - a.revokedAt);
  if (hosts.length === 0 && revocations.length === 0) {
    return { ok: false, error: { code: "not_found", message: "no valid host record" } };
  }
  return {
    ok: true,
    data: {
      records: hosts.map((entry) => ({
        record: entry.record,
        grant: entry.grant,
        authorityPublicKey: entry.authorityPublicKey,
      })),
      revocations: revocations.map((entry) => ({
        authorityPublicKey: entry.authorityPublicKey,
        revocation: entry.revocation,
      })),
      resolvedAt: now,
    },
  };
}

export function handleRendezvousFrame(frame: unknown, now = Date.now()): unknown {
  if (!frame || typeof frame !== "object") return { ok: false, error: { code: "invalid_input", message: "malformed frame" } };
  const type = (frame as { type?: string }).type;
  if (type === "revoke") return revoke(frame as RevokeFrame);
  if (type === "resolve") return resolve(frame as ResolveFrame, now);
  return { ok: false, error: { code: "invalid_input", message: "unknown type" } };
}

export function resetRendezvousState(): void {
  records.clear();
  revokedGrants.clear();
  highWaterMarks.clear();
  rateBuckets.clear();
  hostSockets.clear();
  signalingSessions.clear();
  socketHosts.clear();
  pendingRegistrations.clear();
  pendingRegistrationClaims.clear();
  hostAccess.clear();
  consumedAccessProofs.clear();
  hostDisconnectedAt.clear();
  consumedWitnessNonces.clear();
  consumedPairingTokens.clear();
  promotionVotes.clear();
  socketClientIps.clear();
  durableStateSeq = 0;
  durableStateHash = null;
  bridgeSigningMaterial = null;
}

function readSecret(path: string | undefined): string | null {
  if (!path) return null;
  try {
    const value = readFileSync(path, "utf8").trim();
    return value.length >= 32 ? value : null;
  } catch {
    return null;
  }
}

export function issueTurnCredentials(input: {
  serverId: string;
  hostId: string;
  subject: string;
  ttlSeconds?: number;
}, now = Date.now(), secret = readSecret(process.env.JC_TURN_SHARED_SECRET_FILE)): unknown {
  if (!secret) return { ok: false, error: { code: "unavailable", message: "TURN issuer is not configured" } };
  const ttlSeconds = Math.max(60, Math.min(MAX_TURN_TTL_SECONDS, input.ttlSeconds ?? 300));
  const expiresAtSeconds = Math.floor(now / 1000) + ttlSeconds;
  const opaque = sha256Hex(`${input.serverId}\0${input.hostId}\0${input.subject}\0${randomBytes(16).toString("hex")}`).slice(0, 24);
  const username = `${expiresAtSeconds}:${opaque}`;
  const credential = createHmac("sha1", secret).update(username).digest("base64");
  const domain = process.env.JC_BRIDGE_DOMAIN ?? "localhost";
  return {
    ok: true,
    data: {
      username,
      credential,
      credentialType: "password",
      expiresAt: expiresAtSeconds * 1000,
      urls: [
        `stun:${domain}:${process.env.JC_TURN_PORT ?? 3478}`,
        `turn:${domain}:${process.env.JC_TURN_PORT ?? 3478}?transport=udp`,
        `turns:${domain}:${process.env.JC_TURN_TLS_PORT ?? 5349}?transport=tcp`,
      ],
    },
  };
}

function witnessPrimary(frame: Record<string, unknown>, now = Date.now()): unknown {
  const requestId = typeof frame.requestId === "string" ? frame.requestId : "";
  const denied = () => ({
    type: "witness.primary.result",
    requestId,
    ok: false,
    error: { code: "unauthorized", message: "valid pairing and active promote grant proof required" },
  });
  if (!requestId) return denied();
  const authorityPublicKey = typeof frame.authorityPublicKey === "string" ? frame.authorityPublicKey : "";
  const grant = verifySignedHostGrant(frame.grant, authorityPublicKey, now);
  const proof = frame.proof as { payload?: Record<string, unknown>; publicKey?: unknown; signature?: unknown } | undefined;
  if (!grant || !grant.payload.capabilities.includes("promote") || !proof?.payload) return denied();
  const authorityFingerprint = publicKeyFingerprint(authorityPublicKey);
  const payload = proof.payload;
  const publicKey = decodeCanonicalBase64Url(proof.publicKey, 32);
  const signature = decodeCanonicalBase64Url(proof.signature, 64);
  const expectedKeys = ["expiresAt", "grantId", "issuedAt", "nonce", "primaryHostId", "replicaHostId", "serverId", "version"];
  const scope = authorityFingerprint ? authorityScope(authorityFingerprint, grant.payload.serverId) : "";
  const revocation = revokedGrants.get(scope)?.get(grant.payload.grantId);
  const access = authorityFingerprint
    ? hostAccess.get(hostAccessKey(authorityFingerprint, grant.payload.serverId, grant.payload.hostId, "witness"))
    : undefined;
  const suppliedAccessHash = typeof frame.accessToken === "string"
    ? createHash("sha256").update(frame.accessToken).digest("hex")
    : "";
  if (!authorityFingerprint || !publicKey || !signature
    || proof.publicKey !== grant.payload.devicePublicKey
    || Object.keys(payload).sort().join("\0") !== expectedKeys.sort().join("\0")
    || payload.version !== 1
    || payload.serverId !== grant.payload.serverId
    || payload.grantId !== grant.payload.grantId
    || payload.replicaHostId !== grant.payload.hostId
    || typeof payload.primaryHostId !== "string"
    || typeof payload.nonce !== "string" || consumedWitnessNonces.has(payload.nonce)
    || typeof payload.issuedAt !== "number" || !Number.isSafeInteger(payload.issuedAt)
    || typeof payload.expiresAt !== "number" || !Number.isSafeInteger(payload.expiresAt)
    || Number(payload.issuedAt) < now - 10_000
    || Number(payload.issuedAt) > now + REGISTRATION_PROOF_CLOCK_SKEW_MS
    || Number(payload.expiresAt) <= now
    || Number(payload.expiresAt) > Number(payload.issuedAt) + 30_000
    || (revocation && grant.payload.generation <= revocation.generation)
    || !access || access.expiresAt <= now || access.grantId !== grant.payload.grantId
    || access.generation !== grant.payload.generation || access.tokenHash !== suppliedAccessHash
    || !verifyCanonicalPayload(publicKey, REPLICA_WITNESS_DOMAIN, payload, signature)) return denied();
  const knownPrimary = [...(highWaterMarks.get(scope)?.values() ?? [])]
    .filter((mark) => mark.role === "primary")
    .sort((a, b) => b.epoch - a.epoch || b.recordSeq - a.recordSeq)[0];
  if (!knownPrimary || payload.primaryHostId !== knownPrimary.hostId) return denied();
  consumedWitnessNonces.add(String(payload.nonce));
  const primaryKey = hostBindingKey(authorityFingerprint, grant.payload.serverId, knownPrimary.hostId);
  const primary = hostSockets.get(primaryKey);
  const online = primary?.readyState === WebSocket.OPEN;
  const disconnectedAt = hostDisconnectedAt.get(primaryKey);
  // Production witness grace is deliberately longer than JanjaNode's maximum 15s self-fence
  // window, so a compliant old primary becomes read-only before absence can be attested.
  const minimumGrace = process.env.NODE_ENV === "production" ? 20_000 : 10;
  const absenceGraceMs = Math.max(minimumGrace, Number(process.env.JC_WITNESS_ABSENCE_GRACE_MS ?? 30_000));
  // A missing socket is not itself proof that the old writer has fenced. During the grace
  // period (or when no authenticated disconnect was observed) the bridge vetoes promotion.
  const primaryOnline = online || !disconnectedAt || now - disconnectedAt < absenceGraceMs;
  const signing = bridgeSigningMaterial ?? loadBridgeSigningMaterial();
  if (!signing) {
    return {
      type: "witness.primary.result",
      requestId,
      ok: false,
      error: { code: "unavailable", message: "bridge witness signing is unavailable" },
    };
  }
  bridgeSigningMaterial = signing;
  const observedAt = now;
  const witness = createSignedBridgeWitness({
    version: 1,
    bridgeId: signing.descriptor.payload.bridgeId,
    requestId,
    serverId: grant.payload.serverId,
    replicaHostId: grant.payload.hostId,
    primaryHostId: knownPrimary.hostId,
    primaryRecordHash: knownPrimary.recordHash,
    primaryEpoch: knownPrimary.epoch,
    primaryOnline,
    observedAt,
    expiresAt: observedAt + 5_000,
  }, signing.seed);
  return {
    type: "witness.primary.result",
    requestId,
    ok: true,
    data: { witness },
  };
}

function claimPromotionVote(frame: Record<string, unknown>, now = Date.now()): unknown {
  const requestId = typeof frame.requestId === "string" ? frame.requestId : "";
  const reject = (code: string, message: string) => ({
    type: "promotion.claim.result",
    requestId,
    ok: false,
    error: { code, message },
  });
  if (!requestId) return reject("invalid_input", "requestId required");
  const signing = bridgeSigningMaterial ?? loadBridgeSigningMaterial();
  if (!signing) return reject("unavailable", "bridge promotion signing is unavailable");
  bridgeSigningMaterial = signing;
  const witness = verifySignedBridgeWitness(frame.witness, signing.descriptor, now);
  if (!witness || witness.payload.bridgeId !== signing.descriptor.payload.bridgeId
    || witness.payload.primaryOnline !== false) {
    return reject("unauthorized", "fresh bridge absence witness required");
  }
  const payload = witness.payload;
  const authorityFingerprint = String(frame.authorityFingerprint ?? "").toLowerCase();
  if (!AuthorityFingerprintSchema.safeParse(authorityFingerprint).success) {
    return reject("invalid_input", "authorityFingerprint required");
  }
  const scope = authorityScope(authorityFingerprint, payload.serverId);
  const electionEpoch = payload.primaryEpoch + 1;
  const key = promotionVoteKey(authorityFingerprint, payload.serverId, electionEpoch);
  const existing = promotionVotes.get(key);
  if (existing && (existing.candidateHostId !== payload.replicaHostId
    || existing.primaryHostId !== payload.primaryHostId
    || existing.primaryRecordHash !== payload.primaryRecordHash)) {
    return reject("conflict", "bridge already voted for another candidate in this election epoch");
  }

  const knownPrimary = [...(highWaterMarks.get(scope)?.values() ?? [])]
    .filter((mark) => mark.role === "primary")
    .sort((left, right) => right.epoch - left.epoch || right.recordSeq - left.recordSeq)[0];
  if (!knownPrimary || knownPrimary.hostId !== payload.primaryHostId
    || knownPrimary.recordHash !== payload.primaryRecordHash
    || knownPrimary.epoch !== payload.primaryEpoch) {
    return reject("conflict", "primary checkpoint changed before promotion vote");
  }
  const primaryKey = hostBindingKey(authorityFingerprint, payload.serverId, payload.primaryHostId);
  const primary = hostSockets.get(primaryKey);
  const disconnectedAt = hostDisconnectedAt.get(primaryKey);
  const minimumGrace = process.env.NODE_ENV === "production" ? 20_000 : 10;
  const absenceGraceMs = Math.max(minimumGrace, Number(process.env.JC_WITNESS_ABSENCE_GRACE_MS ?? 30_000));
  if (primary?.readyState === WebSocket.OPEN || !disconnectedAt || now - disconnectedAt < absenceGraceMs) {
    return reject("conflict", "primary is online or its fencing grace has not elapsed");
  }

  const vote: PromotionVote = existing ?? {
    authorityFingerprint,
    serverId: payload.serverId,
    electionEpoch,
    candidateHostId: payload.replicaHostId,
    primaryHostId: payload.primaryHostId,
    primaryRecordHash: payload.primaryRecordHash,
    grantedAt: now,
  };
  if (!existing) {
    if (durableEntryCount() >= MAX_DURABLE_ENTRIES) {
      return reject("unavailable", "promotion vote ledger capacity reached");
    }
    try {
      appendStateEvent({ type: "promotionVote", ...vote });
    } catch {
      return reject("unavailable", "promotion vote could not be persisted");
    }
    if (!applyPromotionVote(vote)) {
      return reject("conflict", "promotion vote changed concurrently");
    }
    maybeCompactState();
  }

  const receiptPayload = {
    version: 1,
    bridgeId: signing.descriptor.payload.bridgeId,
    requestId,
    serverId: vote.serverId,
    candidateHostId: vote.candidateHostId,
    primaryHostId: vote.primaryHostId,
    primaryRecordHash: vote.primaryRecordHash,
    primaryEpoch: payload.primaryEpoch,
    electionEpoch: vote.electionEpoch,
    voteGrantedAt: vote.grantedAt,
    issuedAt: now,
    expiresAt: now + 24 * 3600_000,
  };
  return {
    type: "promotion.claim.result",
    requestId,
    ok: true,
    data: {
      receipt: {
        payload: receiptPayload,
        publicKey: signing.descriptor.publicKey,
        signature: signCanonicalPayload(signing.seed, PROMOTION_VOTE_DOMAIN, receiptPayload).toString("base64url"),
      },
    },
  };
}

type SignalPayload = Record<string, unknown> & { type: string };

function signalingPayload(frame: Record<string, unknown>): SignalPayload | null {
  if (!frame.payload || typeof frame.payload !== "object" || Array.isArray(frame.payload)) return null;
  const payload = frame.payload as Record<string, unknown>;
  if (typeof payload.type !== "string") return null;
  return payload as SignalPayload;
}

function boundedSignalString(value: unknown, maxBytes: number): value is string {
  return typeof value === "string" && !value.includes("\0") && Buffer.byteLength(value) <= maxBytes;
}

export function isValidSignalingPayload(type: "signal.open" | "signal.relay", value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const payload = value as Record<string, unknown>;
  if (Buffer.byteLength(JSON.stringify(payload)) > MAX_SIGNAL_FRAME_BYTES) return false;
  if (payload.type === "ice.request") {
    return type === "signal.open"
      && boundedSignalString(payload.serverId, 128) && payload.serverId.length > 0
      && boundedSignalString(payload.hostId, 128) && payload.hostId.length > 0
      && !!payload.accessProof && typeof payload.accessProof === "object" && !Array.isArray(payload.accessProof);
  }
  if (payload.type === "offer" || payload.type === "answer") {
    return (payload.type === "offer" ? type === "signal.open" : type === "signal.relay")
      && boundedSignalString(payload.sdp, MAX_SIGNAL_SDP_BYTES)
      && payload.sdp.startsWith("v=0");
  }
  if (payload.type === "candidate") {
    return type === "signal.relay"
      && boundedSignalString(payload.candidate, MAX_SIGNAL_CANDIDATE_BYTES)
      && /^(?:a=)?candidate:/i.test(payload.candidate)
      && (payload.mid === undefined || (boundedSignalString(payload.mid, MAX_SIGNAL_MID_BYTES)
        && /^[A-Za-z0-9_.:-]*$/.test(payload.mid)));
  }
  if (payload.type === "ice.refresh") {
    return type === "signal.relay"
      && boundedSignalString(payload.serverId, 128) && payload.serverId.length > 0
      && boundedSignalString(payload.hostId, 128) && payload.hostId.length > 0;
  }
  if (payload.type === "ice.config") {
    return type === "signal.relay" && ["direct", "relay"].includes(String(payload.networkPrivacy));
  }
  if (payload.type === "ice.error") {
    return type === "signal.relay" && boundedSignalString(payload.code, 64) && payload.code.length > 0;
  }
  return false;
}

function relaySignal(ws: WebSocket, frame: Record<string, unknown>): unknown {
  const type = String(frame.type ?? "");
  if (!["signal.open", "signal.relay", "signal.close"].includes(type)) {
    return { ok: false, error: { code: "invalid_input", message: "unsupported signaling frame" } };
  }
  const sessionId = String(frame.sessionId ?? "");
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(sessionId)) return { ok: false, error: { code: "invalid_input", message: "invalid sessionId" } };
  if (Buffer.byteLength(JSON.stringify(frame.payload ?? null)) > MAX_SIGNAL_FRAME_BYTES) {
    return { ok: false, error: { code: "invalid_input", message: "signaling payload too large" } };
  }
  const payload = signalingPayload(frame);
  if (type === "signal.open") {
    if (!payload || !isValidSignalingPayload("signal.open", payload)) {
      return { ok: false, error: { code: "invalid_input", message: "invalid signaling open payload" } };
    }
    const serverId = String(frame.serverId ?? "");
    const authorityFingerprint = String(frame.authorityFingerprint ?? "").toLowerCase();
    const hostId = String(frame.hostId ?? "");
    if (!AuthorityFingerprintSchema.safeParse(authorityFingerprint).success) return { ok: false, error: { code: "invalid_input", message: "authority fingerprint required" } };
    const host = hostSockets.get(hostBindingKey(authorityFingerprint, serverId, hostId));
    if (!host || host.readyState !== WebSocket.OPEN) return { ok: false, error: { code: "not_found", message: "host signaling socket unavailable" } };
    const existing = signalingSessions.get(sessionId);
    if (existing) {
      if (!isSignalingSessionContinuation(existing, host, ws)) {
        return { ok: false, error: { code: "conflict", message: "signaling session already exists" } };
      }
      if (!existing.authorized || payload.type !== "offer") {
        return { ok: false, error: { code: "unauthorized", message: "authenticated ice.request required before offer" } };
      }
      existing.expiresAt = Date.now() + SIGNAL_SESSION_TTL_MS;
      reply(host, { type: "signal.open", sessionId, payload });
      return { ok: true, data: { sessionId } };
    }
    if (payload.type !== "ice.request") {
      return { ok: false, error: { code: "unauthorized", message: "ice.request required before signaling" } };
    }
    if (payload.serverId !== serverId || payload.hostId !== hostId) {
      return { ok: false, error: { code: "invalid_input", message: "ice.request host binding mismatch" } };
    }
    const capacity = signalingAdmissionReason(signalingSessions.values(), host, ws);
    if (capacity) {
      return { ok: false, error: { code: "rate_limited", message: `signaling ${capacity.replace("_", " ")} reached` } };
    }
    signalingSessions.set(sessionId, {
      host,
      client: ws,
      expiresAt: Date.now() + SIGNAL_SESSION_TTL_MS,
      authorized: false,
    });
    console.log("[janjabridge] signaling session opened");
    reply(host, { type: "signal.open", sessionId, payload });
    return { ok: true, data: { sessionId } };
  }
  const session = signalingSessions.get(sessionId);
  if (!session || ![session.host, session.client].includes(ws)) return { ok: false, error: { code: "unauthorized", message: "unknown signaling session" } };
  if (type === "signal.close") {
    closeSignalingSession(sessionId, ws, "closed");
    return { ok: true, data: { sessionId } };
  }
  if (!payload || !isValidSignalingPayload("signal.relay", payload)) {
    return { ok: false, error: { code: "invalid_input", message: "invalid signaling relay payload" } };
  }
  const fromHost = ws === session.host;
  const allowedFromHost = ["ice.config", "ice.error", "answer", "candidate"].includes(payload.type);
  const allowedFromClient = ["candidate", "ice.refresh"].includes(payload.type);
  if ((fromHost && !allowedFromHost) || (!fromHost && !allowedFromClient)) {
    return { ok: false, error: { code: "unauthorized", message: "signaling direction is not allowed" } };
  }
  if (!session.authorized && !(fromHost && ["ice.config", "ice.error"].includes(payload.type))) {
    return { ok: false, error: { code: "unauthorized", message: "authenticated ice.request required before relay" } };
  }
  if (fromHost && payload.type === "ice.config") session.authorized = true;
  const peer = ws === session.host ? session.client : session.host;
  if (peer.readyState === WebSocket.OPEN) reply(peer, { type: "signal.relay", sessionId, payload });
  session.expiresAt = Date.now() + SIGNAL_SESSION_TTL_MS;
  if (fromHost && payload.type === "ice.error") signalingSessions.delete(sessionId);
  return { ok: true, data: { sessionId } };
}

export function startRendezvous(port = PORT): WebSocketServer {
  if (process.env.NODE_ENV === "production" && !process.env.JC_RENDEZVOUS_STATE_FILE) {
    throw new Error("JC_RENDEZVOUS_STATE_FILE is required in production");
  }
  if (process.env.NODE_ENV === "production" && !pairingAdminKey()) {
    throw new Error("JC_BRIDGE_PAIRING_ADMIN_KEY_FILE is required in production");
  }
  bridgeSigningMaterial = loadBridgeSigningMaterial();
  if (process.env.NODE_ENV === "production" && !bridgeSigningMaterial) {
    throw new Error("JC_BRIDGE_DESCRIPTOR_FILE and JC_BRIDGE_SIGNING_KEY_FILE are required in production");
  }
  loadRendezvousState();
  const wss = new WebSocketServer({ port, maxPayload: MAX_RENDEZVOUS_FRAME_BYTES, perMessageDeflate: false });
  wss.on("connection", (ws, request) => {
    // ws emits WS_ERR_UNSUPPORTED_MESSAGE_LENGTH before close(1009); consume it so an
    // adversarial oversized frame cannot become an uncaught process-level exception.
    ws.on("error", () => undefined);
    socketClientIps.set(ws, resolveClientIp(
      request.socket.remoteAddress,
      request.headers["x-forwarded-for"],
      process.env.JC_TRUSTED_PROXY_IPS ?? "",
    ));
    ws.on("message", (raw, isBinary) => {
      if (isBinary) {
        ws.close(1003, "binary frames are not supported");
        return;
      }
      const frameBytes = Array.isArray(raw)
        ? raw.reduce((sum, entry) => sum + entry.length, 0)
        : raw instanceof ArrayBuffer ? raw.byteLength : raw.length;
      if (frameBytes > MAX_RENDEZVOUS_FRAME_BYTES) {
        ws.close(1009, "frame too large");
        return;
      }
      if (rateLimited(clientIp(ws))) {
        reply(ws, { ok: false, error: { code: "rate_limited", message: "too many requests" } });
        return;
      }
      try {
        const frame = JSON.parse(raw.toString()) as Record<string, unknown>;
        if (!isBoundedFrameStructure(frame)) {
          reply(ws, { ok: false, error: { code: "invalid_input", message: "frame structure exceeds limits" } });
          return;
        }
        const type = String(frame.type ?? "");
        cleanup();
        if (type === "health.ready") {
          const requestId = typeof frame.requestId === "string" ? frame.requestId : null;
          reply(ws, requestId
            ? { type: "health.ready.result", requestId, ok: true, data: { ready: true, stateLoaded: true } }
            : { type: "health.ready.result", ok: false, error: { code: "invalid_input", message: "requestId required" } });
          return;
        }
        if (type === "access.issue") {
          reply(ws, issueHostAccess(frame));
          return;
        }
        if (type === "register.cursor") {
          reply(ws, registrationCursor(frame));
          return;
        }
        if (type === "register.begin") {
          reply(ws, beginRegistration(ws, frame as RegisterBeginFrame));
          return;
        }
        if (type === "register.prove") {
          reply(ws, proveRegistration(ws, frame as RegisterProofFrame));
          return;
        }
        if (type.startsWith("signal.")) {
          reply(ws, relaySignal(ws, frame));
          return;
        }
        if (type === "turn.issue") {
          const bound = socketHosts.get(ws);
          if (!bound || bound.serverId !== frame.serverId || bound.hostId !== frame.hostId) {
            reply(ws, {
              type: "turn.issue.result",
              ...(typeof frame.requestId === "string" ? { requestId: frame.requestId } : {}),
              ok: false,
              error: { code: "unauthorized", message: "registered host socket required" },
            });
            return;
          }
          const issued = issueTurnCredentials({
            serverId: bound.serverId,
            hostId: bound.hostId,
            subject: String(frame.subject ?? "session"),
            ttlSeconds: typeof frame.ttlSeconds === "number" ? frame.ttlSeconds : undefined,
          }) as Record<string, unknown>;
          reply(ws, {
            type: "turn.issue.result",
            ...(typeof frame.requestId === "string" ? { requestId: frame.requestId } : {}),
            ...issued,
          });
          return;
        }
        if (type === "witness.primary") {
          reply(ws, witnessPrimary(frame));
          return;
        }
        if (type === "promotion.claim") {
          reply(ws, claimPromotionVote(frame));
          return;
        }
        reply(ws, handleRendezvousFrame(frame));
      } catch {
        reply(ws, { ok: false, error: { code: "invalid_input", message: "malformed frame" } });
      }
    });
    ws.on("close", () => {
      clearPendingRegistration(ws);
      unbindSocket(ws);
      socketClientIps.delete(ws);
    });
  });
  setInterval(cleanup, CLEANUP_MS).unref();
  return wss;
}

if (process.argv[1]?.endsWith("main.js")) {
  startRendezvous();
  console.log(`[janjabridge] rendezvous on ws://127.0.0.1:${PORT}/rendezvous`);
}
