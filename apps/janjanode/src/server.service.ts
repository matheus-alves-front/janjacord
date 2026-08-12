import {
  createCipheriv,
  createHash,
  createHmac,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { EventEmitter } from "node:events";
import type {
  BridgeRegistrationChallenge,
  Channel,
  HostCapability,
  HostCommand,
  HostEvent,
  HostGrantPayload,
  HostRegistration,
  MessageEnvelope,
  Role,
  SignedBridgeDescriptor,
  SignedHostGrant,
  SignedIceAccessProof,
} from "@janjacord/schemas";
import {
  ATTACHMENT_CHUNK_BYTES,
  ATTACHMENT_ENCRYPTION_OVERHEAD_BYTES,
  BridgePairingBindingSchema,
  BridgeRegistrationChallengeSchema,
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENT_CHUNK_BASE64_CHARS,
  ROLE_LEVELS,
  PermissionFlagSchema,
  SignedBridgeDescriptorSchema,
  SignedIceAccessProofSchema,
  canonicalBase64DecodedLength,
} from "@janjacord/schemas";
import { evaluatePermission, canModify, type MemberContext } from "@janjacord/permissions";
import {
  canonicalJson,
  ed25519Fingerprint,
  ed25519PublicKey,
  formatInviteKey,
  parseInviteKey,
  sha256Hex,
  signCanonicalPayload,
  verifyCanonicalPayload,
} from "@janjacord/crypto";
import {
  ReplayGuard,
  SequenceTracker,
  attachmentChunkCount,
  attachmentSha256,
  createSignedHostGrant,
  createSignedHostAuthChallenge,
  createSignedHostGrantRevocation,
  createSignedHostRecord,
  createSignedInviteV3,
  createSignedBridgeRegistrationProof,
  decodeAttachmentChunk,
  decodeEnvelope,
  formatInviteV3,
  hostRegistrationRecordHash,
  parseInviteV3,
  verifyHostRegistration,
  verifySignedHostGrant,
  verifySignedBridgeDescriptor,
} from "@janjacord/protocol";
import { browserRtcIceConfiguration, parseTemporaryTurnCredentials } from "@janjacord/networking";
import type { Store } from "./store.js";

export type HostResult<T> = { ok: true; data: T } | { ok: false; error: { code: string; message: string } };

/** Strict live-witness policy: any online observation vetoes; unavailable bridges never count absent. */
export function strictBridgeWitnessQuorum(total: number, observations: (boolean | null)[]): boolean {
  // A single bridge is not an independent failure-domain quorum. Communities configured with
  // zero or one bridge remain read-only after primary loss and require operator recovery.
  if (!Number.isInteger(total) || total < 2 || total > 3 || observations.length !== total) return false;
  if (observations.some((primaryOnline) => primaryOnline === true)) return false;
  return observations.filter((primaryOnline) => primaryOnline === false).length >= Math.floor(total / 2) + 1;
}

const PROMOTION_VOTE_DOMAIN = "janjacord.promotion-vote.v1";

function trustedBridgePublicKeys(): Map<string, string> {
  let values: unknown = [];
  try { values = JSON.parse(process.env.JC_BRIDGE_DESCRIPTORS ?? "[]"); } catch { return new Map(); }
  if (!Array.isArray(values)) return new Map();
  const trusted = new Map<string, string>();
  for (const value of values) {
    const descriptor = verifySignedBridgeDescriptor(value);
    if (descriptor) trusted.set(descriptor.payload.bridgeId, descriptor.publicKey);
  }
  return trusted;
}

export function validObservedPromotionCertificate(
  value: unknown,
  candidate: HostRegistration,
  expected: { primaryHostId: string; primaryRecordHash: string; primaryEpoch: number },
  now = Date.now(),
): boolean {
  if (!Array.isArray(value) || value.length < 2 || value.length > 3
    || candidate.record.payload.epoch !== expected.primaryEpoch + 1) return false;
  const trusted = trustedBridgePublicKeys();
  const authorityApproved = new Set(candidate.grant.payload.witnessBridgeIds ?? []);
  if (trusted.size < 2 || authorityApproved.size < 2) return false;
  const bridgeIds = new Set<string>();
  const requestIds = new Set<string>();
  const expectedKeys = [
    "bridgeId", "candidateHostId", "electionEpoch", "expiresAt", "issuedAt", "primaryEpoch",
    "primaryHostId", "primaryRecordHash", "requestId", "serverId", "version", "voteGrantedAt",
  ].sort().join("\0");
  for (const item of value) {
    if (!item || typeof item !== "object") return false;
    const receipt = item as { payload?: Record<string, unknown>; publicKey?: unknown; signature?: unknown };
    const payload = receipt.payload;
    if (!payload || Object.keys(payload).sort().join("\0") !== expectedKeys
      || typeof receipt.publicKey !== "string" || typeof receipt.signature !== "string") return false;
    const bridgeId = String(payload.bridgeId ?? "");
    const requestId = String(payload.requestId ?? "");
    const publicKey = Buffer.from(receipt.publicKey, "base64url");
    const signature = Buffer.from(receipt.signature, "base64url");
    if (!authorityApproved.has(bridgeId) || trusted.get(bridgeId) !== receipt.publicKey
      || bridgeId !== `ed25519:${ed25519Fingerprint(publicKey)}`
      || requestId.length < 1 || requestId.length > 128
      || payload.version !== 1
      || payload.serverId !== candidate.record.payload.serverId
      || payload.candidateHostId !== candidate.record.payload.hostId
      || payload.primaryHostId !== expected.primaryHostId
      || payload.primaryRecordHash !== expected.primaryRecordHash
      || payload.primaryEpoch !== expected.primaryEpoch
      || payload.electionEpoch !== candidate.record.payload.epoch
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
    bridgeIds.add(bridgeId);
    requestIds.add(requestId);
  }
  return bridgeIds.size >= 2;
}

const ok = <T>(data: T): HostResult<T> => ({ ok: true, data });
const fail = (code: string, message: string): HostResult<never> => ({ ok: false, error: { code, message } });

function x25519PublicKeyObject(rawPublicKey: Buffer) {
  if (rawPublicKey.length !== 32) throw new Error("X25519 public key must be 32 bytes");
  return createPublicKey({
    key: Buffer.concat([X25519_SPKI_PUBLIC_PREFIX, rawPublicKey]),
    format: "der",
    type: "spki",
  });
}

function sealReplicaEnrollment(
  material: ReplicaEnrollmentMaterial,
  transcript: SignedReplicaEnrollmentTranscript,
): SealedReplicaEnrollment {
  const recipientPublicKeyB64 = transcript.payload.recipientPublicKey;
  const recipientRaw = Buffer.from(recipientPublicKeyB64, "base64url");
  if (recipientRaw.length !== 32 || recipientRaw.toString("base64url") !== recipientPublicKeyB64) {
    throw new Error("invalid replica enrollment public key");
  }
  const ephemeral = generateKeyPairSync("x25519");
  const ephemeralDer = ephemeral.publicKey.export({ format: "der", type: "spki" });
  const ephemeralRaw = Buffer.from(ephemeralDer).subarray(-32);
  const shared = diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: x25519PublicKeyObject(recipientRaw),
  });
  const aad = Buffer.from(canonicalJson(transcript), "utf8");
  const key = Buffer.from(hkdfSync(
    "sha256",
    shared,
    Buffer.concat([ephemeralRaw, recipientRaw]),
    Buffer.concat([ENROLLMENT_AAD, Buffer.from(sha256Hex(aad), "hex")]),
    32,
  ));
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(canonicalJson(material), "utf8")),
    cipher.final(),
  ]);
  return {
    version: 2,
    algorithm: "X25519-HKDF-SHA256-AES-256-GCM",
    transcript,
    ephemeralPublicKey: ephemeralRaw.toString("base64url"),
    nonce: nonce.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
  };
}

interface MemberRow {
  identity_id: string;
  nickname: string;
  role_id: string;
  joined_at: number;
  presence: string;
}

type HostCommandType = HostCommand["type"];

export interface ReplicaEnrollmentMaterial {
  version: 2;
  enrollmentId: string;
  issuedAt: number;
  expiresAt: number;
  serverId: string;
  authorityPublicKey: string;
  authorityFingerprint: string;
  epoch: number;
  seq: number;
  grantId: string;
  subjectIdentityId: string;
  subjectAuthPublicKey: string;
  replicaHost: { hostId: string; publicKey: string };
  primaryHost: { hostId: string; grantId: string; publicKey: string };
  replicaGrant: SignedHostGrant;
  /** Public bridge descriptors only. Operator pairing credentials are never replicated. */
  bridgeAccess: { descriptor: SignedBridgeDescriptor }[];
  dbB64: string;
  dbKeyB64: string;
}

export interface SealedReplicaEnrollment {
  version: 2;
  algorithm: "X25519-HKDF-SHA256-AES-256-GCM";
  transcript: SignedReplicaEnrollmentTranscript;
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
  tag: string;
}

export interface ReplicaEnrollmentTranscript {
  version: 1;
  enrollmentId: string;
  recipientPublicKey: string;
  serverId: string;
  authorityFingerprint: string;
  grantId: string;
  generation: number;
  subjectAuthPublicKey: string;
  replicaHost: { hostId: string; publicKey: string };
  primaryHost: { hostId: string; grantId: string; publicKey: string };
  snapshotHash: string;
  epoch: number;
  seq: number;
  issuedAt: number;
  expiresAt: number;
  bridgeSetHash: string;
}

export interface SignedReplicaEnrollmentTranscript {
  payload: ReplicaEnrollmentTranscript;
  publicKey: string;
  signature: string;
}

export function verifyReplicaEnrollmentTranscript(
  envelope: SealedReplicaEnrollment,
  expectedRecipientPublicKey?: string,
): ReplicaEnrollmentTranscript | null {
  if (envelope.version !== 2 || envelope.algorithm !== "X25519-HKDF-SHA256-AES-256-GCM") return null;
  const transcript = envelope.transcript;
  if (!transcript?.payload || (expectedRecipientPublicKey && transcript.payload.recipientPublicKey !== expectedRecipientPublicKey)) return null;
  const authority = Buffer.from(transcript.publicKey, "base64url");
  const signature = Buffer.from(transcript.signature, "base64url");
  if (authority.length !== 32 || signature.length !== 64
    || ed25519Fingerprint(authority) !== transcript.payload.authorityFingerprint
    || !verifyCanonicalPayload(authority, ENROLLMENT_TRANSCRIPT_DOMAIN, transcript.payload, signature)) return null;
  return transcript.payload;
}

export interface BridgeWitnessObservation {
  bridgeId: string;
  requestId: string;
  candidateHostId: string;
  primaryHostId: string;
  primaryRecordHash: string;
  primaryEpoch: number;
  electionEpoch: number;
  primaryOnline: false;
  observedAt: number;
  expiresAt: number;
  receipt: unknown;
}

interface HostPossessionProof {
  proofId: string;
  issuedAt: number;
  signature: string;
}

const X25519_SPKI_PUBLIC_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const HOST_POSSESSION_DOMAIN = "janjacord.host-possession.v1";
const HOST_CANDIDATE_DEVICE_DOMAIN = "janjacord.host-candidate-device.v1";
const HOST_CANDIDATE_POSSESSION_DOMAIN = "janjacord.host-candidate-possession.v1";
const BRIDGE_ACCESS_DOMAIN = "janjacord.bridge-access.v1";
const ENROLLMENT_AAD = Buffer.from("janjacord.replica-enrollment.v1", "utf8");
const ENROLLMENT_TRANSCRIPT_DOMAIN = "janjacord.replica-enrollment-transcript.v1";
const HARD_MAX_ENVELOPE_BYTES = 2 * 1024 * 1024;
const DEFAULT_MEMBER_SPOOL_BYTES = 256 * 1024 * 1024;
const ABANDONED_ATTACHMENT_TTL_MS = 60 * 60_000;
export const MAX_PENDING_ATTACHMENT_TRANSFERS_PER_MEMBER = 16;
export const MAX_PENDING_ATTACHMENT_TRANSFERS_GLOBAL = 256;

interface AttachmentRow {
  asset_id: string;
  data: string;
  size_bytes: number;
  total_chunks: number;
  ciphertext_hash: string;
  expires_at: number;
  created_at: number;
  owner_id: string;
  channel_id: string;
  audience: string;
  linked_message_id: string | null;
  completed_at: number | null;
}

interface AttachmentChunkRow {
  chunk_index: number;
  data: string;
  size_bytes: number;
  hash: string;
}

export class ServerService {
  /** Eventos para o gateway: deliver(identityId, envelope), presence(identityId, state), stateChanged(). */
  readonly events = new EventEmitter();
  readonly replay = new ReplayGuard(60 * 60 * 1000); // 1h janela anti-replay (retention default 7d > janela)
  readonly sequences = new Map<string, SequenceTracker>();
  private pendingRegistration: {
    endpointsKey: string;
    registration: HostRegistration;
    recordHash: string;
    committed: boolean;
  } | null = null;
  private writer = !(process.env.JC_REPLICA_OF || process.env.JC_REPLICA_ENROLLMENT_FILE);
  private readonly bootedAsReplica = Boolean(process.env.JC_REPLICA_OF || process.env.JC_REPLICA_ENROLLMENT_FILE);
  private writerResumeEligibility: {
    hostId: string;
    grantId: string;
    epoch: number;
    configuredBridgeIds: string[];
    witnessBridgeSets: string[][];
  } | null = null;
  private bridgeIceConfigs = new Map<string, {
    urls: string[];
    username: string;
    credential: string;
    expiresAt: number;
  }>();

  constructor(
    private readonly store: Store,
    private readonly serverId: string,
    private readonly dbPath: string,
    private readonly ownerIdentity: string,
    private readonly ownerNickname: string,
    private readonly serverName: string,
  ) {}

  /** Boot do host: roles default, owner, canal #general (idempotente). */
  bootstrap(): void {
    const db = this.store.raw;
    this.reconcileAuthorityPublicKey();
    const hasRoles = db.prepare("SELECT 1 FROM roles LIMIT 1").get();
    const createdCommunity = !hasRoles;
    if (!hasRoles) {
      if (!this.authoritySeed()) {
        throw new Error("JC_AUTHORITY_SIGNING_SEED is required to create a new authoritative server");
      }
      db.transaction(() => {
        db.prepare("INSERT INTO server_meta (key, value) VALUES (?, ?)").run("server_name", this.serverName);
        db.prepare("INSERT INTO server_meta (key, value) VALUES (?, ?)").run(
          "config",
          JSON.stringify({
            maxRetentionHours: 168,
            networkPrivacy: "direct",
            maxAttachmentBytes: 50 * 1024 * 1024,
            maxSpoolBytes: 2 * 1024 * 1024 * 1024,
            maxVoiceParticipants: 10,
            maxVideoParticipants: 6,
          }),
        );
        const roles: Role[] = [
          { id: "role-owner", name: "Owner", level: ROLE_LEVELS.owner, permissions: [...PermissionFlagSchema.options] },
          { id: "role-admin", name: "Admin", level: ROLE_LEVELS.admin, permissions: ["manage_server", "manage_channels", "manage_roles", "manage_invites", "manage_hosts", "kick_members", "ban_members", "assign_roles", "view_channel", "send_messages", "send_files", "join_call", "speak", "enable_camera", "mute_members", "remove_from_call"] },
          { id: "role-mod", name: "Moderator", level: ROLE_LEVELS.moderator, permissions: ["kick_members", "view_channel", "send_messages", "send_files", "join_call", "speak", "enable_camera", "mute_members", "remove_from_call"] },
          { id: "role-member", name: "Member", level: ROLE_LEVELS.member, permissions: ["view_channel", "send_messages", "send_files", "join_call", "speak", "enable_camera"] },
        ];
        for (const r of roles) {
          db.prepare("INSERT INTO roles (id, name, level, permissions, created_at) VALUES (?,?,?,?,?)").run(
            r.id, r.name, r.level, JSON.stringify(r.permissions), Date.now(),
          );
        }
        db.prepare("INSERT INTO members (identity_id, nickname, role_id, joined_at) VALUES (?,?,?,?)").run(
          this.ownerIdentity, this.ownerNickname, "role-owner", Date.now(),
        );
        db.prepare("INSERT INTO channels (id, type, name, overrides, created_at) VALUES (?,?,?,?,?)").run(
          randomUUID(), "text", "general", "[]", Date.now(),
        );
        this.store.appendOp({ type: "bootstrap", serverId: this.serverId });
      })();
      this.events.emit("stateChanged");
    }
    const ownerPublicKey = process.env.JC_OWNER_PUBLIC_KEY;
    // Built-in Owner permissions are a product contract consumed by server.state/UI. Repair
    // older seeded rows without touching custom roles.
    db.prepare("UPDATE roles SET permissions = ? WHERE id = 'role-owner'")
      .run(JSON.stringify(PermissionFlagSchema.options));
    if (ownerPublicKey) {
      db.prepare(
        "INSERT OR IGNORE INTO member_devices (identity_id, device_public_key, added_at) VALUES (?,?,?)",
      ).run(this.ownerIdentity, ownerPublicKey, Date.now());
    }
    this.restoreWriterState(createdCommunity);
  }

  private writerStateKey(hostId: string): string {
    return `writer_state:${hostId}`;
  }

  private normalizedWitnessBridgeSet(value: unknown): string[] | null {
    if (!Array.isArray(value) || value.length > 3) return null;
    const normalized = [...new Set(value)];
    if (normalized.length !== value.length
      || normalized.some((bridgeId) => typeof bridgeId !== "string" || bridgeId.length < 1 || bridgeId.length > 256)) {
      return null;
    }
    return (normalized as string[]).sort();
  }

  private normalizedWitnessBridgeSets(value: unknown): string[][] | null {
    if (!Array.isArray(value) || value.length > 64) return null;
    const byKey = new Map<string, string[]>();
    for (const item of value) {
      const bridgeIds = this.normalizedWitnessBridgeSet(item);
      if (!bridgeIds || bridgeIds.length < 2) return null;
      byKey.set(JSON.stringify(bridgeIds), bridgeIds);
    }
    return [...byKey.values()].sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  }

  private persistedWriterWitnessState(grant: SignedHostGrant): {
    bridgeSets: string[][];
    historyComplete: boolean;
  } {
    const row = this.store.raw.prepare("SELECT value FROM server_meta WHERE key = ?")
      .get(this.writerStateKey(grant.payload.hostId)) as { value: string } | undefined;
    if (!row) return { bridgeSets: [], historyComplete: true };
    try {
      const value = JSON.parse(row.value) as Record<string, unknown>;
      if (value.version !== 2 || value.hostId !== grant.payload.hostId || value.grantId !== grant.payload.grantId) {
        return { bridgeSets: [], historyComplete: true };
      }
      const bridgeSets = this.normalizedWitnessBridgeSets(value.witnessBridgeSets);
      if (!bridgeSets || typeof value.witnessHistoryComplete !== "boolean") {
        return { bridgeSets: [], historyComplete: false };
      }
      return { bridgeSets, historyComplete: value.witnessHistoryComplete };
    } catch {
      return { bridgeSets: [], historyComplete: false };
    }
  }

  /**
   * Every set in this append-only floor is an election configuration a replica may still use.
   * Writer resumption must reach a strict majority of every preserved set, not merely a majority
   * of the currently configured set. This retains quorum intersection across bridge removals.
   */
  private writerWitnessState(grant: SignedHostGrant, additionalSets: readonly string[][] = []): {
    bridgeSets: string[][];
    historyComplete: boolean;
  } {
    const persisted = this.persistedWriterWitnessState(grant);
    const byKey = new Map<string, string[]>();
    let historyComplete = persisted.historyComplete;
    const grantCanPromote = grant.payload.capabilities.includes("promote");
    const add = (value: unknown): void => {
      const bridgeIds = this.normalizedWitnessBridgeSet(value);
      if (!bridgeIds) {
        historyComplete = false;
        return;
      }
      // Zero/one-bridge configurations can never promote under strictBridgeWitnessQuorum, so
      // they are not election configurations and impose no historical quorum-intersection floor.
      if (bridgeIds.length < 2) return;
      const key = JSON.stringify(bridgeIds);
      if (!byKey.has(key) && byKey.size >= 64) {
        historyComplete = false;
        return;
      }
      byKey.set(key, bridgeIds);
    };
    for (const bridgeIds of persisted.bridgeSets) add(bridgeIds);
    for (const bridgeIds of additionalSets) add(bridgeIds);

    const configured = this.configuredRegistrationBridgeIds();
    if (grantCanPromote && configured.length > 0) add(configured);
    if (grantCanPromote && (grant.payload.witnessBridgeIds?.length ?? 0) > 0) {
      add(grant.payload.witnessBridgeIds);
    }

    const localReplicaTrust = this.store.raw.prepare(
      "SELECT value FROM server_meta WHERE key = 'replica_witness_bridge_ids'",
    ).get() as { value: string } | undefined;
    if (localReplicaTrust) {
      try { add(JSON.parse(localReplicaTrust.value)); } catch { historyComplete = false; }
    }

    const enrolled = this.store.raw.prepare(
      `SELECT h.payload, h.signature
       FROM replica_enrollments r
       JOIN host_grants h ON h.grant_id = r.grant_id`,
    ).all() as { payload: string; signature: string }[];
    for (const row of enrolled) {
      try {
        const payload = JSON.parse(row.payload) as { issuedAt?: unknown };
        const candidate = {
          payload,
          publicKey: this.authorityPublicKey(),
          signature: row.signature,
        };
        const verified = verifySignedHostGrant(candidate, this.authorityPublicKey(), Number(payload.issuedAt));
        if (!verified) historyComplete = false;
        // Only a signed promote capability turns an enrollment's witnesses into an election
        // configuration. Revocation is intentionally not filtered: a stale promoted replica may
        // still exist, so a floor that was once legitimate remains append-only.
        else if (verified.payload.capabilities.includes("promote")) {
          add(verified.payload.witnessBridgeIds ?? []);
        }
      } catch {
        historyComplete = false;
      }
    }
    return {
      bridgeSets: [...byKey.values()].sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))),
      historyComplete,
    };
  }

  private persistWriterState(
    state: "writer" | "fenced",
    grant: SignedHostGrant,
    epoch = this.getEpoch(),
    additionalWitnessSets: readonly string[][] = [],
  ): void {
    const witness = this.writerWitnessState(grant, additionalWitnessSets);
    const value = JSON.stringify({
      version: 2,
      state,
      hostId: grant.payload.hostId,
      grantId: grant.payload.grantId,
      epoch,
      witnessBridgeSets: witness.bridgeSets,
      witnessHistoryComplete: witness.historyComplete,
      updatedAt: Date.now(),
    });
    this.store.raw.prepare(
      "INSERT INTO server_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
    ).run(this.writerStateKey(grant.payload.hostId), value);
  }

  /** Local host role is keyed by its distinct host key, so replicated DB state cannot promote peers. */
  private restoreWriterState(createdCommunity: boolean): void {
    this.writerResumeEligibility = null;
    const current = this.currentHostGrant();
    if (!current.ok) {
      this.writer = false;
      return;
    }
    const row = this.store.raw.prepare("SELECT value FROM server_meta WHERE key = ?")
      .get(this.writerStateKey(current.data.grant.payload.hostId)) as { value: string } | undefined;
    if (!row) {
      const bridgeIds = this.configuredRegistrationBridgeIds();
      const witness = this.writerWitnessState(current.data.grant);
      if (!this.bootedAsReplica && (createdCommunity
        || (bridgeIds.length === 0 && witness.bridgeSets.length === 0 && witness.historyComplete))) {
        this.persistWriterState("writer", current.data.grant, this.getEpoch(), witness.bridgeSets);
        this.writer = true;
        return;
      }
      this.writer = false;
      if (!this.bootedAsReplica && bridgeIds.length > 0) {
        this.persistWriterState("writer", current.data.grant, this.getEpoch(), witness.bridgeSets);
        if (!witness.historyComplete) return;
        this.writerResumeEligibility = {
          hostId: current.data.grant.payload.hostId,
          grantId: current.data.grant.payload.grantId,
          epoch: this.getEpoch(),
          configuredBridgeIds: bridgeIds,
          witnessBridgeSets: witness.bridgeSets,
        };
      }
      return;
    }
    try {
      const value = JSON.parse(row.value) as Record<string, unknown>;
      const version = value.version;
      const exactKeys = (version === 1
        ? ["epoch", "grantId", "hostId", "state", "updatedAt", "version"]
        : ["epoch", "grantId", "hostId", "state", "updatedAt", "version", "witnessBridgeSets", "witnessHistoryComplete"]
      ).sort().join("\0");
      const persistedSets = version === 2 ? this.normalizedWitnessBridgeSets(value.witnessBridgeSets) : [];
      const valid = (version === 1 || version === 2)
        && Object.keys(value).sort().join("\0") === exactKeys
        && value.hostId === current.data.grant.payload.hostId
        && value.grantId === current.data.grant.payload.grantId
        && Number.isSafeInteger(value.epoch)
        && Number(value.epoch) === this.getEpoch()
        && Number.isSafeInteger(value.updatedAt)
        && (version === 1 || (persistedSets !== null && typeof value.witnessHistoryComplete === "boolean"))
        && (value.state === "writer" || value.state === "fenced");
      this.writer = valid && value.state === "writer";
      if (this.writer) {
        const bridgeIds = this.configuredRegistrationBridgeIds();
        const witness = this.writerWitnessState(current.data.grant, persistedSets ?? []);
        this.persistWriterState("writer", current.data.grant, this.getEpoch(), witness.bridgeSets);
        if (witness.bridgeSets.length > 0 || !witness.historyComplete) {
          this.writer = false;
          if (witness.historyComplete) {
            this.writerResumeEligibility = {
              hostId: current.data.grant.payload.hostId,
              grantId: current.data.grant.payload.grantId,
              epoch: this.getEpoch(),
              configuredBridgeIds: bridgeIds,
              witnessBridgeSets: witness.bridgeSets,
            };
          }
        }
      }
    } catch {
      this.writer = false;
    }
  }

  // ------------------------------------------------------------------ state

  updateConfig(actorId: string, patch: Record<string, unknown>): HostResult<Record<string, unknown>> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const actorRole = this.getRole(actor.role_id)!;
    if (!evaluatePermission(this.memberContext(actor), actorRole, null, "manage_server")) {
      return fail("forbidden", "no manage_server");
    }
    const cur = this.getConfig();
    const next = { ...cur, ...patch };
    this.store.raw
      .prepare("INSERT INTO server_meta (key, value) VALUES ('config', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .run(JSON.stringify(next));
    this.store.appendOp({ type: "updateConfig", patch });
    this.events.emit("stateChanged");
    return ok(next);
  }

  getConfig(): Record<string, unknown> {
    const row = this.store.raw.prepare("SELECT value FROM server_meta WHERE key = 'config'").get() as
      | { value: string }
      | undefined;
    return row ? JSON.parse(row.value) : {};
  }

  getState(identityId: string): HostResult<Record<string, unknown>> {
    const member = this.getMember(identityId);
    if (!member) return fail("forbidden", "not a member");
    const rawRoles = this.allRows("roles") as unknown as {
      id: string; name: string; level: number; permissions: string; created_at: number;
    }[];
    const roles: Role[] = rawRoles.map((r) => ({
      id: r.id,
      name: r.name,
      level: r.level,
      permissions: JSON.parse(r.permissions) as Role["permissions"],
      created_at: r.created_at,
    }));
    const rawChannels = this.allRows("channels") as unknown as {
      id: string; type: string; name: string; overrides: string; created_at: number;
    }[];
    const channels: Channel[] = rawChannels.map((c) => ({
      id: c.id,
      serverId: this.serverId,
      type: c.type as Channel["type"],
      name: c.name,
      overrides: JSON.parse(c.overrides) as Channel["overrides"],
      createdAt: c.created_at,
    }));
    const members = this.allRows("members") as unknown as MemberRow[];
    const actorRole = this.getRole(member.role_id)!;
    const mayManageHosts = evaluatePermission(this.memberContext(member), actorRole, null, "manage_hosts");
    return ok({
      serverId: this.serverId,
      serverName: this.serverName,
      authority: {
        publicKey: this.authorityPublicKey(),
        fingerprint: this.authorityFingerprint(),
      },
      epoch: this.getEpoch(),
      hosting: {
        role: this.writer ? "primary" : "replica",
        writer: this.writer,
      },
      // Replication currently ships consistent full SQLCipher snapshots. There is no per-write
      // replica ACK/op-log protocol yet, so this must never be presented as 2-safe durability.
      redundancy: {
        mode: "encrypted-snapshot",
        twoSafe: false,
        writeDurability: "single-writer",
      },
      config: this.getConfig(),
      roles,
      channels,
      members: members.map((m) => ({ identityId: m.identity_id, nickname: m.nickname, roleId: m.role_id, presence: m.presence })),
      me: { identityId, nickname: member.nickname, roleId: member.role_id },
      hostGrants: this.hostGrantRows(mayManageHosts ? undefined : identityId).map((row) => this.publicHostGrant(row)),
      hostCandidates: this.hostCandidateRows(mayManageHosts ? undefined : identityId),
      eligibleHostDevices: mayManageHosts ? this.eligibleHostDevices() : undefined,
    });
  }

  // ----------------------------------------------------------------- helpers

  private allRows(table: string): unknown[] {
    return this.store.raw.prepare(`SELECT * FROM ${table}`).all();
  }

  private getMember(identityId: string): MemberRow | undefined {
    return this.store.raw
      .prepare("SELECT * FROM members WHERE identity_id = ?")
      .get(identityId) as MemberRow | undefined;
  }

  isMember(identityId: string): boolean {
    return !!this.getMember(identityId);
  }

  isAuthorizedDevice(identityId: string, publicKey: string): boolean {
    return !!this.store.raw.prepare(
      "SELECT 1 FROM member_devices WHERE identity_id = ? AND device_public_key = ? AND revoked_at IS NULL",
    ).get(identityId, publicKey);
  }

  authorizeIceAccess(
    value: unknown,
    expected: { sessionId: string; serverId: string; hostId: string },
    now = Date.now(),
  ): value is SignedIceAccessProof {
    const parsed = SignedIceAccessProofSchema.safeParse(value);
    if (!parsed.success) return false;
    const proof = parsed.data;
    const payload = proof.payload;
    if (payload.sessionId !== expected.sessionId || payload.serverId !== expected.serverId
      || payload.hostId !== expected.hostId || payload.serverId !== this.serverId
      || payload.issuedAt > now + 5_000 || payload.expiresAt <= now
      || payload.expiresAt > payload.issuedAt + 30_000
      || !verifyCanonicalPayload(
        Buffer.from(payload.devicePublicKey, "base64url"),
        "janjacord.ice-access.v1",
        payload,
        Buffer.from(proof.signature, "base64url"),
      )) return false;
    if (this.getMember(payload.identityId)) {
      return this.isAuthorizedDevice(payload.identityId, payload.devicePublicKey);
    }
    if (!payload.inviteAccessHash) return false;
    return !!this.store.raw.prepare(
      "SELECT 1 FROM invites WHERE access_hash = ? AND revoked = 0 AND used < max_uses AND (expires_at IS NULL OR expires_at > ?)",
    ).get(payload.inviteAccessHash, now);
  }

  private getRole(roleId: string): Role | undefined {
    return this.store.raw
      .prepare("SELECT * FROM roles WHERE id = ?")
      .get(roleId) as unknown as Role | undefined;
  }

  private getChannel(channelId: string): Channel | undefined {
    const row = this.store.raw
      .prepare("SELECT * FROM channels WHERE id = ?")
      .get(channelId) as
      | { id: string; serverId?: string; type: string; name: string; overrides: string; created_at: number }
      | undefined;
    if (!row) return undefined;
    return {
      id: row.id,
      serverId: this.serverId,
      type: row.type as Channel["type"],
      name: row.name,
      overrides: JSON.parse(row.overrides) as Channel["overrides"],
      createdAt: row.created_at,
    };
  }

  private memberContext(m: MemberRow): MemberContext {
    return { identityId: m.identity_id, roleId: m.role_id, isOwner: m.role_id === "role-owner" };
  }

  /** The current owner is the only server-authorized MLS committer. */
  private isAuthorizedMlsCommitter(identityId: string): boolean {
    return this.getMember(identityId)?.role_id === "role-owner";
  }

  private seqFor(channelId: string): SequenceTracker {
    let t = this.sequences.get(channelId);
    if (!t) {
      t = new SequenceTracker();
      this.sequences.set(channelId, t);
    }
    return t;
  }

  getServerId(): string {
    return this.serverId;
  }

  getEpochPublic(): number {
    return this.getEpoch();
  }

  getAuthorityPublicKey(): string {
    return this.authorityPublicKey();
  }

  getAuthorityFingerprint(): string {
    return this.authorityFingerprint();
  }

  isWriter(): boolean {
    return this.writer;
  }

  isWriterResumePending(): boolean {
    return this.writerResumeEligibility !== null;
  }

  /**
   * A persisted writer is only resume-eligible for a committed, current primary record ACKed by
   * a strict majority of the exact bridge set configured when this process started and of every
   * historical witness set retained in its monotonic quorum floor. The ACKs are verified by the
   * rendezvous coordinator before it calls this internal transition.
   */
  resumeWriterAfterRegistrationQuorum(
    binding: { recordHash: string; epoch: number; role: "primary" | "replica" },
    acknowledgedBridgeIds: readonly string[],
    configuredBridgeIds: readonly string[],
  ): boolean {
    const eligible = this.writerResumeEligibility;
    if (!eligible || this.writer || binding.role !== "primary") return false;
    const configured = [...new Set(configuredBridgeIds)].sort();
    const acknowledged = [...new Set(acknowledgedBridgeIds)].sort();
    if (configured.length !== configuredBridgeIds.length
      || acknowledged.length !== acknowledgedBridgeIds.length
      || configured.length !== eligible.configuredBridgeIds.length
      || configured.some((bridgeId, index) => bridgeId !== eligible.configuredBridgeIds[index])
      || acknowledged.some((bridgeId) => !configured.includes(bridgeId))
      || configured.length === 0
      || acknowledged.length < Math.floor(configured.length / 2) + 1
      || eligible.witnessBridgeSets.some((bridgeIds) => (
        acknowledged.filter((bridgeId) => bridgeIds.includes(bridgeId)).length
          < Math.floor(bridgeIds.length / 2) + 1
      ))) return false;
    const pending = this.pendingRegistration;
    if (!pending?.committed || pending.recordHash !== binding.recordHash) return false;
    const record = pending.registration.record.payload;
    if (record.role !== "primary" || record.epoch !== binding.epoch
      || record.epoch !== eligible.epoch || record.hostId !== eligible.hostId
      || record.grantId !== eligible.grantId) return false;
    const current = this.currentHostGrant();
    if (!current.ok || current.data.grant.payload.hostId !== eligible.hostId
      || current.data.grant.payload.grantId !== eligible.grantId) return false;
    this.persistWriterState("writer", current.data.grant, eligible.epoch, eligible.witnessBridgeSets);
    this.writerResumeEligibility = null;
    this.writer = true;
    this.events.emit("stateChanged");
    return true;
  }

  configureReplicaTrust(primaryHostId: string, bridgeIds: string[]): void {
    if (this.writer) return;
    const normalized = [...new Set(bridgeIds)].sort();
    if (!primaryHostId || normalized.length > 3) throw new Error("invalid replica witness trust configuration");
    const previous = this.store.raw.prepare(
      "SELECT value FROM server_meta WHERE key = 'replica_primary_host_id'",
    ).get() as { value: string } | undefined;
    if (previous && previous.value !== primaryHostId) throw new Error("replica primary trust substitution rejected");
    this.store.raw.transaction(() => {
      this.store.raw.prepare(
        "INSERT INTO server_meta (key, value) VALUES ('replica_primary_host_id', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      ).run(primaryHostId);
      this.store.raw.prepare(
        "INSERT INTO server_meta (key, value) VALUES ('replica_witness_bridge_ids', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      ).run(JSON.stringify(normalized));
    })();
  }

  /** Only the next primary epoch plus its trusted 2-bridge promotion certificate can fence a writer. */
  observeHigherEpoch(registration: unknown): boolean {
    const candidate = registration as {
      record?: unknown;
      grant?: unknown;
      authorityPublicKey?: unknown;
      promotionCertificate?: unknown;
    };
    if (candidate.authorityPublicKey !== this.authorityPublicKey()) return false;
    const verified = verifyHostRegistration({
      record: candidate.record,
      grant: candidate.grant,
      authorityPublicKey: this.authorityPublicKey(),
    });
    if (!verified || verified.record.payload.serverId !== this.serverId
      || verified.record.payload.role !== "primary" || verified.record.payload.epoch !== this.getEpoch() + 1) return false;
    const current = this.currentHostGrant();
    if (!current.ok) return false;
    const activeCandidate = this.store.raw.prepare(
      "SELECT payload, signature, accepted_at, revoked_at, expires_at FROM host_grants WHERE grant_id = ?",
    ).get(verified.grant.payload.grantId) as {
      payload: string;
      signature: string;
      accepted_at: number | null;
      revoked_at: number | null;
      expires_at: number;
    } | undefined;
    if (!activeCandidate || !activeCandidate.accepted_at || activeCandidate.revoked_at
      || activeCandidate.expires_at <= Date.now()
      || canonicalJson(JSON.parse(activeCandidate.payload)) !== canonicalJson(verified.grant.payload)
      || activeCandidate.signature !== verified.grant.signature) return false;
    const prior = this.registrationChain()
      .filter((entry) => entry.registration.record.payload.role === "primary"
        && entry.registration.record.payload.epoch === this.getEpoch())
      .sort((left, right) => right.recordSeq - left.recordSeq)[0];
    if (!prior || !validObservedPromotionCertificate(
      candidate.promotionCertificate,
      {
        authorityPublicKey: candidate.authorityPublicKey as string,
        grant: verified.grant,
        record: verified.record,
      },
      {
        primaryHostId: current.data.grant.payload.hostId,
        primaryRecordHash: prior.recordHash,
        primaryEpoch: this.getEpoch(),
      },
    )) return false;
    this.store.raw.transaction(() => {
      this.store.raw.prepare(
        "INSERT INTO server_meta (key, value) VALUES ('epoch', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      ).run(String(verified.record.payload.epoch));
      this.store.raw.prepare(
        "INSERT INTO server_meta (key, value) VALUES ('writer_fenced_at', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      ).run(String(Date.now()));
      this.persistWriterState("fenced", current.data.grant, verified.record.payload.epoch);
    })();
    this.writerResumeEligibility = null;
    this.pendingRegistration = null;
    this.writer = false;
    this.events.emit("stateChanged");
    return true;
  }

  /** Connectivity loss fencing prevents an isolated old primary from remaining a writer. */
  fencePrimaryWriter(): boolean {
    if (!this.writer && !this.writerResumeEligibility) return false;
    const current = this.currentHostGrant();
    this.store.raw.transaction(() => {
      this.store.raw.prepare(
        "INSERT INTO server_meta (key, value) VALUES ('writer_fenced_at', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      ).run(String(Date.now()));
      if (current.ok) this.persistWriterState("fenced", current.data.grant);
    })();
    this.writerResumeEligibility = null;
    this.pendingRegistration = null;
    this.writer = false;
    this.events.emit("stateChanged");
    return true;
  }

  canAcceptCommand(type: HostCommandType): boolean {
    if (this.writer) return true;
    return new Set<HostCommandType>([
      "server.state",
      "connectivity.iceConfig",
      "host.grant.list",
      "message.getPending",
      "attachment.download",
      "attachment.download.chunk",
      "keypackage.get",
      "welcome.pending",
      "replica.ping",
    ]).has(type);
  }

  private configuredSeed(name: "JC_AUTHORITY_SIGNING_SEED" | "JC_HOST_SIGNING_SEED"): Buffer | null {
    const value = process.env[name];
    if (!value) return null;
    if (!/^[0-9a-f]{64}$/i.test(value)) throw new Error(`${name} must be exactly 32 bytes encoded as hex`);
    return Buffer.from(value, "hex");
  }

  private authoritySeed(): Buffer | null {
    return this.configuredSeed("JC_AUTHORITY_SIGNING_SEED");
  }

  private hostSigningSeed(): Buffer | null {
    return this.configuredSeed("JC_HOST_SIGNING_SEED");
  }

  private reconcileAuthorityPublicKey(): void {
    const seed = this.authoritySeed();
    const configuredPublicKey = seed ? ed25519PublicKey(seed).toString("base64url") : null;
    const stored = this.store.raw.prepare(
      "SELECT value FROM server_meta WHERE key = 'authority_public_key'",
    ).get() as { value: string } | undefined;
    if (!stored && configuredPublicKey) {
      this.store.raw.prepare("INSERT INTO server_meta (key, value) VALUES ('authority_public_key', ?)")
        .run(configuredPublicKey);
      return;
    }
    if (stored && configuredPublicKey && stored.value !== configuredPublicKey) {
      const signedGrant = this.store.raw.prepare("SELECT 1 FROM host_grants LIMIT 1").get();
      if (signedGrant) {
        throw new Error("JC_AUTHORITY_SIGNING_SEED does not match the persisted authority_public_key");
      }
      // Legacy databases had an unrelated random server_key. Before the first signed grant,
      // rotate safely to the explicitly configured authority while preserving invite hashes.
      this.store.raw.transaction(() => {
        this.store.raw.prepare("UPDATE server_meta SET value = ? WHERE key = 'authority_public_key'")
          .run(configuredPublicKey);
        this.store.raw.prepare("DELETE FROM server_meta WHERE key IN ('host_record_seq', 'host_record_hash')").run();
      })();
    }
  }

  private authorityPublicKey(): string {
    const row = this.store.raw.prepare(
      "SELECT value FROM server_meta WHERE key = 'authority_public_key'",
    ).get() as { value: string } | undefined;
    if (!row) throw new Error("authority_public_key is not provisioned");
    return row.value;
  }

  private authorityFingerprint(): string {
    return ed25519Fingerprint(Buffer.from(this.authorityPublicKey(), "base64url"));
  }

  private inviteHashKey(): Buffer {
    const row = this.store.raw.prepare(
      "SELECT value FROM server_meta WHERE key = 'invite_hash_key'",
    ).get() as { value: string } | undefined;
    if (!row || !/^[0-9a-f]{64}$/i.test(row.value)) throw new Error("invite_hash_key is not provisioned");
    return Buffer.from(row.value, "hex");
  }

  private currentHostGeneration(hostId: string): number {
    const rows = this.store.raw.prepare(
      "SELECT payload, revocation_payload FROM host_grants WHERE host_id = ?",
    ).all(hostId) as { payload: string; revocation_payload: string | null }[];
    let generation = 0;
    for (const row of rows) {
      try {
        generation = Math.max(generation, Number((JSON.parse(row.payload) as { generation?: number }).generation ?? 0));
        if (row.revocation_payload) {
          generation = Math.max(
            generation,
            Number((JSON.parse(row.revocation_payload) as { generation?: number }).generation ?? 0),
          );
        }
      } catch {
        throw new Error(`invalid persisted host grant generation for ${hostId}`);
      }
    }
    return generation;
  }

  private nextHostGeneration(hostId: string): number {
    return this.currentHostGeneration(hostId) + 1;
  }

  private currentHostGrant(now = Date.now()): HostResult<{ hostSeed: Buffer; grant: SignedHostGrant }> {
    const hostSeed = this.hostSigningSeed();
    if (!hostSeed) return fail("unavailable", "JC_HOST_SIGNING_SEED is required for host authentication");
    const hostPublicKey = ed25519PublicKey(hostSeed).toString("base64url");
    const row = this.store.raw.prepare(
      "SELECT payload, signature FROM host_grants WHERE device_public_key = ? AND accepted_at IS NOT NULL AND revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC LIMIT 1",
    ).get(hostPublicKey, now) as { payload: string; signature: string } | undefined;
    if (row) {
      const candidate = {
        payload: JSON.parse(row.payload),
        publicKey: this.authorityPublicKey(),
        signature: row.signature,
      };
      const grant = verifySignedHostGrant(candidate, this.authorityPublicKey(), now);
      if (grant && grant.payload.serverId === this.serverId && grant.payload.capabilities.includes("register")) {
        return ok({ hostSeed, grant });
      }
    }

    const authoritySeed = this.authoritySeed();
    if (!authoritySeed) return fail("forbidden", "no accepted host grant matches this host signing key");
    const subjectAuthPublicKey = process.env.JC_OWNER_PUBLIC_KEY;
    if (!subjectAuthPublicKey || !this.isAuthorizedDevice(this.ownerIdentity, subjectAuthPublicKey)) {
      return fail("forbidden", "owner device must be enrolled before the primary host grant can be issued");
    }
    const hostId = `primary-${ed25519Fingerprint(ed25519PublicKey(hostSeed)).slice(0, 24)}`;
    const grant = createSignedHostGrant({
      version: 1,
      grantId: randomUUID(),
      serverId: this.serverId,
      issuerIdentityId: this.ownerIdentity,
      subjectIdentityId: this.ownerIdentity,
      subjectAuthPublicKey,
      devicePublicKey: hostPublicKey,
      hostId,
      capabilities: ["register", "replicate", "promote"],
      ...(trustedBridgePublicKeys().size >= 2
        ? { witnessBridgeIds: [...trustedBridgePublicKeys().keys()].sort() }
        : {}),
      generation: this.nextHostGeneration(hostId),
      issuedAt: now,
      expiresAt: now + 10 * 365 * 24 * 3600_000,
    }, authoritySeed);
    this.store.raw.prepare(
      "INSERT INTO host_grants (grant_id, subject_identity_id, host_id, subject_auth_public_key, device_public_key, capabilities, payload, signature, expires_at, created_at, accepted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
    ).run(
      grant.payload.grantId,
      this.ownerIdentity,
      hostId,
      subjectAuthPublicKey,
      hostPublicKey,
      JSON.stringify(grant.payload.capabilities),
      JSON.stringify(grant.payload),
      grant.signature,
      grant.payload.expiresAt,
      now,
      now,
    );
    this.store.appendOp({ type: "hostGrantCreate", grantId: grant.payload.grantId, subjectIdentityId: this.ownerIdentity, hostId });
    return ok({ hostSeed, grant });
  }

  signedAuthChallenge(challengeId: string, nonce: string, expiresAt: number): Record<string, unknown> {
    const current = this.currentHostGrant();
    if (!current.ok) return { error: current.error };
    return createSignedHostAuthChallenge({
      version: 1,
      serverId: this.serverId,
      authorityFingerprint: this.authorityFingerprint(),
      hostId: current.data.grant.payload.hostId,
      grantId: current.data.grant.payload.grantId,
      challengeId,
      nonce,
      issuedAt: Date.now(),
      expiresAt,
    }, current.data.hostSeed);
  }

  createBridgeAccessRequest(bridgeId: string): HostResult<Record<string, unknown>> {
    const current = this.currentHostGrant();
    if (!current.ok) return current;
    const issuedAt = Date.now();
    const payload = {
      version: 1 as const,
      bridgeId,
      serverId: this.serverId,
      hostId: current.data.grant.payload.hostId,
      grantId: current.data.grant.payload.grantId,
      slot: "registration" as const,
      proofId: randomUUID(),
      issuedAt,
      expiresAt: issuedAt + 30_000,
    };
    return ok({
      authorityPublicKey: this.authorityPublicKey(),
      grant: current.data.grant,
      proof: {
        payload,
        publicKey: current.data.grant.payload.devicePublicKey,
        signature: signCanonicalPayload(current.data.hostSeed, BRIDGE_ACCESS_DOMAIN, payload).toString("base64url"),
      },
    });
  }

  createPrimaryRegistration(endpoints: string | string[]): HostResult<{
    registration: HostRegistration;
    recordHash: string;
  }> {
    const normalizedEndpoints = [...new Set(Array.isArray(endpoints) ? endpoints : [endpoints])].sort();
    if (normalizedEndpoints.length === 0 || normalizedEndpoints.length > 3) {
      return fail("invalid_input", "one to three signaling endpoints are required");
    }
    const endpointsKey = JSON.stringify(normalizedEndpoints);
    if (this.pendingRegistration?.endpointsKey === endpointsKey) return ok(this.pendingRegistration);
    if (this.pendingRegistration) return fail("conflict", "another host registration is awaiting bridge acknowledgement");

    const current = this.currentHostGrant();
    if (!current.ok) return current;
    const { grant, hostSeed } = current.data;
    const seqKey = `host_record_seq:${grant.payload.hostId}`;
    const hashKey = `host_record_hash:${grant.payload.hostId}`;
    const sequenceRow = this.store.raw.prepare("SELECT value FROM server_meta WHERE key = ?").get(seqKey) as { value: string } | undefined;
    const previousRow = this.store.raw.prepare("SELECT value FROM server_meta WHERE key = ?").get(hashKey) as { value: string } | undefined;
    const recordSeq = Number(sequenceRow?.value ?? 0) + 1;
    const now = Date.now();
    const payload = {
      version: 1 as const,
      serverId: this.serverId,
      grantId: grant.payload.grantId,
      hostId: grant.payload.hostId,
      // A restart-suspended writer must publish the current primary role while proving fresh
      // bridge quorum. Advertising it as a replica would make safe resumption impossible.
      role: (this.writer || this.writerResumeEligibility ? "primary" : "replica") as "primary" | "replica",
      epoch: this.getEpoch(),
      recordSeq,
      previousRecordHash: previousRow?.value ?? null,
      endpoints: normalizedEndpoints,
      candidates: [],
      issuedAt: now,
      ttlMs: 5 * 60_000,
      expiresAt: now + 5 * 60_000,
    };
    const record = createSignedHostRecord(payload, hostSeed);
    const registration = {
      authorityPublicKey: this.authorityPublicKey(),
      grant,
      record,
    } satisfies HostRegistration;
    this.pendingRegistration = {
      endpointsKey,
      registration,
      recordHash: hostRegistrationRecordHash(record),
      committed: false,
    };
    return ok(this.pendingRegistration);
  }

  provePrimaryRegistration(challenge: unknown): HostResult<Record<string, unknown>> {
    const input = (challenge ?? {}) as Record<string, unknown>;
    const parsed = BridgeRegistrationChallengeSchema.safeParse({
      requestId: input.requestId,
      challengeId: input.challengeId,
      nonce: input.nonce,
      recordHash: input.recordHash,
      expiresAt: input.expiresAt,
    });
    if (!parsed.success) return fail("invalid_input", "malformed bridge registration challenge");
    const registration = this.pendingRegistration?.recordHash === parsed.data.recordHash
      ? this.pendingRegistration.registration
      : this.registrationChain().find((entry) => entry.recordHash === parsed.data.recordHash)?.registration;
    if (!registration) {
      return fail("unauthorized", "bridge challenge does not match the pending host record");
    }
    const now = Date.now();
    if (parsed.data.expiresAt <= now) return fail("unauthorized", "bridge registration challenge expired");
    const hostSeed = this.hostSigningSeed();
    if (!hostSeed) return fail("unavailable", "JC_HOST_SIGNING_SEED is required for registration proof");
    const { record } = registration;
    const proof = createSignedBridgeRegistrationProof({
      version: 1,
      serverId: record.payload.serverId,
      hostId: record.payload.hostId,
      grantId: record.payload.grantId,
      recordHash: parsed.data.recordHash,
      challengeId: parsed.data.challengeId,
      nonce: parsed.data.nonce,
      issuedAt: now,
      expiresAt: Math.min(parsed.data.expiresAt, now + 30_000),
    }, hostSeed);
    return ok(proof);
  }

  commitPrimaryRegistration(recordHash: string): HostResult<null> {
    if (!this.pendingRegistration || this.pendingRegistration.recordHash !== recordHash) {
      return fail("conflict", "no matching pending host registration");
    }
    if (this.pendingRegistration.committed) return ok(null);
    const { record } = this.pendingRegistration.registration;
    this.store.raw.transaction(() => {
      this.store.raw.prepare(
        "INSERT INTO server_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      ).run(`host_record_seq:${record.payload.hostId}`, String(record.payload.recordSeq));
      this.store.raw.prepare(
        "INSERT INTO server_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      ).run(`host_record_hash:${record.payload.hostId}`, hostRegistrationRecordHash(record));
      this.store.raw.prepare(
        "INSERT OR IGNORE INTO host_record_chains (host_id, record_seq, record_hash, registration, committed_at) VALUES (?,?,?,?,?)",
      ).run(record.payload.hostId, record.payload.recordSeq, hostRegistrationRecordHash(record), JSON.stringify(this.pendingRegistration!.registration), Date.now());
    })();
    // Keep the committed round available so late challenges/ACKs from slower bridges can use
    // exactly the same record. The coordinator abandons it only when starting the next renewal.
    this.pendingRegistration.committed = true;
    return ok(null);
  }

  registrationChain(): { recordSeq: number; recordHash: string; registration: HostRegistration }[] {
    const current = this.currentHostGrant();
    if (!current.ok) return [];
    const rows = this.store.raw.prepare(
      "SELECT record_seq, record_hash, registration FROM host_record_chains WHERE host_id = ? ORDER BY record_seq",
    ).all(current.data.grant.payload.hostId) as { record_seq: number; record_hash: string; registration: string }[];
    return rows.map((row) => ({
      recordSeq: row.record_seq,
      recordHash: row.record_hash,
      registration: JSON.parse(row.registration) as HostRegistration,
    }));
  }

  abandonPrimaryRegistration(recordHash?: string): void {
    if (!this.pendingRegistration) return;
    if (!recordHash || this.pendingRegistration.recordHash === recordHash) this.pendingRegistration = null;
  }

  private isBanned(identityId: string): boolean {
    return !!this.store.raw.prepare("SELECT 1 FROM bans WHERE identity_id = ?").get(identityId);
  }

  // ------------------------------------------------------------- membership

  joinByInvite(identityId: string, nickname: string, secret: string, devicePublicKey: string): HostResult<Record<string, unknown>> {
    if (this.getMember(identityId)) return fail("conflict", "already a member");
    if (this.isBanned(identityId)) return fail("banned", "identity banned from this server");
    const parsedV3 = parseInviteV3(secret);
    const parsedLegacy = parsedV3 ? null : parseInviteKey(secret);
    if (!parsedV3 && !parsedLegacy) return fail("invalid_invite", "invite malformado ou assinatura inválida");
    const inviteServerId = parsedV3?.payload.serverId ?? parsedLegacy!.serverId;
    if (inviteServerId !== this.serverId) return fail("invalid_invite", "invite de outro server");
    if (parsedV3 && parsedV3.publicKey !== this.authorityPublicKey()) return fail("invalid_invite", "autoridade do invite não corresponde ao server");
    const secretBytes = parsedV3
      ? Buffer.from(parsedV3.payload.inviteSecret, "base64url")
      : parsedLegacy!.secret;
    const hash = sha256Hex(createHmac("sha256", this.inviteHashKey()).update(secretBytes).digest());
    const invite = this.store.raw
      .prepare("SELECT * FROM invites WHERE secret_hash = ?")
      .get(hash) as
      | { id: string; initial_role_id: string; max_uses: number; used: number; expires_at: number | null; revoked: number }
      | undefined;
    if (!invite) return fail("invalid_invite", "invite not found");
    if (invite.revoked) return fail("invite_revoked", "invite revoked");
    if (invite.expires_at && invite.expires_at < Date.now()) return fail("invite_expired", "invite expired");
    if (invite.used >= invite.max_uses) return fail("invite_exhausted", "invite exhausted");
    this.store.raw.transaction(() => {
      this.store.raw.prepare("UPDATE invites SET used = used + 1 WHERE id = ?").run(invite.id);
      this.store.raw
        .prepare("INSERT INTO members (identity_id, nickname, role_id, joined_at) VALUES (?,?,?,?)")
        .run(identityId, nickname, invite.initial_role_id, Date.now());
      this.store.raw.prepare(
        "INSERT INTO member_devices (identity_id, device_public_key, added_at) VALUES (?,?,?)",
      ).run(identityId, devicePublicKey, Date.now());
      this.store.appendOp({ type: "join", identityId, inviteId: invite.id });
    })();
    this.events.emit("inviteUsed", invite.id);
    this.events.emit("stateChanged");
    return this.getState(identityId);
  }

  authorizeDeviceLink(
    identityId: string,
    authorizingDevicePublicKey: string,
    newDevicePublicKey: string,
    expiresInMs = 5 * 60_000,
  ): HostResult<{ capability: string; expiresAt: number }> {
    if (!this.getMember(identityId)) return fail("forbidden", "not a member");
    if (!this.isAuthorizedDevice(identityId, authorizingDevicePublicKey)) {
      return fail("unauthorized", "an already-linked device must authorize the new device");
    }
    if (this.isAuthorizedDevice(identityId, newDevicePublicKey)) {
      return fail("conflict", "device is already linked to this identity");
    }
    const ttl = Math.max(30_000, Math.min(10 * 60_000, expiresInMs));
    const issuedAt = Date.now();
    const expiresAt = issuedAt + ttl;
    const capability = `JDL1-${randomBytes(32).toString("base64url")}`;
    const tokenHash = sha256Hex(capability);
    try {
      this.store.raw.transaction(() => {
        this.store.raw.prepare(
          "DELETE FROM device_link_capabilities WHERE expires_at <= ? OR consumed_at IS NOT NULL",
        ).run(issuedAt);
        const active = this.store.raw.prepare(
          "SELECT COUNT(*) AS count FROM device_link_capabilities WHERE identity_id = ? AND expires_at > ? AND consumed_at IS NULL",
        ).get(identityId, issuedAt) as { count: number };
        if (Number(active.count) >= 8) throw new Error("active capability limit reached");
        this.store.raw.prepare(
          "INSERT INTO device_link_capabilities (token_hash, identity_id, device_public_key, issued_at, expires_at) VALUES (?,?,?,?,?)",
        ).run(tokenHash, identityId, newDevicePublicKey, issuedAt, expiresAt);
      })();
    } catch {
      return fail("rate_limited", "too many active device-link capabilities");
    }
    return ok({ capability, expiresAt });
  }

  enrollDevice(identityId: string, devicePublicKey: string, capability: string): HostResult<Record<string, unknown>> {
    if (!this.getMember(identityId)) return fail("forbidden", "not a member");
    if (!/^JDL1-[A-Za-z0-9_-]{43}$/.test(capability)) {
      return fail("unauthorized", "valid device-link capability required");
    }
    const now = Date.now();
    const tokenHash = sha256Hex(capability);
    try {
      this.store.raw.transaction(() => {
        const consumed = this.store.raw.prepare(
          "UPDATE device_link_capabilities SET consumed_at = ? WHERE token_hash = ? AND identity_id = ? AND device_public_key = ? AND consumed_at IS NULL AND expires_at > ?",
        ).run(now, tokenHash, identityId, devicePublicKey, now);
        if (consumed.changes !== 1) throw new Error("capability rejected");
        this.store.raw.prepare(
          "INSERT INTO member_devices (identity_id, device_public_key, added_at) VALUES (?,?,?)",
        ).run(identityId, devicePublicKey, now);
        this.store.appendOp({ type: "deviceEnroll", identityId, devicePublicKey });
      })();
    } catch {
      return fail("unauthorized", "device-link capability is invalid, expired, consumed, or bound to another device");
    }
    this.events.emit("stateChanged");
    return ok({ enrolled: true });
  }

  leave(identityId: string): HostResult<null> {
    const m = this.getMember(identityId);
    if (!m) return fail("not_found", "not a member");
    if (m.role_id === "role-owner") return fail("forbidden", "owner cannot leave; transfer ownership first");
    this.store.raw.prepare("DELETE FROM members WHERE identity_id = ?").run(identityId);
    this.store.appendOp({ type: "leave", identityId });
    this.events.emit("memberRemoved", identityId, "left");
    this.events.emit("stateChanged");
    return ok(null);
  }

  transferOwnership(actorId: string, newOwnerId: string): HostResult<null> {
    const actor = this.getMember(actorId);
    const target = this.getMember(newOwnerId);
    if (!actor || actor.role_id !== "role-owner") return fail("forbidden", "only owner can transfer");
    if (!target) return fail("not_found", "target not a member");
    this.store.raw.transaction(() => {
      this.store.raw.prepare("UPDATE members SET role_id = 'role-member' WHERE identity_id = ?").run(actorId);
      this.store.raw.prepare("UPDATE members SET role_id = 'role-owner' WHERE identity_id = ?").run(newOwnerId);
      this.store.appendOp({ type: "transferOwnership", from: actorId, to: newOwnerId });
    })();
    this.events.emit("stateChanged");
    return ok(null);
  }

  // ----------------------------------------------------------------- invites

  inviteCreate(
    actorId: string,
    initialRoleId: string,
    maxUses: number,
    expiresInMs?: number,
  ): HostResult<{ inviteId: string; inviteKey: string }> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const role = this.getRole(initialRoleId);
    if (!role) return fail("not_found", "role not found");
    const actorRole = this.getRole(actor.role_id)!;
    const actorCtx = this.memberContext(actor);
    if (!evaluatePermission(actorCtx, actorRole, null, "manage_invites")) {
      return fail("forbidden", "no manage_invites");
    }
    const authoritySeed = this.authoritySeed();
    if (!authoritySeed) return fail("forbidden", "authority signing is unavailable on this replica");
    const secret = randomBytes(16);
    const issuedAt = Date.now();
    const expiresAt = issuedAt + (expiresInMs ?? 30 * 24 * 3600_000);
    const hash = sha256Hex(createHmac("sha256", this.inviteHashKey()).update(secret).digest());
    const accessHash = sha256Hex(secret);
    const id = randomUUID();
    this.store.raw
      .prepare("INSERT INTO invites (id, secret_hash, access_hash, initial_role_id, max_uses, used, expires_at, revoked, created_at) VALUES (?,?,?,?,?,0,?,0,?)")
      .run(id, hash, accessHash, initialRoleId, maxUses, expiresAt, issuedAt);
    this.store.appendOp({ type: "inviteCreate", inviteId: id });
    this.events.emit("stateChanged");
    const hints = this.configuredBridgeHints();
    if (hints.length === 0) {
      const directEndpoint = process.env.JC_DIRECT_ENDPOINT ?? `127.0.0.1:${process.env.JC_PORT ?? "8931"}`;
      return ok({ inviteId: id, inviteKey: formatInviteKey(this.serverId, secret, directEndpoint) });
    }
    for (let count = hints.length; count >= 0; count--) {
      try {
        const invite = createSignedInviteV3({
          version: 3,
          serverId: this.serverId,
          authorityFingerprint: this.authorityFingerprint(),
          inviteSecret: secret.toString("base64url"),
          bridgeHints: hints.slice(0, count),
          issuedAt,
          expiresAt,
        }, authoritySeed);
        return ok({ inviteId: id, inviteKey: formatInviteV3(invite) });
      } catch (error) {
        if (count === 0) return fail("invalid_input", `could not encode JC3: ${(error as Error).message}`);
      }
    }
    return fail("internal", "could not encode JC3");
  }

  inviteList(actorId: string): HostResult<Record<string, unknown>[]> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const role = this.getRole(actor.role_id)!;
    if (!evaluatePermission(this.memberContext(actor), role, null, "manage_invites")) {
      return fail("forbidden", "no manage_invites");
    }
    const now = Date.now();
    const rows = this.store.raw.prepare(
      "SELECT id, initial_role_id, max_uses, used, expires_at, revoked, created_at FROM invites ORDER BY created_at DESC",
    ).all() as { id: string; initial_role_id: string; max_uses: number; used: number; expires_at: number | null; revoked: number; created_at: number }[];
    return ok(rows.map((row) => ({
      inviteId: row.id,
      initialRoleId: row.initial_role_id,
      maxUses: row.max_uses,
      used: row.used,
      expiresAt: row.expires_at,
      createdAt: row.created_at,
      status: row.revoked ? "revoked" : row.expires_at !== null && row.expires_at <= now
        ? "expired" : row.used >= row.max_uses ? "exhausted" : "active",
    })));
  }

  private configuredBridgeHints(): SignedBridgeDescriptor[] {
    const source = process.env.JC_BRIDGE_DESCRIPTORS;
    if (!source) return [];
    try {
      const values = JSON.parse(source) as unknown[];
      if (!Array.isArray(values)) return [];
      return values
        .slice(0, 3)
        .map((value) => SignedBridgeDescriptorSchema.safeParse(value))
        .filter((entry) => entry.success)
        .map((entry) => verifySignedBridgeDescriptor(entry.data))
        .filter((entry): entry is SignedBridgeDescriptor => entry !== null);
    } catch {
      return [];
    }
  }

  private configuredBridgePairings(): Map<string, string> {
    try {
      const input = JSON.parse(process.env.JC_BRIDGE_PAIRINGS ?? "[]") as unknown;
      if (!Array.isArray(input)) return new Map();
      const entries = input.slice(0, 3)
        .map((value) => BridgePairingBindingSchema.safeParse(value))
        .filter((entry) => entry.success)
        .map((entry) => [entry.data.bridgeId, entry.data.pairingToken] as const);
      return new Map(entries);
    } catch {
      return new Map();
    }
  }

  private configuredBridgeAccess(): { descriptor: SignedBridgeDescriptor }[] {
    return this.configuredBridgeHints().map((descriptor) => ({ descriptor }));
  }

  private configuredRegistrationBridgeIds(): string[] {
    const targets = [...new Map(
      this.bridgeRegistrationTargets().map((target) => [target.rendezvousUrl, target] as const),
    ).values()];
    if (targets.length > 0) return targets.map((target) => target.bridgeId).sort();
    return process.env.JC_RENDEZVOUS_URL && process.env.JC_PUBLIC_URL ? ["legacy"] : [];
  }

  bridgeRegistrationTargets(): { bridgeId: string; rendezvousUrl: string; signalingUrl: string; pairingToken?: string }[] {
    const allowLoopbackDowngrade = process.env.JC_ALLOW_INSECURE_BRIDGE_LOOPBACK === "1";
    const pairings = this.configuredBridgePairings();
    const targets: { bridgeId: string; rendezvousUrl: string; signalingUrl: string; pairingToken?: string }[] = [];
    for (const descriptor of this.configuredBridgeHints()) {
      const endpoint = descriptor.payload.endpoints.find((value) => value.startsWith("wss://") || value.startsWith("https://"));
      if (!endpoint) continue;
      const base = new URL(endpoint);
      const rendezvous = new URL(base);
      const signaling = new URL(base);
      rendezvous.protocol = "wss:";
      signaling.protocol = "wss:";
      rendezvous.pathname = "/rendezvous";
      signaling.pathname = "/signaling";
      if (allowLoopbackDowngrade && ["127.0.0.1", "localhost", "::1"].includes(rendezvous.hostname)) {
        rendezvous.protocol = "ws:";
      }
      targets.push({
        bridgeId: descriptor.payload.bridgeId,
        rendezvousUrl: rendezvous.toString(),
        signalingUrl: signaling.toString(),
        ...(pairings.get(descriptor.payload.bridgeId) ? { pairingToken: pairings.get(descriptor.payload.bridgeId) } : {}),
      });
    }
    return targets.slice(0, 3);
  }

  upsertBridgeIceConfig(source: string, value: unknown): boolean {
    const parsed = parseTemporaryTurnCredentials(value);
    if (!parsed) return false;
    this.bridgeIceConfigs.set(source, parsed);
    return true;
  }

  removeBridgeIceConfig(source: string): void {
    this.bridgeIceConfigs.delete(source);
  }

  connectivityIceConfig(actorId: string): HostResult<ReturnType<typeof browserRtcIceConfiguration>> {
    if (!this.getMember(actorId)) return fail("forbidden", "active member required");
    const now = Date.now();
    for (const [source, config] of this.bridgeIceConfigs) {
      if (config.expiresAt <= now) this.bridgeIceConfigs.delete(source);
    }
    const configs = [...this.bridgeIceConfigs.values()].sort((a, b) => b.expiresAt - a.expiresAt);
    if (configs.length === 0) return fail("host_offline", "no valid temporary TURN credential is available");
    const policy = this.getConfig().networkPrivacy === "relay" ? "relay" : "direct";
    return ok(browserRtcIceConfiguration([], configs[0], policy));
  }

  // --------------------------------------------------------- community hosts

  private mayManageHosts(actorId: string): MemberRow | null {
    const actor = this.getMember(actorId);
    if (!actor) return null;
    const role = this.getRole(actor.role_id)!;
    return evaluatePermission(this.memberContext(actor), role, null, "manage_hosts") ? actor : null;
  }

  private hostGrantRows(subjectIdentityId?: string): Record<string, unknown>[] {
    return this.store.raw.prepare(
      "SELECT * FROM host_grants WHERE (? IS NULL OR subject_identity_id = ?) ORDER BY created_at DESC",
    ).all(subjectIdentityId ?? null, subjectIdentityId ?? null) as Record<string, unknown>[];
  }

  private hostCandidateRows(subjectIdentityId?: string): Record<string, unknown>[] {
    const rows = this.store.raw.prepare(
      `SELECT c.*, m.nickname
       FROM host_candidates c
       JOIN members m ON m.identity_id = c.subject_identity_id
       JOIN member_devices d
         ON d.identity_id = c.subject_identity_id
        AND d.device_public_key = c.subject_auth_public_key
        AND d.revoked_at IS NULL
       WHERE (? IS NULL OR c.subject_identity_id = ?)
       ORDER BY c.created_at DESC`,
    ).all(subjectIdentityId ?? null, subjectIdentityId ?? null) as Record<string, unknown>[];
    const now = Date.now();
    return rows.map((row) => {
      const accepted = this.store.raw.prepare(
        `SELECT 1 FROM host_grants
         WHERE subject_identity_id = ? AND host_id = ? AND device_public_key = ?
           AND enrollment_public_key = ? AND accepted_at IS NOT NULL
           AND revoked_at IS NULL AND expires_at > ? LIMIT 1`,
      ).get(row.subject_identity_id, row.host_id, row.host_public_key, row.enrollment_public_key, now);
      const status = row.revoked_at ? "revoked" : Number(row.expires_at) <= now ? "expired" : accepted ? "accepted" : "pending";
      return {
        candidateId: row.candidate_id,
        subjectIdentityId: row.subject_identity_id,
        nickname: row.nickname,
        subjectAuthPublicKey: row.subject_auth_public_key,
        hostPublicKey: row.host_public_key,
        enrollmentPublicKey: row.enrollment_public_key,
        hostId: row.host_id,
        status,
        createdAt: row.created_at,
        expiresAt: row.expires_at,
      };
    });
  }

  private publicHostGrant(row: Record<string, unknown>): Record<string, unknown> {
    const now = Date.now();
    const status = row.revoked_at ? "revoked" : Number(row.expires_at) <= now ? "expired" : row.accepted_at ? "accepted" : "pending";
    return {
      grantId: row.grant_id,
      subjectIdentityId: row.subject_identity_id,
      subjectAuthPublicKey: row.subject_auth_public_key,
      hostPublicKey: row.device_public_key,
      enrollmentPublicKey: row.enrollment_public_key,
      hostId: row.host_id,
      status,
      capabilities: JSON.parse(String(row.capabilities)) as string[],
      expiresAt: row.expires_at,
      createdAt: row.created_at,
      acceptedAt: row.accepted_at,
      revokedAt: row.revoked_at,
    };
  }

  private eligibleHostDevices(subjectIdentityId?: string): Record<string, unknown>[] {
    const rows = this.store.raw.prepare(
      `SELECT d.identity_id, m.nickname, d.device_public_key, d.added_at
       FROM member_devices d
       JOIN members m ON m.identity_id = d.identity_id
       WHERE d.revoked_at IS NULL
         AND (? IS NULL OR d.identity_id = ?)
       ORDER BY d.added_at DESC`,
    ).all(subjectIdentityId ?? null, subjectIdentityId ?? null) as {
      identity_id: string;
      nickname: string;
      device_public_key: string;
      added_at: number;
    }[];
    return rows.map((row) => ({
      subjectIdentityId: row.identity_id,
      nickname: row.nickname,
      subjectDevicePublicKey: row.device_public_key,
      addedAt: row.added_at,
    }));
  }

  hostCandidateRegister(
    actorId: string,
    subjectAuthPublicKey: string,
    hostPublicKey: string,
    enrollmentPublicKey: string,
    hostId: string,
    deviceProof: HostPossessionProof,
    hostProof: HostPossessionProof,
  ): HostResult<Record<string, unknown>> {
    if (!this.getMember(actorId) || !this.isAuthorizedDevice(actorId, subjectAuthPublicKey)) {
      return fail("forbidden", "active member and authorized device required");
    }
    if (hostPublicKey === subjectAuthPublicKey) {
      return fail("invalid_input", "host signing key must be distinct from identity authentication key");
    }
    const enrollmentRaw = Buffer.from(enrollmentPublicKey, "base64url");
    if (enrollmentRaw.length !== 32 || enrollmentRaw.toString("base64url") !== enrollmentPublicKey) {
      return fail("invalid_input", "replica enrollment public key must be a raw X25519 public key");
    }
    const common = { serverId: this.serverId, subjectIdentityId: actorId, subjectAuthPublicKey, hostPublicKey, enrollmentPublicKey, hostId };
    const verify = (proof: HostPossessionProof, publicKey: string, domain: string): boolean => {
      if (!Number.isSafeInteger(proof.issuedAt) || Math.abs(Date.now() - proof.issuedAt) > 30_000) return false;
      const signature = Buffer.from(proof.signature, "base64url");
      return signature.length === 64 && signature.toString("base64url") === proof.signature
        && verifyCanonicalPayload(Buffer.from(publicKey, "base64url"), domain, {
          ...common, proofId: proof.proofId, issuedAt: proof.issuedAt,
        }, signature);
    };
    if (!verify(deviceProof, subjectAuthPublicKey, HOST_CANDIDATE_DEVICE_DOMAIN)) {
      return fail("unauthorized", "fresh authenticated device proof required");
    }
    if (!verify(hostProof, hostPublicKey, HOST_CANDIDATE_POSSESSION_DOMAIN)) {
      return fail("unauthorized", "fresh proof of possession of the distinct host signing key required");
    }
    const candidateId = randomUUID();
    const createdAt = Date.now();
    const expiresAt = createdAt + 30 * 24 * 3600_000;
    try {
      this.store.raw.transaction(() => {
        this.consumeSecurityProof(deviceProof.proofId, "candidate-device");
        this.consumeSecurityProof(hostProof.proofId, "candidate-host");
        this.store.raw.prepare(
          `INSERT INTO host_candidates
           (candidate_id, subject_identity_id, subject_auth_public_key, host_public_key,
            enrollment_public_key, host_id, device_proof, host_proof, created_at, expires_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)`,
        ).run(
          candidateId, actorId, subjectAuthPublicKey, hostPublicKey, enrollmentPublicKey, hostId,
          JSON.stringify(deviceProof), JSON.stringify(hostProof), createdAt, expiresAt,
        );
        this.store.appendOp({ type: "hostCandidateRegister", candidateId, subjectIdentityId: actorId, hostId });
      })();
    } catch {
      return fail("conflict", "candidate proof was already consumed");
    }
    this.events.emit("stateChanged");
    return ok({ candidate: this.hostCandidateRows(actorId).find((candidate) => candidate.candidateId === candidateId) });
  }

  hostGrantCreate(
    actorId: string,
    subjectIdentityId: string,
    candidateId: string,
    capabilities: HostCapability[],
    expiresInMs = 365 * 24 * 3600_000,
  ): HostResult<Record<string, unknown>> {
    if (!this.mayManageHosts(actorId)) return fail("forbidden", "no manage_hosts");
    if (!this.getMember(subjectIdentityId)) return fail("not_found", "host subject is not a member");
    const candidate = this.hostCandidateRows(subjectIdentityId).find((entry) => (
      entry.candidateId === candidateId && !["revoked", "expired"].includes(String(entry.status))
    ));
    if (!candidate) return fail("forbidden", "active host candidate from an authorized member device required");
    const subjectAuthPublicKey = String(candidate.subjectAuthPublicKey);
    const hostPublicKey = String(candidate.hostPublicKey);
    const enrollmentPublicKey = String(candidate.enrollmentPublicKey);
    const hostId = String(candidate.hostId);
    const authoritySeed = this.authoritySeed();
    if (!authoritySeed) return fail("forbidden", "authority signing is unavailable on this replica");
    const now = Date.now();
    const grant = createSignedHostGrant({
      version: 1,
      grantId: randomUUID(),
      serverId: this.serverId,
      issuerIdentityId: actorId,
      subjectIdentityId,
      subjectAuthPublicKey,
      devicePublicKey: hostPublicKey,
      hostId,
      capabilities,
      ...(trustedBridgePublicKeys().size >= 2
        ? { witnessBridgeIds: [...trustedBridgePublicKeys().keys()].sort() }
        : {}),
      generation: this.nextHostGeneration(hostId),
      issuedAt: now,
      expiresAt: now + expiresInMs,
    }, authoritySeed);
    this.store.raw.prepare(
      "INSERT INTO host_grants (grant_id, subject_identity_id, host_id, subject_auth_public_key, device_public_key, enrollment_public_key, capabilities, payload, signature, expires_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
    ).run(
      grant.payload.grantId,
      subjectIdentityId,
      hostId,
      subjectAuthPublicKey,
      hostPublicKey,
      enrollmentPublicKey,
      JSON.stringify(capabilities),
      JSON.stringify(grant.payload),
      grant.signature,
      grant.payload.expiresAt,
      now,
    );
    this.store.appendOp({ type: "hostGrantCreate", grantId: grant.payload.grantId, subjectIdentityId, hostId });
    this.events.emit("stateChanged");
    return ok({
      grant,
      candidateId,
    });
  }

  hostGrantRevoke(actorId: string, grantId: string, reason?: string): HostResult<Record<string, unknown>> {
    if (!this.mayManageHosts(actorId)) return fail("forbidden", "no manage_hosts");
    const authoritySeed = this.authoritySeed();
    if (!authoritySeed) return fail("forbidden", "authority signing is unavailable on this replica");
    const row = this.store.raw.prepare("SELECT grant_id, host_id, revoked_at FROM host_grants WHERE grant_id = ?").get(grantId) as
      | { grant_id: string; host_id: string; revoked_at: number | null }
      | undefined;
    if (!row) return fail("not_found", "host grant not found");
    if (row.revoked_at) return fail("conflict", "host grant already revoked");
    const revokedAt = Date.now();
    const revocation = createSignedHostGrantRevocation({
      version: 1,
      serverId: this.serverId,
      grantId,
      hostId: row.host_id,
      issuerIdentityId: actorId,
      revokedAt,
      generation: this.nextHostGeneration(row.host_id),
      ...(reason ? { reason } : {}),
    }, authoritySeed);
    this.store.raw.prepare(
      "UPDATE host_grants SET revoked_at = ?, revocation_payload = ?, revocation_signature = ? WHERE grant_id = ?",
    ).run(revokedAt, JSON.stringify(revocation.payload), revocation.signature, grantId);
    this.store.appendOp({ type: "hostGrantRevoke", grantId, revokedAt });
    this.events.emit("hostGrantRevoked", revocation);
    this.events.emit("stateChanged");
    return ok({ revocation });
  }

  private verifyHostPossession(
    purpose: "accept" | "enroll",
    grant: SignedHostGrant,
    enrollmentPublicKey: string,
    proof: HostPossessionProof,
  ): boolean {
    const now = Date.now();
    if (!Number.isSafeInteger(proof.issuedAt) || Math.abs(now - proof.issuedAt) > 30_000) return false;
    const signature = Buffer.from(proof.signature, "base64url");
    if (signature.length !== 64 || signature.toString("base64url") !== proof.signature) return false;
    const hostPublicKey = Buffer.from(grant.payload.devicePublicKey, "base64url");
    return verifyCanonicalPayload(hostPublicKey, HOST_POSSESSION_DOMAIN, {
      purpose,
      serverId: this.serverId,
      grantId: grant.payload.grantId,
      subjectIdentityId: grant.payload.subjectIdentityId,
      subjectAuthPublicKey: grant.payload.subjectAuthPublicKey,
      hostPublicKey: grant.payload.devicePublicKey,
      enrollmentPublicKey,
      proofId: proof.proofId,
      issuedAt: proof.issuedAt,
    }, signature);
  }

  private consumeSecurityProof(proofId: string, purpose: string): void {
    this.store.raw.prepare(
      "INSERT INTO security_proofs (proof_id, purpose, consumed_at) VALUES (?,?,?)",
    ).run(proofId, purpose, Date.now());
  }

  hostGrantAccept(
    actorId: string,
    devicePublicKey: string,
    grantId: string,
    hostProof: HostPossessionProof,
  ): HostResult<Record<string, unknown>> {
    if (!this.getMember(actorId) || !this.isAuthorizedDevice(actorId, devicePublicKey)) {
      return fail("forbidden", "active member and authorized device required");
    }
    const row = this.store.raw.prepare(
      "SELECT subject_identity_id, subject_auth_public_key, device_public_key, enrollment_public_key, payload, signature, expires_at, accepted_at, revoked_at FROM host_grants WHERE grant_id = ?",
    ).get(grantId) as {
      subject_identity_id: string;
      subject_auth_public_key: string;
      device_public_key: string;
      enrollment_public_key: string;
      payload: string;
      signature: string;
      expires_at: number;
      accepted_at: number | null;
      revoked_at: number | null;
    } | undefined;
    if (!row) return fail("not_found", "host grant not found");
    if (row.subject_identity_id !== actorId || row.subject_auth_public_key !== devicePublicKey) {
      return fail("forbidden", "grant is bound to another member or authenticated device");
    }
    if (row.revoked_at || row.expires_at <= Date.now()) return fail("forbidden", "grant is revoked or expired");
    const grant = verifySignedHostGrant({
      payload: JSON.parse(row.payload),
      publicKey: this.authorityPublicKey(),
      signature: row.signature,
    }, this.authorityPublicKey());
    if (!grant || !this.verifyHostPossession("accept", grant, row.enrollment_public_key, hostProof)) {
      return fail("unauthorized", "fresh proof of possession of the distinct host signing key required");
    }
    if (row.accepted_at) return fail("conflict", "grant acceptance proof was already consumed");
    const acceptedAt = Date.now();
    try {
      this.store.raw.transaction(() => {
        this.consumeSecurityProof(hostProof.proofId, "grant-accept");
        this.store.raw.prepare("UPDATE host_grants SET accepted_at = ? WHERE grant_id = ?").run(acceptedAt, grantId);
        this.store.appendOp({ type: "hostGrantAccept", grantId, actorId, acceptedAt });
      })();
    } catch {
      return fail("conflict", "grant acceptance proof was already consumed");
    }
    this.events.emit("stateChanged");
    return ok({ grantId, accepted: true });
  }

  private activeHostGrant(
    actorId: string,
    subjectAuthPublicKey: string,
    grantId: string,
    capability: HostCapability,
  ): HostResult<SignedHostGrant> {
    const actor = this.getMember(actorId);
    if (!actor || !this.isAuthorizedDevice(actorId, subjectAuthPublicKey)) {
      return fail("forbidden", "active member and authorized grant-bound device required");
    }
    const row = this.store.raw.prepare(
      "SELECT subject_identity_id, subject_auth_public_key, device_public_key, host_id, payload, signature, accepted_at, revoked_at, expires_at FROM host_grants WHERE grant_id = ?",
    ).get(grantId) as {
      subject_identity_id: string;
      subject_auth_public_key: string;
      device_public_key: string;
      host_id: string;
      payload: string;
      signature: string;
      accepted_at: number | null;
      revoked_at: number | null;
      expires_at: number;
    } | undefined;
    if (
      !row ||
      row.subject_identity_id !== actorId ||
      row.subject_auth_public_key !== subjectAuthPublicKey ||
      !row.accepted_at ||
      row.revoked_at ||
      row.expires_at <= Date.now()
    ) {
      return fail("forbidden", "accepted active host grant required");
    }
    const grant = verifySignedHostGrant({
      payload: JSON.parse(row.payload),
      publicKey: this.authorityPublicKey(),
      signature: row.signature,
    }, this.authorityPublicKey());
    if (
      !grant ||
      grant.payload.serverId !== this.serverId ||
      grant.payload.grantId !== grantId ||
      grant.payload.subjectIdentityId !== actorId ||
      grant.payload.subjectAuthPublicKey !== subjectAuthPublicKey ||
      grant.payload.devicePublicKey !== row.device_public_key ||
      grant.payload.hostId !== row.host_id ||
      !grant.payload.capabilities.includes(capability)
    ) {
      return fail("forbidden", `active ${capability} grant required`);
    }
    if (grant.payload.generation !== this.currentHostGeneration(grant.payload.hostId)) {
      return fail("forbidden", "host grant generation is stale");
    }
    return ok(grant);
  }

  hostGrantList(actorId: string): HostResult<Record<string, unknown>> {
    if (!this.mayManageHosts(actorId)) return fail("forbidden", "no manage_hosts");
    return ok({
      grants: this.hostGrantRows().map((row) => ({
        ...this.publicHostGrant(row),
        grant: {
          payload: JSON.parse(String(row.payload)),
          publicKey: this.authorityPublicKey(),
          signature: row.signature,
        },
        revocation: row.revocation_payload ? {
          payload: JSON.parse(String(row.revocation_payload)),
          publicKey: this.authorityPublicKey(),
          signature: row.revocation_signature,
        } : null,
      })),
      candidates: this.hostCandidateRows(),
      eligibleHostDevices: this.eligibleHostDevices(),
    });
  }

  hostRevocations(): Record<string, unknown>[] {
    return this.hostGrantRows().filter((row) => row.revocation_payload).map((row) => ({
      payload: JSON.parse(String(row.revocation_payload)),
      publicKey: this.authorityPublicKey(),
      signature: row.revocation_signature,
    }));
  }

  inviteRevoke(actorId: string, inviteId: string): HostResult<null> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const actorRole = this.getRole(actor.role_id)!;
    if (!evaluatePermission(this.memberContext(actor), actorRole, null, "manage_invites")) {
      return fail("forbidden", "no manage_invites");
    }
    const r = this.store.raw.prepare("UPDATE invites SET revoked = 1 WHERE id = ?").run(inviteId);
    if (r.changes === 0) return fail("not_found", "invite not found");
    this.store.appendOp({ type: "inviteRevoke", inviteId });
    this.events.emit("stateChanged");
    return ok(null);
  }

  // -------------------------------------------------------------- channels

  channelCreate(actorId: string, type: "text" | "call", name: string): HostResult<Channel> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const actorRole = this.getRole(actor.role_id)!;
    if (!evaluatePermission(this.memberContext(actor), actorRole, null, "manage_channels")) {
      return fail("forbidden", "no manage_channels");
    }
    const channel: Channel = { id: randomUUID(), serverId: this.serverId, type, name, overrides: [], createdAt: Date.now() };
    this.store.raw
      .prepare("INSERT INTO channels (id, type, name, overrides, created_at) VALUES (?,?,?,?,?)")
      .run(channel.id, channel.type, channel.name, "[]", channel.createdAt);
    this.store.appendOp({ type: "channelCreate", channelId: channel.id });
    this.events.emit("stateChanged");
    return ok(channel);
  }

  channelUpdateOverrides(
    actorId: string,
    channelId: string,
    overrides: Channel["overrides"],
  ): HostResult<Channel> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const actorRole = this.getRole(actor.role_id)!;
    if (!evaluatePermission(this.memberContext(actor), actorRole, null, "manage_channels")) {
      return fail("forbidden", "no manage_channels");
    }
    const channel = this.getChannel(channelId);
    if (!channel) return fail("not_found", "channel not found");
    this.store.raw.prepare("UPDATE channels SET overrides = ? WHERE id = ?").run(JSON.stringify(overrides), channelId);
    this.store.appendOp({ type: "channelOverrides", channelId });
    this.events.emit("stateChanged");
    return ok({ ...channel, overrides });
  }

  // ----------------------------------------------------------------- roles

  roleCreate(actorId: string, name: string, level: number, permissions: string[]): HostResult<Role> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    const actorRole = this.getRole(actor.role_id)!;
    if (!evaluatePermission(this.memberContext(actor), actorRole, null, "manage_roles")) {
      return fail("forbidden", "no manage_roles");
    }
    const isOwner = actor.role_id === "role-owner";
    if (!isOwner && level >= actorRole.level) return fail("forbidden", "cannot create role at/above your level");
    const requested = PermissionFlagSchema.options.filter((permission) => permissions.includes(permission));
    if (!isOwner && requested.some((permission) => !actorRole.permissions.includes(permission))) {
      return fail("forbidden", "cannot delegate a permission you do not hold");
    }
    if (!isOwner && requested.includes("manage_hosts")) {
      return fail("forbidden", "only owner can delegate manage_hosts");
    }
    const role: Role = { id: randomUUID(), name, level, permissions: requested };
    this.store.raw
      .prepare("INSERT INTO roles (id, name, level, permissions, created_at) VALUES (?,?,?,?,?)")
      .run(role.id, role.name, role.level, JSON.stringify(role.permissions), Date.now());
    this.store.appendOp({ type: "roleCreate", roleId: role.id });
    this.events.emit("stateChanged");
    return ok(role);
  }

  roleAssign(actorId: string, memberIdentityId: string, roleId: string): HostResult<null> {
    const actor = this.getMember(actorId);
    const target = this.getMember(memberIdentityId);
    if (!actor || !target) return fail("not_found", "member not found");
    const actorRole = this.getRole(actor.role_id)!;
    const targetRole = this.getRole(target.role_id)!;
    if (!canModify({ ...this.memberContext(actor), role: actorRole }, targetRole, "assign_roles")) {
      return fail("forbidden", "cannot assign roles at/above your level");
    }
    const newRole = this.getRole(roleId);
    if (!newRole) return fail("not_found", "role not found");
    const isOwner = actor.role_id === "role-owner";
    if (!isOwner && newRole.level >= actorRole.level) return fail("forbidden", "cannot assign role at/above your level");
    if (!isOwner && newRole.permissions.some((permission) => !actorRole.permissions.includes(permission))) {
      return fail("forbidden", "cannot assign permissions you do not hold");
    }
    this.store.raw.prepare("UPDATE members SET role_id = ? WHERE identity_id = ?").run(roleId, memberIdentityId);
    this.store.appendOp({ type: "roleAssign", member: memberIdentityId, roleId });
    this.events.emit("stateChanged");
    return ok(null);
  }

  // ------------------------------------------------------------------ kick/ban

  kick(actorId: string, targetId: string): HostResult<null> {
    const actor = this.getMember(actorId);
    const target = this.getMember(targetId);
    if (!actor || !target) return fail("not_found", "member not found");
    const actorRole = this.getRole(actor.role_id)!;
    const targetRole = this.getRole(target.role_id)!;
    if (!canModify({ ...this.memberContext(actor), role: actorRole }, targetRole, "kick_members")) {
      return fail("forbidden", "cannot kick member at/above your level");
    }
    this.store.raw.prepare("DELETE FROM members WHERE identity_id = ?").run(targetId);
    this.store.appendOp({ type: "kick", member: targetId });
    this.events.emit("memberRemoved", targetId, "kick");
    this.events.emit("stateChanged");
    return ok(null);
  }

  ban(actorId: string, targetId: string): HostResult<null> {
    const actor = this.getMember(actorId);
    const target = this.getMember(targetId);
    if (!actor || !target) return fail("not_found", "member not found");
    const actorRole = this.getRole(actor.role_id)!;
    const targetRole = this.getRole(target.role_id)!;
    if (!canModify({ ...this.memberContext(actor), role: actorRole }, targetRole, "ban_members")) {
      return fail("forbidden", "cannot ban member at/above your level");
    }
    this.store.raw.transaction(() => {
      this.store.raw.prepare("DELETE FROM members WHERE identity_id = ?").run(targetId);
      this.store.raw.prepare("INSERT INTO bans (identity_id, banned_at) VALUES (?, ?)").run(targetId, Date.now());
      this.store.appendOp({ type: "ban", member: targetId });
    })();
    this.events.emit("memberRemoved", targetId, "ban");
    this.events.emit("stateChanged");
    return ok(null);
  }

  // ------------------------------------------------------------------- spool

  private authorizedAudience(channel: Channel, members: string[]): HostResult<string[]> {
    const normalized = [...new Set(members)].sort();
    if (normalized.length !== members.length || normalized.length === 0) return fail("invalid_input", "audience must contain unique members");
    for (const identityId of normalized) {
      const member = this.getMember(identityId);
      const role = member ? this.getRole(member.role_id) : undefined;
      if (!member || !role || !evaluatePermission(this.memberContext(member), role, channel, "view_channel")) {
        return fail("forbidden", "audience contains a member without channel access");
      }
    }
    return ok(normalized);
  }

  private memberSpoolQuota(): number {
    const config = this.getConfig();
    const total = Number(config.maxSpoolBytes ?? 2 * 1024 * 1024 * 1024);
    const configured = Number(config.maxMemberSpoolBytes ?? DEFAULT_MEMBER_SPOOL_BYTES);
    return Math.max(1, Math.min(total, configured));
  }

  private currentMemberSpoolBytes(identityId: string): number {
    const row = this.store.raw.prepare(
      "SELECT size_bytes FROM spool_usage WHERE scope_id = ?",
    ).get(`member:${identityId}`) as { size_bytes: number } | undefined;
    return Number(row?.size_bytes ?? 0);
  }

  sendEnvelope(actorId: string, envelope: MessageEnvelope): HostResult<null> {
    const actor = this.getMember(actorId);
    if (!actor) return fail("forbidden", "not a member");
    if (envelope.serverId !== this.serverId) return fail("invalid_input", "server mismatch");
    const channel = this.getChannel(envelope.channelId);
    if (!channel) return fail("not_found", "channel not found");
    const actorRole = this.getRole(actor.role_id)!;
    const need: "send_messages" | "send_files" = envelope.attachments.length > 0 ? "send_files" : "send_messages";
    if (!evaluatePermission(this.memberContext(actor), actorRole, channel, need)) {
      return fail("forbidden", `no ${need}`);
    }
    if (envelope.sender !== actorId) return fail("forbidden", "sender mismatch");
    if (!envelope.audience.members.includes(actorId)) return fail("forbidden", "sender must be in audience");
    const audience = this.authorizedAudience(channel, envelope.audience.members);
    if (!audience.ok) return audience;
    const expectedCommitment = sha256Hex(audience.data.join("\0"));
    if (envelope.audience.commitment !== expectedCommitment) return fail("invalid_input", "audience commitment mismatch");
    const seq = this.seqFor(envelope.channelId).next(actorId);
    envelope.ordering = { seq, prevMessageId: undefined };
    const encodedEnvelope = JSON.stringify(envelope);
    const envelopeBytes = Buffer.byteLength(encodedEnvelope, "utf8");
    if (envelopeBytes > HARD_MAX_ENVELOPE_BYTES) return fail("invalid_input", "message envelope exceeds hard byte limit");
    const spoolQuota = (this.getConfig().maxSpoolBytes as number) ?? 2 * 1024 * 1024 * 1024;
    if (this.currentSpoolBytes() + envelopeBytes > spoolQuota) return fail("rate_limited", "spool quota exceeded");
    if (this.currentMemberSpoolBytes(actorId) + envelopeBytes > this.memberSpoolQuota()) {
      return fail("rate_limited", "member spool quota exceeded");
    }

    // recipients = audiência ∩ membros com view_channel
    const recipients = audience.data;
    const retentionH = (this.getConfig().maxRetentionHours as number) ?? 168;
    const expiresAt = Math.min(
      Date.now() + retentionH * 3600_000,
      envelope.expiresAt ?? Number.POSITIVE_INFINITY,
    );
    try {
      this.store.raw.transaction(() => {
        for (const attachment of envelope.attachments) {
          const row = this.store.raw.prepare(
            "SELECT owner_id, channel_id, audience, linked_message_id, expires_at, size_bytes, total_chunks, completed_at FROM attachments WHERE asset_id = ?",
          ).get(attachment.assetId) as {
            owner_id: string;
            channel_id: string;
            audience: string;
            linked_message_id: string | null;
            expires_at: number;
            size_bytes: number;
            total_chunks: number;
            completed_at: number | null;
          } | undefined;
          if (!row || row.owner_id !== actorId || row.channel_id !== envelope.channelId
            || row.linked_message_id || !row.completed_at || row.expires_at <= Date.now()
            || row.size_bytes !== attachment.sizeBytes + ATTACHMENT_ENCRYPTION_OVERHEAD_BYTES
            || row.total_chunks !== attachment.totalChunks
            || JSON.stringify(JSON.parse(row.audience).sort()) !== JSON.stringify(recipients)) {
            throw new Error("attachment_binding");
          }
        }
        if (!this.replay.check(envelope.messageId)) throw new Error("replay");
        this.store.raw.prepare(
          "INSERT INTO spool (message_id, channel_id, envelope, expires_at, recipients, consumed, created_at, sender_id, size_bytes) VALUES (?,?,?,?,?,?,?,?,?)",
        ).run(envelope.messageId, envelope.channelId, encodedEnvelope, expiresAt, JSON.stringify(recipients), "[]", Date.now(), actorId, envelopeBytes);
        for (const attachment of envelope.attachments) {
          this.store.raw.prepare("UPDATE attachments SET linked_message_id = ? WHERE asset_id = ? AND linked_message_id IS NULL")
            .run(envelope.messageId, attachment.assetId);
        }
        this.store.appendOp({ type: "envelope", messageId: envelope.messageId, channelId: envelope.channelId, sender: actorId });
      })();
    } catch (error) {
      return fail("conflict", (error as Error).message === "replay" ? "duplicate messageId (replay)" : "attachment is not authorized for this envelope");
    }

    for (const r of recipients) {
      if (r !== actorId) this.events.emit("deliver", r, envelope);
    }
    this.events.emit("activity");
    return ok(null);
  }

  getPending(identityId: string): HostResult<MessageEnvelope[]> {
    const member = this.getMember(identityId);
    if (!member) return fail("forbidden", "not a member");
    const rows = this.store.raw.prepare("SELECT envelope, recipients FROM spool WHERE expires_at > ?")
      .all(Date.now()) as { envelope: string; recipients: string }[];
    const out: MessageEnvelope[] = [];
    for (const r of rows) {
      const recipients = JSON.parse(r.recipients) as string[];
      if (!recipients.includes(identityId)) continue;
      const env = JSON.parse(r.envelope) as MessageEnvelope;
      const channel = this.getChannel(env.channelId);
      const role = this.getRole(member.role_id);
      if (channel && role && evaluatePermission(this.memberContext(member), role, channel, "view_channel")) out.push(env);
    }
    return ok(out.sort((a, b) => a.createdAt - b.createdAt));
  }

  ackConsumed(identityId: string, messageId: string): HostResult<null> {
    const member = this.getMember(identityId);
    if (!member) return fail("forbidden", "not a member");
    const row = this.store.raw.prepare("SELECT recipients, consumed FROM spool WHERE message_id = ?").get(messageId) as
      | { recipients: string; consumed: string }
      | undefined;
    if (!row) return ok(null); // já purgada — idempotente
    const recipients = JSON.parse(row.recipients) as string[];
    const consumed = new Set(JSON.parse(row.consumed) as string[]);
    if (!recipients.includes(identityId)) return fail("forbidden", "message was not addressed to this member");
    consumed.add(identityId);
    this.store.raw.prepare("UPDATE spool SET consumed = ? WHERE message_id = ?").run(JSON.stringify([...consumed]), messageId);
    if (recipients.every((r) => consumed.has(r))) {
      // purge imediato (ADR-004: todos consumiram)
      this.purgeMessage(messageId);
    }
    return ok(null);
  }

  private purgeMessage(messageId: string): void {
    this.store.raw.transaction(() => {
      this.store.raw.prepare("DELETE FROM attachments WHERE linked_message_id = ?").run(messageId);
      this.store.raw.prepare("DELETE FROM spool WHERE message_id = ?").run(messageId);
      this.store.appendOp({ type: "purge", messageId });
    })();
    this.events.emit("purged", messageId);
  }

  /** Cron de retenção: hard purge de expirados (default 7d; ADR-004). */
  startRetentionLoop(intervalMs = 60_000): NodeJS.Timeout {
    return setInterval(() => {
      if (!this.writer) return;
      const rows = this.store.raw.prepare("SELECT message_id FROM spool WHERE expires_at < ?").all(Date.now()) as {
        message_id: string;
      }[];
      for (const r of rows) this.purgeMessage(r.message_id);
    }, intervalMs);
  }

  // ------------------------------------------------- key packages / welcome (MLS)

  /** Publica o KeyPackage MLS do membro (TTL 24h; o owner puxa para add ao grupo). */
  keyPackageUpload(identityId: string, keyPackageB64: string): HostResult<null> {
    const m = this.getMember(identityId);
    if (!m) return fail("forbidden", "not a member");
    this.store.raw
      .prepare("INSERT INTO key_packages (identity_id, key_package, expires_at) VALUES (?,?,?) ON CONFLICT(identity_id) DO UPDATE SET key_package=excluded.key_package, expires_at=excluded.expires_at")
      .run(identityId, keyPackageB64, Date.now() + 24 * 3600_000);
    // The owner may have reconciled the join before this package existed. Trigger another
    // state reconciliation so the MLS welcome is not lost to that ordering race.
    this.events.emit("stateChanged");
    return ok(null);
  }

  keyPackageGet(identityId: string, targetId: string): HostResult<{ keyPackageB64: string }> {
    if (!this.isAuthorizedMlsCommitter(identityId)) {
      return fail("forbidden", "only the authorized MLS committer can fetch key packages");
    }
    if (!this.getMember(targetId)) return fail("not_found", "target not a member");
    const row = this.store.raw
      .prepare("SELECT key_package FROM key_packages WHERE identity_id = ? AND expires_at > ?")
      .get(targetId, Date.now()) as { key_package: string } | undefined;
    if (!row) return fail("not_found", "no key package for member");
    return ok({ keyPackageB64: row.key_package });
  }

  /** Owner entrega o welcome MLS ao novo membro (cifrado para o KeyPackage dele). */
  welcomePush(actorId: string, targetIdentityId: string, welcomeB64: string): HostResult<null> {
    if (!this.isAuthorizedMlsCommitter(actorId)) {
      return fail("forbidden", "only the authorized MLS committer can push welcomes");
    }
    const target = this.getMember(targetIdentityId);
    if (!target) return fail("not_found", "target not a member");

    const existing = this.store.raw
      .prepare("SELECT welcome FROM welcomes WHERE identity_id = ?")
      .get(targetIdentityId) as { welcome: string } | undefined;
    if (existing) {
      if (existing.welcome === welcomeB64) return ok(null);
      return fail("conflict", "an unconsumed welcome is already pending for this member");
    }

    this.store.raw.prepare("INSERT INTO welcomes (identity_id, welcome, created_at) VALUES (?,?,?)")
      .run(targetIdentityId, welcomeB64, Date.now());
    this.events.emit("welcome", targetIdentityId, sha256Hex(welcomeB64), welcomeB64);
    return ok(null);
  }

  welcomePending(identityId: string): HostResult<{ welcomeId: string; welcomeB64: string } | null> {
    if (!this.getMember(identityId)) return fail("forbidden", "not a member");
    const row = this.store.raw
      .prepare("SELECT welcome FROM welcomes WHERE identity_id = ?")
      .get(identityId) as { welcome: string } | undefined;
    if (!row) return ok(null);
    return ok({ welcomeId: sha256Hex(row.welcome), welcomeB64: row.welcome });
  }

  /** Explicit recipient acknowledgement is the sole command path that removes a Welcome. */
  welcomeAckConsumed(identityId: string, welcomeId: string): HostResult<null> {
    if (!this.getMember(identityId)) return fail("forbidden", "not a member");
    const row = this.store.raw.prepare("SELECT welcome FROM welcomes WHERE identity_id = ?")
      .get(identityId) as { welcome: string } | undefined;
    if (!row || sha256Hex(row.welcome) !== welcomeId) return ok(null);
    this.store.raw.prepare("DELETE FROM welcomes WHERE identity_id = ? AND welcome = ?")
      .run(identityId, row.welcome);
    return ok(null);
  }

  // -------------------------------------------------------------- replicação

  enrollReplica(
    actorId: string,
    subjectAuthPublicKey: string,
    grantId: string,
    hostProof: HostPossessionProof,
  ): HostResult<{ sealedEnrollment: SealedReplicaEnrollment }> {
    if (!this.writer) return fail("conflict", "only the active primary can enroll a replica");
    const authorized = this.activeHostGrant(actorId, subjectAuthPublicKey, grantId, "replicate");
    if (!authorized.ok) return authorized;
    const enrollment = this.store.raw.prepare(
      "SELECT enrollment_public_key FROM host_grants WHERE grant_id = ?",
    ).get(grantId) as { enrollment_public_key: string } | undefined;
    if (!enrollment || !this.verifyHostPossession("enroll", authorized.data, enrollment.enrollment_public_key, hostProof)) {
      return fail("unauthorized", "fresh proof of possession of the distinct host signing key required");
    }
    const authoritySeed = this.authoritySeed();
    if (!authoritySeed) return fail("forbidden", "authority signing is unavailable on this replica");
    const prior = this.store.raw.prepare(
      "SELECT 1 FROM replica_enrollments WHERE grant_id = ? AND generation = ?",
    ).get(grantId, authorized.data.payload.generation);
    if (prior) return fail("conflict", "enrollment for this grant generation was already issued");
    const primary = this.currentHostGrant();
    if (!primary.ok) return primary;
    const snapshot = this.store.consistentSnapshot();
    const grant = authorized.data;
    const bridgeAccess = this.configuredBridgeAccess();
    const enrollmentId = randomUUID();
    const issuedAt = Date.now();
    const expiresAt = issuedAt + 10 * 60_000;
    const snapshotHash = sha256Hex(snapshot.encryptedDb);
    const bridgeSetHash = sha256Hex(canonicalJson(
      bridgeAccess.map((entry) => entry.descriptor).sort((a, b) => a.payload.bridgeId.localeCompare(b.payload.bridgeId)),
    ));
    const transcriptPayload: ReplicaEnrollmentTranscript = {
      version: 1,
      enrollmentId,
      recipientPublicKey: enrollment.enrollment_public_key,
      serverId: snapshot.serverId,
      authorityFingerprint: this.authorityFingerprint(),
      grantId,
      generation: grant.payload.generation,
      subjectAuthPublicKey,
      replicaHost: { hostId: grant.payload.hostId, publicKey: grant.payload.devicePublicKey },
      primaryHost: {
        hostId: primary.data.grant.payload.hostId,
        grantId: primary.data.grant.payload.grantId,
        publicKey: ed25519PublicKey(primary.data.hostSeed).toString("base64url"),
      },
      snapshotHash,
      epoch: snapshot.epoch,
      seq: snapshot.seq,
      issuedAt,
      expiresAt,
      bridgeSetHash,
    };
    const transcript: SignedReplicaEnrollmentTranscript = {
      payload: transcriptPayload,
      publicKey: this.authorityPublicKey(),
      signature: signCanonicalPayload(authoritySeed, ENROLLMENT_TRANSCRIPT_DOMAIN, transcriptPayload).toString("base64url"),
    };

    /*
     * The DB key grants a Community Host access to the SQLCipher metadata/state it must host.
     * Message bodies, attachment keys and member private MLS state are not stored here in
     * plaintext; MLS private keys remain on member devices. Thus enrollment enables metadata
     * hosting/failover, not decryption of MLS application plaintext.
     *
     * This response is permitted only after signed challenge authentication, an accepted active
     * replicate grant, and fresh host-key proof. The complete material (including DB key) is
     * sealed to a replica-exclusive X25519 key. Even an authenticated plaintext WS transport can
     * observe only the sealed envelope; only the replica private key can open it.
     */
    const material: ReplicaEnrollmentMaterial = {
      version: 2,
      enrollmentId,
      issuedAt,
      expiresAt,
      serverId: snapshot.serverId,
      authorityPublicKey: snapshot.authorityPublicKey,
      authorityFingerprint: this.authorityFingerprint(),
      epoch: snapshot.epoch,
      seq: snapshot.seq,
      grantId,
      subjectIdentityId: actorId,
      subjectAuthPublicKey,
      replicaHost: {
        hostId: grant.payload.hostId,
        publicKey: grant.payload.devicePublicKey,
      },
      replicaGrant: grant,
      primaryHost: {
        hostId: primary.data.grant.payload.hostId,
        grantId: primary.data.grant.payload.grantId,
        publicKey: ed25519PublicKey(primary.data.hostSeed).toString("base64url"),
      },
      bridgeAccess,
      dbB64: snapshot.encryptedDb.toString("base64"),
      dbKeyB64: this.store.enrollmentDbKey().toString("base64url"),
    };
    let sealedEnrollment: SealedReplicaEnrollment;
    try {
      sealedEnrollment = sealReplicaEnrollment(material, transcript);
      this.store.raw.transaction(() => {
        this.consumeSecurityProof(hostProof.proofId, "replica-enroll");
        this.store.raw.prepare(
          `INSERT INTO replica_enrollments
           (enrollment_id, grant_id, generation, snapshot_hash, epoch, seq, issued_at, expires_at, consumed_at)
           VALUES (?,?,?,?,?,?,?,?,?)`,
        ).run(enrollmentId, grantId, grant.payload.generation, snapshotHash, snapshot.epoch, snapshot.seq, issuedAt, expiresAt, issuedAt);
        this.persistWriterState(
          "writer",
          primary.data.grant,
          snapshot.epoch,
          grant.payload.capabilities.includes("promote") && bridgeAccess.length > 0
            ? [bridgeAccess.map((entry) => entry.descriptor.payload.bridgeId)]
            : [],
        );
      })();
    } catch {
      return fail("conflict", "enrollment proof or enrollment generation was already consumed");
    }
    return ok({ sealedEnrollment });
  }

  /** Snapshot SQLCipher consistente; a DB key is intentionally absent after enrollment. */
  getSnapshot(
    actorId: string,
    subjectAuthPublicKey: string,
    grantId: string,
    expectedServerId: string,
  ): HostResult<{ dbB64: string; serverId: string; authorityPublicKey: string; epoch: number; seq: number }> {
    const authorized = this.activeHostGrant(actorId, subjectAuthPublicKey, grantId, "replicate");
    if (!authorized.ok) return authorized;
    if (expectedServerId !== this.serverId) return fail("conflict", "replica serverId mismatch");
    const snapshot = this.store.consistentSnapshot();
    return ok({
      dbB64: snapshot.encryptedDb.toString("base64"),
      serverId: snapshot.serverId,
      authorityPublicKey: snapshot.authorityPublicKey,
      epoch: snapshot.epoch,
      seq: snapshot.seq,
    });
  }

  applyReplicaSnapshot(input: {
    dbB64: string;
    serverId: string;
    authorityPublicKey: string;
    epoch: number;
    seq: number;
  }): HostResult<{ epoch: number; seq: number }> {
    if (this.writer) return fail("conflict", "primary host cannot replace its live database from replica sync");
    let encryptedDb: Buffer;
    try {
      encryptedDb = Buffer.from(input.dbB64, "base64");
      if (encryptedDb.toString("base64") !== input.dbB64) throw new Error("non-canonical base64");
      if (input.serverId !== this.serverId || input.authorityPublicKey !== this.authorityPublicKey()) {
        return fail("conflict", "replica snapshot identity mismatch");
      }
      const localSeq = this.store.raw.prepare("SELECT COALESCE(MAX(seq), 0) AS seq FROM op_log").get() as { seq: number };
      const localGrant = this.currentHostGrant();
      const localHostId = localGrant.ok ? localGrant.data.grant.payload.hostId : null;
      const localReplicaRows = this.store.raw.prepare(
        "SELECT key, value FROM server_meta WHERE key IN ('replica_enrollment_id', 'replica_primary_host_id', 'replica_witness_bridge_ids', 'replica_fenced_grant_id')",
      ).all() as { key: string; value: string }[];
      const localReplicaMeta = Object.fromEntries(localReplicaRows.map((row) => [row.key, row.value]));
      const localRegistrationMeta = localHostId
        ? this.store.raw.prepare(
          "SELECT key, value FROM server_meta WHERE key IN (?, ?)",
        ).all(`host_record_seq:${localHostId}`, `host_record_hash:${localHostId}`) as { key: string; value: string }[]
        : [];
      for (const row of localRegistrationMeta) localReplicaMeta[row.key] = row.value;
      const localHostRegistrations = localHostId
        ? this.store.raw.prepare(
          "SELECT host_id AS hostId, record_seq AS recordSeq, record_hash AS recordHash, registration, committed_at AS committedAt FROM host_record_chains WHERE host_id = ? ORDER BY record_seq",
        ).all(localHostId) as import("./store.js").PreservedHostRegistration[]
        : [];
      const metadata = this.store.replaceEncryptedSnapshot(encryptedDb, {
        serverId: this.serverId,
        authorityPublicKey: this.authorityPublicKey(),
        minimumEpoch: this.getEpoch(),
        minimumSeq: Number(localSeq.seq ?? 0),
        exactEpoch: input.epoch,
        exactSeq: input.seq,
      }, localReplicaMeta, localHostRegistrations);
      this.sequences.clear();
      this.calls.clear();
      return ok({ epoch: metadata.epoch, seq: metadata.seq });
    } catch (error) {
      return fail("conflict", `replica snapshot rejected: ${(error as Error).message}`);
    }
  }

  private getEpoch(): number {
    const row = this.store.raw.prepare("SELECT value FROM server_meta WHERE key = 'epoch'").get() as
      | { value: string }
      | undefined;
    return row ? Number(row.value) : 0;
  }

  replicaPing(
    actorId: string,
    subjectAuthPublicKey: string,
    grantId: string,
    expectedServerId: string,
    expectedEpoch: number,
  ): HostResult<Record<string, unknown>> {
    const authorized = this.activeHostGrant(actorId, subjectAuthPublicKey, grantId, "replicate");
    if (!authorized.ok) return authorized;
    if (expectedServerId !== this.serverId || expectedEpoch !== this.getEpoch()) {
      return fail("conflict", "replica serverId/epoch mismatch");
    }
    return ok({
      serverId: this.serverId,
      epoch: this.getEpoch(),
      syncMode: "encrypted-snapshot",
      twoSafe: false,
    });
  }

  /** Internal-only promotion path. There is deliberately no HostCommand/API route for this. */
  promoteFromWitness(
    actorId: string,
    subjectAuthPublicKey: string,
    grantId: string,
    expectedEpoch: number,
    observations: BridgeWitnessObservation[],
  ): HostResult<{ epoch: number }> {
    if (this.writer) return fail("conflict", "host is already primary");
    const authorized = this.activeHostGrant(actorId, subjectAuthPublicKey, grantId, "promote");
    if (!authorized.ok) return authorized;
    if (expectedEpoch !== this.getEpoch()) return fail("conflict", "replica epoch changed before promotion");
    const primary = this.store.raw.prepare(
      "SELECT value FROM server_meta WHERE key = 'replica_primary_host_id'",
    ).get() as { value: string } | undefined;
    const bridges = this.store.raw.prepare(
      "SELECT value FROM server_meta WHERE key = 'replica_witness_bridge_ids'",
    ).get() as { value: string } | undefined;
    let bridgeIds: string[] = [];
    try { bridgeIds = bridges ? JSON.parse(bridges.value) as string[] : []; } catch { return fail("forbidden", "replica witness trust is corrupt"); }
    const byBridge = new Map(observations.map((entry) => [entry.bridgeId, entry]));
    const now = Date.now();
    const next = expectedEpoch + 1;
    if (!primary || bridgeIds.length < 2 || new Set(bridgeIds).size !== bridgeIds.length
      || new Set(observations.map((entry) => entry.bridgeId)).size !== observations.length
      || new Set(observations.map((entry) => entry.requestId)).size !== observations.length
      || new Set(observations.map((entry) => entry.primaryRecordHash)).size !== 1
      || observations.some((entry) => !bridgeIds.includes(entry.bridgeId)
        || entry.candidateHostId !== authorized.data.payload.hostId
        || entry.primaryHostId !== primary.value || entry.primaryOnline !== false
        || entry.primaryEpoch !== expectedEpoch
        || entry.electionEpoch !== next
        || !/^[0-9a-f]{64}$/.test(entry.primaryRecordHash)
        || entry.expiresAt <= now || entry.expiresAt > entry.observedAt + 24 * 3600_000
        || Math.abs(now - entry.observedAt) > 10_000)
      || !strictBridgeWitnessQuorum(bridgeIds.length, bridgeIds.map((id) => byBridge.has(id) ? false : null))) {
      return fail("forbidden", "fresh strict-majority promotion votes bound to this candidate and primary are required");
    }
    this.store.raw.transaction(() => {
      this.store.raw
        .prepare("INSERT INTO server_meta (key, value) VALUES ('epoch', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .run(String(next));
      this.store.appendOp({ type: "promote", epoch: next, grantId, candidateHostId: authorized.data.payload.hostId });
      this.store.raw.prepare(
        "INSERT INTO server_meta (key, value) VALUES ('promotion_certificate', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      ).run(JSON.stringify(observations.map((entry) => entry.receipt)));
      this.persistWriterState("writer", authorized.data, next);
    })();
    this.writerResumeEligibility = null;
    this.pendingRegistration = null;
    this.writer = true;
    this.events.emit("writerPromoted", { epoch: next });
    this.events.emit("stateChanged");
    return ok({ epoch: next });
  }

  promotionCertificate(): unknown[] {
    const row = this.store.raw.prepare(
      "SELECT value FROM server_meta WHERE key = 'promotion_certificate'",
    ).get() as { value: string } | undefined;
    if (!row) return [];
    try {
      const value = JSON.parse(row.value);
      return Array.isArray(value) ? value.slice(0, 3) : [];
    } catch {
      return [];
    }
  }

  /** Explicit upstream denial fences the local stale grant so it cannot later promote manually. */
  fenceReplicaGrant(grantId: string): void {
    if (this.writer) return;
    this.store.raw.transaction(() => {
      this.store.raw.prepare(
        "UPDATE host_grants SET revoked_at = COALESCE(revoked_at, ?) WHERE grant_id = ?",
      ).run(Date.now(), grantId);
      this.store.raw.prepare(
        "INSERT INTO server_meta (key, value) VALUES ('replica_fenced_grant_id', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      ).run(grantId);
    })();
  }

  // ------------------------------------------------------------- attachments

  attachmentUploadBegin(
    actorId: string,
    assetId: string,
    channelId: string,
    audienceMembers: string[],
    sizeBytes: number,
    totalChunks: number,
    ciphertextHash: string,
    ttlHours = 24,
  ): HostResult<{ receivedChunks: number[] }> {
    const member = this.getMember(actorId);
    if (!member) return fail("forbidden", "not a member");
    const channel = this.getChannel(channelId);
    const role = this.getRole(member.role_id);
    if (!channel || !role) return fail("not_found", "channel not found");
    if (!evaluatePermission(this.memberContext(member), role, channel, "send_files")) return fail("forbidden", "no send_files");
    const audience = this.authorizedAudience(channel, audienceMembers);
    if (!audience.ok || !audience.data.includes(actorId)) return fail("forbidden", "invalid attachment audience");
    try {
      if (sizeBytes <= ATTACHMENT_ENCRYPTION_OVERHEAD_BYTES) throw new Error("ciphertext too short");
      if (attachmentChunkCount(sizeBytes) !== totalChunks) throw new Error("chunk count mismatch");
    } catch {
      return fail("invalid_input", "attachment size or chunk count is invalid");
    }
    if (!/^[0-9a-f]{64}$/.test(ciphertextHash)) return fail("invalid_input", "attachment ciphertext hash is invalid");
    if (!Number.isSafeInteger(ttlHours) || ttlHours < 1 || ttlHours > 24) return fail("invalid_input", "attachment TTL is invalid");
    const configured = Number(this.getConfig().maxAttachmentBytes ?? MAX_ATTACHMENT_BYTES);
    const maxBytes = Number.isSafeInteger(configured) && configured > 0
      ? Math.min(MAX_ATTACHMENT_BYTES, configured)
      : MAX_ATTACHMENT_BYTES;
    if (sizeBytes > maxBytes) return fail("invalid_input", `attachment exceeds limit (${maxBytes})`);

    const existing = this.store.raw.prepare(
      "SELECT * FROM attachments WHERE asset_id = ?",
    ).get(assetId) as AttachmentRow | undefined;
    if (existing) {
      if (existing.owner_id !== actorId || existing.channel_id !== channelId || existing.linked_message_id
        || existing.size_bytes !== sizeBytes || existing.total_chunks !== totalChunks
        || existing.ciphertext_hash !== ciphertextHash) {
        return fail("conflict", "assetId already belongs to a different transfer");
      }
      try {
        if (JSON.stringify(JSON.parse(existing.audience).sort()) !== JSON.stringify(audience.data)) {
          return fail("conflict", "assetId already belongs to a different transfer");
        }
      } catch {
        return fail("internal", "stored attachment audience metadata is invalid");
      }
      const receivedChunks = (this.store.raw.prepare(
        "SELECT chunk_index FROM attachment_chunks WHERE asset_id = ? ORDER BY chunk_index",
      ).all(assetId) as { chunk_index: number }[]).map((row) => row.chunk_index);
      return ok({ receivedChunks });
    }

    let rejection: HostResult<{ receivedChunks: number[] }> | null = null;
    this.store.raw.transaction(() => {
      const pending = this.store.raw.prepare(
        `SELECT COUNT(*) AS total,
          COALESCE(SUM(CASE WHEN owner_id = ? THEN 1 ELSE 0 END), 0) AS member
         FROM attachments WHERE linked_message_id IS NULL`,
      ).get(actorId) as { total: number; member: number };
      if (Number(pending.member) >= MAX_PENDING_ATTACHMENT_TRANSFERS_PER_MEMBER) {
        rejection = fail("rate_limited", "pending attachment transfer limit exceeded");
        return;
      }
      if (Number(pending.total) >= MAX_PENDING_ATTACHMENT_TRANSFERS_GLOBAL) {
        rejection = fail("rate_limited", "global pending attachment transfer limit exceeded");
        return;
      }

      const spoolQuota = Number(this.getConfig().maxSpoolBytes ?? 2 * 1024 * 1024 * 1024);
      if (this.currentSpoolBytes() + sizeBytes > spoolQuota) {
        rejection = fail("rate_limited", "spool quota exceeded");
        return;
      }
      if (this.currentMemberSpoolBytes(actorId) + sizeBytes > this.memberSpoolQuota()) {
        rejection = fail("rate_limited", "member spool quota exceeded");
        return;
      }
      const now = Date.now();
      this.store.raw
        .prepare("INSERT INTO attachments (asset_id, data, size_bytes, expires_at, created_at, owner_id, channel_id, audience, linked_message_id, total_chunks, ciphertext_hash, completed_at) VALUES (?,'',?,?,?,?,?,?,NULL,?,?,NULL)")
        .run(assetId, sizeBytes, now + Math.min(24, ttlHours) * 3600_000, now, actorId, channelId, JSON.stringify(audience.data), totalChunks, ciphertextHash);
    })();
    if (rejection) return rejection;
    return ok({ receivedChunks: [] });
  }

  attachmentUploadChunk(
    actorId: string,
    assetId: string,
    index: number,
    dataB64: string,
    sizeBytes: number,
    hash: string,
  ): HostResult<null> {
    const transfer = this.store.raw.prepare("SELECT * FROM attachments WHERE asset_id = ? AND expires_at > ?")
      .get(assetId, Date.now()) as AttachmentRow | undefined;
    if (!transfer) return fail("not_found", "attachment transfer not found or expired");
    if (transfer.owner_id !== actorId || transfer.linked_message_id) return fail("forbidden", "attachment transfer is not writable");
    const member = this.getMember(actorId);
    const channel = this.getChannel(transfer.channel_id);
    const role = member ? this.getRole(member.role_id) : undefined;
    if (!member || !channel || !role || !evaluatePermission(this.memberContext(member), role, channel, "send_files")) {
      return fail("forbidden", "no send_files");
    }
    let expectedSize: number;
    try {
      expectedSize = index === transfer.total_chunks - 1
        ? transfer.size_bytes - ATTACHMENT_CHUNK_BYTES * (transfer.total_chunks - 1)
        : ATTACHMENT_CHUNK_BYTES;
      if (!Number.isSafeInteger(index) || index < 0 || index >= transfer.total_chunks || expectedSize < 1) throw new Error("index");
      decodeAttachmentChunk(dataB64, expectedSize, hash);
    } catch (error) {
      return fail("invalid_input", String((error as Error).message));
    }
    if (sizeBytes !== expectedSize) return fail("invalid_input", "attachment chunk declared size mismatch");
    const existing = this.store.raw.prepare(
      "SELECT chunk_index, data, size_bytes, hash FROM attachment_chunks WHERE asset_id = ? AND chunk_index = ?",
    ).get(assetId, index) as AttachmentChunkRow | undefined;
    if (existing) {
      return existing.size_bytes === sizeBytes && existing.hash === hash && existing.data === dataB64
        ? ok(null)
        : fail("conflict", "attachment chunk retry does not match stored bytes");
    }
    this.store.raw.prepare(
      "INSERT INTO attachment_chunks (asset_id, chunk_index, data, size_bytes, hash, created_at) VALUES (?,?,?,?,?,?)",
    ).run(assetId, index, dataB64, sizeBytes, hash, Date.now());
    return ok(null);
  }

  attachmentUploadComplete(actorId: string, assetId: string): HostResult<null> {
    const transfer = this.store.raw.prepare("SELECT * FROM attachments WHERE asset_id = ? AND expires_at > ?")
      .get(assetId, Date.now()) as AttachmentRow | undefined;
    if (!transfer) return fail("not_found", "attachment transfer not found or expired");
    if (transfer.owner_id !== actorId || transfer.linked_message_id) return fail("forbidden", "attachment transfer is not completable");
    if (transfer.completed_at) return ok(null);
    const chunks = this.store.raw.prepare(
      "SELECT chunk_index, data, size_bytes, hash FROM attachment_chunks WHERE asset_id = ? ORDER BY chunk_index",
    ).all(assetId) as AttachmentChunkRow[];
    if (chunks.length !== transfer.total_chunks) return fail("conflict", "attachment transfer is incomplete");
    const aggregate = createHash("sha256");
    let aggregateBytes = 0;
    try {
      for (let index = 0; index < chunks.length; index += 1) {
        const row = chunks[index]!;
        if (row.chunk_index !== index) throw new Error("attachment chunk sequence is incomplete");
        const expectedSize = index === transfer.total_chunks - 1
          ? transfer.size_bytes - ATTACHMENT_CHUNK_BYTES * (transfer.total_chunks - 1)
          : ATTACHMENT_CHUNK_BYTES;
        const decoded = decodeAttachmentChunk(row.data, expectedSize, row.hash);
        aggregate.update(decoded);
        aggregateBytes += decoded.length;
      }
    } catch (error) {
      return fail("conflict", String((error as Error).message));
    }
    if (aggregateBytes !== transfer.size_bytes || aggregate.digest("hex") !== transfer.ciphertext_hash) {
      return fail("conflict", "attachment ciphertext aggregate hash mismatch");
    }
    this.store.raw.prepare("UPDATE attachments SET completed_at = ? WHERE asset_id = ? AND completed_at IS NULL")
      .run(Date.now(), assetId);
    return ok(null);
  }

  attachmentUploadAbort(actorId: string, assetId: string): HostResult<null> {
    const transfer = this.store.raw.prepare("SELECT owner_id, linked_message_id FROM attachments WHERE asset_id = ?")
      .get(assetId) as { owner_id: string; linked_message_id: string | null } | undefined;
    if (!transfer) return ok(null);
    if (transfer.owner_id !== actorId) return fail("forbidden", "attachment transfer belongs to another member");
    if (transfer.linked_message_id) return fail("conflict", "linked attachment cannot be aborted");
    this.store.raw.prepare("DELETE FROM attachments WHERE asset_id = ?").run(assetId);
    return ok(null);
  }

  private currentSpoolBytes(): number {
    const row = this.store.raw.prepare(
      "SELECT size_bytes FROM spool_usage WHERE scope_id = 'global'",
    ).get() as { size_bytes: number } | undefined;
    return Number(row?.size_bytes ?? 0);
  }

  private migrateLegacyAttachment(assetId: string): void {
    const legacy = this.store.raw.prepare("SELECT * FROM attachments WHERE asset_id = ?")
      .get(assetId) as AttachmentRow | undefined;
    if (!legacy || legacy.completed_at || !legacy.data) return;
    if (legacy.data.length > Math.ceil(MAX_ATTACHMENT_BYTES / 3) * 4) return;
    const decodedLength = canonicalBase64DecodedLength(legacy.data);
    if (decodedLength === null || decodedLength !== legacy.size_bytes || decodedLength > MAX_ATTACHMENT_BYTES) return;
    const totalChunks = attachmentChunkCount(decodedLength);
    const chunks: { index: number; data: string; sizeBytes: number; hash: string }[] = [];
    const aggregate = createHash("sha256");
    for (let index = 0; index < totalChunks; index += 1) {
      const data = legacy.data.slice(index * MAX_ATTACHMENT_CHUNK_BASE64_CHARS, (index + 1) * MAX_ATTACHMENT_CHUNK_BASE64_CHARS);
      const expectedSize = index === totalChunks - 1
        ? decodedLength - ATTACHMENT_CHUNK_BYTES * (totalChunks - 1)
        : ATTACHMENT_CHUNK_BYTES;
      const decoded = decodeAttachmentChunk(data, expectedSize);
      const hash = attachmentSha256(decoded);
      chunks.push({ index, data, sizeBytes: decoded.length, hash });
      aggregate.update(decoded);
    }
    this.store.raw.transaction(() => {
      this.store.raw.prepare("DELETE FROM attachment_chunks WHERE asset_id = ?").run(assetId);
      const insert = this.store.raw.prepare(
        "INSERT INTO attachment_chunks (asset_id, chunk_index, data, size_bytes, hash, created_at) VALUES (?,?,?,?,?,?)",
      );
      for (const chunk of chunks) insert.run(assetId, chunk.index, chunk.data, chunk.sizeBytes, chunk.hash, legacy.created_at);
      this.store.raw.prepare(
        "UPDATE attachments SET data = '', total_chunks = ?, ciphertext_hash = ?, completed_at = ? WHERE asset_id = ?",
      ).run(totalChunks, aggregate.digest("hex"), legacy.created_at, assetId);
    })();
  }

  private readableAttachment(actorId: string, assetId: string): HostResult<AttachmentRow> {
    const member = this.getMember(actorId);
    if (!member) return fail("forbidden", "not a member");
    try {
      this.migrateLegacyAttachment(assetId);
    } catch {
      return fail("internal", "stored legacy attachment failed migration validation");
    }
    const row = this.store.raw.prepare("SELECT * FROM attachments WHERE asset_id = ? AND expires_at > ?")
      .get(assetId, Date.now()) as AttachmentRow | undefined;
    if (!row) return fail("not_found", "attachment not found or expired");
    const channel = this.getChannel(row.channel_id);
    const role = this.getRole(member.role_id);
    let audience: string[] = [];
    try { audience = JSON.parse(row.audience) as string[]; } catch { return fail("invalid_input", "attachment audience metadata is invalid"); }
    if (!row.completed_at || !row.linked_message_id || !audience.includes(actorId) || !channel || !role
      || !evaluatePermission(this.memberContext(member), role, channel, "view_channel")) {
      return fail("forbidden", "attachment is not authorized for this member/channel");
    }
    return ok(row);
  }

  attachmentDownload(actorId: string, assetId: string): HostResult<{ sizeBytes: number; totalChunks: number; hash: string }> {
    const readable = this.readableAttachment(actorId, assetId);
    if (!readable.ok) return readable;
    return ok({
      sizeBytes: readable.data.size_bytes,
      totalChunks: readable.data.total_chunks,
      hash: readable.data.ciphertext_hash,
    });
  }

  attachmentDownloadChunk(
    actorId: string,
    assetId: string,
    index: number,
  ): HostResult<{ index: number; data: string; sizeBytes: number; hash: string }> {
    const readable = this.readableAttachment(actorId, assetId);
    if (!readable.ok) return readable;
    if (!Number.isSafeInteger(index) || index < 0 || index >= readable.data.total_chunks) {
      return fail("invalid_input", "attachment chunk index out of range");
    }
    const row = this.store.raw.prepare(
      "SELECT chunk_index, data, size_bytes, hash FROM attachment_chunks WHERE asset_id = ? AND chunk_index = ?",
    ).get(assetId, index) as AttachmentChunkRow | undefined;
    if (!row) return fail("not_found", "attachment chunk not found");
    const expectedSize = index === readable.data.total_chunks - 1
      ? readable.data.size_bytes - ATTACHMENT_CHUNK_BYTES * (readable.data.total_chunks - 1)
      : ATTACHMENT_CHUNK_BYTES;
    try {
      decodeAttachmentChunk(row.data, expectedSize, row.hash);
    } catch {
      return fail("internal", "stored attachment chunk failed integrity validation");
    }
    return ok({ index, data: row.data, sizeBytes: row.size_bytes, hash: row.hash });
  }

  /** Cleanup de attachments expirados (alinhado à retention). */
  startAttachmentCleanup(intervalMs = 60_000): NodeJS.Timeout {
    return setInterval(() => {
      if (!this.writer) return;
      const now = Date.now();
      this.store.raw.prepare("DELETE FROM attachments WHERE expires_at < ? OR (linked_message_id IS NULL AND created_at < ?)")
        .run(now, now - ABANDONED_ATTACHMENT_TTL_MS);
    }, intervalMs);
  }

  // -------------------------------------------------------------------- call

  private calls = new Map<string, Set<string>>(); // channelId -> identityIds (efêmero)

  callJoin(identityId: string, channelId: string): HostResult<{ participants: string[] }> {
    const m = this.getMember(identityId);
    if (!m) return fail("forbidden", "not a member");
    const channel = this.getChannel(channelId);
    if (!channel || channel.type !== "call") return fail("not_found", "call channel not found");
    const role = this.getRole(m.role_id)!;
    if (!evaluatePermission(this.memberContext(m), role, channel, "join_call")) {
      return fail("forbidden", "no join_call");
    }
    const limit = (this.getConfig().maxVoiceParticipants as number) ?? 10;
    const participants = this.calls.get(channelId) ?? new Set<string>();
    if (!participants.has(identityId) && participants.size >= limit) {
      return fail("channel_full", `call limit reached (${limit})`);
    }
    participants.add(identityId);
    this.calls.set(channelId, participants);
    this.events.emit("callMembership", channelId, [...participants]);
    return ok({ participants: [...participants] });
  }

  callLeave(identityId: string, channelId: string): HostResult<null> {
    const participants = this.calls.get(channelId);
    if (participants) {
      participants.delete(identityId);
      this.events.emit("callMembership", channelId, [...participants]);
    }
    return ok(null);
  }

  /** Rele de signaling entre peers (SDP/candidates passam pelo host; conteúdo é E2EE). */
  callSignal(identityId: string, channelId: string, to: string, payload: unknown): HostResult<null> {
    const participants = this.calls.get(channelId);
    if (!participants?.has(to) || !participants.has(identityId)) {
      return fail("forbidden", "both peers must be in the call");
    }
    this.events.emit("callSignal", to, { channelId, from: identityId, payload });
    return ok(null);
  }

  // ---------------------------------------------------------------- presence

  setPresence(identityId: string, state: "online" | "offline" | "in_call"): HostResult<null> {
    const m = this.getMember(identityId);
    if (!m) return fail("forbidden", "not a member");
    this.store.raw.prepare("UPDATE members SET presence = ? WHERE identity_id = ?").run(state, identityId);
    this.events.emit("presence", identityId, state);
    return ok(null);
  }
}
