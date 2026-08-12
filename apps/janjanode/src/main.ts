import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { WsAdapter } from "@nestjs/platform-ws";
import { WebSocket } from "ws";
import {
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  randomUUID,
} from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { canonicalJson, ed25519Fingerprint, ed25519PublicKey, sha256Hex, signCanonicalPayload, verifyCanonicalPayload } from "@janjacord/crypto";
import { createExternalWebSocket, HostClient, IceHostTransport } from "@janjacord/networking";
import { hostRegistrationRecordHash, verifyHostRegistration } from "@janjacord/protocol";
import { AppModule } from "./app.module.js";
import {
  ServerService,
  strictBridgeWitnessQuorum,
  type ReplicaEnrollmentMaterial,
  type SealedReplicaEnrollment,
  verifyReplicaEnrollmentTranscript,
} from "./server.service.js";
import { Store } from "./store.js";
import { attachIceHostGateway } from "./ice-gateway.js";
import {
  RegistrationAckQuorum,
  RegistrationWriteAuthorityLease,
  type RegistrationAckBinding,
} from "./registration-quorum.js";
import { validateBridgeWitnessResponse, type ValidatedBridgeWitness } from "./bridge-witness.js";

interface ReplicaRuntime {
  material: ReplicaEnrollmentMaterial;
  memberDeviceSeed: Buffer;
}

const X25519_PKCS8_PRIVATE_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PUBLIC_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const ENROLLMENT_AAD = Buffer.from("janjacord.replica-enrollment.v1", "utf8");
const PROMOTION_VOTE_DOMAIN = "janjacord.promotion-vote.v1";

type PromotionVoteClaim =
  | { kind: "granted"; observation: import("./server.service.js").BridgeWitnessObservation }
  | { kind: "conflict" }
  | { kind: "unavailable" };

type CollectedBridgeWitness = {
  validated: ValidatedBridgeWitness;
  signed: unknown;
};

function openControlWebSocket(url: string): WebSocket {
  return createExternalWebSocket(url);
}

async function registerRendezvous(svc: ServerService): Promise<void> {
  const targets = svc.bridgeRegistrationTargets();
  const legacyUrl = process.env.JC_RENDEZVOUS_URL;
  const legacyPublicUrl = process.env.JC_PUBLIC_URL;
  if (targets.length === 0 && legacyUrl && legacyPublicUrl) targets.push({
    bridgeId: "legacy",
    rendezvousUrl: legacyUrl,
    signalingUrl: legacyPublicUrl,
    ...(process.env.JC_BRIDGE_PAIRING_TOKEN ? { pairingToken: process.env.JC_BRIDGE_PAIRING_TOKEN } : {}),
  });
  else if (targets.length === 0 && legacyUrl) {
    console.warn("[janjanode] JC_RENDEZVOUS_URL definido mas JC_PUBLIC_URL ausente — pulando registro legado");
  }
  const unique = [...new Map(targets.map((target) => [target.rendezvousUrl, target])).values()].slice(0, 3);
  if (unique.length > 0) registerRendezvousTargets(svc, unique);
}

/**
 * A host record is one authority chain checkpoint, not one checkpoint per bridge. This
 * coordinator signs one record containing every configured signaling endpoint and publishes
 * byte-identical registration/requestId values to every bridge. One valid ACK commits seq/hash,
 * while write authority requires a strict majority of the configured bridge set. ACKs from the
 * remaining bridges are tracked and accepted against the same retained round.
 */
function registerRendezvousTargets(
  svc: ServerService,
  targets: { bridgeId: string; rendezvousUrl: string; signalingUrl: string; pairingToken?: string }[],
): void {
  const renewMs = Number(process.env.JC_RENDEZVOUS_RENEW_MS ?? 2 * 60_000);
  const signalingEndpoints = targets.map((target) => target.signalingUrl);
  type Round = {
    requestId: string;
    registration: import("@janjacord/schemas").HostRegistration;
    recordHash: string;
    committed: boolean;
    acked: Set<string>;
    binding: RegistrationAckBinding;
  };
  type Connection = {
    target: { bridgeId: string; rendezvousUrl: string; signalingUrl: string; pairingToken?: string };
    ws: WebSocket | null;
    backoffMs: number;
    retry: NodeJS.Timeout | null;
    accessToken: string | null;
    accessRequestId: string | null;
    pairingAttempted: boolean;
    cursorRequestId: string | null;
    nextRecordSeq: number | null;
    pendingPublish: { requestId: string; recordHash: string; registration: import("@janjacord/schemas").HostRegistration; current: boolean } | null;
    livenessRoundId: string | null;
  };
  let round: Round | null = null;
  const ackQuorum = new RegistrationAckQuorum(targets.map((target) => target.bridgeId));
  const writeAuthority = new RegistrationWriteAuthorityLease(ackQuorum, performance.now());
  const configuredFenceMs = Number(process.env.JC_PRIMARY_FENCE_MS ?? 15_000);
  const primaryFenceMs = Number.isFinite(configuredFenceMs)
    ? Math.max(5_000, Math.min(15_000, configuredFenceMs))
    : 15_000;
  const connections = targets.map<Connection>((target) => ({
    target, ws: null, backoffMs: 1_000, retry: null, accessToken: null, accessRequestId: null, pairingAttempted: false,
    cursorRequestId: null, nextRecordSeq: null, pendingPublish: null, livenessRoundId: null,
  }));
  const configuredBridgeIds = targets.map((target) => target.bridgeId);
  let writerObserved = svc.isWriter();

  const requestHostAccess = (connection: Connection, usePairing = false): void => {
    if (connection.ws?.readyState !== WebSocket.OPEN) return;
    const access = svc.createBridgeAccessRequest(connection.target.bridgeId);
    if (!access.ok) {
      console.warn(`[janjanode] credencial de bridge indisponível: ${access.error.message}`);
      return;
    }
    connection.accessRequestId = randomUUID();
    connection.ws.send(JSON.stringify({
      type: "access.issue",
      requestId: connection.accessRequestId,
      ...(usePairing && connection.target.pairingToken ? { pairingToken: connection.target.pairingToken } : {}),
      ...access.data,
    }));
  };

  const ensureRound = (): Round | null => {
    if (round) return round;
    const candidate = svc.createPrimaryRegistration(signalingEndpoints);
    if (!candidate.ok) {
      console.warn(`[janjanode] registro assinado indisponível: ${candidate.error.message}`);
      return null;
    }
    round = {
      requestId: randomUUID(),
      registration: candidate.data.registration,
      recordHash: candidate.data.recordHash,
      committed: false,
      acked: new Set(),
      binding: {
        recordHash: candidate.data.recordHash,
        epoch: candidate.data.registration.record.payload.epoch,
        role: candidate.data.registration.record.payload.role,
      },
    };
    ackQuorum.begin(round.binding);
    return round;
  };

  const requestCursor = (connection: Connection): void => {
    const current = ensureRound();
    if (!current || connection.ws?.readyState !== WebSocket.OPEN || !connection.accessToken) return;
    connection.cursorRequestId = randomUUID();
    connection.ws.send(JSON.stringify({
      type: "register.cursor",
      requestId: connection.cursorRequestId,
      authorityFingerprint: svc.getAuthorityFingerprint(),
      serverId: svc.getServerId(),
      hostId: current.registration.record.payload.hostId,
      accessToken: connection.accessToken,
    }));
  };

  const publish = (connection: Connection): void => {
    const current = ensureRound();
    if (!current || connection.ws?.readyState !== WebSocket.OPEN || !connection.accessToken
      || connection.nextRecordSeq === null) return;
    const replay = svc.registrationChain().find((entry) => entry.recordSeq === connection.nextRecordSeq);
    const item = replay ?? (current.registration.record.payload.recordSeq === connection.nextRecordSeq
      ? { registration: current.registration, recordHash: current.recordHash }
      : null);
    if (!item) return;
    const requestId = item.recordHash === current.recordHash ? current.requestId : randomUUID();
    connection.pendingPublish = {
      requestId,
      registration: item.registration,
      recordHash: item.recordHash,
      current: item.recordHash === current.recordHash,
    };
    connection.ws.send(JSON.stringify({
      type: "register.begin",
      requestId,
      accessToken: connection.accessToken,
      ...(item.registration.record.payload.role === "primary" && svc.promotionCertificate().length > 0
        ? { promotionCertificate: svc.promotionCertificate() }
        : {}),
      ...item.registration,
    }));
  };

  const publishPromotedWriter = (): void => {
    if (!svc.isWriter()) return;
    writerObserved = true;
    if (round?.committed) svc.abandonPrimaryRegistration(round.recordHash);
    round = null;
    ackQuorum.clear();
    writeAuthority.reset(performance.now());
    for (const connection of connections) {
      connection.nextRecordSeq = null;
      connection.pendingPublish = null;
      requestCursor(connection);
    }
  };

  const requestTemporaryTurn = (connection: Connection, current: Round): void => {
    if (connection.ws?.readyState !== WebSocket.OPEN) return;
    connection.ws.send(JSON.stringify({
      type: "turn.issue",
      serverId: current.registration.record.payload.serverId,
      hostId: current.registration.record.payload.hostId,
      subject: "calls",
      ttlSeconds: 300,
    }));
  };

  const connect = (connection: Connection): void => {
    const { rendezvousUrl } = connection.target;
    const ws = openControlWebSocket(rendezvousUrl);
    connection.ws = ws;
    let openTimer: NodeJS.Timeout | null = null;
    let closed = false;

    const scheduleReconnect = (reason: string): void => {
      if (closed) return;
      closed = true;
      if (openTimer) clearTimeout(openTimer);
      svc.removeBridgeIceConfig(rendezvousUrl);
      ackQuorum.remove(connection.target.bridgeId);
      round?.acked.delete(connection.target.bridgeId);
      svc.events.off("hostGrantRevoked", sendRevocation);
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.terminate();
      const delay = connection.backoffMs + Math.floor(Math.random() * Math.max(1, connection.backoffMs / 4));
      console.warn(`[janjanode] rendezvous desconectado (${reason}); reconectando em ${delay}ms`);
      connection.retry = setTimeout(() => connect(connection), delay);
      connection.retry.unref();
      connection.backoffMs = Math.min(connection.backoffMs * 2, 30_000);
    };

    const sendRevocation = (revocation: Record<string, unknown>): void => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: "revoke",
          authorityPublicKey: (revocation as { publicKey: string }).publicKey,
          revocation,
        }));
      }
    };

    ws.on("message", (raw) => {
      let frame: Record<string, unknown>;
      try {
        frame = JSON.parse(raw.toString()) as Record<string, unknown>;
      } catch {
        return;
      }
      // TURN is issued only to this already-registered host socket. The shared issuer
      // secret never crosses this boundary; JanjaNode caches only the short credential.
      if (frame.ok === true && svc.upsertBridgeIceConfig(rendezvousUrl, frame.data)) return;
      if (frame.type === "host.epoch") {
        if (svc.observeHigherEpoch(frame.registration)) {
          if (round) svc.abandonPrimaryRegistration(round.recordHash);
          round = null;
          ackQuorum.clear();
        }
        return;
      }
      if (frame.type === "access.result" && frame.requestId === connection.accessRequestId) {
        if (frame.ok === true && typeof (frame.data as { accessToken?: unknown } | undefined)?.accessToken === "string") {
          connection.accessToken = (frame.data as { accessToken: string }).accessToken;
          requestCursor(connection);
        } else {
          const code = (frame.error as { code?: unknown } | undefined)?.code;
          if (code === "pairing_required" && !connection.pairingAttempted && connection.target.pairingToken) {
            connection.pairingAttempted = true;
            requestHostAccess(connection, true);
          } else {
            console.warn("[janjanode] JanjaBridge rejeitou emissão de credencial de host");
          }
        }
        return;
      }
      if (frame.type === "register.cursor.result" && frame.requestId === connection.cursorRequestId) {
        const next = (frame.data as { nextRecordSeq?: unknown } | undefined)?.nextRecordSeq;
        if (frame.ok === true && typeof next === "number" && Number.isSafeInteger(next) && next >= 1) {
          connection.nextRecordSeq = next;
          publish(connection);
        } else {
          console.warn(`[janjanode] JanjaBridge rejeitou cursor da cadeia de host records: ${JSON.stringify(frame.error ?? "invalid cursor")}`);
        }
        return;
      }
      if (frame.type === "register.challenge") {
        const pending = connection.pendingPublish;
        if (!pending || frame.requestId !== pending.requestId || frame.recordHash !== pending.recordHash) return;
        const proven = svc.provePrimaryRegistration(frame);
        if (!proven.ok) {
          console.warn(`[janjanode] desafio de registro rejeitado: ${proven.error.message}`);
          return;
        }
        ws.send(JSON.stringify({
          type: "register.prove",
          requestId: pending.requestId,
          challengeId: frame.challengeId,
          proof: proven.data,
        }));
        return;
      }
      const current = round;
      const pending = connection.pendingPublish;
      if (frame.type === "register.result" && current && pending && frame.requestId === pending.requestId) {
        if (frame.ok === true) {
          const ack = (frame.data ?? {}) as { recordHash?: unknown; epoch?: unknown; role?: unknown };
          const pendingBinding = {
            recordHash: pending.recordHash,
            epoch: pending.registration.record.payload.epoch,
            role: pending.registration.record.payload.role,
          };
          if (ack.recordHash !== pendingBinding.recordHash || ack.epoch !== pendingBinding.epoch
            || ack.role !== pendingBinding.role) {
            console.warn("[janjanode] JanjaBridge ACK não corresponde ao recordHash/epoch/role pendente");
            return;
          }
          if (pending.current && !current.committed) {
            const committed = svc.commitPrimaryRegistration(current.recordHash);
            if (!committed.ok) {
              console.warn(`[janjanode] ACK de registro não pôde ser commitado: ${committed.error.message}`);
              return;
            }
            current.committed = true;
            console.log("[janjanode] host record confirmado por ao menos um JanjaBridge");
          }
          connection.nextRecordSeq = (connection.nextRecordSeq ?? pending.registration.record.payload.recordSeq) + 1;
          connection.pendingPublish = null;
          if (pending.current) {
            if (!ackQuorum.acknowledge(connection.target.bridgeId, current.binding)) return;
            current.acked.add(connection.target.bridgeId);
            const now = performance.now();
            if (svc.resumeWriterAfterRegistrationQuorum(
              current.binding,
              [...current.acked],
              configuredBridgeIds,
            )) {
              writerObserved = true;
              console.log("[janjanode] persisted writer resumed after strict current registration quorum");
            }
            // Record the verified ACK at receipt time. The renewal heartbeat may rotate the
            // in-memory round before the one-second fence loop observes its quorum object. A
            // minority ACK never renews write authority.
            if (svc.isWriter()) writeAuthority.observe(current.binding, now);
            requestTemporaryTurn(connection, current);
          } else {
            publish(connection);
          }
        } else {
          if (frame.higherRegistration && svc.observeHigherEpoch(frame.higherRegistration)) {
            if (round) svc.abandonPrimaryRegistration(round.recordHash);
            round = null;
            ackQuorum.clear();
            console.warn("[janjanode] higher signed host epoch observed; stale writer fenced");
          }
          console.warn(`[janjanode] JanjaBridge rejeitou registro: ${JSON.stringify(frame.error ?? "unknown")}`);
          const retry = setTimeout(() => publish(connection), Math.min(renewMs, 2_000));
          retry.unref();
        }
      }
    });

    ws.on("pong", (payload) => {
      const current = round;
      const roundId = payload.toString();
      if (!current || roundId !== connection.livenessRoundId) return;
      connection.livenessRoundId = null;
      if (ackQuorum.confirmLiveness(connection.target.bridgeId, current.binding, roundId)
        && svc.isWriter()) writeAuthority.observe(current.binding, performance.now());
    });

    ws.once("open", () => {
      if (openTimer) clearTimeout(openTimer);
      connection.backoffMs = 1_000;
      connection.accessToken = null;
      connection.pairingAttempted = false;
      connection.nextRecordSeq = null;
      connection.pendingPublish = null;
      connection.livenessRoundId = null;
      requestHostAccess(connection);
      attachIceHostGateway(ws, Number(process.env.JC_PORT ?? 8931), (proof, expected) => svc.authorizeIceAccess(proof, expected));
      for (const revocation of svc.hostRevocations()) sendRevocation(revocation);
      svc.events.on("hostGrantRevoked", sendRevocation);
    });
    ws.once("error", (error) => scheduleReconnect(error.message));
    ws.once("close", (code) => scheduleReconnect(`close ${code}`));
    openTimer = setTimeout(() => scheduleReconnect("connect timeout"), 5_000);
    openTimer.unref();
  };
  svc.events.on("writerPromoted", publishPromotedWriter);
  for (const connection of connections) connect(connection);
  const heartbeat = setInterval(() => {
    if (round?.committed) {
      svc.abandonPrimaryRegistration(round.recordHash);
      round = null;
      ackQuorum.clear();
    }
    for (const connection of connections) publish(connection);
  }, renewMs);
  heartbeat.unref();
  const bridgeLiveness = setInterval(() => {
    const current = round;
    if (!svc.isWriter() || !current) return;
    const roundId = randomUUID();
    if (!ackQuorum.beginLivenessRound(current.binding, roundId)) return;
    for (const connection of connections) {
      connection.livenessRoundId = null;
      if (connection.ws?.readyState !== WebSocket.OPEN) continue;
      connection.livenessRoundId = roundId;
      connection.ws.ping(roundId);
    }
  }, 1_000);
  bridgeLiveness.unref();
  const writerFence = setInterval(() => {
    if (!svc.isWriter()) {
      writerObserved = false;
      // Restart-suspended writers must retain verified current-round ACKs long enough to
      // establish strict quorum. Fenced writers and ordinary replicas remain fail-closed.
      if (!svc.isWriterResumePending()) ackQuorum.clear();
      return;
    }
    if (!writerObserved) {
      // A newly promoted replica gets a fresh bounded registration window. Time spent
      // read-only before promotion must never trigger an immediate stale-writer fence.
      writerObserved = true;
      writeAuthority.reset(performance.now());
      ackQuorum.clear();
      round = null;
      return;
    }
    if (writeAuthority.fenceIfQuorumExpired(
      primaryFenceMs,
      () => svc.fencePrimaryWriter(),
      performance.now(),
    )) {
      console.error("[janjanode] primary fenced after loss of strict bridge registration quorum");
    }
  }, 1_000);
  writerFence.unref();
}

async function bootstrap(): Promise<void> {
  const replicaRuntime = (process.env.JC_REPLICA_ENROLLMENT_FILE || process.env.JC_REPLICA_OF)
    ? prepareReplicaEnrollment()
    : null;
  const app = await NestFactory.create(AppModule, { logger: ["error", "warn", "log"] });
  app.useWebSocketAdapter(new WsAdapter(app));
  await app.init();
  const port = Number(process.env.JC_PORT ?? 8931);
  console.log(`[janjanode] JanjaNode host ativo — ws://127.0.0.1:${port}/signal`);
  const svc = app.get(ServerService);
  if (replicaRuntime) {
    const { material } = replicaRuntime;
    if (
      svc.getServerId() !== material.serverId ||
      svc.getAuthorityPublicKey() !== material.authorityPublicKey ||
      svc.getEpochPublic() < material.epoch
    ) {
      throw new Error("replica enrollment metadata does not match the opened database");
    }
    svc.configureReplicaTrust(
      material.primaryHost.hostId,
      material.bridgeAccess.map((entry) => entry.descriptor.payload.bridgeId),
    );
  }
  await registerRendezvous(svc);
  startPushPinger(svc);
  if (replicaRuntime) {
    startReplicaLoop(svc, process.env.JC_REPLICA_OF, replicaRuntime);
  }
}

/** Push genérico (spec mobile/push): em atividade, pinga o push service com o ticket
 *  do host — payload 100% estático, sem conteúdo/sender/server/channel. */
function startPushPinger(svc: ServerService): void {
  const pushUrl = process.env.JC_PUSH_URL;
  const ticket = process.env.JC_PUSH_TICKET;
  if (!pushUrl || !ticket) return;
  const serverId = svc.getServerId();
  let lastPing = 0;
  svc.events.on("activity", () => {
    const now = Date.now();
    if (now - lastPing < 5000) return; // debounce (evita flood de pings)
    lastPing = now;
    void (async () => {
      try {
        const ws = openControlWebSocket(pushUrl);
        await new Promise<void>((res, rej) => {
          let settled = false;
          const finish = (error?: Error) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            ws.off("open", onOpen);
            ws.off("error", onError);
            if (error) rej(error);
            else res();
          };
          const onOpen = () => finish();
          const onError = (error: Error) => finish(error);
          const timer = setTimeout(() => {
            // `ws` emits an error while aborting CONNECTING; retain a sink after cleanup.
            ws.once("error", () => undefined);
            ws.terminate();
            finish(new Error("push handshake timeout"));
          }, 4000);
          ws.once("open", onOpen);
          ws.once("error", onError);
        });
        ws.send(JSON.stringify({ type: "host.ping", ticket, serverId }));
        ws.close();
      } catch {
        // push é best-effort — falha não afeta o fluxo
      }
    })();
  });
}

function prepareReplicaEnrollment(): ReplicaRuntime {
  const encoded = process.env.JC_REPLICA_ENROLLMENT;
  const file = process.env.JC_REPLICA_ENROLLMENT_FILE;
  if (!encoded && !file) throw new Error("JC_REPLICA_ENROLLMENT or JC_REPLICA_ENROLLMENT_FILE is required");
  if (file && process.platform !== "win32" && (statSync(file).mode & 0o077) !== 0) {
    throw new Error("replica enrollment file must not be readable by group/others");
  }
  const raw = file
    ? readFileSync(file, "utf8")
    : encoded!.trim().startsWith("{")
      ? encoded!
      : Buffer.from(encoded!, "base64url").toString("utf8");
  const parsed = JSON.parse(raw) as SealedReplicaEnrollment | { sealedEnrollment?: SealedReplicaEnrollment };
  const sealed = "sealedEnrollment" in parsed
    ? parsed.sealedEnrollment
    : parsed as SealedReplicaEnrollment;
  if (!sealed) throw new Error("replica enrollment file does not contain a sealed enrollment");
  const material = openReplicaEnrollment(sealed);
  assertReplicaEnrollment(material);

  const memberDeviceSeed = parseSeed("JC_REPLICA_DEVICE_SEED");
  const hostSeed = parseSeed("JC_HOST_SIGNING_SEED");
  if (memberDeviceSeed.equals(hostSeed)) {
    throw new Error("JC_REPLICA_DEVICE_SEED and JC_HOST_SIGNING_SEED must be distinct secrets");
  }
  if (ed25519PublicKey(memberDeviceSeed).toString("base64url") !== material.subjectAuthPublicKey) {
    throw new Error("JC_REPLICA_DEVICE_SEED does not match the enrollment grant-bound member device");
  }
  if (ed25519PublicKey(hostSeed).toString("base64url") !== material.replicaHost.publicKey) {
    throw new Error("JC_HOST_SIGNING_SEED does not match the enrolled replica host key");
  }

  const dbKey = Buffer.from(material.dbKeyB64, "base64url");
  const encryptedDb = Buffer.from(material.dbB64, "base64");
  const dbPath = process.env.JC_DB_PATH ?? "./janjanode-data/server.db";
  if (!existsSync(dbPath) && material.expiresAt <= Date.now()) throw new Error("replica enrollment expired before first installation");
  if (!process.env.JC_BRIDGE_DESCRIPTORS && material.bridgeAccess.length > 0) {
    process.env.JC_BRIDGE_DESCRIPTORS = JSON.stringify(material.bridgeAccess.map((entry) => entry.descriptor));
  }
  process.env.JC_DB_KEY = dbKey.toString("hex");
  const expected = {
    serverId: material.serverId,
    authorityPublicKey: material.authorityPublicKey,
  };
  if (existsSync(dbPath)) {
    Store.validateEncryptedFile(dbPath, dbKey, {
      ...expected,
      minimumEpoch: material.epoch,
      minimumSeq: material.seq,
    });
    const installed = new Store(dbPath, dbKey);
    try {
      const row = installed.raw.prepare(
        "SELECT value FROM server_meta WHERE key = 'replica_enrollment_id'",
      ).get() as { value: string } | undefined;
      if (row?.value !== material.enrollmentId) {
        if (row || sha256Hex(readFileSync(dbPath)) !== sealed.transcript.payload.snapshotHash) {
          throw new Error("replica enrollment replay/substitution rejected");
        }
        installed.raw.prepare("INSERT INTO server_meta (key, value) VALUES ('replica_enrollment_id', ?)")
          .run(material.enrollmentId);
      }
    } finally {
      installed.close();
    }
  } else {
    Store.installEncryptedSnapshot(dbPath, encryptedDb, dbKey, {
      ...expected,
      exactEpoch: material.epoch,
      exactSeq: material.seq,
    });
    const installed = new Store(dbPath, dbKey);
    try {
      installed.raw.prepare("INSERT INTO server_meta (key, value) VALUES ('replica_enrollment_id', ?)")
        .run(material.enrollmentId);
    } finally {
      installed.close();
    }
  }
  return { material, memberDeviceSeed };
}

function openReplicaEnrollment(envelope: SealedReplicaEnrollment): ReplicaEnrollmentMaterial {
  if (
    envelope.version !== 2 ||
    envelope.algorithm !== "X25519-HKDF-SHA256-AES-256-GCM"
  ) throw new Error("unsupported sealed replica enrollment");
  const privateRaw = parseSeed("JC_REPLICA_ENROLLMENT_PRIVATE_KEY");
  const privateKey = createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PRIVATE_PREFIX, privateRaw]),
    format: "der",
    type: "pkcs8",
  });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const recipientRaw = Buffer.from(publicDer).subarray(-32);
  const transcript = envelope.transcript;
  if (!verifyReplicaEnrollmentTranscript(envelope, recipientRaw.toString("base64url"))) {
    throw new Error("replica enrollment authority transcript signature is invalid");
  }
  const aad = Buffer.from(canonicalJson(transcript), "utf8");
  const ephemeralRaw = Buffer.from(envelope.ephemeralPublicKey, "base64url");
  const ephemeralKey = createPublicKey({
    key: Buffer.concat([X25519_SPKI_PUBLIC_PREFIX, ephemeralRaw]),
    format: "der",
    type: "spki",
  });
  const shared = diffieHellman({ privateKey, publicKey: ephemeralKey });
  const key = Buffer.from(hkdfSync(
    "sha256",
    shared,
    Buffer.concat([ephemeralRaw, recipientRaw]),
    Buffer.concat([ENROLLMENT_AAD, Buffer.from(sha256Hex(aad), "hex")]),
    32,
  ));
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.nonce, "base64url"));
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
    decipher.final(),
  ]);
  const material = JSON.parse(plaintext.toString("utf8")) as ReplicaEnrollmentMaterial;
  const bridgeSetHash = sha256Hex(canonicalJson(
    material.bridgeAccess.map((entry) => entry.descriptor).sort((a, b) => a.payload.bridgeId.localeCompare(b.payload.bridgeId)),
  ));
  const snapshotHash = sha256Hex(Buffer.from(material.dbB64, "base64"));
  const payload = transcript.payload;
  if (material.authorityPublicKey !== transcript.publicKey
    || material.enrollmentId !== payload.enrollmentId
    || material.serverId !== payload.serverId
    || material.authorityFingerprint !== payload.authorityFingerprint
    || material.grantId !== payload.grantId
    || material.replicaGrant.payload.generation !== payload.generation
    || material.subjectAuthPublicKey !== payload.subjectAuthPublicKey
    || canonicalJson(material.replicaHost) !== canonicalJson(payload.replicaHost)
    || canonicalJson(material.primaryHost) !== canonicalJson(payload.primaryHost)
    || material.epoch !== payload.epoch || material.seq !== payload.seq
    || material.issuedAt !== payload.issuedAt || material.expiresAt !== payload.expiresAt
    || snapshotHash !== payload.snapshotHash || bridgeSetHash !== payload.bridgeSetHash) {
    throw new Error("replica enrollment transcript/material mismatch");
  }
  return material;
}

function parseSeed(name: string): Buffer {
  const value = process.env[name] ?? "";
  if (!/^[0-9a-f]{64}$/i.test(value)) throw new Error(`${name} must be exactly 32 bytes encoded as hex`);
  return Buffer.from(value, "hex");
}

function assertReplicaEnrollment(value: ReplicaEnrollmentMaterial): void {
  if (!value || value.version !== 2) throw new Error("unsupported replica enrollment version");
  const strings = [
    value.serverId,
    value.enrollmentId,
    value.authorityPublicKey,
    value.authorityFingerprint,
    value.grantId,
    value.subjectIdentityId,
    value.subjectAuthPublicKey,
    value.replicaHost?.hostId,
    value.replicaHost?.publicKey,
    value.primaryHost?.hostId,
    value.primaryHost?.grantId,
    value.primaryHost?.publicKey,
    value.dbB64,
    value.dbKeyB64,
  ];
  if (strings.some((item) => typeof item !== "string" || item.length === 0)) {
    throw new Error("replica enrollment is missing required metadata");
  }
  if (!Array.isArray(value.bridgeAccess) || value.bridgeAccess.length > 3 || value.bridgeAccess.some((entry) => (
    !entry || !entry.descriptor || typeof entry.descriptor.payload?.bridgeId !== "string"
  ))) throw new Error("replica enrollment bridge access is invalid");
  if (!Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt)
    || value.expiresAt <= value.issuedAt || value.expiresAt > value.issuedAt + 10 * 60_000) {
    throw new Error("replica enrollment validity window is invalid");
  }
  if (!Number.isSafeInteger(value.epoch) || value.epoch < 0 || !Number.isSafeInteger(value.seq) || value.seq < 0) {
    throw new Error("replica enrollment epoch/seq is invalid");
  }
  const authorityKey = Buffer.from(value.authorityPublicKey, "base64url");
  if (authorityKey.length !== 32 || ed25519Fingerprint(authorityKey) !== value.authorityFingerprint) {
    throw new Error("replica enrollment authority fingerprint mismatch");
  }
  if (Buffer.from(value.dbKeyB64, "base64url").length !== 32) throw new Error("replica enrollment DB key is invalid");
  if (Buffer.from(value.dbB64, "base64").toString("base64") !== value.dbB64) {
    throw new Error("replica enrollment DB snapshot is not canonical base64");
  }
}

type ReplicaResponse =
  | { ok: true; data: Record<string, unknown> }
  | { ok: false; error: { code?: string; message?: string } };

async function replicaRequest(
  url: string | undefined,
  runtime: ReplicaRuntime,
  trust: { publicKey: string; hostId: string; grantId: string },
  command: import("@janjacord/schemas").HostCommand,
): Promise<ReplicaResponse> {
  const { material, memberDeviceSeed } = runtime;
  if (material.bridgeAccess.length > 0) {
    const resolved = await resolvePrimaryRegistration(material);
    if (!resolved) throw new Error("primary signed registration is unavailable from configured bridges");
    const transport = new IceHostTransport({
      bridgeUrls: material.bridgeAccess.map((entry) => bridgeEndpoint(entry.descriptor, "signaling")),
      serverId: material.serverId,
      hostId: trust.hostId,
      identityId: material.subjectIdentityId,
      authorityFingerprint: material.authorityFingerprint,
      hostRegistration: resolved,
      deviceSeed: memberDeviceSeed,
      iceServers: [],
      networkPrivacy: "direct",
      connectionTimeoutMs: 8_000,
      maxReconnectAttempts: material.bridgeAccess.length,
    });
    try {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("authenticated WAN replica connection timeout")), 12_000);
        transport.onOpen(() => { clearTimeout(timer); resolve(); });
        transport.onClose(() => { clearTimeout(timer); reject(new Error("WAN replica transport closed before authentication")); });
      });
      return await transport.request(command, 8_000) as ReplicaResponse;
    } finally {
      transport.close();
    }
  }
  if (!url) throw new Error("replica has neither bridge access nor an explicit LAN primary URL");
  // HostClient intentionally owns authenticated protocol state but does not expose its raw
  // socket. A bounded reachability probe keeps an expected offline primary from becoming an
  // unhandled ws error in the periodic replica worker.
  await new Promise<void>((resolve, reject) => {
    const probe = openControlWebSocket(url);
    const timer = setTimeout(() => { probe.terminate(); reject(new Error("LAN primary probe timeout")); }, 2_000);
    probe.once("open", () => { clearTimeout(timer); probe.close(); resolve(); });
    probe.once("error", (error) => { clearTimeout(timer); reject(error); });
  });
  const client = new HostClient(url, {
    identityId: material.subjectIdentityId,
    deviceSeed: memberDeviceSeed,
    serverId: material.serverId,
    authorityFingerprint: material.authorityFingerprint,
    expectedHostPublicKey: trust.publicKey,
    expectedHostId: trust.hostId,
    expectedGrantId: trust.grantId,
  });
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("authenticated replica connection timeout")), 4_000);
      client.onOpen(() => {
        clearTimeout(timer);
        resolve();
      });
      client.onClose(() => {
        clearTimeout(timer);
        reject(new Error("replica connection closed before authentication"));
      });
    });
    return await client.request(command, 6_000) as ReplicaResponse;
  } finally {
    client.close();
  }
}

function bridgeEndpoint(descriptor: import("@janjacord/schemas").SignedBridgeDescriptor, path: "rendezvous" | "signaling"): string {
  const endpoint = descriptor.payload.endpoints.find((value) => value.startsWith("wss://") || value.startsWith("https://"));
  if (!endpoint) throw new Error("bridge descriptor has no TLS endpoint");
  const url = new URL(endpoint);
  url.protocol = "wss:";
  url.pathname = `/${path}`;
  if (process.env.JC_ALLOW_INSECURE_BRIDGE_LOOPBACK === "1" && ["127.0.0.1", "localhost", "::1"].includes(url.hostname)) {
    url.protocol = "ws:";
  }
  return url.toString();
}

async function resolvePrimaryRegistration(material: ReplicaEnrollmentMaterial): Promise<unknown | null> {
  for (const access of material.bridgeAccess) {
    const ws = openControlWebSocket(bridgeEndpoint(access.descriptor, "rendezvous"));
    try {
      const response = await new Promise<Record<string, unknown>>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("bridge resolve timeout")), 4_000);
        ws.once("open", () => ws.send(JSON.stringify({
          type: "resolve",
          serverId: material.serverId,
          authorityFingerprint: material.authorityFingerprint,
        })));
        ws.once("message", (raw) => { clearTimeout(timer); resolve(JSON.parse(raw.toString()) as Record<string, unknown>); });
        ws.once("error", (error) => { clearTimeout(timer); reject(error); });
      });
      const records = (response.data as { records?: unknown[] } | undefined)?.records ?? [];
      const registration = records.find((entry) => {
        const value = entry as { record?: { payload?: { hostId?: string; grantId?: string } }; grant?: { payload?: { grantId?: string; devicePublicKey?: string } } };
        return value.record?.payload?.hostId === material.primaryHost.hostId
          && value.grant?.payload?.grantId === material.primaryHost.grantId
          && value.grant?.payload?.devicePublicKey === material.primaryHost.publicKey;
      });
      if (registration) return registration;
    } catch {
      // Try the next independently configured bridge.
    } finally {
      ws.close();
    }
  }
  return null;
}

function isGrantDenied(response: ReplicaResponse): boolean {
  return !response.ok && ["forbidden", "unauthorized"].includes(response.error.code ?? "");
}

async function claimPromotionVoteAtBridge(
  access: ReplicaEnrollmentMaterial["bridgeAccess"][number],
  authorityFingerprint: string,
  serverId: string,
  witness: CollectedBridgeWitness,
  expectedEpoch: number,
  candidateHostId: string,
): Promise<PromotionVoteClaim> {
  const requestId = randomUUID();
  const ws = openControlWebSocket(bridgeEndpoint(access.descriptor, "rendezvous"));
  try {
    const frame = await new Promise<Record<string, unknown>>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("promotion claim timeout")), 4_000);
      ws.once("open", () => ws.send(JSON.stringify({
        type: "promotion.claim",
        requestId,
        authorityFingerprint,
        witness: witness.signed,
      })));
      ws.once("message", (raw) => {
        clearTimeout(timer);
        try { resolve(JSON.parse(raw.toString()) as Record<string, unknown>); } catch (error) { reject(error); }
      });
      ws.once("error", (error) => { clearTimeout(timer); reject(error); });
    });
    if (frame.requestId !== requestId || frame.ok !== true) {
      const code = (frame.error as { code?: unknown } | undefined)?.code;
      return code === "conflict" ? { kind: "conflict" } : { kind: "unavailable" };
    }
    const receipt = (frame.data as { receipt?: unknown } | undefined)?.receipt as {
      payload?: Record<string, unknown>;
      publicKey?: unknown;
      signature?: unknown;
    } | undefined;
    const payload = receipt?.payload;
    const expectedKeys = [
      "bridgeId", "candidateHostId", "electionEpoch", "expiresAt", "issuedAt", "primaryEpoch",
      "primaryHostId", "primaryRecordHash", "requestId", "serverId", "version", "voteGrantedAt",
    ];
    const signature = typeof receipt?.signature === "string" ? Buffer.from(receipt.signature, "base64url") : Buffer.alloc(0);
    const now = Date.now();
    if (!payload || receipt?.publicKey !== access.descriptor.publicKey
      || Object.keys(payload).sort().join("\0") !== expectedKeys.sort().join("\0")
      || payload.version !== 1
      || payload.bridgeId !== access.descriptor.payload.bridgeId
      || payload.requestId !== requestId
      || payload.serverId !== serverId
      || payload.candidateHostId !== candidateHostId
      || payload.primaryHostId !== witness.validated.primaryHostId
      || payload.primaryRecordHash !== witness.validated.primaryRecordHash
      || payload.primaryEpoch !== expectedEpoch
      || payload.electionEpoch !== expectedEpoch + 1
      || !Number.isSafeInteger(payload.voteGrantedAt)
      || !Number.isSafeInteger(payload.issuedAt)
      || !Number.isSafeInteger(payload.expiresAt)
      || Number(payload.voteGrantedAt) > Number(payload.issuedAt)
      || Number(payload.issuedAt) > now + 5_000
      || Number(payload.expiresAt) <= now
      || Number(payload.expiresAt) > Number(payload.issuedAt) + 24 * 3600_000
      || signature.length !== 64 || signature.toString("base64url") !== receipt.signature
      || !verifyCanonicalPayload(Buffer.from(access.descriptor.publicKey, "base64url"), PROMOTION_VOTE_DOMAIN, payload, signature)) {
      return { kind: "unavailable" };
    }
    return {
      kind: "granted",
      observation: {
        bridgeId: String(payload.bridgeId),
        requestId,
        candidateHostId,
        primaryHostId: String(payload.primaryHostId),
        primaryRecordHash: String(payload.primaryRecordHash),
        primaryEpoch: Number(payload.primaryEpoch),
        electionEpoch: Number(payload.electionEpoch),
        primaryOnline: false,
        observedAt: Number(payload.issuedAt),
        expiresAt: Number(payload.expiresAt),
        receipt,
      },
    };
  } catch {
    return { kind: "unavailable" };
  } finally {
    ws.close();
  }
}

async function bridgeWitnessQuorum(runtime: ReplicaRuntime, expectedEpoch: number): Promise<import("./server.service.js").BridgeWitnessObservation[] | null> {
  const { material } = runtime;
  const resolvedPrimary = await resolvePrimaryRegistration(material) as { record?: unknown; grant?: unknown } | null;
  if (!resolvedPrimary) return null;
  const verifiedPrimary = verifyHostRegistration({
    record: resolvedPrimary.record,
    grant: resolvedPrimary.grant,
    authorityPublicKey: material.authorityPublicKey,
  });
  if (!verifiedPrimary || verifiedPrimary.record.payload.role !== "primary"
    || verifiedPrimary.record.payload.hostId !== material.primaryHost.hostId
    || verifiedPrimary.record.payload.epoch !== expectedEpoch) return null;
  const primaryRecordHash = hostRegistrationRecordHash(verifiedPrimary.record);
  const hostSeed = parseSeed("JC_HOST_SIGNING_SEED");
  const issuedAt = Date.now();
  const payload = {
    version: 1,
    serverId: material.serverId,
    primaryHostId: material.primaryHost.hostId,
    replicaHostId: material.replicaHost.hostId,
    grantId: material.grantId,
    nonce: randomUUID(),
    issuedAt,
    expiresAt: issuedAt + 15_000,
  };
  const proof = {
    payload,
    publicKey: material.replicaHost.publicKey,
    signature: signCanonicalPayload(hostSeed, "janjacord.replica-witness.v1", payload).toString("base64url"),
  };
  const responses = await Promise.all(material.bridgeAccess.map(async (access) => {
    const ws = openControlWebSocket(bridgeEndpoint(access.descriptor, "rendezvous"));
    try {
      const accessToken = await new Promise<string | null>((resolve) => {
        const requestId = randomUUID();
        const accessIssuedAt = Date.now();
        const accessPayload = {
          version: 1,
          bridgeId: access.descriptor.payload.bridgeId,
          serverId: material.serverId,
          hostId: material.replicaHost.hostId,
          grantId: material.grantId,
          slot: "witness" as const,
          proofId: randomUUID(),
          issuedAt: accessIssuedAt,
          expiresAt: accessIssuedAt + 30_000,
        };
        const timer = setTimeout(() => resolve(null), 4_000);
        ws.once("open", () => ws.send(JSON.stringify({
          type: "access.issue",
          requestId,
          authorityPublicKey: material.authorityPublicKey,
          grant: material.replicaGrant,
          proof: {
            payload: accessPayload,
            publicKey: material.replicaHost.publicKey,
            signature: signCanonicalPayload(hostSeed, "janjacord.bridge-access.v1", accessPayload).toString("base64url"),
          },
        })));
        ws.once("message", (raw) => {
          clearTimeout(timer);
          try {
            const frame = JSON.parse(raw.toString()) as { requestId?: string; ok?: boolean; data?: { accessToken?: unknown }; error?: { code?: string } };
            if (process.env.JC_HOST_DIAGNOSTICS === "1" && frame.ok !== true) {
              console.debug(`[janjanode] witness access unavailable (${frame.error?.code ?? "invalid_response"})`);
            }
            resolve(frame.requestId === requestId && frame.ok === true && typeof frame.data?.accessToken === "string"
              ? frame.data.accessToken : null);
          } catch { resolve(null); }
        });
        ws.once("error", () => { clearTimeout(timer); resolve(null); });
      });
      if (!accessToken) return { access, witness: null };
      const requestId = randomUUID();
      const witness = await new Promise<CollectedBridgeWitness | null>((resolve) => {
        const timer = setTimeout(() => { ws.terminate(); resolve(null); }, 4_000);
        ws.send(JSON.stringify({
          type: "witness.primary",
          requestId,
          accessToken,
          authorityPublicKey: material.authorityPublicKey,
          grant: material.replicaGrant,
          proof,
        }));
        ws.once("message", (raw) => {
          clearTimeout(timer);
          try {
            const frame = JSON.parse(raw.toString()) as { requestId?: string; ok?: boolean; data?: { witness?: unknown }; error?: { code?: string } };
            if (process.env.JC_HOST_DIAGNOSTICS === "1" && frame.ok !== true) {
              console.debug(`[janjanode] witness observation unavailable (${frame.error?.code ?? "invalid_response"})`);
            }
            if (frame.requestId !== requestId || frame.ok !== true) return resolve(null);
            const validated = validateBridgeWitnessResponse(frame.data?.witness, access.descriptor, {
              requestId,
              serverId: material.serverId,
              replicaHostId: material.replicaHost.hostId,
              primaryHostId: material.primaryHost.hostId,
              primaryRecordHash,
              primaryEpoch: expectedEpoch,
            });
            resolve(validated ? { validated, signed: frame.data?.witness } : null);
          } catch { resolve(null); }
        });
        ws.once("error", () => { clearTimeout(timer); resolve(null); });
      });
      return { access, witness };
    } finally {
      ws.close();
    }
  }));
  if (process.env.JC_HOST_DIAGNOSTICS === "1") {
    console.debug(`[janjanode] witness observations=${responses.map(({ witness }) => witness?.validated.primaryOnline === false ? "absent" : witness?.validated.primaryOnline === true ? "online" : "unavailable").join(",")}`);
  }
  if (!strictBridgeWitnessQuorum(material.bridgeAccess.length, responses.map(({ witness }) => witness?.validated.primaryOnline ?? null))) return null;
  const absent = responses
    .filter((entry): entry is { access: ReplicaEnrollmentMaterial["bridgeAccess"][number]; witness: CollectedBridgeWitness } => entry.witness?.validated.primaryOnline === false)
    .sort((left, right) => left.access.descriptor.payload.bridgeId.localeCompare(right.access.descriptor.payload.bridgeId));
  const observed = absent.map(({ witness }) => witness.validated.observedAt);
  if (Math.max(...observed) - Math.min(...observed) > 10_000) return null;

  // Vote sequentially in stable bridge order. Safety comes from one durable vote per bridge and
  // intersecting strict quorums; stopping on a conflicting first vote also avoids poisoning
  // follower bridges during a concurrent election.
  const votes: import("./server.service.js").BridgeWitnessObservation[] = [];
  for (const { access, witness } of absent) {
    const claim = await claimPromotionVoteAtBridge(
      access,
      material.authorityFingerprint,
      material.serverId,
      witness,
      expectedEpoch,
      material.replicaHost.hostId,
    );
    if (claim.kind === "conflict") break;
    if (claim.kind === "granted") votes.push(claim.observation);
  }
  if (!strictBridgeWitnessQuorum(
    material.bridgeAccess.length,
    material.bridgeAccess.map(({ descriptor }) => votes.some((vote) => vote.bridgeId === descriptor.payload.bridgeId) ? false : null),
  )) return null;
  return votes;
}

async function startReplicaLoop(
  svc: ServerService,
  primaryUrl: string | undefined,
  runtime: ReplicaRuntime,
): Promise<void> {
  const intervalMs = Number(process.env.JC_LEASE_INTERVAL_MS ?? 5000);
  const revokeAfter = Number(process.env.JC_LEASE_REVOKE_MS ?? 15000);
  const { material } = runtime;
  let lastHealthyAt = Date.now();
  let fenced = false;
  let running = false;
  console.log(`[janjanode] modo réplica autenticada ativo (offline threshold ${revokeAfter}ms)`);

  const primaryTrust = {
    publicKey: material.primaryHost.publicKey,
    hostId: material.primaryHost.hostId,
    grantId: material.primaryHost.grantId,
  };
  const sync = async (): Promise<"ok" | "denied" | "failed"> => {
    let response: ReplicaResponse;
    try {
      response = await replicaRequest(primaryUrl, runtime, primaryTrust, {
        type: "replica.snapshot",
        grantId: material.grantId,
        serverId: material.serverId,
      });
    } catch (error) {
      console.warn(`[janjanode] snapshot sync interrompido: ${(error as Error).message}`);
      return "failed";
    }
    if (isGrantDenied(response)) return "denied";
    if (!response.ok) return "failed";
    const data = response.data as {
      dbB64?: string;
      serverId?: string;
      authorityPublicKey?: string;
      epoch?: number;
      seq?: number;
    };
    if (
      typeof data.dbB64 !== "string" ||
      data.serverId !== material.serverId ||
      data.authorityPublicKey !== material.authorityPublicKey ||
      !Number.isSafeInteger(data.epoch) ||
      !Number.isSafeInteger(data.seq)
    ) return "failed";
    const applied = svc.applyReplicaSnapshot(data as Required<typeof data>);
    if (!applied.ok) {
      console.warn(`[janjanode] snapshot rejeitado: ${applied.error.message}`);
      return "failed";
    }
    return "ok";
  };

  const tick = async (): Promise<void> => {
    if (running || svc.isWriter() || svc.isWriterResumePending() || fenced) return;
    running = true;
    try {
      const localEpoch = svc.getEpochPublic();
      let ping: ReplicaResponse;
      try {
        ping = await replicaRequest(primaryUrl, runtime, primaryTrust, {
          type: "replica.ping",
          grantId: material.grantId,
          serverId: material.serverId,
          epoch: localEpoch,
        });
      } catch (error) {
        const elapsed = Date.now() - lastHealthyAt;
        console.warn(`[janjanode] primary inalcançável; lease=${elapsed}/${revokeAfter}ms`);
        if (elapsed >= revokeAfter && material.bridgeAccess.length > 0) {
          const witness = await bridgeWitnessQuorum(runtime, localEpoch);
          if (!witness) {
            console.error("[janjanode] primary offline; witness quorum unavailable or primary still online; replica remains read-only");
            return;
          }
          const promoted = svc.promoteFromWitness(
            material.subjectIdentityId,
            material.subjectAuthPublicKey,
            material.grantId,
            svc.getEpochPublic(),
            witness,
          );
          if (!promoted.ok) {
            console.error(`[janjanode] witness quorum obtained but local promote grant rejected: ${promoted.error.message}`);
            return;
          }
          // Consume this live decision once. If registration later self-fences the new
          // primary, stay closed until an operator-controlled restart instead of cycling
          // the epoch on the same absence observations.
          fenced = true;
          console.log("[janjanode] replica promoted after strict bridge witness quorum observed primary absent");
        }
        return;
      }

      if (isGrantDenied(ping)) {
        fenced = true;
        svc.fenceReplicaGrant(material.grantId);
        console.error("[janjanode] grant de réplica negado/revogado; sync e promoção foram bloqueados");
        return;
      }
      if (
        ping.ok &&
        ping.data.serverId === material.serverId &&
        ping.data.epoch === localEpoch
      ) {
        lastHealthyAt = Date.now();
        const synced = await sync();
        if (synced === "denied") {
          fenced = true;
          svc.fenceReplicaGrant(material.grantId);
        }
        return;
      }

      // Authenticated but mismatched/error responses are unhealthy and never advance the lease.
      // A mismatch may be repaired by a higher/equal-epoch snapshot, but must not trigger promotion.
      const synced = await sync();
      if (synced === "denied") {
        fenced = true;
        svc.fenceReplicaGrant(material.grantId);
      }
    } finally {
      running = false;
    }
  };

  await tick();
  setInterval(() => void tick(), intervalMs).unref();
}

bootstrap().catch((err) => {
  console.error("[janjanode] fatal:", err);
  process.exit(1);
});
