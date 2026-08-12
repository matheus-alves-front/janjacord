import { WebSocket } from "ws";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import nodeDataChannel, { type DataChannel, type IceServer, type PeerConnection } from "node-datachannel";
import { HostRegistrationSchema, SignedIceAccessProofSchema, type HostCommand, type HostEvent, type ErrorCode, type HostRegistration, type SignedIceAccessProof } from "@janjacord/schemas";
import { ed25519Fingerprint, ed25519PublicKey, signCanonicalPayload } from "@janjacord/crypto";
import { createSignedSessionAuth, hostRegistrationRecordHash, verifySignedHostAuthChallenge } from "@janjacord/protocol";
import { verifyHostAuthenticationContext, type VerifiedHostAuthenticationContext } from "./connectivity.js";

export * from "./connectivity.js";

export const EXTERNAL_WEBSOCKET_MAX_PAYLOAD_BYTES = 64 * 1024;
export const REPLICA_TRANSFER_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024;
export const EXTERNAL_WEBSOCKET_HANDSHAKE_TIMEOUT_MS = 5_000;

export type ExternalWebSocketBoundary = "protocol" | "replica-transfer";

const EXTERNAL_WEBSOCKET_POLICIES = Object.freeze({
  protocol: Object.freeze({
    maxPayload: EXTERNAL_WEBSOCKET_MAX_PAYLOAD_BYTES,
    perMessageDeflate: false as const,
    handshakeTimeout: EXTERNAL_WEBSOCKET_HANDSHAKE_TIMEOUT_MS,
  }),
  "replica-transfer": Object.freeze({
    // Full SQLCipher snapshots are currently sent as one authenticated JSON result. Keep that
    // privileged compatibility path separate from the 64 KiB public protocol boundary and
    // bounded well below ws's former 100 MiB default until the protocol gains chunking.
    maxPayload: REPLICA_TRANSFER_MAX_PAYLOAD_BYTES,
    perMessageDeflate: false as const,
    handshakeTimeout: EXTERNAL_WEBSOCKET_HANDSHAKE_TIMEOUT_MS,
  }),
});

export function externalWebSocketPolicy(boundary: ExternalWebSocketBoundary = "protocol") {
  return EXTERNAL_WEBSOCKET_POLICIES[boundary];
}

export function createExternalWebSocket(
  url: string,
): WebSocket {
  return new WebSocket(url, externalWebSocketPolicy("protocol"));
}

function setExternalWebSocketInboundBoundary(socket: WebSocket, boundary: ExternalWebSocketBoundary): boolean {
  const receiver = (socket as unknown as { _receiver?: { _maxPayload?: number } })._receiver;
  if (!receiver || typeof receiver._maxPayload !== "number") return false;
  receiver._maxPayload = externalWebSocketPolicy(boundary).maxPayload;
  return true;
}

/**
 * Transport abstraction (ADR-006/013):
 * - HostTransport: WebSocket p/ o JanjaNode (spool, membership, signaling)
 * - DirectTransport: DataChannel P2P (mensagens realtime entre peers online)
 * - RelayTransport: TURN-only (policy relay, ADR-007)
 * Cada transport entrega frames {event, data} validados por Zod.
 */

export interface Transport {
  /**
   * Fire-and-forget for the caller, but conservatively serialized against FIFO `result` frames.
   * Server-push remains inbound-only through onEvent().
   */
  send(event: string, data: unknown): void;
  onEvent(handler: (event: HostEvent) => void): void;
  onAuthenticatedOpen(handler: (event: AuthenticatedOpenEvent) => void): () => void;
  close(): void;
}

export interface AuthenticatedOpenEvent {
  /** Monotonic for each authenticated transition, including an authenticated ICE restart. */
  generation: number;
  /** False only for the transport's first authenticated opening. */
  reconnected: boolean;
}

/** Cliente WebSocket do host (signaling `{event,data}`, path /signal). */
export interface LegacyHostFirstUseCandidate {
  hostPublicKey: string;
  hostKeyFingerprint: string;
  serverId: string;
  authorityFingerprint: string;
  hostId: string;
  grantId: string;
}

export interface PendingLegacyHostConfirmation extends LegacyHostFirstUseCandidate {
  fingerprint: string;
  tokenHash: string;
  observedAt: number;
  expiresAt: number;
}

type PendingHostClientRequest = {
  frame: string;
  resolve?: (data: unknown) => void;
  timer: ReturnType<typeof setTimeout>;
  settled: boolean;
  inboundBoundary: ExternalWebSocketBoundary;
};

export function issueLegacyHostConfirmation(
  candidate: LegacyHostFirstUseCandidate,
  now = Date.now(),
  token = randomBytes(32).toString("base64url"),
): { pending: PendingLegacyHostConfirmation; challenge: { hostPublicKey: string; fingerprint: string; confirmationToken: string; expiresAt: number } } {
  const expiresAt = now + 2 * 60_000;
  return {
    pending: {
      ...candidate,
      fingerprint: candidate.hostKeyFingerprint,
      tokenHash: createHash("sha256").update(token).digest("hex"),
      observedAt: now,
      expiresAt,
    },
    challenge: {
      hostPublicKey: candidate.hostPublicKey,
      fingerprint: candidate.hostKeyFingerprint,
      confirmationToken: token,
      expiresAt,
    },
  };
}

export function validateLegacyHostConfirmation(
  pending: PendingLegacyHostConfirmation | null | undefined,
  supplied: { confirmationToken?: unknown; hostPublicKey?: unknown; fingerprint?: unknown },
  now = Date.now(),
): boolean {
  if (!pending || pending.expiresAt < now || supplied.hostPublicKey !== pending.hostPublicKey
    || supplied.fingerprint !== pending.fingerprint || typeof supplied.confirmationToken !== "string"
    || !/^[0-9a-f]{64}$/i.test(pending.tokenHash)) return false;
  const actual = createHash("sha256").update(supplied.confirmationToken).digest();
  const expected = Buffer.from(pending.tokenHash, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export class HostClient implements Transport {
  private ws!: WebSocket;
  private handler: ((event: HostEvent) => void) | null = null;
  private authenticated = false;
  private challengeVerified = false;
  private hostTrust: Pick<VerifiedHostAuthenticationContext, "hostPublicKey" | "hostId" | "grantId"> | null;
  private openHandlers: (() => void)[] = [];
  private authenticatedOpenGeneration = 0;
  private authenticatedOpenHandlers = new Set<(event: AuthenticatedOpenEvent) => void>();
  private legacyTrustPending = false;
  private closed = false;
  private socketGeneration = 0;
  private closeHandlers = new Set<() => void>();
  private pendingRequests: PendingHostClientRequest[] = [];
  private inFlightRequest: PendingHostClientRequest | null = null;

  constructor(
    private readonly url: string,
    private readonly auth: {
      identityId: string;
      deviceSeed?: Buffer;
      serverId?: string;
      authorityFingerprint?: string;
      hostRegistration?: unknown;
      expectedHostPublicKey?: string;
      expectedHostId?: string;
      expectedGrantId?: string;
      /** @deprecated No longer grants trust. Supply onLegacyHostFirstUse or a persisted pin. */
      allowUnverifiedLegacyHost?: boolean;
      /** Caller must confirm and persist this key before returning true. Session-only trust is then pinned to it. */
      onLegacyHostFirstUse?: (candidate: LegacyHostFirstUseCandidate) => boolean | Promise<boolean>;
    },
  ) {
    const verified = auth.hostRegistration && auth.serverId && auth.authorityFingerprint
      ? verifyHostAuthenticationContext(auth.hostRegistration, {
        serverId: auth.serverId,
        authorityFingerprint: auth.authorityFingerprint,
        hostId: auth.expectedHostId,
      })
      : null;
    if (auth.hostRegistration && !verified) throw new Error("invalid host authority/grant/record chain");
    this.hostTrust = verified ?? (auth.expectedHostPublicKey ? {
      hostPublicKey: auth.expectedHostPublicKey,
      hostId: auth.expectedHostId ?? "",
      grantId: auth.expectedGrantId ?? "",
    } : null);
    this.connect();
  }

  private connect(): void {
    if (this.closed) return;
    const generation = ++this.socketGeneration;
    const socket = createExternalWebSocket(this.url);
    this.ws = socket;
    this.authenticated = false;
    this.challengeVerified = false;
    this.legacyTrustPending = false;
    socket.on("open", () => {
      if (generation !== this.socketGeneration || this.closed) return;
      if (this.auth.deviceSeed) {
        socket.send(JSON.stringify({
          event: "auth.begin",
          data: {
            identityId: this.auth.identityId,
            publicKey: ed25519PublicKey(this.auth.deviceSeed).toString("base64url"),
          },
        }));
      } else {
        this.markOpen();
      }
    });
    socket.on("message", async (raw) => {
      if (generation !== this.socketGeneration || this.closed) return;
      try {
        const frame = JSON.parse(raw.toString()) as { event: string; data: unknown };
        if (frame.event === "auth.challenge" && this.auth.deviceSeed) {
          let verified = verifySignedHostAuthChallenge(frame.data, {
            serverId: this.auth.serverId,
            authorityFingerprint: this.auth.authorityFingerprint,
            hostPublicKey: this.hostTrust?.hostPublicKey,
            hostId: this.hostTrust?.hostId || undefined,
            grantId: this.hostTrust?.grantId || undefined,
          });
          if (!this.hostTrust) {
            if (!verified || !this.auth.onLegacyHostFirstUse || this.legacyTrustPending) {
              socket.close(1008, "explicit legacy host key confirmation required");
              return;
            }
            this.legacyTrustPending = true;
            const candidate: LegacyHostFirstUseCandidate = {
              hostPublicKey: verified.publicKey,
              hostKeyFingerprint: ed25519Fingerprint(Buffer.from(verified.publicKey, "base64url")),
              serverId: verified.payload.serverId,
              authorityFingerprint: verified.payload.authorityFingerprint,
              hostId: verified.payload.hostId,
              grantId: verified.payload.grantId,
            };
            const accepted = await this.auth.onLegacyHostFirstUse(candidate);
            if (generation !== this.socketGeneration || this.closed) return;
            this.legacyTrustPending = false;
            if (!accepted) {
              socket.close(1008, "legacy host key rejected");
              return;
            }
            // Re-verify against the exact key the caller just confirmed; no post-confirmation substitution.
            verified = verifySignedHostAuthChallenge(frame.data, {
              serverId: candidate.serverId,
              authorityFingerprint: candidate.authorityFingerprint,
              hostPublicKey: candidate.hostPublicKey,
              hostId: candidate.hostId,
              grantId: candidate.grantId,
            });
            if (verified) {
              this.hostTrust = {
                hostPublicKey: candidate.hostPublicKey,
                hostId: candidate.hostId,
                grantId: candidate.grantId,
              };
            }
          }
          if (!verified) {
            socket.close(1008, "invalid host authority");
            return;
          }
          this.challengeVerified = true;
          const challenge = verified.payload;
          const proof = createSignedSessionAuth({
            version: 1,
            serverId: challenge.serverId,
            identityId: this.auth.identityId,
            publicKey: ed25519PublicKey(this.auth.deviceSeed).toString("base64url"),
            challengeId: challenge.challengeId,
            nonce: challenge.nonce,
            issuedAt: Date.now(),
            expiresAt: Math.min(challenge.expiresAt, Date.now() + 30_000),
          }, this.auth.deviceSeed);
          socket.send(JSON.stringify({ event: "auth.prove", data: proof }));
          return;
        }
        if (frame.event === "auth.ready") {
          if (this.auth.deviceSeed && !this.challengeVerified) {
            socket.close(1008, "host challenge required");
            return;
          }
          this.markOpen();
          return;
        }
        if (frame.event === "result" && this.authenticated) this.handleRequestResult(frame.data);
        // entrega o HostEvent (payload de 'event'), não o envelope de transporte
        if (frame.event === "event") this.handler?.(frame.data as HostEvent);
      } catch {
        if (this.legacyTrustPending && generation === this.socketGeneration) {
          this.legacyTrustPending = false;
          socket.close(1008, "legacy host key confirmation failed");
        }
        // Other malformed frames are ignored locally.
      }
    });
    // `ws` emits `error` before `close` for ordinary host loss (ECONNRESET/REFUSED). Without
    // a listener Node treats that network condition as an uncaught process exception.
    socket.on("error", () => undefined);
    socket.on("close", () => {
      if (generation !== this.socketGeneration) return;
      this.closed = true;
      this.authenticated = false;
      this.challengeVerified = false;
      this.failRequests("host connection closed");
      for (const handler of this.closeHandlers) handler();
    });
  }

  private markOpen(): void {
    if (this.authenticated) return;
    this.authenticated = true;
    this.dispatchNextRequest();
    for (const handler of this.openHandlers) handler();
    this.openHandlers = [];
    const event = {
      generation: ++this.authenticatedOpenGeneration,
      reconnected: this.authenticatedOpenGeneration > 1,
    };
    for (const handler of this.authenticatedOpenHandlers) handler(event);
  }

  /** Envia comando; resposta via evento ou promise curta. */
  command(cmd: HostCommand): void {
    if (this.closed) throw new Error("host transport is closed");
    this.enqueueResultFrame("command", cmd);
  }

  send(event: string, data: unknown): void {
    if (this.closed) throw new Error("host transport is closed");
    // Recognized application events and the unknown-event fallback both emit FIFO `result` frames.
    // The caller intentionally ignores this result, but its slot must still be drained before a
    // later request can be correlated safely.
    this.enqueueResultFrame(event, data);
  }

  onEvent(handler: (event: HostEvent) => void): void {
    this.handler = handler;
  }

  /** Listener one-shot para um frame de resultado específico (event === 'result'). */
  onEventOnce(event: string, handler: (frame: { event: string; data: unknown }) => void): void {
    const socket = this.ws;
    const h = (raw: unknown) => {
      try {
        const frame = JSON.parse(String(raw)) as { event: string; data: unknown };
        if (frame.event === event) {
          socket.off("message", h);
          handler(frame);
        }
      } catch {
        // ignora
      }
    };
    socket.on("message", h);
  }

  /**
   * Requests are sent one at a time because the legacy host result frame has no
   * correlation id. If an in-flight request times out, the socket is replaced
   * before the next request is sent so a late result from the old socket cannot
   * be mistaken for the next request's result.
   */
  request(cmd: HostCommand, timeoutMs = 8000): Promise<unknown> {
    if (this.closed) return Promise.resolve(this.requestFailure("host_offline", "transport closed"));
    return new Promise((resolve) => {
      this.enqueueResultFrame(
        "command",
        cmd,
        timeoutMs,
        resolve,
        cmd.type === "replica.enroll" || cmd.type === "replica.snapshot" ? "replica-transfer" : "protocol",
      );
    });
  }

  private enqueueResultFrame(
    event: string,
    data: unknown,
    timeoutMs = 8000,
    resolve?: (data: unknown) => void,
    inboundBoundary: ExternalWebSocketBoundary = "protocol",
  ): void {
    const request = {} as PendingHostClientRequest;
    request.frame = JSON.stringify({ event, data });
    request.resolve = resolve;
    request.settled = false;
    request.inboundBoundary = inboundBoundary;
    request.timer = setTimeout(() => this.handleRequestTimeout(request), timeoutMs);
    this.pendingRequests.push(request);
    this.dispatchNextRequest();
  }

  private dispatchNextRequest(): void {
    if (this.inFlightRequest || !this.authenticated || this.ws.readyState !== WebSocket.OPEN) return;
    const request = this.pendingRequests.shift();
    if (!request) return;
    this.inFlightRequest = request;
    if (!setExternalWebSocketInboundBoundary(this.ws, request.inboundBoundary)) {
      this.inFlightRequest = null;
      this.settleRequest(request, this.requestFailure("host_offline", "host receive policy unavailable"));
      this.replaceTimedOutConnection();
      return;
    }
    try {
      this.ws.send(request.frame);
    } catch {
      this.inFlightRequest = null;
      this.settleRequest(request, this.requestFailure("host_offline", "host send failed"));
      this.replaceTimedOutConnection();
    }
  }

  private handleRequestResult(data: unknown): void {
    const request = this.inFlightRequest;
    if (!request) return;
    this.inFlightRequest = null;
    if (!setExternalWebSocketInboundBoundary(this.ws, "protocol")) {
      this.settleRequest(request, this.requestFailure("host_offline", "host receive policy unavailable"));
      this.replaceTimedOutConnection();
      return;
    }
    this.settleRequest(request, data);
    this.dispatchNextRequest();
  }

  private handleRequestTimeout(request: PendingHostClientRequest): void {
    if (request.settled) return;
    if (this.inFlightRequest === request) {
      this.inFlightRequest = null;
      this.settleRequest(request, this.requestFailure("timeout", "host timeout"));
      this.replaceTimedOutConnection();
      return;
    }
    const queued = this.pendingRequests.indexOf(request);
    if (queued >= 0) this.pendingRequests.splice(queued, 1);
    this.settleRequest(request, this.requestFailure("timeout", "host timeout"));
  }

  private settleRequest(request: PendingHostClientRequest, value: unknown): void {
    if (request.settled) return;
    request.settled = true;
    clearTimeout(request.timer);
    request.resolve?.(value);
  }

  private failRequests(message: string): void {
    const value = this.requestFailure("host_offline", message);
    if (this.inFlightRequest) {
      const inFlight = this.inFlightRequest;
      this.inFlightRequest = null;
      this.settleRequest(inFlight, value);
    }
    for (const request of this.pendingRequests.splice(0)) this.settleRequest(request, value);
  }

  private replaceTimedOutConnection(): void {
    if (this.closed) return;
    const stale = this.ws;
    this.authenticated = false;
    this.challengeVerified = false;
    this.connect();
    try {
      stale.close(1000, "request correlation reset");
    } catch {
      stale.terminate();
    }
  }

  private requestFailure(code: ErrorCode | "timeout", message: string): { ok: false; error: { code: ErrorCode | "timeout"; message: string } } {
    return { ok: false, error: { code, message } };
  }

  onOpen(handler: () => void): void {
    if (this.authenticated) handler();
    else this.openHandlers.push(handler);
  }

  /** Persistent authenticated lifecycle; unlike onOpen it is not consumed after the first call. */
  onAuthenticatedOpen(handler: (event: AuthenticatedOpenEvent) => void): () => void {
    this.authenticatedOpenHandlers.add(handler);
    if (this.authenticatedOpenGeneration > 0) {
      handler({ generation: this.authenticatedOpenGeneration, reconnected: this.authenticatedOpenGeneration > 1 });
    }
    return () => this.authenticatedOpenHandlers.delete(handler);
  }

  onClose(handler: () => void): void {
    this.closeHandlers.add(handler);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.authenticated = false;
    this.failRequests("transport closed");
    this.ws.close();
  }

  get ready(): boolean {
    return this.ws.readyState === WebSocket.OPEN && this.authenticated;
  }
}

export interface HostRegistrationHighWaterMark {
  authorityFingerprint: string;
  serverId: string;
  hostId: string;
  grantId: string;
  grantGeneration: number;
  epoch: number;
  recordSeq: number;
  recordHash: string;
}

export interface HostRegistrationHighWater {
  version: 1;
  marks: HostRegistrationHighWaterMark[];
}

export type HostRegistrationRejectionReason =
  | "invalid"
  | "revoked"
  | "downgrade"
  | "replay"
  | "conflict"
  | "ambiguous";

export interface SelectedHostRegistration extends VerifiedHostAuthenticationContext {
  registration: HostRegistration;
  recordHash: string;
}

export interface HostRegistrationSelectionResult {
  registrations: SelectedHostRegistration[];
  highWater: HostRegistrationHighWater;
  rejected: {
    index: number;
    reason: HostRegistrationRejectionReason;
    hostId?: string;
    grantId?: string;
  }[];
}

const HEX_64 = /^[0-9a-f]{64}$/;
const MAX_HIGH_WATER_MARKS = 1024;

function highWaterKey(mark: Pick<HostRegistrationHighWaterMark, "authorityFingerprint" | "serverId" | "hostId">): string {
  return `${mark.authorityFingerprint.toLowerCase()}\0${mark.serverId}\0${mark.hostId}`;
}

function validHighWaterMark(value: unknown): value is HostRegistrationHighWaterMark {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const mark = value as Record<string, unknown>;
  const keys = Object.keys(mark).sort().join("\0");
  const expected = ["authorityFingerprint", "epoch", "grantGeneration", "grantId", "hostId", "recordHash", "recordSeq", "serverId"].sort().join("\0");
  return keys === expected
    && typeof mark.authorityFingerprint === "string"
    && HEX_64.test(mark.authorityFingerprint.toLowerCase())
    && typeof mark.serverId === "string" && mark.serverId.length > 0 && mark.serverId.length <= 128
    && typeof mark.hostId === "string" && mark.hostId.length > 0 && mark.hostId.length <= 128
    && typeof mark.grantId === "string" && mark.grantId.length > 0 && mark.grantId.length <= 128
    && Number.isSafeInteger(mark.grantGeneration) && Number(mark.grantGeneration) > 0
    && Number.isSafeInteger(mark.epoch) && Number(mark.epoch) >= 0
    && Number.isSafeInteger(mark.recordSeq) && Number(mark.recordSeq) > 0
    && typeof mark.recordHash === "string" && HEX_64.test(mark.recordHash);
}

/** Strict JSON boundary for Electron persistence. Malformed or duplicate marks fail closed. */
export function deserializeHostRegistrationHighWater(serialized: string): HostRegistrationHighWater {
  let value: unknown;
  try {
    value = JSON.parse(serialized);
  } catch {
    throw new Error("invalid host registration high-water JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid host registration high-water state");
  const state = value as Record<string, unknown>;
  if (Object.keys(state).sort().join("\0") !== ["marks", "version"].sort().join("\0") || state.version !== 1 || !Array.isArray(state.marks)) {
    throw new Error("invalid host registration high-water state");
  }
  if (state.marks.length > MAX_HIGH_WATER_MARKS || state.marks.some((mark) => !validHighWaterMark(mark))) {
    throw new Error("invalid host registration high-water marks");
  }
  const marks = (state.marks as HostRegistrationHighWaterMark[]).map((mark) => ({
    ...mark,
    authorityFingerprint: mark.authorityFingerprint.toLowerCase(),
  }));
  const keys = marks.map(highWaterKey);
  if (new Set(keys).size !== keys.length) throw new Error("duplicate host registration high-water mark");
  return { version: 1, marks };
}

export function serializeHostRegistrationHighWater(state: HostRegistrationHighWater): string {
  const parsed = deserializeHostRegistrationHighWater(JSON.stringify(state));
  parsed.marks.sort((a, b) => highWaterKey(a).localeCompare(highWaterKey(b)));
  return JSON.stringify(parsed);
}

function dominates(
  left: Pick<HostRegistrationHighWaterMark, "grantGeneration" | "epoch" | "recordSeq">,
  right: Pick<HostRegistrationHighWaterMark, "grantGeneration" | "epoch" | "recordSeq">,
): boolean {
  return left.grantGeneration >= right.grantGeneration
    && left.epoch >= right.epoch
    && left.recordSeq >= right.recordSeq
    && (left.grantGeneration > right.grantGeneration || left.epoch > right.epoch || left.recordSeq > right.recordSeq);
}

/**
 * Verifies, de-duplicates and selects signed host registrations without trusting bridge order.
 * The supplied revocation set must already come from a verified authority source.
 */
export function selectHostRegistrations(
  values: readonly unknown[],
  options: {
    serverId: string;
    authorityFingerprint: string;
    highWater?: HostRegistrationHighWater;
    verifiedRevokedGrantIds?: ReadonlySet<string>;
    verifiedGenerationFloors?: ReadonlyMap<string, number>;
    now?: number;
  },
): HostRegistrationSelectionResult {
  const authorityFingerprint = options.authorityFingerprint.toLowerCase();
  const prior = options.highWater
    ? deserializeHostRegistrationHighWater(serializeHostRegistrationHighWater(options.highWater))
    : { version: 1 as const, marks: [] };
  const priorByHost = new Map(prior.marks.map((mark) => [highWaterKey(mark), mark]));
  const rejected: HostRegistrationSelectionResult["rejected"] = [];
  type Candidate = SelectedHostRegistration & { index: number; mark: HostRegistrationHighWaterMark };
  const candidatesByHost = new Map<string, Candidate[]>();
  const globalPriorEpoch = Math.max(0, ...prior.marks
    .filter((mark) => mark.authorityFingerprint === authorityFingerprint && mark.serverId === options.serverId)
    .map((mark) => mark.epoch));

  values.forEach((value, index) => {
    const registration = HostRegistrationSchema.safeParse(value);
    const context = verifyHostAuthenticationContext(value, {
      serverId: options.serverId,
      authorityFingerprint,
      now: options.now,
    });
    if (!registration.success || !context) {
      rejected.push({ index, reason: "invalid" });
      return;
    }
    const grantId = context.grant.payload.grantId;
    const hostId = context.record.payload.hostId;
    if (options.verifiedRevokedGrantIds?.has(grantId)) {
      rejected.push({ index, reason: "revoked", hostId, grantId });
      return;
    }
    const generationFloor = options.verifiedGenerationFloors?.get(hostId) ?? 0;
    if (context.grant.payload.generation <= generationFloor) {
      rejected.push({ index, reason: "revoked", hostId, grantId });
      return;
    }
    const mark: HostRegistrationHighWaterMark = {
      authorityFingerprint,
      serverId: options.serverId,
      hostId,
      grantId,
      grantGeneration: context.grant.payload.generation,
      epoch: context.record.payload.epoch,
      recordSeq: context.record.payload.recordSeq,
      recordHash: hostRegistrationRecordHash(context.record),
    };
    const previous = priorByHost.get(highWaterKey(mark));
    if (mark.epoch < globalPriorEpoch
      || (previous && (mark.grantGeneration < previous.grantGeneration || mark.epoch < previous.epoch || mark.recordSeq < previous.recordSeq))) {
      rejected.push({ index, reason: "downgrade", hostId, grantId });
      return;
    }
    if (previous && mark.grantGeneration === previous.grantGeneration && mark.grantId !== previous.grantId) {
      rejected.push({ index, reason: "conflict", hostId, grantId });
      return;
    }
    if (previous && mark.recordSeq === previous.recordSeq) {
      rejected.push({ index, reason: mark.recordHash === previous.recordHash ? "replay" : "conflict", hostId, grantId });
      return;
    }
    if (previous && (mark.recordSeq !== previous.recordSeq + 1
      || context.record.payload.previousRecordHash !== previous.recordHash)) {
      rejected.push({ index, reason: "conflict", hostId, grantId });
      return;
    }
    const candidate: Candidate = { ...context, registration: registration.data, recordHash: mark.recordHash, index, mark };
    candidatesByHost.set(hostId, [...(candidatesByHost.get(hostId) ?? []), candidate]);
  });

  const selected: Candidate[] = [];
  for (const group of candidatesByHost.values()) {
    const unique = [...new Map(group.map((candidate) => [candidate.recordHash, candidate])).values()];
    for (const candidate of group) {
      if (unique.some((item) => item.recordHash === candidate.recordHash && item.index !== candidate.index)) {
        rejected.push({ index: candidate.index, reason: "replay", hostId: candidate.mark.hostId, grantId: candidate.mark.grantId });
      }
    }
    const maximal = unique.filter((candidate) => !unique.some((other) => dominates(other.mark, candidate.mark)));
    if (maximal.length !== 1) {
      for (const candidate of unique) rejected.push({ index: candidate.index, reason: "ambiguous", hostId: candidate.mark.hostId, grantId: candidate.mark.grantId });
      continue;
    }
    const winner = maximal[0]!;
    for (const candidate of unique) {
      if (candidate !== winner) rejected.push({ index: candidate.index, reason: "downgrade", hostId: candidate.mark.hostId, grantId: candidate.mark.grantId });
    }
    selected.push(winner);
  }

  const globalEpoch = Math.max(globalPriorEpoch, ...selected.map((candidate) => candidate.mark.epoch));
  const epochSafe = selected.filter((candidate) => {
    if (candidate.mark.epoch >= globalEpoch) return true;
    rejected.push({ index: candidate.index, reason: "downgrade", hostId: candidate.mark.hostId, grantId: candidate.mark.grantId });
    return false;
  });
  for (const candidate of epochSafe) priorByHost.set(highWaterKey(candidate.mark), candidate.mark);
  const highWater: HostRegistrationHighWater = { version: 1, marks: [...priorByHost.values()] };
  highWater.marks.sort((a, b) => highWaterKey(a).localeCompare(highWaterKey(b)));
  epochSafe.sort((a, b) => b.mark.epoch - a.mark.epoch || a.mark.hostId.localeCompare(b.mark.hostId));
  rejected.sort((a, b) => a.index - b.index || a.reason.localeCompare(b.reason));
  return {
    registrations: epochSafe.map(({ index: _index, mark: _mark, ...candidate }) => candidate),
    highWater,
    rejected,
  };
}

export interface TemporaryTurnCredentials {
  urls: string[];
  username: string;
  credential: string;
  credentialType: "password";
  expiresAt: number;
}

export type IceServerConfig = string | IceServer;

const TURN_URL = /^(turn|turns):(?:\/\/)?(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(?::(\d{1,5}))?(?:\?transport=(udp|tcp))?$/;
const STUN_URL = /^stuns?:(?:\/\/)?(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(?::\d{1,5})?$/;

export function parseTemporaryTurnCredentials(value: unknown, now = Date.now()): TemporaryTurnCredentials | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const credentials = value as Partial<TemporaryTurnCredentials>;
  if (!Array.isArray(credentials.urls) || credentials.urls.length === 0 || credentials.urls.length > 8
    || typeof credentials.username !== "string" || credentials.username.length === 0 || credentials.username.length > 512
    || typeof credentials.credential !== "string" || credentials.credential.length === 0 || credentials.credential.length > 512
    || credentials.credentialType !== "password"
    || !Number.isSafeInteger(credentials.expiresAt) || Number(credentials.expiresAt) <= now + 1_000) return null;
  for (const url of credentials.urls) {
    if (typeof url !== "string" || (!TURN_URL.test(url) && !STUN_URL.test(url))) return null;
  }
  return {
    urls: [...credentials.urls],
    username: credentials.username,
    credential: credentials.credential,
    credentialType: "password",
    expiresAt: Number(credentials.expiresAt),
  };
}

export function temporaryTurnIceServers(value: unknown, now = Date.now()): IceServer[] {
  const credentials = parseTemporaryTurnCredentials(value, now);
  if (!credentials) return [];
  const servers: IceServer[] = [];
  for (const url of credentials.urls) {
    if (STUN_URL.test(url)) continue;
    const matched = TURN_URL.exec(url);
    if (!matched) return [];
    const scheme = matched[1]!;
    const hostname = matched[2]!.replace(/^\[|\]$/g, "");
    const port = Number(matched[3] ?? (scheme === "turns" ? 5349 : 3478));
    if (!Number.isInteger(port) || port < 1 || port > 65535) return [];
    servers.push({
      hostname,
      port,
      username: credentials.username,
      password: credentials.credential,
      relayType: scheme === "turns" ? "TurnTls" : matched[4] === "tcp" ? "TurnTcp" : "TurnUdp",
    });
  }
  return servers;
}

export interface BrowserRtcIceServer {
  urls: string | string[];
  username?: string;
  credential?: string;
  credentialType?: "password";
}

export interface BrowserRtcIceConfiguration {
  iceServers: BrowserRtcIceServer[];
  iceTransportPolicy: "all" | "relay";
  /** Earliest temporary TURN credential expiry. Absent when direct-only/STUN is active. */
  expiresAt?: number;
}

function baseIceServers(values: readonly IceServerConfig[]): IceServerConfig[] {
  return values.map((value) => {
    if (typeof value === "string") {
      if (!/^stuns?:[^\s]+$/i.test(value)) throw new Error("base ICE servers may only contain STUN; TURN credentials must come from host signaling");
      return value;
    }
    if (!value || typeof value.hostname !== "string" || !Number.isInteger(value.port)
      || value.port < 1 || value.port > 65535 || value.relayType || value.username || value.password) {
      throw new Error("base ICE servers may only contain credential-free STUN configuration");
    }
    return { hostname: value.hostname, port: value.port };
  });
}

export function iceServerConfiguration(
  base: readonly IceServerConfig[],
  temporaryCredentials: unknown,
  networkPrivacy: "direct" | "relay",
  now = Date.now(),
): { iceServers: IceServerConfig[]; iceTransportPolicy: "all" | "relay" } {
  const temporary = temporaryTurnIceServers(temporaryCredentials, now);
  const issued = parseTemporaryTurnCredentials(temporaryCredentials, now);
  const issuedStun = issued?.urls.filter((url) => STUN_URL.test(url)) ?? [];
  if (networkPrivacy === "relay" && temporary.length === 0) throw new Error("relay-only requires valid temporary TURN credentials");
  return {
    iceServers: networkPrivacy === "relay" ? temporary : [...baseIceServers(base), ...issuedStun, ...temporary],
    iceTransportPolicy: networkPrivacy === "relay" ? "relay" : "all",
  };
}

/** Browser/Electron equivalent used by call PeerConnections; never contains the TURN shared secret. */
export function browserRtcIceConfiguration(
  base: readonly IceServerConfig[],
  temporaryCredentials: unknown,
  networkPrivacy: "direct" | "relay",
  now = Date.now(),
): BrowserRtcIceConfiguration {
  const parsed = parseTemporaryTurnCredentials(temporaryCredentials, now);
  const turnUrls = parsed?.urls.filter((url) => TURN_URL.test(url)) ?? [];
  const issuedStun = parsed?.urls.filter((url) => STUN_URL.test(url)).map<BrowserRtcIceServer>((url) => ({ urls: url })) ?? [];
  if (networkPrivacy === "relay" && turnUrls.length === 0) throw new Error("relay-only requires valid temporary TURN credentials");
  const stun = networkPrivacy === "relay" ? [] : baseIceServers(base).map<BrowserRtcIceServer>((server) => {
    if (typeof server === "string") return { urls: server };
    const hostname = server.hostname.includes(":") ? `[${server.hostname}]` : server.hostname;
    return { urls: `stun:${hostname}:${server.port}` };
  });
  const turn: BrowserRtcIceServer[] = parsed && turnUrls.length > 0 ? [{
    urls: turnUrls,
    username: parsed.username,
    credential: parsed.credential,
    credentialType: "password",
  }] : [];
  return {
    iceServers: [...stun, ...(networkPrivacy === "relay" ? [] : issuedStun), ...turn],
    iceTransportPolicy: networkPrivacy === "relay" ? "relay" : "all",
    ...(parsed ? { expiresAt: parsed.expiresAt } : {}),
  };
}

export function reconnectBackoffDelay(attempt: number, baseMs: number, maxMs: number, random = Math.random): number {
  const boundedAttempt = Math.max(0, Math.min(30, Math.floor(attempt)));
  const raw = Math.min(Math.max(baseMs, 1) * 2 ** boundedAttempt, Math.max(maxMs, 1));
  const jitter = Math.max(0, Math.min(1, random())) * Math.min(raw * 0.2, 1_000);
  return Math.round(raw + jitter);
}

export function isRelayOnlyCandidatePair(pair: {
  local?: { type?: string };
  remote?: { type?: string };
} | null | undefined): boolean {
  return pair?.local?.type?.toLowerCase() === "relay" && pair.remote?.type?.toLowerCase() === "relay";
}

export interface IceHostTransportOptions {
  /** Kept for compatibility; bridgeUrls is preferred for failover. */
  bridgeUrl?: string;
  bridgeUrls?: readonly string[];
  serverId: string;
  hostId: string;
  identityId: string;
  authorityFingerprint: string;
  hostRegistration: unknown;
  deviceSeed: Buffer;
  /** SHA-256 of the JC3 invite secret for a not-yet-member's first ICE session. */
  inviteAccessHash?: string;
  /** Credential-free STUN only. Temporary TURN credentials arrive from the registered host. */
  iceServers: readonly IceServerConfig[];
  networkPrivacy?: "direct" | "relay";
  connectionTimeoutMs?: number;
  reconnectBaseDelayMs?: number;
  reconnectMaxDelayMs?: number;
  maxReconnectAttempts?: number;
}

export function createSignedIceAccessProof(
  options: Pick<IceHostTransportOptions, "serverId" | "hostId" | "identityId" | "deviceSeed" | "inviteAccessHash">,
  sessionId: string,
  now = Date.now(),
): SignedIceAccessProof {
  const payload = {
    version: 1 as const,
    sessionId,
    serverId: options.serverId,
    hostId: options.hostId,
    identityId: options.identityId,
    devicePublicKey: ed25519PublicKey(options.deviceSeed).toString("base64url"),
    ...(options.inviteAccessHash ? { inviteAccessHash: options.inviteAccessHash } : {}),
    issuedAt: now,
    expiresAt: now + 30_000,
  };
  return SignedIceAccessProofSchema.parse({
    payload,
    signature: signCanonicalPayload(options.deviceSeed, "janjacord.ice-access.v1", payload).toString("base64url"),
  });
}

type PendingRequest = {
  resolve?: (data: unknown) => void;
  timer: ReturnType<typeof setTimeout>;
  settled: boolean;
};

type OutboundFrame = { raw: string; request?: PendingRequest };

const MAX_REMOTE_ICE_SDP_BYTES = 48 * 1024;
const MAX_REMOTE_ICE_CANDIDATE_BYTES = 4 * 1024;
const MAX_REMOTE_ICE_MID_BYTES = 64;

function parseRemoteIceAnswer(value: unknown): { type: "answer"; sdp: string } | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const candidate = value as { type?: unknown; sdp?: unknown };
  if (candidate.type !== "answer" || typeof candidate.sdp !== "string"
    || !candidate.sdp.startsWith("v=0") || candidate.sdp.includes("\0")
    || Buffer.byteLength(candidate.sdp) > MAX_REMOTE_ICE_SDP_BYTES) return null;
  return { type: "answer", sdp: candidate.sdp };
}

function parseRemoteIceCandidate(value: unknown): { type: "candidate"; candidate: string; mid: string } | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const input = value as { type?: unknown; candidate?: unknown; mid?: unknown };
  if (input.type !== "candidate" || typeof input.candidate !== "string"
    || !/^(?:a=)?candidate:/i.test(input.candidate) || input.candidate.includes("\0")
    || Buffer.byteLength(input.candidate) > MAX_REMOTE_ICE_CANDIDATE_BYTES
    || (input.mid !== undefined && (typeof input.mid !== "string"
      || Buffer.byteLength(input.mid) > MAX_REMOTE_ICE_MID_BYTES
      || !/^[A-Za-z0-9_.:-]*$/.test(input.mid)))) return null;
  return { type: "candidate", candidate: input.candidate, mid: input.mid ?? "0" };
}

export function settleTransportGenerationRequests(
  requests: PendingRequest[],
  value: unknown,
): void {
  for (const request of requests.splice(0)) {
    if (request.settled) continue;
    request.settled = true;
    clearTimeout(request.timer);
    request.resolve?.(value);
  }
}

function normalizeBridgeUrls(options: IceHostTransportOptions): string[] {
  const input = [...(options.bridgeUrls ?? []), ...(options.bridgeUrl ? [options.bridgeUrl] : [])];
  const urls = [...new Set(input)].map((value) => {
    const url = new URL(value);
    if (!['ws:', 'wss:'].includes(url.protocol) || url.username || url.password || url.hash) throw new Error("invalid JanjaBridge signaling URL");
    return url.toString();
  });
  if (urls.length === 0 || urls.length > 3) throw new Error("between one and three JanjaBridge URLs are required");
  return urls;
}

/** JanjaNode command transport over WebRTC DataChannel with JanjaBridge signaling. */
export class IceHostTransport implements Transport {
  private bridge: WebSocket | null = null;
  private pc: PeerConnection | null = null;
  private channel: DataChannel | null = null;
  private sessionId = "";
  private generation = 0;
  private bridgeCursor = 0;
  private reconnectAttempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private connectionTimer: ReturnType<typeof setTimeout> | null = null;
  private disconnectedTimer: ReturnType<typeof setTimeout> | null = null;
  private credentialRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  private authenticated = false;
  private challengeVerified = false;
  private restartingIce = false;
  private closed = false;
  private closeNotified = false;
  private readonly hostTrust: VerifiedHostAuthenticationContext;
  private readonly bridgeUrls: string[];
  private readonly baseServers: IceServerConfig[];
  private activeRtcConfiguration: BrowserRtcIceConfiguration | null = null;
  private iceConfigurationHandlers: ((configuration: BrowserRtcIceConfiguration) => void)[] = [];
  private handler: ((event: HostEvent) => void) | null = null;
  private openHandlers: (() => void)[] = [];
  private authenticatedOpenGeneration = 0;
  private authenticatedOpenHandlers = new Set<(event: AuthenticatedOpenEvent) => void>();
  private closeHandlers: (() => void)[] = [];
  private inFlight: PendingRequest[] = [];
  private outbound: OutboundFrame[] = [];
  private remoteCandidates: { candidate: string; mid: string }[] = [];
  private once = new Map<string, ((frame: { event: string; data: unknown }) => void)[]>();

  constructor(private readonly options: IceHostTransportOptions) {
    const hostTrust = verifyHostAuthenticationContext(options.hostRegistration, {
      serverId: options.serverId,
      authorityFingerprint: options.authorityFingerprint,
      hostId: options.hostId,
    });
    if (!hostTrust) throw new Error("invalid host authority/grant/record chain");
    this.hostTrust = hostTrust;
    this.bridgeUrls = normalizeBridgeUrls(options);
    this.baseServers = baseIceServers(options.iceServers);
    this.beginAttempt();
  }

  private beginAttempt(): void {
    if (this.closed) return;
    const maxAttempts = this.options.maxReconnectAttempts ?? Number.POSITIVE_INFINITY;
    if (this.reconnectAttempt > maxAttempts) {
      this.notifyClose();
      this.failQueuedRequests("host_offline", "all JanjaBridge connection attempts failed");
      return;
    }
    const generation = ++this.generation;
    this.teardownAttempt(false);
    this.authenticated = false;
    this.challengeVerified = false;
    this.restartingIce = false;
    this.remoteCandidates = [];
    this.sessionId = randomBytes(24).toString("base64url");
    const bridgeUrl = this.bridgeUrls[this.bridgeCursor % this.bridgeUrls.length]!;
    this.bridgeCursor = (this.bridgeCursor + 1) % this.bridgeUrls.length;
    const bridge = createExternalWebSocket(bridgeUrl);
    this.bridge = bridge;
    bridge.on("open", () => {
      if (generation !== this.generation || this.closed) return;
      this.sendBridge({
        type: "signal.open",
        sessionId: this.sessionId,
        serverId: this.options.serverId,
        authorityFingerprint: this.options.authorityFingerprint,
        hostId: this.options.hostId,
        payload: {
          type: "ice.request",
          serverId: this.options.serverId,
          hostId: this.options.hostId,
          networkPrivacy: this.options.networkPrivacy === "relay" ? "relay" : "direct",
          accessProof: createSignedIceAccessProof(this.options, this.sessionId),
        },
      });
    });
    bridge.on("message", (raw) => {
      if (generation === this.generation) this.handleBridgeFrame(raw.toString(), generation);
    });
    bridge.on("close", () => {
      if (generation === this.generation && !this.closed) this.scheduleReconnect(false);
    });
    bridge.on("error", () => {
      if (generation === this.generation && !this.closed && bridge.readyState !== WebSocket.OPEN) this.scheduleReconnect(false);
    });
    this.connectionTimer = setTimeout(() => {
      if (generation === this.generation && !this.authenticated) this.scheduleReconnect(false);
    }, this.options.connectionTimeoutMs ?? 15_000);
  }

  private createPeerConnection(credentials: unknown, policy: "direct" | "relay", generation: number): void {
    if (generation !== this.generation || this.closed) return;
    if (this.options.networkPrivacy === "relay" && policy !== "relay") {
      this.scheduleReconnect(false);
      return;
    }
    let configuration: ReturnType<typeof iceServerConfiguration>;
    try {
      configuration = iceServerConfiguration(this.baseServers, credentials, policy);
      this.acceptRtcIceConfiguration(credentials, policy, generation);
    } catch {
      this.scheduleReconnect(false);
      return;
    }
    if (this.pc) return;
    const pc = new nodeDataChannel.PeerConnection(`client-${this.sessionId}`, configuration);
    this.pc = pc;
    for (const candidate of this.remoteCandidates.splice(0)) {
      pc.addRemoteCandidate(candidate.candidate, candidate.mid);
    }
    pc.onLocalDescription((sdp, type) => {
      if (generation !== this.generation || this.closed) return;
      this.sendBridge({
        type: type.toLowerCase() === "offer" ? "signal.open" : "signal.relay",
        sessionId: this.sessionId,
        serverId: this.options.serverId,
        authorityFingerprint: this.options.authorityFingerprint,
        hostId: this.options.hostId,
        payload: { type: type.toLowerCase(), sdp },
      });
    });
    pc.onLocalCandidate((candidate, mid) => {
      if (generation === this.generation) this.sendBridge({ type: "signal.relay", sessionId: this.sessionId, payload: { type: "candidate", candidate, mid } });
    });
    pc.onStateChange((state) => {
      if (generation !== this.generation || this.closed) return;
      const normalized = state.toLowerCase();
      if (normalized === "connected") {
        if (this.options.networkPrivacy === "relay" && !isRelayOnlyCandidatePair(pc.getSelectedCandidatePair())) {
          this.scheduleReconnect(false);
          return;
        }
        if (this.disconnectedTimer) clearTimeout(this.disconnectedTimer);
        this.disconnectedTimer = null;
        if (this.restartingIce && this.channel?.isOpen()) this.sendAuthenticationBegin();
      } else if (normalized === "failed") {
        this.scheduleReconnect(true);
      } else if (normalized === "disconnected" && !this.disconnectedTimer) {
        this.disconnectedTimer = setTimeout(() => {
          this.disconnectedTimer = null;
          if (generation === this.generation) this.scheduleReconnect(true);
        }, 750);
      }
    });
    const channel = pc.createDataChannel("janjanode");
    this.channel = channel;
    channel.onOpen(() => {
      if (generation === this.generation) {
        this.sendAuthenticationBegin();
      }
    });
    channel.onMessage((message) => {
      if (generation === this.generation) this.handleHostFrame(typeof message === "string" ? message : Buffer.from(message as ArrayBuffer).toString("utf8"));
    });
    channel.onClosed(() => {
      if (generation === this.generation && !this.closed) this.scheduleReconnect(false);
    });
    channel.onError(() => {
      if (generation === this.generation && !this.closed) this.scheduleReconnect(false);
    });
    pc.setLocalDescription("offer");
  }

  private handleBridgeFrame(raw: string, generation: number): void {
    try {
      const frame = JSON.parse(raw) as {
        type?: string;
        sessionId?: string;
        ok?: boolean;
        payload?: {
          type?: string;
          sdp?: string;
          candidate?: string;
          mid?: string;
          networkPrivacy?: "direct" | "relay";
          credentials?: unknown;
        };
      };
      if (frame.ok === false && !frame.sessionId) {
        this.scheduleReconnect(false);
        return;
      }
      if (frame.sessionId !== this.sessionId || frame.type !== "signal.relay") return;
      if (frame.payload?.type === "ice.config") {
        const policy = frame.payload.networkPrivacy === "relay" ? "relay" : "direct";
        this.createPeerConnection(frame.payload.credentials, policy, generation);
        return;
      }
      if (frame.payload?.type === "ice.error") {
        this.scheduleReconnect(false);
        return;
      }
      if (frame.payload?.type === "answer") {
        const answer = parseRemoteIceAnswer(frame.payload);
        if (answer && this.pc) this.pc.setRemoteDescription(answer.sdp, answer.type);
        return;
      }
      if (frame.payload?.type === "candidate") {
        const candidate = parseRemoteIceCandidate(frame.payload);
        if (!candidate) return;
        if (this.pc) this.pc.addRemoteCandidate(candidate.candidate, candidate.mid);
        else if (this.remoteCandidates.length < 64) this.remoteCandidates.push(candidate);
      }
    } catch {
      // Malformed bridge frames never influence transport state.
    }
  }

  private sendAuthenticationBegin(): void {
    this.authenticated = false;
    this.challengeVerified = false;
    this.sendChannelFrame("auth.begin", {
      identityId: this.options.identityId,
      publicKey: ed25519PublicKey(this.options.deviceSeed).toString("base64url"),
    });
  }

  private acceptRtcIceConfiguration(credentials: unknown, policy: "direct" | "relay", generation: number): void {
    const configuration = browserRtcIceConfiguration(this.baseServers, credentials, policy);
    this.activeRtcConfiguration = configuration;
    for (const handler of this.iceConfigurationHandlers) handler(this.copyRtcIceConfiguration(configuration));
    if (this.credentialRefreshTimer) clearTimeout(this.credentialRefreshTimer);
    this.credentialRefreshTimer = null;
    // Direct mode retries issuance even when TURN was temporarily unavailable; relay mode never
    // reaches this point without valid credentials.
    const refreshIn = configuration.expiresAt
      ? Math.max(5_000, configuration.expiresAt - Date.now() - 60_000)
      : 60_000;
    this.credentialRefreshTimer = setTimeout(() => {
      this.credentialRefreshTimer = null;
      if (generation !== this.generation || this.closed || !this.sendBridge({
        type: "signal.relay",
        sessionId: this.sessionId,
        payload: {
          type: "ice.refresh",
          serverId: this.options.serverId,
          hostId: this.options.hostId,
          networkPrivacy: this.options.networkPrivacy === "relay" ? "relay" : "direct",
        },
      })) this.scheduleReconnect(false);
    }, refreshIn);
  }

  private copyRtcIceConfiguration(configuration: BrowserRtcIceConfiguration): BrowserRtcIceConfiguration {
    return {
      ...configuration,
      iceServers: configuration.iceServers.map((server) => ({
        ...server,
        urls: Array.isArray(server.urls) ? [...server.urls] : server.urls,
      })),
    };
  }

  private handleHostFrame(raw: string): void {
    try {
      const frame = JSON.parse(raw) as { event: string; data: unknown };
      if (frame.event === "auth.challenge") {
        const verified = verifySignedHostAuthChallenge(frame.data, {
          serverId: this.options.serverId,
          authorityFingerprint: this.options.authorityFingerprint,
          hostPublicKey: this.hostTrust.hostPublicKey,
          hostId: this.hostTrust.hostId,
          grantId: this.hostTrust.grantId,
        });
        if (!verified) {
          this.close();
          return;
        }
        this.challengeVerified = true;
        const challenge = verified.payload;
        const now = Date.now();
        const proof = createSignedSessionAuth({
          version: 1,
          serverId: challenge.serverId,
          identityId: this.options.identityId,
          publicKey: ed25519PublicKey(this.options.deviceSeed).toString("base64url"),
          challengeId: challenge.challengeId,
          nonce: challenge.nonce,
          issuedAt: now,
          expiresAt: Math.min(challenge.expiresAt, now + 30_000),
        }, this.options.deviceSeed);
        this.sendChannelFrame("auth.prove", proof);
        return;
      }
      if (frame.event === "auth.error") {
        this.close();
        return;
      }
      if (frame.event === "auth.ready") {
        if (!this.challengeVerified) {
          this.close();
          return;
        }
        // A duplicated auth.ready frame belongs to the same transition and must not start
        // another desktop recovery pass.
        if (this.authenticated) return;
        this.authenticated = true;
        this.restartingIce = false;
        this.reconnectAttempt = 0;
        this.closeNotified = false;
        if (this.connectionTimer) clearTimeout(this.connectionTimer);
        this.connectionTimer = null;
        this.flushOutbound();
        for (const open of this.openHandlers.splice(0)) open();
        const event = {
          generation: ++this.authenticatedOpenGeneration,
          reconnected: this.authenticatedOpenGeneration > 1,
        };
        for (const handler of this.authenticatedOpenHandlers) handler(event);
        return;
      }
      if (!this.authenticated) return;
      if (frame.event === "event") this.handler?.(frame.data as HostEvent);
      if (frame.event === "result") this.settleRequest(this.inFlight.shift(), frame.data);
      const listeners = this.once.get(frame.event) ?? [];
      this.once.delete(frame.event);
      for (const listener of listeners) listener(frame);
    } catch {
      // Ignore malformed host frames.
    }
  }

  private sendBridge(frame: unknown): boolean {
    if (!this.bridge || this.bridge.readyState !== WebSocket.OPEN) return false;
    this.bridge.send(JSON.stringify(frame));
    return true;
  }

  private sendChannelFrame(event: string, data: unknown): boolean {
    if (!this.channel?.isOpen()) return false;
    try {
      return this.channel.sendMessage(JSON.stringify({ event, data }));
    } catch {
      return false;
    }
  }

  private queueApplicationFrame(event: string, data: unknown, request?: PendingRequest): void {
    if (this.closed) throw new Error("ICE host transport is closed");
    const frame = { raw: JSON.stringify({ event, data }), request };
    if (this.authenticated && this.channel?.isOpen()) this.deliverFrame(frame);
    else {
      if (this.outbound.length >= 256) throw new Error("ICE host outbound queue limit reached");
      this.outbound.push(frame);
    }
  }

  private deliverFrame(frame: OutboundFrame): void {
    if (!this.channel?.isOpen()) {
      this.outbound.unshift(frame);
      return;
    }
    if (frame.request) this.inFlight.push(frame.request);
    let sent = false;
    try {
      sent = this.channel.sendMessage(frame.raw);
    } catch {
      sent = false;
    }
    if (!sent) {
      if (frame.request) {
        const pending = this.inFlight.indexOf(frame.request);
        if (pending >= 0) this.inFlight.splice(pending, 1);
      }
      throw new Error("ICE host channel backpressure rejected frame");
    }
  }

  private flushOutbound(): void {
    while (this.authenticated && this.channel?.isOpen() && this.outbound.length > 0) this.deliverFrame(this.outbound.shift()!);
  }

  private settleRequest(request: PendingRequest | undefined, value: unknown): void {
    if (!request || request.settled) return;
    request.settled = true;
    clearTimeout(request.timer);
    request.resolve?.(value);
  }

  private tryIceRestart(): boolean {
    const pc = this.pc as (PeerConnection & { restartIce?: () => void | Promise<void> }) | null;
    if (!pc || typeof pc.restartIce !== "function" || !this.bridge || this.bridge.readyState !== WebSocket.OPEN) return false;
    const generation = this.generation;
    this.restartingIce = true;
    this.authenticated = false;
    Promise.resolve().then(() => pc.restartIce!()).then(() => {
      if (generation === this.generation && !this.closed) pc.setLocalDescription("offer");
    }).catch(() => {
      if (generation === this.generation && !this.closed) this.scheduleReconnect(false);
    });
    return true;
  }

  private scheduleReconnect(preferIceRestart: boolean): void {
    if (this.closed || this.reconnectTimer) return;
    if (preferIceRestart && this.tryIceRestart()) return;
    // Fence the failed attempt before teardown: close/error callbacks may run synchronously,
    // and must not schedule another reconnect or affect the next session during backoff.
    ++this.generation;
    this.authenticated = false;
    settleTransportGenerationRequests(this.inFlight, {
      ok: false,
      error: { code: "host_offline", message: "connection generation changed before host response" },
    });
    this.notifyClose();
    const delay = reconnectBackoffDelay(
      this.reconnectAttempt++,
      this.options.reconnectBaseDelayMs ?? 250,
      this.options.reconnectMaxDelayMs ?? 8_000,
    );
    this.teardownAttempt(true);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.beginAttempt();
    }, delay);
  }

  private teardownAttempt(signalClose: boolean): void {
    if (this.connectionTimer) clearTimeout(this.connectionTimer);
    if (this.disconnectedTimer) clearTimeout(this.disconnectedTimer);
    this.connectionTimer = null;
    this.disconnectedTimer = null;
    if (signalClose && this.bridge?.readyState === WebSocket.OPEN && this.sessionId) {
      this.sendBridge({ type: "signal.close", sessionId: this.sessionId });
    }
    try { this.channel?.close(); } catch { /* already closed */ }
    try { this.pc?.close(); } catch { /* already closed */ }
    try { this.bridge?.close(); } catch { /* already closed */ }
    this.channel = null;
    this.pc = null;
    this.bridge = null;
  }

  private notifyClose(): void {
    if (this.closeNotified) return;
    this.closeNotified = true;
    for (const handler of this.closeHandlers) handler();
  }

  private failQueuedRequests(code: ErrorCode, message: string): void {
    const value = { ok: false, error: { code, message } };
    for (const frame of this.outbound.splice(0)) this.settleRequest(frame.request, value);
    for (const request of this.inFlight.splice(0)) this.settleRequest(request, value);
  }

  send(event: string, data: unknown): void {
    // DataChannel ordering lets multiple frames be in flight, but every public send conservatively
    // reserves a FIFO result slot because known and unknown application events both receive one.
    this.queueResultFrame(event, data);
  }

  command(command: HostCommand): void {
    this.queueResultFrame("command", command);
  }

  request(command: HostCommand, timeoutMs = 8000): Promise<unknown> {
    if (this.closed) {
      return Promise.resolve({ ok: false, error: { code: "host_offline", message: "transport closed" } });
    }
    return new Promise((resolve) => {
      this.queueResultFrame("command", command, timeoutMs, resolve);
    });
  }

  private queueResultFrame(
    event: string,
    data: unknown,
    timeoutMs = 8000,
    resolve?: (data: unknown) => void,
  ): void {
    const request = {} as PendingRequest;
    request.resolve = resolve;
    request.settled = false;
    request.timer = setTimeout(() => this.handleResultTimeout(request), timeoutMs);
    try {
      this.queueApplicationFrame(event, data, request);
    } catch (error) {
      request.settled = true;
      clearTimeout(request.timer);
      throw error;
    }
  }

  private handleResultTimeout(request: PendingRequest): void {
    if (request.settled) return;
    const queued = this.outbound.findIndex((frame) => frame.request === request);
    if (queued >= 0) {
      this.outbound.splice(queued, 1);
      this.settleRequest(request, { ok: false, error: { code: "timeout", message: "host timeout" } });
      return;
    }
    const pending = this.inFlight.indexOf(request);
    if (pending >= 0) {
      this.inFlight.splice(pending, 1);
      this.settleRequest(request, { ok: false, error: { code: "timeout", message: "host timeout" } });
      // Result frames are FIFO and carry no correlation id. Fence this generation before
      // another result-producing frame is sent, otherwise a late result can settle its slot.
      this.scheduleReconnect(false);
      return;
    }
    this.settleRequest(request, { ok: false, error: { code: "timeout", message: "host timeout" } });
  }

  onEvent(handler: (event: HostEvent) => void): void {
    this.handler = handler;
  }

  onEventOnce(event: string, handler: (frame: { event: string; data: unknown }) => void): void {
    this.once.set(event, [...(this.once.get(event) ?? []), handler]);
  }

  onOpen(handler: () => void): void {
    if (this.authenticated) handler();
    else this.openHandlers.push(handler);
  }

  /**
   * Persistent authenticated lifecycle signal. Every false -> true authentication transition
   * receives a unique generation, while duplicate auth.ready frames are ignored.
   */
  onAuthenticatedOpen(handler: (event: AuthenticatedOpenEvent) => void): () => void {
    this.authenticatedOpenHandlers.add(handler);
    if (this.authenticatedOpenGeneration > 0) {
      handler({ generation: this.authenticatedOpenGeneration, reconnected: this.authenticatedOpenGeneration > 1 });
    }
    return () => this.authenticatedOpenHandlers.delete(handler);
  }

  onClose(handler: () => void): void {
    this.closeHandlers.push(handler);
  }

  /** Current call/media ICE config. Subscribe to refreshes before passing it to renderer peers. */
  rtcIceConfiguration(): BrowserRtcIceConfiguration | null {
    if (!this.activeRtcConfiguration || (this.activeRtcConfiguration.expiresAt ?? Number.POSITIVE_INFINITY) <= Date.now()) return null;
    return this.copyRtcIceConfiguration(this.activeRtcConfiguration);
  }

  onIceConfiguration(handler: (configuration: BrowserRtcIceConfiguration) => void): void {
    this.iceConfigurationHandlers.push(handler);
    const current = this.rtcIceConfiguration();
    if (current) handler(current);
  }

  get ready(): boolean {
    return this.authenticated && Boolean(this.channel?.isOpen());
  }

  diagnostics(): {
    networkPrivacy: "direct" | "relay";
    bridgeIndex: number;
    peerState: string | null;
    selectedCandidatePair: ReturnType<PeerConnection["getSelectedCandidatePair"]>;
  } {
    return {
      networkPrivacy: this.options.networkPrivacy === "relay" ? "relay" : "direct",
      bridgeIndex: (this.bridgeCursor + this.bridgeUrls.length - 1) % this.bridgeUrls.length,
      peerState: this.pc?.state() ?? null,
      selectedCandidatePair: this.pc?.getSelectedCandidatePair() ?? null,
    };
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    ++this.generation;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.credentialRefreshTimer) clearTimeout(this.credentialRefreshTimer);
    this.reconnectTimer = null;
    this.credentialRefreshTimer = null;
    this.teardownAttempt(true);
    this.failQueuedRequests("host_offline", "transport closed");
    this.notifyClose();
  }
}

/** Resposta helper: ok(data) | err(code, message) — forma estável para o host responder. */
export type HostOk<T> = { ok: true; data: T };
export type HostErr = { ok: false; error: { code: ErrorCode; message: string } };
export type HostResult<T> = HostOk<T> | HostErr;

export function ok<T>(data: T): HostOk<T> {
  return { ok: true, data };
}

export function err(code: ErrorCode, message: string): HostErr {
  return { ok: false, error: { code, message } };
}
