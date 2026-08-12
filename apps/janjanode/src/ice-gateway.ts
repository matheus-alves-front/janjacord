import nodeDataChannel, { type PeerConnection } from "node-datachannel";
import {
  iceServerConfiguration,
  isRelayOnlyCandidatePair,
  parseTemporaryTurnCredentials,
  type IceServerConfig,
  type TemporaryTurnCredentials,
} from "@janjacord/networking";
import { randomUUID } from "node:crypto";
import { WebSocket, type RawData } from "ws";

const MAX_ACTIVE_ICE_PEERS_GLOBAL = 128;
const MAX_AUTHORIZED_ICE_SESSIONS = 256;
const MAX_PENDING_CANDIDATES_PER_SESSION = 32;
const MAX_PENDING_CANDIDATES_GLOBAL = 2_048;
const MAX_ICE_SDP_BYTES = 48 * 1024;
const MAX_ICE_CANDIDATE_BYTES = 4 * 1024;
const MAX_ICE_MID_BYTES = 64;
const MAX_BRIDGE_FRAME_BYTES = 64 * 1024;
const TURN_ISSUE_TIMEOUT_MS = 1_500;
const LOOPBACK_AUTH_DEADLINE_MS = 9_000;
const MAX_LOOPBACK_QUEUE_BYTES = 512 * 1024;
const ICE_SESSION_TTL_MS = 10 * 60_000;
const ICE_SESSION_CLEANUP_MS = 15_000;
let activeIcePeerCount = 0;
let authorizedIceSessionCount = 0;
let pendingIceCandidateCount = 0;

type NetworkPrivacy = "direct" | "relay";
type SessionConfiguration = {
  serverId: string;
  hostId: string;
  networkPrivacy: NetworkPrivacy;
  credentials: TemporaryTurnCredentials | null;
};
type AuthorizedSession = Omit<SessionConfiguration, "credentials"> & { expiresAt: number };
type IceAccessAuthorizer = (proof: unknown, expected: { sessionId: string; serverId: string; hostId: string }) => boolean;

function validSessionId(value: string): boolean {
  return /^[A-Za-z0-9_-]{16,128}$/.test(value);
}

export function isValidIceSdp(value: unknown): value is string {
  return typeof value === "string"
    && value.startsWith("v=0")
    && !value.includes("\0")
    && Buffer.byteLength(value) <= MAX_ICE_SDP_BYTES;
}

export function isValidIceCandidate(value: unknown, mid: unknown): value is string {
  return typeof value === "string"
    && /^(?:a=)?candidate:/i.test(value)
    && !value.includes("\0")
    && Buffer.byteLength(value) <= MAX_ICE_CANDIDATE_BYTES
    && (mid === undefined || (typeof mid === "string" && Buffer.byteLength(mid) <= MAX_ICE_MID_BYTES
      && /^[A-Za-z0-9_.:-]*$/.test(mid)));
}

function rawDataBytes(raw: RawData): number {
  if (Array.isArray(raw)) return raw.reduce((total, entry) => total + entry.length, 0);
  return raw instanceof ArrayBuffer ? raw.byteLength : raw.length;
}

function configuredBaseIceServers(): IceServerConfig[] {
  try {
    const parsed = JSON.parse(process.env.JC_ICE_SERVERS ?? "[]") as unknown;
    if (!Array.isArray(parsed)) return [];
    // The shared networking boundary rejects static TURN credentials and retains STUN only.
    return iceServerConfiguration(parsed as IceServerConfig[], null, "direct").iceServers;
  } catch {
    return [];
  }
}

function effectivePolicy(requested: NetworkPrivacy): NetworkPrivacy {
  return process.env.JC_NETWORK_PRIVACY === "relay" || requested === "relay" ? "relay" : "direct";
}

/** WAN DataChannels terminate in the existing authenticated local WebSocket gateway. */
export function attachIceHostGateway(bridge: WebSocket, localPort: number, authorizeAccess: IceAccessAuthorizer): () => void {
  const peers = new Map<string, PeerConnection>();
  const pendingCandidates = new Map<string, { candidate: string; mid: string }[]>();
  const sessionConfigurations = new Map<string, SessionConfiguration>();
  const authorizedSessions = new Map<string, AuthorizedSession>();
  const turnQueue: {
    requestId: string;
    sessionId: string;
    configuration: Omit<SessionConfiguration, "credentials">;
  }[] = [];
  let activeTurnRequest: (typeof turnQueue)[number] | null = null;
  let activeTurnTimer: ReturnType<typeof setTimeout> | null = null;

  let disposed = false;

  const relay = (sessionId: string, payload: unknown) => {
    if (bridge.readyState === WebSocket.OPEN) bridge.send(JSON.stringify({ type: "signal.relay", sessionId, payload }));
  };

  const relayAuthorized = (sessionId: string, payload: unknown) => {
    if (authorizedSession(sessionId, false)) relay(sessionId, payload);
  };

  const closePeerOnly = (sessionId: string) => {
    const peer = peers.get(sessionId);
    if (peers.delete(sessionId)) activeIcePeerCount = Math.max(0, activeIcePeerCount - 1);
    try { peer?.close(); } catch { /* already closed */ }
  };

  const clearPendingCandidates = (sessionId: string) => {
    const pending = pendingCandidates.get(sessionId);
    if (pending) pendingIceCandidateCount = Math.max(0, pendingIceCandidateCount - pending.length);
    pendingCandidates.delete(sessionId);
  };

  const removeQueuedTurnRequests = (sessionId: string) => {
    for (let index = turnQueue.length - 1; index >= 0; index--) {
      if (turnQueue[index]?.sessionId === sessionId) turnQueue.splice(index, 1);
    }
    if (activeTurnRequest?.sessionId === sessionId) {
      if (activeTurnTimer) clearTimeout(activeTurnTimer);
      activeTurnTimer = null;
      activeTurnRequest = null;
      queueMicrotask(() => pumpTurnRequests());
    }
  };

  const cleanupSession = (sessionId: string) => {
    closePeerOnly(sessionId);
    clearPendingCandidates(sessionId);
    sessionConfigurations.delete(sessionId);
    if (authorizedSessions.delete(sessionId)) {
      authorizedIceSessionCount = Math.max(0, authorizedIceSessionCount - 1);
    }
    removeQueuedTurnRequests(sessionId);
  };

  const authorizedSession = (sessionId: string, touch = true): AuthorizedSession | null => {
    const session = authorizedSessions.get(sessionId);
    if (!session) return null;
    if (session.expiresAt <= Date.now()) {
      cleanupSession(sessionId);
      return null;
    }
    if (touch) session.expiresAt = Date.now() + ICE_SESSION_TTL_MS;
    return session;
  };

  const completeTurnRequest = (requestId: string, credentials: TemporaryTurnCredentials | null) => {
    if (!activeTurnRequest || activeTurnRequest.requestId !== requestId) return;
    if (activeTurnTimer) clearTimeout(activeTurnTimer);
    activeTurnTimer = null;
    const request = activeTurnRequest;
    activeTurnRequest = null;
    if (!authorizedSession(request.sessionId, false)) {
      pumpTurnRequests();
      return;
    }
    const configuration: SessionConfiguration = { ...request.configuration, credentials };
    if (configuration.networkPrivacy === "relay" && !credentials) {
      relay(request.sessionId, { type: "ice.error", code: "relay_unavailable" });
      cleanupSession(request.sessionId);
    } else {
      sessionConfigurations.set(request.sessionId, configuration);
      relayAuthorized(request.sessionId, {
        type: "ice.config",
        networkPrivacy: configuration.networkPrivacy,
        credentials,
      });
    }
    pumpTurnRequests();
  };

  const pumpTurnRequests = () => {
    if (disposed || activeTurnRequest || bridge.readyState !== WebSocket.OPEN) return;
    const request = turnQueue.shift();
    if (!request) return;
    activeTurnRequest = request;
    bridge.send(JSON.stringify({
      type: "turn.issue",
      requestId: request.requestId,
      serverId: request.configuration.serverId,
      hostId: request.configuration.hostId,
      subject: request.sessionId,
      ttlSeconds: 300,
    }));
    activeTurnTimer = setTimeout(() => completeTurnRequest(request.requestId, null), TURN_ISSUE_TIMEOUT_MS);
  };

  const requestTurn = (sessionId: string, configuration: Omit<SessionConfiguration, "credentials">) => {
    if (!authorizedSession(sessionId) || turnQueue.length >= MAX_AUTHORIZED_ICE_SESSIONS) return;
    const queued = turnQueue.some((request) => request.sessionId === sessionId);
    if (activeTurnRequest?.sessionId === sessionId || queued) return;
    turnQueue.push({ requestId: randomUUID(), sessionId, configuration });
    pumpTurnRequests();
  };

  const openPeer = (sessionId: string, offer: { sdp?: string }) => {
    const authorization = authorizedSession(sessionId);
    const session = sessionConfigurations.get(sessionId);
    if (!authorization || !session) {
      relay(sessionId, { type: "ice.error", code: "unauthorized" });
      return;
    }
    closePeerOnly(sessionId);
    if (!isValidIceSdp(offer.sdp) || activeIcePeerCount >= MAX_ACTIVE_ICE_PEERS_GLOBAL) {
      relay(sessionId, { type: "ice.error", code: activeIcePeerCount >= MAX_ACTIVE_ICE_PEERS_GLOBAL ? "capacity" : "invalid_offer" });
      if (!isValidIceSdp(offer.sdp)) cleanupSession(sessionId);
      return;
    }
    let rtcConfiguration: ReturnType<typeof iceServerConfiguration>;
    try {
      rtcConfiguration = iceServerConfiguration(configuredBaseIceServers(), session.credentials, session.networkPrivacy);
    } catch {
      relay(sessionId, { type: "ice.error", code: "relay_unavailable" });
      cleanupSession(sessionId);
      return;
    }
    if (process.env.JC_DEBUG_LOGS === "1") console.log(`[janjanode] ICE session opened policy=${session.networkPrivacy}`);
    let pc: PeerConnection;
    try {
      pc = new nodeDataChannel.PeerConnection(`janjanode-${sessionId}`, rtcConfiguration);
    } catch {
      relay(sessionId, { type: "ice.error", code: "peer_unavailable" });
      cleanupSession(sessionId);
      return;
    }
    peers.set(sessionId, pc);
    activeIcePeerCount += 1;
    pc.onLocalDescription((sdp, type) => {
      if (peers.get(sessionId) !== pc) return;
      if (isValidIceSdp(sdp)) relayAuthorized(sessionId, { type: type.toLowerCase(), sdp });
      else cleanupSession(sessionId);
    });
    pc.onLocalCandidate((candidate, mid) => {
      if (peers.get(sessionId) !== pc) return;
      if (!candidate.trim()) return;
      const candidateType = /\styp\s+([A-Za-z]+)/i.exec(candidate)?.[1]?.toLowerCase();
      if (session.networkPrivacy === "relay" && candidateType !== "relay") {
        console.warn(`[janjanode] relay-only rejected local ICE candidate type=${candidateType ?? "unknown"}`);
        relayAuthorized(sessionId, { type: "ice.error", code: "relay_policy_violation" });
        cleanupSession(sessionId);
        return;
      }
      if (!isValidIceCandidate(candidate, mid)) {
        cleanupSession(sessionId);
        return;
      }
      relayAuthorized(sessionId, { type: "candidate", candidate, mid });
    });
    pc.onStateChange((state) => {
      if (peers.get(sessionId) !== pc) return;
      const normalized = state.toLowerCase();
      if (process.env.JC_DEBUG_LOGS === "1") console.log(`[janjanode] ICE state=${normalized}`);
      if (normalized === "connected" && session.networkPrivacy === "relay") {
        const pair = pc.getSelectedCandidatePair();
        if (process.env.JC_DEBUG_LOGS === "1") console.log(`[janjanode] ICE pair=${pair?.local.type ?? "none"}/${pair?.remote.type ?? "none"}`);
        if (!isRelayOnlyCandidatePair(pair)) {
          relayAuthorized(sessionId, { type: "ice.error", code: "relay_policy_violation" });
          cleanupSession(sessionId);
        }
      }
      if (["failed", "closed", "disconnected"].includes(normalized)) cleanupSession(sessionId);
    });
    pc.onDataChannel((channel) => {
      if (peers.get(sessionId) !== pc) {
        channel.close();
        return;
      }
      const local = new WebSocket(`ws://127.0.0.1:${localPort}/signal`, {
        headers: { "x-jc-ice-session": sessionId },
        perMessageDeflate: false,
      });
      const queue: (string | Buffer)[] = [];
      let queuedBytes = 0;
      const authDeadline = setTimeout(() => {
        local.close(1008, "loopback authentication deadline exceeded");
        if (peers.get(sessionId) === pc) cleanupSession(sessionId);
      }, LOOPBACK_AUTH_DEADLINE_MS);
      local.on("open", () => {
        for (const message of queue) local.send(message);
        queue.length = 0;
        queuedBytes = 0;
      });
      local.on("message", (raw, binary) => {
        if (!channel.isOpen()) return;
        try {
          if (binary) {
            local.close(1003, "binary host frames are forbidden");
            channel.close();
          } else {
            const text = raw.toString();
            channel.sendMessage(text);
            try {
              const frame = JSON.parse(text) as { event?: string };
              if (frame.event === "auth.ready" || frame.event === "auth.error") clearTimeout(authDeadline);
            } catch { /* gateway will close malformed authentication */ }
          }
        } catch {
          local.close();
        }
      });
      channel.onMessage((message) => {
        if (typeof message !== "string" || Buffer.byteLength(message) > 64 * 1024) {
          local.close(1003, "invalid DataChannel frame");
          channel.close();
          return;
        }
        const value = message;
        if (local.readyState === WebSocket.OPEN) local.send(value);
        else if (queue.length < 64 && queuedBytes + Buffer.byteLength(value) <= MAX_LOOPBACK_QUEUE_BYTES) {
          queue.push(value);
          queuedBytes += Buffer.byteLength(value);
        } else {
          local.close(1008, "loopback queue limit exceeded");
          channel.close();
        }
      });
      channel.onClosed(() => {
        clearTimeout(authDeadline);
        local.close();
      });
      channel.onError(() => {
        clearTimeout(authDeadline);
        local.close();
      });
      // This internal response plane carries encrypted replica snapshots, which are larger than
      // public signaling frames. Public SDP/candidate limits are enforced before this boundary.
      local.on("error", () => {
        clearTimeout(authDeadline);
        channel.close();
        if (peers.get(sessionId) === pc) cleanupSession(sessionId);
      });
      local.on("close", () => { clearTimeout(authDeadline); channel.close(); });
    });
    try {
      pc.setRemoteDescription(offer.sdp, "offer");
      for (const candidate of pendingCandidates.get(sessionId) ?? []) pc.addRemoteCandidate(candidate.candidate, candidate.mid);
      clearPendingCandidates(sessionId);
    } catch {
      cleanupSession(sessionId);
    }
  };

  const onMessage = (raw: RawData, isBinary = false) => {
    try {
      if (isBinary || rawDataBytes(raw) > MAX_BRIDGE_FRAME_BYTES) return;
      const frame = JSON.parse(raw.toString()) as {
        type?: string;
        sessionId?: string;
        requestId?: string;
        ok?: boolean;
        data?: unknown;
        payload?: {
          type?: string;
          sdp?: string;
          candidate?: string;
          mid?: string;
          serverId?: string;
          hostId?: string;
          networkPrivacy?: NetworkPrivacy;
          accessProof?: unknown;
        };
      };
      if (activeTurnRequest && frame.type === "turn.issue.result"
        && frame.requestId === activeTurnRequest.requestId) {
        completeTurnRequest(frame.requestId, frame.ok === true ? parseTemporaryTurnCredentials(frame.data) : null);
        return;
      }
      const sessionId = frame.sessionId ?? "";
      if (!validSessionId(sessionId)) return;
      if (frame.type === "signal.open" && frame.payload?.type === "ice.request") {
        if (typeof frame.payload.serverId !== "string" || frame.payload.serverId.length > 128
          || typeof frame.payload.hostId !== "string" || frame.payload.hostId.length > 128) {
          relay(sessionId, { type: "ice.error", code: "invalid_request" });
          return;
        }
        const now = Date.now();
        for (const [id, session] of authorizedSessions) if (session.expiresAt <= now) cleanupSession(id);
        if (authorizedSessions.has(sessionId) || authorizedIceSessionCount >= MAX_AUTHORIZED_ICE_SESSIONS
          || !authorizeAccess(frame.payload.accessProof, {
            sessionId,
            serverId: frame.payload.serverId,
            hostId: frame.payload.hostId,
          })) {
          relay(sessionId, { type: "ice.error", code: "unauthorized" });
          return;
        }
        const authorization = {
          serverId: frame.payload.serverId,
          hostId: frame.payload.hostId,
          networkPrivacy: effectivePolicy(frame.payload.networkPrivacy === "relay" ? "relay" : "direct"),
          expiresAt: now + ICE_SESSION_TTL_MS,
        };
        authorizedSessions.set(sessionId, authorization);
        authorizedIceSessionCount += 1;
        requestTurn(sessionId, {
          serverId: authorization.serverId,
          hostId: authorization.hostId,
          networkPrivacy: authorization.networkPrivacy,
        });
      } else if (frame.type === "signal.relay" && frame.payload?.type === "ice.refresh") {
        const authorization = authorizedSession(sessionId);
        if (!authorization || frame.payload.serverId !== authorization.serverId
          || frame.payload.hostId !== authorization.hostId) {
          relay(sessionId, { type: "ice.error", code: "unauthorized" });
          return;
        }
        const previous = sessionConfigurations.get(sessionId);
        if (previous) requestTurn(sessionId, {
          serverId: previous.serverId,
          hostId: previous.hostId,
          networkPrivacy: previous.networkPrivacy,
        });
      } else if (frame.type === "signal.open" && frame.payload?.type === "offer") {
        openPeer(sessionId, frame.payload);
      } else if (frame.type === "signal.relay" && frame.payload?.type === "candidate") {
        if (!authorizedSession(sessionId) || !sessionConfigurations.has(sessionId)) {
          relay(sessionId, { type: "ice.error", code: "unauthorized" });
          return;
        }
        if (!isValidIceCandidate(frame.payload.candidate, frame.payload.mid)) {
          relay(sessionId, { type: "ice.error", code: "invalid_candidate" });
          cleanupSession(sessionId);
          return;
        }
        const pc = peers.get(sessionId);
        const candidate = { candidate: frame.payload.candidate, mid: frame.payload.mid || "0" };
        if (pc) pc.addRemoteCandidate(candidate.candidate, candidate.mid);
        else {
          const pending = pendingCandidates.get(sessionId) ?? [];
          if (pending.length >= MAX_PENDING_CANDIDATES_PER_SESSION || pendingIceCandidateCount >= MAX_PENDING_CANDIDATES_GLOBAL) {
            relay(sessionId, { type: "ice.error", code: "capacity" });
            cleanupSession(sessionId);
            return;
          }
          pendingCandidates.set(sessionId, [...pending, candidate]);
          pendingIceCandidateCount += 1;
        }
      } else if (frame.type === "signal.close") {
        cleanupSession(sessionId);
      }
    } catch {
      // Ignore malformed bridge frames.
    }
  };

  const cleanupExpiredSessions = () => {
    const now = Date.now();
    for (const [sessionId, session] of authorizedSessions) {
      if (session.expiresAt <= now) cleanupSession(sessionId);
    }
    pumpTurnRequests();
  };
  const sessionCleanupTimer = setInterval(cleanupExpiredSessions, ICE_SESSION_CLEANUP_MS);
  sessionCleanupTimer.unref();

  const dispose = () => {
    if (disposed) return;
    disposed = true;
    bridge.off("message", onMessage);
    bridge.off("open", pumpTurnRequests);
    bridge.off("close", dispose);
    clearInterval(sessionCleanupTimer);
    if (activeTurnTimer) clearTimeout(activeTurnTimer);
    activeTurnTimer = null;
    activeTurnRequest = null;
    turnQueue.length = 0;
    for (const sessionId of new Set([
      ...authorizedSessions.keys(),
      ...sessionConfigurations.keys(),
      ...pendingCandidates.keys(),
      ...peers.keys(),
    ])) cleanupSession(sessionId);
    sessionConfigurations.clear();
    authorizedSessions.clear();
  };

  bridge.on("message", onMessage);
  bridge.on("open", pumpTurnRequests);
  bridge.on("close", dispose);
  return dispose;
}
