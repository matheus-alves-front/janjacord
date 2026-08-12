import { EventEmitter } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WebSocket } from "ws";

const rtc = vi.hoisted(() => ({ peers: [] as any[] }));

vi.mock("node-datachannel", () => ({
  default: {
    PeerConnection: class FakePeerConnection {
      readonly candidates: { candidate: string; mid: string }[] = [];
      remoteDescription: { sdp: string; type: string } | null = null;
      closeCount = 0;
      private localDescriptionHandler: ((sdp: string, type: string) => void) | null = null;
      private localCandidateHandler: ((candidate: string, mid: string) => void) | null = null;
      private stateHandler: ((state: string) => void) | null = null;
      private dataChannelHandler: ((channel: unknown) => void) | null = null;

      constructor(public readonly name: string, public readonly configuration: unknown) {
        rtc.peers.push(this);
      }

      onLocalDescription(handler: (sdp: string, type: string) => void) { this.localDescriptionHandler = handler; }
      onLocalCandidate(handler: (candidate: string, mid: string) => void) { this.localCandidateHandler = handler; }
      onStateChange(handler: (state: string) => void) { this.stateHandler = handler; }
      onDataChannel(handler: (channel: unknown) => void) { this.dataChannelHandler = handler; }
      setRemoteDescription(sdp: string, type: string) { this.remoteDescription = { sdp, type }; }
      addRemoteCandidate(candidate: string, mid: string) { this.candidates.push({ candidate, mid }); }
      getSelectedCandidatePair() { return null; }
      close() {
        this.closeCount += 1;
        this.stateHandler?.("closed");
      }
    },
  },
}));

import { attachIceHostGateway, isValidIceCandidate, isValidIceSdp } from "./ice-gateway.js";

const SESSION_A = "a".repeat(32);
const SESSION_B = "b".repeat(32);
const OFFER = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
const CANDIDATE = "candidate:1 1 UDP 2122260223 192.0.2.1 5000 typ host";

class FakeBridge extends EventEmitter {
  readyState: number = WebSocket.OPEN;
  readonly sent: Record<string, any>[] = [];

  send(raw: string) {
    this.sent.push(JSON.parse(raw) as Record<string, any>);
  }

  frame(value: unknown) {
    this.emit("message", Buffer.from(JSON.stringify(value)), false);
  }

  disconnect() {
    this.readyState = WebSocket.CLOSED;
    this.emit("close");
  }
}

function lastMatching(
  frames: readonly Record<string, any>[],
  predicate: (frame: Record<string, any>) => boolean,
): Record<string, any> | undefined {
  for (let index = frames.length - 1; index >= 0; index--) {
    const frame = frames[index]!;
    if (predicate(frame)) return frame;
  }
  return undefined;
}

function request(sessionId: string, networkPrivacy: "direct" | "relay" = "direct") {
  return {
    type: "signal.open",
    sessionId,
    payload: {
      type: "ice.request",
      serverId: "11111111-1111-4111-8111-111111111111",
      hostId: "primary-host",
      networkPrivacy,
      accessProof: { signed: true },
    },
  };
}

function completeDirectTurn(bridge: FakeBridge, sessionId: string) {
  const turn = lastMatching(bridge.sent, (frame) => frame.type === "turn.issue" && frame.subject === sessionId);
  expect(turn).toBeDefined();
  bridge.frame({ type: "turn.issue.result", requestId: turn!.requestId, ok: false });
  expect(lastMatching(bridge.sent, (frame) => frame.sessionId === sessionId)).toMatchObject({
    type: "signal.relay",
    payload: { type: "ice.config", networkPrivacy: "direct", credentials: null },
  });
  return turn!;
}

const disposers: (() => void)[] = [];

afterEach(() => {
  for (const dispose of disposers.splice(0)) dispose();
  rtc.peers.splice(0);
  vi.useRealTimers();
});

describe("ICE host gateway authorization boundary", () => {
  it("enforces strict SDP and candidate syntax and byte limits", () => {
    expect(isValidIceSdp(OFFER)).toBe(true);
    expect(isValidIceSdp("not-sdp")).toBe(false);
    expect(isValidIceSdp(`v=0\r\n${"x".repeat(49 * 1024)}`)).toBe(false);
    expect(isValidIceCandidate(CANDIDATE, "0")).toBe(true);
    expect(isValidIceCandidate("not-a-candidate", "0")).toBe(false);
    expect(isValidIceCandidate(`candidate:${"x".repeat(4 * 1024)}`, "0")).toBe(false);
    expect(isValidIceCandidate(CANDIDATE, "bad mid with spaces")).toBe(false);
  });

  it("rejects offer, candidate, and refresh before an authenticated ice.request", () => {
    const bridge = new FakeBridge();
    disposers.push(attachIceHostGateway(bridge as unknown as WebSocket, 8931, () => true));

    bridge.frame({ type: "signal.open", sessionId: SESSION_A, payload: { type: "offer", sdp: OFFER } });
    bridge.frame({ type: "signal.relay", sessionId: SESSION_A, payload: { type: "candidate", candidate: CANDIDATE, mid: "0" } });
    bridge.frame({
      type: "signal.relay",
      sessionId: SESSION_A,
      payload: { type: "ice.refresh", serverId: "server", hostId: "host" },
    });

    expect(rtc.peers).toHaveLength(0);
    expect(bridge.sent.filter((frame) => frame.type === "turn.issue")).toHaveLength(0);
    expect(bridge.sent.filter((frame) => frame.payload?.code === "unauthorized")).toHaveLength(3);
  });

  it("binds post-auth signaling to the session and idempotently clears peer, candidates, auth, config, and TURN", () => {
    const bridge = new FakeBridge();
    const authorize = vi.fn(() => true);
    const dispose = attachIceHostGateway(bridge as unknown as WebSocket, 8931, authorize);
    disposers.push(dispose);

    bridge.frame(request(SESSION_A));
    completeDirectTurn(bridge, SESSION_A);
    bridge.frame({ type: "signal.relay", sessionId: SESSION_A, payload: { type: "candidate", candidate: CANDIDATE, mid: "0" } });
    bridge.frame({ type: "signal.open", sessionId: SESSION_A, payload: { type: "offer", sdp: OFFER } });

    expect(authorize).toHaveBeenCalledWith({ signed: true }, expect.objectContaining({ sessionId: SESSION_A }));
    expect(rtc.peers).toHaveLength(1);
    expect(rtc.peers[0].remoteDescription).toEqual({ sdp: OFFER, type: "offer" });
    expect(rtc.peers[0].candidates).toEqual([{ candidate: CANDIDATE, mid: "0" }]);

    bridge.frame({ type: "signal.close", sessionId: SESSION_A });
    bridge.frame({ type: "signal.close", sessionId: SESSION_A });
    expect(rtc.peers[0].closeCount).toBe(1);

    bridge.frame({ type: "signal.open", sessionId: SESSION_A, payload: { type: "offer", sdp: OFFER } });
    expect(rtc.peers).toHaveLength(1);
    expect(lastMatching(bridge.sent, (frame) => frame.sessionId === SESSION_A)).toMatchObject({ payload: { code: "unauthorized" } });

    bridge.frame(request(SESSION_A));
    expect(authorize).toHaveBeenCalledTimes(2);
  });

  it("ignores stale TURN results after churn and correlates the next session response", async () => {
    const bridge = new FakeBridge();
    disposers.push(attachIceHostGateway(bridge as unknown as WebSocket, 8931, () => true));

    bridge.frame(request(SESSION_A));
    const firstTurn = bridge.sent.find((frame) => frame.type === "turn.issue");
    expect(firstTurn).toBeDefined();
    bridge.frame({ type: "signal.close", sessionId: SESSION_A });
    bridge.frame(request(SESSION_B));
    await Promise.resolve();
    const secondTurn = lastMatching(bridge.sent, (frame) => frame.type === "turn.issue");
    expect(secondTurn?.requestId).not.toBe(firstTurn?.requestId);

    bridge.frame({ type: "turn.issue.result", requestId: firstTurn!.requestId, ok: false });
    expect(bridge.sent.some((frame) => frame.sessionId === SESSION_B && frame.payload?.type === "ice.config")).toBe(false);
    bridge.frame({ type: "turn.issue.result", requestId: secondTurn!.requestId, ok: false });
    expect(lastMatching(bridge.sent, (frame) => frame.sessionId === SESSION_B)).toMatchObject({ payload: { type: "ice.config" } });
  });

  it("preserves relay-only setup with correlated temporary TURN credentials", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-12T12:00:00Z"));
    const bridge = new FakeBridge();
    disposers.push(attachIceHostGateway(bridge as unknown as WebSocket, 8931, () => true));

    bridge.frame(request(SESSION_A, "relay"));
    const turn = lastMatching(bridge.sent, (frame) => frame.type === "turn.issue" && frame.subject === SESSION_A);
    bridge.frame({
      type: "turn.issue.result",
      requestId: turn!.requestId,
      ok: true,
      data: {
        urls: ["turn:turn.example:3478?transport=udp", "turns:turn.example:5349?transport=tcp"],
        username: "temporary-user",
        credential: "temporary-password",
        credentialType: "password",
        expiresAt: Date.now() + 300_000,
      },
    });
    expect(lastMatching(bridge.sent, (frame) => frame.sessionId === SESSION_A)).toMatchObject({
      payload: { type: "ice.config", networkPrivacy: "relay", credentials: { username: "temporary-user" } },
    });

    bridge.frame({ type: "signal.open", sessionId: SESSION_A, payload: { type: "offer", sdp: OFFER } });
    expect(rtc.peers).toHaveLength(1);
    expect(rtc.peers[0].configuration).toMatchObject({ iceTransportPolicy: "relay" });
  });

  it("caps authorized sessions globally before invoking more access proofs", () => {
    const bridge = new FakeBridge();
    const authorize = vi.fn(() => true);
    disposers.push(attachIceHostGateway(bridge as unknown as WebSocket, 8931, authorize));

    for (let index = 0; index < 257; index++) {
      const sessionId = index.toString(36).padStart(32, "0");
      bridge.frame(request(sessionId));
    }

    expect(authorize).toHaveBeenCalledTimes(256);
    expect(bridge.sent.filter((frame) => frame.payload?.code === "unauthorized")).toHaveLength(1);
  });

  it("caps pending candidates per session and releases all state on TTL and bridge disconnect", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-12T12:00:00Z"));
    const bridge = new FakeBridge();
    const dispose = attachIceHostGateway(bridge as unknown as WebSocket, 8931, () => true);
    disposers.push(dispose);

    bridge.frame(request(SESSION_A));
    completeDirectTurn(bridge, SESSION_A);
    for (let index = 0; index < 33; index++) {
      bridge.frame({
        type: "signal.relay",
        sessionId: SESSION_A,
        payload: { type: "candidate", candidate: `candidate:${index} 1 UDP 1 192.0.2.1 ${5000 + index} typ host`, mid: "0" },
      });
    }
    expect(lastMatching(bridge.sent, (frame) => frame.sessionId === SESSION_A)).toMatchObject({ payload: { code: "capacity" } });
    bridge.frame({ type: "signal.open", sessionId: SESSION_A, payload: { type: "offer", sdp: OFFER } });
    expect(rtc.peers).toHaveLength(0);

    bridge.frame(request(SESSION_B));
    completeDirectTurn(bridge, SESSION_B);
    bridge.frame({ type: "signal.open", sessionId: SESSION_B, payload: { type: "offer", sdp: OFFER } });
    expect(rtc.peers).toHaveLength(1);
    vi.advanceTimersByTime(10 * 60_000 + 15_000);
    expect(rtc.peers[0].closeCount).toBe(1);

    bridge.disconnect();
    dispose();
    expect(rtc.peers[0].closeCount).toBe(1);
  });
});
