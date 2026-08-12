import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_CALL_ICE_CANDIDATE_BYTES, MAX_CALL_SDP_BYTES } from "@janjacord/schemas";
import { MeshCall, type CallSignal, type MeshCallOptions } from "./webrtc";

const SDP = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
const ICE_CANDIDATE = {
  candidate: "candidate:1 1 UDP 2122260223 192.0.2.1 5000 typ host",
  sdpMid: "audio-0",
  sdpMLineIndex: 0,
  usernameFragment: "iceUfrag/1",
};

class FakePeerConnection {
  static instances: FakePeerConnection[] = [];

  signalingState: RTCSignalingState = "stable";
  onicecandidate: ((event: RTCPeerConnectionIceEvent) => void) | null = null;
  ontrack: ((event: RTCTrackEvent) => void) | null = null;
  createOffer = vi.fn(async () => ({ type: "offer" as const, sdp: SDP }));
  createAnswer = vi.fn(async () => ({ type: "answer" as const, sdp: SDP }));
  setLocalDescription = vi.fn(async (description: RTCSessionDescriptionInit) => {
    this.signalingState = description.type === "offer" ? "have-local-offer" : "stable";
  });
  setRemoteDescription = vi.fn(async (description: RTCSessionDescriptionInit) => {
    this.signalingState = description.type === "answer" ? "stable" : "have-remote-offer";
  });
  addIceCandidate = vi.fn(async (_candidate: RTCIceCandidateInit) => undefined);
  addTrack = vi.fn();
  close = vi.fn();

  constructor(_configuration?: RTCConfiguration) {
    FakePeerConnection.instances.push(this);
  }
}

const createMesh = () => {
  const sendSignal = vi.fn<MeshCallOptions["sendSignal"]>();
  const mesh = new MeshCall({
    selfId: "alice",
    sendSignal,
    onRemoteStream: vi.fn(),
    onPeerLeft: vi.fn(),
  });
  return { mesh, sendSignal };
};

beforeEach(() => {
  FakePeerConnection.instances = [];
  vi.stubGlobal("RTCPeerConnection", FakePeerConnection);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("MeshCall signaling validation", () => {
  it("keeps valid offer, answer, and trickle ICE working", async () => {
    const offerSide = createMesh();
    await offerSide.mesh.handleSignal({ from: "bob", payload: { type: "offer", sdp: SDP } });

    const offeredPc = FakePeerConnection.instances[0]!;
    expect(offeredPc.setRemoteDescription).toHaveBeenCalledWith({ type: "offer", sdp: SDP });
    expect(offeredPc.createAnswer).toHaveBeenCalledOnce();
    expect(offerSide.sendSignal).toHaveBeenCalledWith("bob", { type: "answer", sdp: SDP });

    const answerSide = createMesh();
    await answerSide.mesh.connectTo("bob");
    const answeredPc = FakePeerConnection.instances[1]!;
    await answerSide.mesh.handleSignal({ from: "bob", payload: { type: "answer", sdp: SDP } });
    await answerSide.mesh.handleSignal({
      from: "bob",
      payload: { type: "candidate", candidate: JSON.stringify(ICE_CANDIDATE) },
    });

    expect(answeredPc.setRemoteDescription).toHaveBeenCalledWith({ type: "answer", sdp: SDP });
    expect(answeredPc.addIceCandidate).toHaveBeenCalledWith(ICE_CANDIDATE);
  });

  it("does not call native RTC description or candidate parsers for invalid payloads", async () => {
    const { mesh } = createMesh();
    const invalidOffer = {
      from: "bob",
      payload: { type: "offer", sdp: `v=0\r\n${"x".repeat(MAX_CALL_SDP_BYTES)}` },
    } as unknown as CallSignal;

    await mesh.handleSignal(invalidOffer);
    expect(FakePeerConnection.instances).toHaveLength(0);

    await mesh.connectTo("bob");
    const pc = FakePeerConnection.instances[0]!;
    pc.setRemoteDescription.mockClear();
    pc.addIceCandidate.mockClear();

    const invalidSignals = [
      { from: "bob", payload: { type: "answer", sdp: "v=0\0\r\n" } },
      { from: "bob", payload: { type: "candidate", candidate: "not-json" } },
      {
        from: "bob",
        payload: {
          type: "candidate",
          candidate: JSON.stringify({ candidate: ICE_CANDIDATE.candidate, mid: "audio-0" }),
        },
      },
      {
        from: "bob",
        payload: {
          type: "candidate",
          candidate: JSON.stringify({ ...ICE_CANDIDATE, candidate: "not-a-candidate" }),
        },
      },
      {
        from: "bob",
        payload: {
          type: "candidate",
          candidate: JSON.stringify({
            ...ICE_CANDIDATE,
            candidate: `candidate:${"x".repeat(MAX_CALL_ICE_CANDIDATE_BYTES)}`,
          }),
        },
      },
      {
        from: "bob",
        payload: {
          type: "candidate",
          candidate: JSON.stringify({ ...ICE_CANDIDATE, unexpected: true }),
        },
      },
      {
        from: "bob",
        payload: {
          type: "candidate",
          candidate: JSON.stringify({ ...ICE_CANDIDATE, sdpMid: "m".repeat(65) }),
        },
      },
      {
        from: "bob",
        payload: {
          type: "candidate",
          candidate: JSON.stringify({ ...ICE_CANDIDATE, sdpMLineIndex: 1.5 }),
        },
      },
    ] as unknown as CallSignal[];

    for (const signal of invalidSignals) await mesh.handleSignal(signal);

    expect(pc.setRemoteDescription).not.toHaveBeenCalled();
    expect(pc.addIceCandidate).not.toHaveBeenCalled();
  });
});
