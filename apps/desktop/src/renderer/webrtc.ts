/**
 * MeshCall — WebRTC mesh P2P (ADR-006) no renderer (Chromium nativo).
 * Signaling via host (relé SDP/candidates; conteúdo E2EE por DTLS).
 * Guardrails: maxVoiceParticipants (host) — aqui apenas gestão de peers.
 */
export interface CallSignal {
  from: string;
  payload: { type: "offer" | "answer" | "candidate"; sdp?: string; candidate?: string };
}

export interface MeshCallOptions {
  selfId: string;
  iceServers?: RTCIceServer[];
  /** Policy de rede do server (ADR-007): 'relay' nunca expõe rota direta. */
  networkPrivacy?: "direct" | "relay";
  /** Envia signaling ao host (main → janjanode). */
  sendSignal: (to: string, payload: CallSignal["payload"]) => void;
  onRemoteStream: (peerId: string, stream: MediaStream) => void;
  onPeerLeft: (peerId: string) => void;
}

const DEFAULT_ICE: RTCIceServer[] = [{ urls: "stun:stun.l.google.com:19302" }];

export class MeshCall {
  private peers = new Map<string, RTCPeerConnection>();
  private streams = new Map<string, MediaStream>();
  private readonly opts: MeshCallOptions;
  localStream: MediaStream | null = null;

  constructor(opts: MeshCallOptions) {
    this.opts = { iceServers: DEFAULT_ICE, ...opts };
  }

  private makePc(): RTCPeerConnection {
    const relayOnly = this.opts.networkPrivacy === "relay";
    const pc = new RTCPeerConnection({
      iceServers: this.opts.iceServers,
      iceTransportPolicy: relayOnly ? "relay" : "all", // ADR-007: relay-only não emite host/srflx
    });
    pc.onicecandidate = (e) => {
      if (e.candidate) this.opts.sendSignal(this.currentPeer(pc)!, { type: "candidate", candidate: JSON.stringify(e.candidate) });
    };
    pc.ontrack = (e) => {
      const peerId = this.currentPeer(pc);
      if (!peerId) return;
      const stream = e.streams[0] ?? new MediaStream([e.track]);
      this.streams.set(peerId, stream);
      this.opts.onRemoteStream(peerId, stream);
    };
    return pc;
  }

  private peerIds = new Map<RTCPeerConnection, string>();
  private currentPeer(pc: RTCPeerConnection): string | undefined {
    return this.peerIds.get(pc);
  }

  async startLocalStream(video: boolean): Promise<MediaStream> {
    this.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video });
    return this.localStream;
  }

  setVideoEnabled(video: boolean): void {
    this.localStream?.getVideoTracks().forEach((t) => (t.enabled = video));
  }

  setMicEnabled(audio: boolean): void {
    this.localStream?.getAudioTracks().forEach((t) => (t.enabled = audio));
  }

  /** Cria PC com um peer e envia offer (o chamador faz offer). */
  async connectTo(peerId: string): Promise<void> {
    if (this.peers.has(peerId)) return;
    const pc = this.makePc();
    this.peers.set(peerId, pc);
    this.peerIds.set(pc, peerId);
    for (const track of this.localStream?.getTracks() ?? []) pc.addTrack(track, this.localStream!);
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    this.opts.sendSignal(peerId, { type: "offer", sdp: offer.sdp });
  }

  /** Processa signaling recebido do peer (offer/answer/candidate). */
  async handleSignal(signal: CallSignal): Promise<void> {
    const { from, payload } = signal;
    if (payload.type === "offer") {
      let pc = this.peers.get(from);
      if (!pc) {
        pc = this.makePc();
        this.peers.set(from, pc);
        this.peerIds.set(pc, from);
        for (const track of this.localStream?.getTracks() ?? []) pc.addTrack(track, this.localStream!);
      }
      await pc.setRemoteDescription({ type: "offer", sdp: payload.sdp });
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      this.opts.sendSignal(from, { type: "answer", sdp: answer.sdp });
    } else if (payload.type === "answer") {
      const pc = this.peers.get(from);
      if (pc && pc.signalingState !== "stable") {
        await pc.setRemoteDescription({ type: "answer", sdp: payload.sdp });
      }
    } else if (payload.type === "candidate") {
      const pc = this.peers.get(from);
      if (pc) {
        try {
          await pc.addIceCandidate(JSON.parse(payload.candidate!));
        } catch {
          // candidato obsoleto — ignora
        }
      }
    }
  }

  leave(peerId: string): void {
    const pc = this.peers.get(peerId);
    if (pc) {
      pc.close();
      this.peers.delete(peerId);
      this.peerIds.delete(pc);
      this.streams.delete(peerId);
      this.opts.onPeerLeft(peerId);
    }
  }

  close(): void {
    for (const pc of this.peers.values()) pc.close();
    this.peers.clear();
    this.peerIds.clear();
    this.streams.clear();
    this.localStream?.getTracks().forEach((t) => t.stop());
    this.localStream = null;
  }

  remoteStream(peerId: string): MediaStream | null {
    return this.streams.get(peerId) ?? null;
  }

  peerList(): string[] {
    return [...this.peers.keys()];
  }
}
