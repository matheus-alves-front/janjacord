import { useEffect, useRef, useState } from "react";
import { LoaderCircle, RefreshCw } from "lucide-react";
import { MeshCall, type CallSignal } from "../webrtc";

interface CallViewProps {
  channelId: string;
  members: { identityId: string; nickname: string }[];
  selfId: string;
  networkPrivacy?: "direct" | "relay";
  iceServers?: RTCIceServer[];
  connectionError?: string | null;
  onRetryConnection?: () => Promise<void> | void;
  /** IPC exposto via preload — call signaling. */
  callJoin: (channelId: string) => Promise<{ ok: boolean; data?: { participants: string[] }; error?: { message: string } }>;
  callLeave: (channelId: string) => Promise<unknown>;
  callSignal: (channelId: string, to: string, payload: unknown) => Promise<unknown>;
  onSignal: (cb: (signal: CallSignal) => void) => void;
}

export function CallView({ channelId, members, selfId, networkPrivacy, iceServers, connectionError, onRetryConnection, callJoin, callLeave, callSignal, onSignal }: CallViewProps) {
  const meshRef = useRef<MeshCall | null>(null);
  const [remoteStreams, setRemoteStreams] = useState<Map<string, MediaStream>>(new Map());
  const [peers, setPeers] = useState<string[]>([]);
  const [micOn, setMicOn] = useState(true);
  const [camOn, setCamOn] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [loading, setLoading] = useState(true);
  const [retryKey, setRetryKey] = useState(0);

  const others = members.filter((m) => m.identityId !== selfId);

  useEffect(() => {
    let cancelled = false;
    const mesh = new MeshCall({
      selfId,
      networkPrivacy: networkPrivacy,
      iceServers,
      sendSignal: (to, payload) => callSignal(channelId, to, payload),
      onRemoteStream: (peerId, stream) => {
        setRemoteStreams((prev) => new Map(prev).set(peerId, stream));
        setPeers((prev) => (prev.includes(peerId) ? prev : [...prev, peerId]));
      },
      onPeerLeft: (peerId) => {
        setRemoteStreams((prev) => {
          const next = new Map(prev);
          next.delete(peerId);
          return next;
        });
        setPeers((prev) => prev.filter((p) => p !== peerId));
      },
    });
    meshRef.current = mesh;

    onSignal((signal) => {
      mesh.handleSignal(signal).catch(() => {
        if (!cancelled) setError("A conexão com outro participante foi interrompida.");
      });
    });

    const boot = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await callJoin(channelId);
        if (!res.ok) {
          setError(res.error?.message ?? "Não foi possível entrar na call.");
          return;
        }
        const participants = res.data?.participants ?? [];
        const stream = await mesh.startLocalStream(true);
        if (cancelled) return;
        setLocalStream(stream);
        // mesh: connecta com todos os participantes existentes (o último a entrar faz offer)
        for (const p of participants) {
          if (p !== selfId) await mesh.connectTo(p);
        }
      } catch (e) {
        if (!cancelled) setError(`Permissão de microfone/câmera negada: ${(e as Error).message}`);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    boot();

    return () => {
      cancelled = true;
      mesh.close();
      callLeave(channelId);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [channelId, iceServers, retryKey]);

  const videoRef = (stream: MediaStream | null) => (el: HTMLVideoElement | null) => {
    if (el && stream) el.srcObject = stream;
  };

  return (
    <div className="flex flex-1 flex-col bg-zinc-950">
      <div className="grid flex-1 auto-rows-fr gap-3 overflow-y-auto p-4" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}>
        {loading && (
          <div className="flex min-h-40 items-center justify-center gap-2 text-sm text-zinc-300" role="status">
            <LoaderCircle className="h-4 w-4 animate-spin text-sky-400" aria-hidden />
            Entrando na chamada...
          </div>
        )}
        {/* local preview */}
        <div className="relative overflow-hidden rounded-lg border border-zinc-800 bg-zinc-900">
          <video ref={videoRef(localStream)} autoPlay muted playsInline className="h-full w-full object-cover" />
          <span className="absolute bottom-2 left-2 rounded bg-black/60 px-2 py-0.5 text-[11px] text-white">
            você {micOn ? "🎙" : "🔇"} {camOn ? "" : "🚫"}
          </span>
        </div>
        {/* remotos */}
        {peers.map((p) => (
          <div key={p} className="relative overflow-hidden rounded-lg border border-zinc-800 bg-zinc-900">
            {remoteStreams.get(p) ? (
              <video ref={videoRef(remoteStreams.get(p)!)} autoPlay playsInline className="h-full w-full object-cover" />
            ) : (
              <div className="flex h-full items-center justify-center text-zinc-400">
                {members.find((m) => m.identityId === p)?.nickname ?? p.slice(0, 8)}
              </div>
            )}
            <span className="absolute bottom-2 left-2 rounded bg-black/60 px-2 py-0.5 text-[11px] text-white">
              {members.find((m) => m.identityId === p)?.nickname ?? p.slice(0, 8)}
            </span>
          </div>
        ))}
        {peers.length === 0 && others.length === 0 && (
          <div className="flex items-center justify-center text-zinc-400">Você é o primeiro na call.</div>
        )}
      </div>
      {(error || connectionError) && (
        <div className="flex items-center justify-between gap-3 px-4 pb-2" role="alert">
          <p className="text-xs text-red-400">{error ?? connectionError}</p>
          <button
            className="flex shrink-0 items-center gap-1 text-xs text-zinc-300 hover:text-white"
            onClick={async () => {
              await onRetryConnection?.();
              setRetryKey((value) => value + 1);
            }}
          >
            <RefreshCw className="h-3.5 w-3.5" aria-hidden />
            Tentar novamente
          </button>
        </div>
      )}
      <div className="flex items-center justify-center gap-3 border-t border-zinc-800 p-3">
        <button
          className={`h-11 w-11 rounded-full text-lg ${micOn ? "bg-zinc-800 hover:bg-zinc-700" : "bg-red-600 hover:bg-red-500"}`}
          onClick={() => {
            const next = !micOn;
            setMicOn(next);
            meshRef.current?.setMicEnabled(next);
          }}
          title="Microfone"
        >
          {micOn ? "🎙" : "🔇"}
        </button>
        <button
          className={`h-11 w-11 rounded-full text-lg ${camOn ? "bg-zinc-800 hover:bg-zinc-700" : "bg-zinc-600"}`}
          onClick={() => {
            const next = !camOn;
            setCamOn(next);
            meshRef.current?.setVideoEnabled(next);
          }}
          title="Câmera"
        >
          🎥
        </button>
        <button
          className="h-11 rounded-full bg-red-600 px-5 text-sm font-medium text-white hover:bg-red-500"
          onClick={() => meshRef.current?.localStream?.getAudioTracks().forEach((t) => (t.enabled = false))}
          title="Sair"
        >
          Sair
        </button>
      </div>
    </div>
  );
}
