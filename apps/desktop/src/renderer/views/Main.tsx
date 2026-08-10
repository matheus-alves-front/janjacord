import { useEffect, useMemo, useRef, useState } from "react";

interface ServerState {
  serverId: string;
  serverName: string;
  config?: { networkPrivacy?: "direct" | "relay"; maxRetentionHours?: number };
  channels: { id: string; type: string; name: string }[];
  members: { identityId: string; nickname: string; roleId: string; presence: string }[];
  roles: { id: string; name: string; level: number; permissions: string[] }[];
  me: { identityId: string; nickname: string; roleId: string };
}

interface Message {
  messageId: string;
  channelId: string;
  sender: string;
  text: string;
  createdAt: number;
  self?: boolean;
  attachment?: { assetId: string; name: string; mimeType: string; dataUrl: string | null; sizeBytes: number } | null;
}

import { CallView } from "./CallView";
import { ServerSettings } from "./ServerSettings";
import type { CallSignal } from "../webrtc";

export function Main({ identity, recoveryKey }: { identity: { identityId: string; nickname: string } | null; recoveryKey: string | null }) {
  const [view, setView] = useState<"home" | "server">("home");
  const [server, setServer] = useState<ServerState | null>(null);
  const [channelId, setChannelId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Record<string, Message[]>>({});
  const [inviteKey, setInviteKey] = useState<string | null>(null);
  const [hostUrl, setHostUrl] = useState("");
  const [joinKey, setJoinKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState("");
  const [busySend, setBusySend] = useState(false);
  const [qrData, setQrData] = useState<string | null>(null);
  const [qrPayload, setQrPayload] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    window.janjacord.hostUrl().then(setHostUrl);
    window.janjacord.on("message", (data) => {
      const m = data as Message;
      setMessages((prev) => ({ ...prev, [m.channelId]: [...(prev[m.channelId] ?? []), m] }));
    });
    window.janjacord.on("member.presence", () => refreshState());
    window.janjacord.on("server.stateChanged", () => refreshState());
    window.janjacord.serverState().then((r) => {
      if (r.ok && r.data) {
        setServer(r.data as ServerState);
        setView("server");
      }
    });
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, channelId]);

  const refreshState = async () => {
    const r = await window.janjacord.serverState();
    if (r.ok && r.data) setServer(r.data as ServerState);
  };

  const createServer = async () => {
    setBusy(true);
    setError(null);
    const r = await window.janjacord.serverCreate();
    setBusy(false);
    if (r.ok && r.data) {
      setServer(r.data as ServerState);
      setView("server");
    } else {
      setError((r as { error?: { message: string } }).error?.message ?? "Falha ao criar server.");
    }
  };

  const joinServer = async () => {
    setBusy(true);
    setError(null);
    const r = await window.janjacord.serverJoin(hostUrl.trim() || `ws://127.0.0.1:8931/signal`, joinKey.trim());
    setBusy(false);
    if (r.ok && r.data) {
      setServer(r.data as ServerState);
      setView("server");
    } else {
      setError((r as { error?: { message: string } }).error?.message ?? "Falha ao entrar.");
    }
  };

  const makeInvite = async () => {
    const r = await window.janjacord.inviteCreate();
    if (r.ok && r.data) setInviteKey(r.data.inviteKey);
  };

  const send = async () => {
    if (!draft.trim() || !channelId) return;
    const text = draft.trim();
    setDraft("");
    await window.janjacord.sendMessage(channelId, text);
  };

  const attach = async (file: File) => {
    if (!channelId) return;
    setBusySend(true);
    try {
      const buf = new Uint8Array(await file.arrayBuffer());
      let binary = "";
      for (let i = 0; i < buf.length; i += 0x8000) {
        binary += String.fromCharCode(...buf.subarray(i, i + 0x8000));
      }
      const res = await window.janjacord.attachmentSend(channelId, file.name, file.type || "application/octet-stream", btoa(binary));
      if (res.ok) {
        const isImage = file.type.startsWith("image/");
        setMessages((prev) => ({
          ...prev,
          [channelId]: [
            ...(prev[channelId] ?? []),
            {
              messageId: res.data!.assetId,
              channelId,
              sender: server?.me.identityId ?? "",
              text: `📎 ${file.name}`,
              createdAt: Date.now(),
              self: true,
              attachment: isImage
                ? { assetId: res.data!.assetId, name: file.name, mimeType: file.type, dataUrl: URL.createObjectURL(file), sizeBytes: file.size }
                : { assetId: res.data!.assetId, name: file.name, mimeType: file.type, dataUrl: null, sizeBytes: file.size },
            },
          ],
        }));
      }
    } finally {
      setBusySend(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const activeChannel = useMemo(() => server?.channels.find((c) => c.id === channelId) ?? null, [server, channelId]);

  if (view === "home") {
    return (
      <div className="w-[420px] rounded-xl border border-zinc-800 bg-zinc-900/60 p-8">
        <h1 className="text-xl font-semibold text-white">Servers</h1>
        <p className="mt-1 text-sm text-zinc-400">Crie um server ou entre com uma chave de convite.</p>
        {recoveryKey && (
          <div className="mt-4 rounded-md border border-amber-700/40 bg-amber-950/40 p-3">
            <p className="text-[11px] font-medium text-amber-300">Sua chave de recuperação (anote!)</p>
            <p className="mt-1 font-mono text-xs break-all text-amber-100">{recoveryKey}</p>
          </div>
        )}
        <div className="mt-6 space-y-4">
          <button
            className="w-full rounded-md bg-indigo-600 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
            onClick={createServer}
            disabled={busy}
          >
            {busy ? "Criando…" : "Criar server (self-hosted)"}
          </button>
          <button
            className="w-full rounded-md border border-zinc-700 py-2 text-sm text-zinc-300 hover:bg-zinc-800"
            onClick={async () => {
              const r = await window.janjacord.linkingCreate();
              if (r.ok && r.data) {
                setQrPayload(r.data.payload);
                const QRCode = (await import("qrcode")).default;
                const url = await QRCode.toDataURL(r.data.payload, { width: 220, margin: 1, color: { dark: "#e6e8eb", light: "#0b0d10" } });
                setQrData(url);
              }
            }}
          >
            + Vincular dispositivo (QR)
          </button>
          {qrData && (
            <div className="flex flex-col items-center gap-2 rounded-md border border-zinc-800 bg-zinc-950 p-3">
              <img src={qrData} alt="QR de vinculação" className="h-44 w-44" />
              <p className="text-center text-[11px] text-zinc-500">
                Abra o JanjaCord no celular → “Vincular identidade existente” → escaneie.
                <br />
                Válido por 5 minutos. O seed nunca sai deste dispositivo.
              </p>
            </div>
          )}
          <div className="space-y-2 border-t border-zinc-800 pt-4">
            <input
              className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-indigo-500"
              placeholder={`Host (padrão: ${hostUrl || "ws://127.0.0.1:8931/signal"})`}
              value={hostUrl}
              onChange={(e) => setHostUrl(e.target.value)}
            />
            <input
              className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-indigo-500"
              placeholder="Invite key (JC1-…)"
              value={joinKey}
              onChange={(e) => setJoinKey(e.target.value)}
            />
            <button
              className="w-full rounded-md border border-zinc-600 py-2 text-sm text-zinc-200 hover:bg-zinc-800 disabled:opacity-50"
              onClick={joinServer}
              disabled={busy}
            >
              Entrar com convite
            </button>
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>
      </div>
    );
  }

  // view === server
  return (
    <div className="flex h-full w-full">
      {/* rail de servers */}
      <div className="flex w-14 flex-col items-center gap-2 border-r border-zinc-800 bg-zinc-950 py-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-indigo-600 text-xs font-bold text-white" title={server?.serverName ?? "server"}>
          {server?.serverName?.[0]?.toUpperCase() ?? "S"}
        </div>
        <button
          className="flex h-10 w-10 items-center justify-center rounded-2xl border border-zinc-700 text-zinc-400 hover:bg-zinc-800"
          title="Voltar"
          onClick={() => setView("home")}
        >
          ←
        </button>
      </div>
      {/* canais */}
      <div className="flex w-56 flex-col border-r border-zinc-800 bg-zinc-900/40">
        <div className="border-b border-zinc-800 px-4 py-3">
          <div className="flex items-center justify-between">
            <button className="text-sm font-semibold text-white hover:text-zinc-300" onClick={() => setShowSettings(true)} title="Configurações do server">
              {server?.serverName} ⚙
            </button>
            <button className="text-xs text-zinc-500 hover:text-zinc-300" onClick={makeInvite} title="Criar convite">
              + invite
            </button>
          </div>
          {inviteKey && (
            <div className="mt-2 rounded bg-zinc-950 p-2">
              <p className="text-[10px] text-zinc-500">Convite (1 uso)</p>
              <p className="font-mono text-[11px] break-all text-emerald-300">{inviteKey}</p>
            </div>
          )}
        </div>
        <div className="flex-1 overflow-y-auto p-2">
          {server?.channels.map((c) => (
            <button
              key={c.id}
              className={`mb-1 flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-left text-sm ${
                channelId === c.id ? "bg-zinc-800 text-white" : "text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-200"
              }`}
              onClick={() => setChannelId(c.id)}
            >
              <span>{c.type === "text" ? "#" : "🔊"}</span>
              <span className="truncate">{c.name}</span>
            </button>
          ))}
        </div>
        <div className="border-t border-zinc-800 p-3">
          <p className="text-[11px] text-zinc-500">Membros ({server?.members.length ?? 0})</p>
          <div className="mt-1 space-y-0.5">
            {server?.members.map((m) => (
              <p key={m.identityId} className="truncate text-[11px] text-zinc-400">
                <span className={`mr-1 inline-block h-1.5 w-1.5 rounded-full ${m.presence === "online" ? "bg-emerald-500" : "bg-zinc-700"}`} />
                {m.nickname}
              </p>
            ))}
          </div>
        </div>
      </div>
      {showSettings && server && (
        <ServerSettings
          server={server}
          onClose={() => {
            setShowSettings(false);
            refreshState();
          }}
        />
      )}
      {/* conversa */}
      <div className="flex flex-1 flex-col bg-zinc-950">
        <div className="border-b border-zinc-800 px-4 py-3">
          <h3 className="text-sm font-medium text-white">
            {activeChannel ? (activeChannel.type === "text" ? "# " : "🔊 ") + activeChannel.name : "Conversa"}
          </h3>
        </div>
        <div className="flex-1 overflow-y-auto p-4">
          {channelId && (messages[channelId] ?? []).map((m) => (
            <div key={m.messageId} className="mb-3">
              <p className="text-xs">
                <span className={`font-medium ${m.self ? "text-indigo-400" : "text-zinc-300"}`}>
                  {m.self ? "você" : m.sender.slice(0, 8)}
                </span>
                <span className="ml-2 text-[10px] text-zinc-600">
                  {new Date(m.createdAt).toLocaleTimeString()}
                </span>
              </p>
              <p className="mt-0.5 text-sm text-zinc-200">{m.text}</p>
              {m.attachment?.dataUrl && (
                <img src={m.attachment.dataUrl} alt={m.attachment.name} className="mt-1 max-h-64 rounded-md border border-zinc-800" />
              )}
              {m.attachment && !m.attachment.dataUrl && (
                <button
                  className="mt-1 rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-300 hover:bg-zinc-800"
                  onClick={() => window.janjacord.attachmentSave(m.attachment!.assetId, m.attachment!.name)}
                >
                  ⬇ {m.attachment.name} ({Math.round(m.attachment.sizeBytes / 1024)} KB)
                </button>
              )}
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
        {activeChannel?.type === "call" && (
          <CallView
            channelId={activeChannel.id}
            members={server?.members ?? []}
            selfId={server?.me.identityId ?? ""}
            networkPrivacy={server?.config?.networkPrivacy ?? "direct"}
            callJoin={(cid) => window.janjacord.callJoin(cid)}
            callLeave={(cid) => window.janjacord.callLeave(cid)}
            callSignal={(cid, to, payload) => window.janjacord.callSignal(cid, to, payload)}
            onSignal={(cb) => window.janjacord.on("call.signal", (d) => cb(d as CallSignal))}
          />
        )}
        {activeChannel?.type === "text" && (
          <div className="border-t border-zinc-800 p-3">
            <div className="flex gap-2">
              <input
                ref={fileRef}
                type="file"
                className="hidden"
                onChange={(e) => e.target.files?.[0] && attach(e.target.files[0])}
              />
              <button
                className="rounded-md border border-zinc-700 px-3 text-zinc-300 hover:bg-zinc-800"
                onClick={() => fileRef.current?.click()}
                title="Anexar arquivo"
              >
                📎
              </button>
              <input
                className="flex-1 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm outline-none focus:border-indigo-500"
                placeholder="Mensagem (efêmera — some após todos lerem)"
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && !busySend && send()}
              />
              <button
                className="rounded-md bg-indigo-600 px-4 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
                onClick={send}
                disabled={busySend}
              >
                Enviar
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
