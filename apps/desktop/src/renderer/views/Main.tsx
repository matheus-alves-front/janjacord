import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowRight, BookOpen, Check, ChevronDown, Copy, Hash, Home, Link2, LoaderCircle, Plus, RefreshCw, Server as ServerIcon, Settings, ShieldCheck, TriangleAlert, UserPlus, Users, Volume2, Wifi, X } from "lucide-react";

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
import { BridgePairingDialog } from "./BridgePairingDialog";
import { JanjaBridgeTutorial } from "./JanjaBridgeTutorial";
import { ServerSettings } from "./ServerSettings";
import { SetupProgress, type SetupStepId, type SetupStepState, type SetupStepStatus } from "./SetupProgress";
import type { CommunitySummary, ConnectivityRoute } from "../App";
import type { CallSignal } from "../webrtc";
import { friendlyIpcError, legacyFingerprint, rejectedIpcError, type IpcError } from "../ipcErrors";
import { attachmentSizeIsAllowed, encodeAttachmentBytes } from "../attachmentEncoding";

type ActiveAction = "create" | "join" | "invite" | null;
type LoadState = "loading" | "ready" | "error";
type InviteCopyState = "idle" | "copied" | "error";
type QuickChannelType = "text" | "call";

export function restoreConsumedInviteFocus({
  pending,
  inviteKey,
  view,
  settingsOpen,
  button,
}: {
  pending: boolean;
  inviteKey: string | null;
  view: "home" | "server";
  settingsOpen: boolean;
  button: Pick<HTMLButtonElement, "focus"> | null;
}): boolean {
  if (!pending || inviteKey || view !== "server" || settingsOpen || !button) return false;
  button.focus({ preventScroll: true });
  return true;
}

const INITIAL_SETUP_STEPS: SetupStepId[] = ["host", "direct", "bridge", "access"];
const MAX_INLINE_IMAGE_BYTES = 8 * 1024 * 1024;
const MAX_INLINE_IMAGE_PREVIEWS = 12;
const MAX_MESSAGES_PER_CHANNEL = 100;
const MAX_RETAINED_MESSAGES = 500;

function objectUrlFromDataUrl(dataUrl: string, mimeType: string): string | null {
  const separator = dataUrl.indexOf(",");
  if (separator < 0 || !dataUrl.slice(0, separator).includes(";base64")) return null;
  try {
    const decoded = atob(dataUrl.slice(separator + 1));
    const bytes = new Uint8Array(decoded.length);
    for (let index = 0; index < decoded.length; index += 1) bytes[index] = decoded.charCodeAt(index);
    return URL.createObjectURL(new Blob([bytes], { type: mimeType }));
  } catch {
    return null;
  }
}

export function Main({ identity, recoveryKey }: { identity: { identityId: string; nickname: string } | null; recoveryKey: string | null }) {
  const [view, setView] = useState<"home" | "server">("home");
  const [server, setServer] = useState<ServerState | null>(null);
  const [communities, setCommunities] = useState<CommunitySummary[]>([]);
  const [communityState, setCommunityState] = useState<LoadState>("loading");
  const [communityError, setCommunityError] = useState<string | null>(null);
  const [communityAction, setCommunityAction] = useState<string | null>(null);
  const [channelId, setChannelId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Record<string, Message[]>>({});
  const [inviteKey, setInviteKey] = useState<string | null>(null);
  const [hostUrl, setHostUrl] = useState("");
  const [joinKey, setJoinKey] = useState("");
  const [communityName, setCommunityName] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [joinError, setJoinError] = useState<string | null>(null);
  const [activeAction, setActiveAction] = useState<ActiveAction>(null);
  const [bootState, setBootState] = useState<LoadState>("loading");
  const [bootError, setBootError] = useState<string | null>(null);
  const [connectivityState, setConnectivityState] = useState<LoadState>("loading");
  const [connectivityError, setConnectivityError] = useState<string | null>(null);
  const [iceError, setIceError] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [busySend, setBusySend] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showAdvancedJoin, setShowAdvancedJoin] = useState(false);
  const [showBridgePairing, setShowBridgePairing] = useState(false);
  const [showBridgeTutorial, setShowBridgeTutorial] = useState(false);
  const [showSetupChecklist, setShowSetupChecklist] = useState(false);
  const [showQuickCreate, setShowQuickCreate] = useState(false);
  const [quickChannelName, setQuickChannelName] = useState("");
  const [quickChannelType, setQuickChannelType] = useState<QuickChannelType>("text");
  const [quickChannelBusy, setQuickChannelBusy] = useState(false);
  const [quickChannelError, setQuickChannelError] = useState<string | null>(null);
  const [setupSteps, setSetupSteps] = useState<SetupStepState[]>([]);
  const [setupFocusRequest, setSetupFocusRequest] = useState(0);
  const [pendingServer, setPendingServer] = useState<ServerState | null>(null);
  const [bridgeCount, setBridgeCount] = useState<number | null>(null);
  const [activeRoute, setActiveRoute] = useState<ConnectivityRoute | null>(null);
  const [settingsInitialTab, setSettingsInitialTab] = useState<"members" | "connectivity">("members");
  const [legacyChallenge, setLegacyChallenge] = useState<{ invite: string; fingerprint: string } | null>(null);
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [inviteNotice, setInviteNotice] = useState<string | null>(null);
  const [inviteCopyState, setInviteCopyState] = useState<InviteCopyState>("idle");
  const [inviteFocusPending, setInviteFocusPending] = useState(false);
  const [messageError, setMessageError] = useState<string | null>(null);
  const [callIceServers, setCallIceServers] = useState<RTCIceServer[]>([]);
  const fileRef = useRef<HTMLInputElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const setupRegionRef = useRef<HTMLDivElement>(null);
  const addBridgeRef = useRef<HTMLButtonElement>(null);
  const inviteButtonRef = useRef<HTMLButtonElement>(null);
  const inviteIdRef = useRef<string | null>(null);
  const subscribedRef = useRef(false);
  const objectUrlsRef = useRef(new Set<string>());

  const releaseObjectUrl = (url: string | null | undefined) => {
    if (!url?.startsWith("blob:") || !objectUrlsRef.current.delete(url)) return;
    URL.revokeObjectURL(url);
  };

  const retainMessageState = (candidate: Record<string, Message[]>) => {
    const next: Record<string, Message[]> = {};
    for (const [candidateChannelId, channelMessages] of Object.entries(candidate)) {
      const retained = channelMessages.slice(-MAX_MESSAGES_PER_CHANNEL);
      channelMessages.slice(0, -MAX_MESSAGES_PER_CHANNEL).forEach((message) => releaseObjectUrl(message.attachment?.dataUrl));
      next[candidateChannelId] = retained;
    }

    let total = Object.values(next).reduce((count, channelMessages) => count + channelMessages.length, 0);
    while (total > MAX_RETAINED_MESSAGES) {
      const oldestChannel = Object.entries(next)
        .filter(([, channelMessages]) => channelMessages.length > 0)
        .sort(([, left], [, right]) => left[0]!.createdAt - right[0]!.createdAt)[0]?.[0];
      if (!oldestChannel) break;
      const [removed, ...remaining] = next[oldestChannel]!;
      releaseObjectUrl(removed?.attachment?.dataUrl);
      next[oldestChannel] = remaining;
      total -= 1;
    }

    const previews = Object.entries(next)
      .flatMap(([candidateChannelId, channelMessages]) => channelMessages.map((message, index) => ({ candidateChannelId, index, message })))
      .filter(({ message }) => Boolean(message.attachment?.dataUrl))
      .sort((left, right) => right.message.createdAt - left.message.createdAt);
    for (const preview of previews.slice(MAX_INLINE_IMAGE_PREVIEWS)) {
      const channelMessages = next[preview.candidateChannelId]!;
      const message = channelMessages[preview.index]!;
      releaseObjectUrl(message.attachment?.dataUrl);
      next[preview.candidateChannelId] = channelMessages.map((item, index) => index === preview.index
        ? { ...item, attachment: item.attachment ? { ...item.attachment, dataUrl: null } : null }
        : item);
    }
    return next;
  };

  const prepareIncomingMessage = (incoming: Message) => {
    let message = incoming;
    const dataUrl = message.attachment?.dataUrl;
    if (dataUrl?.startsWith("data:")) {
      const objectUrl = message.attachment!.sizeBytes <= MAX_INLINE_IMAGE_BYTES
        ? objectUrlFromDataUrl(dataUrl, message.attachment!.mimeType)
        : null;
      if (objectUrl) objectUrlsRef.current.add(objectUrl);
      message = { ...message, attachment: { ...message.attachment!, dataUrl: objectUrl } };
    }
    return message;
  };

  const appendCanonicalMessage = (incoming: Message) => {
    const message = prepareIncomingMessage(incoming);
    setMessages((current) => {
      const channelMessages = current[message.channelId] ?? [];
      const existingIndex = channelMessages.findIndex((item) => item.messageId === message.messageId);
      const updatedChannel = existingIndex >= 0
        ? channelMessages.map((item, index) => {
          if (index !== existingIndex) return item;
          const attachment = message.attachment ?? item.attachment;
          if (item.attachment?.dataUrl && item.attachment.dataUrl !== attachment?.dataUrl) {
            releaseObjectUrl(item.attachment.dataUrl);
          }
          return { ...item, ...message, attachment };
        })
        : [...channelMessages, message];
      return retainMessageState({ ...current, [message.channelId]: updatedChannel });
    });
  };

  useEffect(() => {
    if (subscribedRef.current) return;
    subscribedRef.current = true;
    window.janjacord.on("message", (data) => {
      appendCanonicalMessage(data as Message);
    });
    window.janjacord.on("delivery.error", (data) => {
      const event = data as { message?: string };
      setMessageError(event.message ?? "Não foi possível validar uma mensagem recebida.");
    });
    window.janjacord.on("member.presence", () => refreshState());
    window.janjacord.on("invite.used", (data) => {
      const event = data as { inviteId?: string };
      if (!event.inviteId || event.inviteId !== inviteIdRef.current) return;
      inviteIdRef.current = null;
      setInviteKey((current) => {
        if (current) void window.janjacord.clipboardClearIfEquals(current).catch(() => undefined);
        return null;
      });
      setInviteCopyState("idle");
      setInviteNotice("Convite utilizado. Crie outro para convidar mais alguém.");
      setInviteFocusPending(true);
    });
    window.janjacord.on("server.stateChanged", () => {
      void refreshState();
      void loadCommunities();
    });
    window.janjacord.on("connectivity.setup", (data) => {
      const event = data as { step: SetupStepId; status: SetupStepStatus; detail?: string };
      const visibleEvent = event.status === "error"
        ? { ...event, detail: "Não foi possível concluir esta etapa." }
        : event;
      setSetupSteps((current) => {
        const exists = current.some((item) => item.step === visibleEvent.step);
        return exists
          ? current.map((item) => item.step === visibleEvent.step ? { ...item, ...visibleEvent } : item)
          : [...current, visibleEvent];
      });
    });
    window.janjacord.on("connectivity.iceConfig", (data) => {
      const configuration = data as { iceServers?: RTCIceServer[] };
      if (configuration.iceServers) {
        setCallIceServers(configuration.iceServers);
        setIceError(null);
      }
    });
    void loadBootState();
    void loadConnectivity();
    void loadIceConfiguration();
    // Event subscriptions are owned by the preload for the app lifetime.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => () => {
    objectUrlsRef.current.forEach((url) => URL.revokeObjectURL(url));
    objectUrlsRef.current.clear();
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, channelId]);

  useEffect(() => {
    const restored = restoreConsumedInviteFocus({
      pending: inviteFocusPending,
      inviteKey,
      view,
      settingsOpen: showSettings,
      button: inviteButtonRef.current,
    });
    if (restored) setInviteFocusPending(false);
  }, [inviteFocusPending, inviteKey, showSettings, view]);

  useEffect(() => {
    if (setupFocusRequest === 0) return;
    const frame = requestAnimationFrame(() => {
      setupRegionRef.current?.scrollIntoView({ block: "start" });
      setupRegionRef.current?.focus({ preventScroll: true });
    });
    return () => cancelAnimationFrame(frame);
  }, [setupFocusRequest]);

  useEffect(() => {
    if (!pendingServer) return;
    requestAnimationFrame(() => {
      addBridgeRef.current?.scrollIntoView({ block: "nearest" });
      addBridgeRef.current?.focus({ preventScroll: true });
    });
  }, [pendingServer]);

  useEffect(() => {
    if (!server) return;
    void loadIceConfiguration();
    void loadConnectivity();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [server?.serverId, communities]);

  const activateServer = (next: ServerState, open = true) => {
    setServer(next);
    setChannelId((current) => {
      if (current && next.channels.some((channel) => channel.id === current)) return current;
      return next.channels.find((channel) => channel.type === "text")?.id ?? next.channels[0]?.id ?? null;
    });
    if (open) {
      setPendingServer(null);
      setSetupSteps([]);
      setView("server");
    }
  };

  const loadCommunities = async () => {
    setCommunityState("loading");
    setCommunityError(null);
    try {
      const result = await window.janjacord.communityList();
      if (!result.ok || !result.data) {
        setCommunityState("error");
        setCommunityError(friendlyIpcError(result.error, "Não foi possível carregar suas comunidades."));
        return;
      }
      setCommunities(result.data);
      setCommunityState("ready");
    } catch (error) {
      setCommunityState("error");
      setCommunityError(rejectedIpcError(error, "Não foi possível carregar suas comunidades."));
    }
  };

  const activateCommunity = async (community: CommunitySummary) => {
    setCommunityAction(community.serverId);
    setCommunityError(null);
    try {
      const result = await window.janjacord.communityActivate(community.serverId);
      if (!result.ok || !result.data) {
        setCommunityError(friendlyIpcError(result.error, "Não foi possível abrir esta comunidade."));
        return;
      }
      activateServer(result.data as ServerState);
      await loadCommunities();
    } catch (error) {
      setCommunityError(rejectedIpcError(error, "Não foi possível abrir esta comunidade."));
    } finally {
      setCommunityAction(null);
    }
  };

  const loadBootState = async () => {
    setBootState("loading");
    setBootError(null);
    try {
      const [result] = await Promise.all([
        window.janjacord.serverState(),
        loadCommunities(),
      ]);
      if (!result.ok) {
        setBootError(friendlyIpcError(result.error, "Não foi possível recuperar a comunidade atual."));
        setBootState("error");
        return;
      }
      if (result.data) activateServer(result.data as ServerState);
      setBootState("ready");
    } catch (error) {
      setBootError(rejectedIpcError(error, "Não foi possível recuperar a comunidade atual."));
      setBootState("error");
    }
  };

  const loadConnectivity = async () => {
    const activeCommunity = server ? communities.find((community) => community.serverId === server.serverId) : null;
    if (activeCommunity?.connectionKind === "remote") {
      setBridgeCount(null);
      setActiveRoute(null);
      setConnectivityError(null);
      setConnectivityState("ready");
      return;
    }
    setConnectivityState("loading");
    setConnectivityError(null);
    try {
      const result = await window.janjacord.connectivityStatus();
      if (!result.ok || !result.data) {
        setBridgeCount(null);
        setConnectivityError(friendlyIpcError(result.error, "Não foi possível verificar os JanjaBridges configurados."));
        setConnectivityState("error");
        return;
      }
      setBridgeCount(result.data.bridges.length);
      setActiveRoute(result.data.activeRoute ?? null);
      setConnectivityState("ready");
    } catch (error) {
      setBridgeCount(null);
      setConnectivityError(rejectedIpcError(error, "Não foi possível verificar os JanjaBridges configurados."));
      setConnectivityState("error");
    }
  };

  const loadIceConfiguration = async () => {
    try {
      const result = await window.janjacord.iceConfiguration();
      if (!result.ok || !result.data) {
        setCallIceServers([]);
        setIceError(friendlyIpcError(result.error, "Não foi possível obter as rotas de chamada disponíveis."));
        return;
      }
      setCallIceServers(result.data.iceServers);
      setIceError(null);
    } catch (error) {
      setCallIceServers([]);
      setIceError(rejectedIpcError(error, "Não foi possível obter as rotas de chamada disponíveis."));
    }
  };

  const refreshState = async (preferredChannelName?: string) => {
    try {
      const result = await window.janjacord.serverState();
      if (result.ok && result.data) {
        const next = result.data as ServerState;
        activateServer(next, false);
        if (preferredChannelName) {
          const preferred = next.channels.find((channel) => channel.name === preferredChannelName);
          if (preferred) setChannelId(preferred.id);
        }
      }
    } catch {
      // Keep the last known server visible; event refresh is best-effort.
    }
  };

  const createServer = async () => {
    if (communities.some((community) => community.connectionKind === "primary")) {
      setCreateError("Este dispositivo já hospeda uma comunidade local. Entre em outra comunidade usando um convite.");
      return;
    }
    setActiveAction("create");
    setCreateError(null);
    setPendingServer(null);
    setSetupSteps(INITIAL_SETUP_STEPS.map((step) => ({ step, status: "pending" })));
    setSetupFocusRequest((request) => request + 1);
    try {
      const result = await window.janjacord.serverCreate(communityName.trim());
      if (result.ok && result.data) {
        const created = result.data as ServerState;
        setCommunityName("");
        void loadCommunities();
        setSetupSteps((steps) => steps.map((item) => item.status === "running" ? { ...item, status: "done" } : item));
        if (result.connectivity?.needsBridge) setPendingServer(created);
        else {
          activateServer(created);
          setShowSetupChecklist(true);
        }
      } else {
        setCreateError(friendlyIpcError(result.error, "Não foi possível criar a comunidade."));
        settleSetupFailure(result.error);
      }
    } catch (error) {
      setCreateError(rejectedIpcError(error, "Não foi possível criar a comunidade."));
      settleSetupFailure(error as IpcError);
    } finally {
      setActiveAction(null);
    }
  };

  const createQuickChannel = async () => {
    const name = quickChannelName.trim();
    if (!name || quickChannelBusy) return;
    setQuickChannelBusy(true);
    setQuickChannelError(null);
    try {
      const result = await window.janjacord.channelCreate(quickChannelType, name);
      if (!result.ok) {
        setQuickChannelError(friendlyIpcError(result.error, "Não foi possível criar o canal."));
        return;
      }
      setQuickChannelName("");
      setShowQuickCreate(false);
      await refreshState(name);
    } catch (error) {
      setQuickChannelError(rejectedIpcError(error, "Não foi possível criar o canal."));
    } finally {
      setQuickChannelBusy(false);
    }
  };

  const settleSetupFailure = (error?: IpcError) => {
    setSetupSteps((steps) => {
      const hasKnownFailure = steps.some((item) => item.status === "running" || item.status === "error");
      const fallbackFailureStep = hasKnownFailure
        ? null
        : steps.find((item) => item.step === "access" && item.status === "pending")?.step
          ?? steps.find((item) => item.status === "pending")?.step
          ?? null;
      const failureDetail = friendlyIpcError(error, "Preparação interrompida");
      return steps.map((item) => {
        if (item.status === "running" || (item.status === "pending" && item.step === fallbackFailureStep)) {
          return { ...item, status: "error", detail: failureDetail };
        }
        if (item.status === "pending") {
          return { ...item, status: "skipped", detail: "Não executada porque a preparação foi interrompida." };
        }
        return item;
      });
    });
  };

  const joinServer = async (confirmLegacy = false) => {
    const invite = joinKey.trim();
    setActiveAction("join");
    setJoinError(null);
    try {
      const result = await window.janjacord.serverJoin(hostUrl.trim(), invite, confirmLegacy);
      if (result.ok && result.data) {
        setLegacyChallenge(null);
        activateServer(result.data as ServerState);
        void loadCommunities();
        return;
      }
      if (result.error?.code === "legacy_confirmation_required") {
        const fingerprint = legacyFingerprint(result.error);
        if (fingerprint) {
          setLegacyChallenge({ invite, fingerprint });
          setJoinError(null);
        } else {
          setLegacyChallenge(null);
          setJoinError("Este host legado não forneceu a fingerprint necessária para uma confirmação segura. Atualize o host ou use um convite JC3.");
        }
        return;
      }
      setLegacyChallenge(null);
      setJoinError(friendlyIpcError(result.error, "Não foi possível entrar nesta comunidade."));
    } catch (error) {
      setLegacyChallenge(null);
      setJoinError(rejectedIpcError(error, "Não foi possível entrar nesta comunidade."));
    } finally {
      setActiveAction(null);
    }
  };

  const makeInvite = async () => {
    setActiveAction("invite");
    setInviteError(null);
    setInviteNotice(null);
    setInviteKey(null);
    inviteIdRef.current = null;
    setInviteCopyState("idle");
    try {
      const result = await window.janjacord.inviteCreate();
      if (result.ok && result.data) {
        inviteIdRef.current = result.data.inviteId;
        setInviteKey(result.data.inviteKey);
      }
      else setInviteError(friendlyIpcError(result.error, "Não foi possível criar um convite."));
    } catch (error) {
      setInviteError(rejectedIpcError(error, "Não foi possível criar um convite."));
    } finally {
      setActiveAction(null);
    }
  };

  const copyInvite = async () => {
    if (!inviteKey) return;
    setInviteCopyState("idle");
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard API unavailable");
      await navigator.clipboard.writeText(inviteKey);
      setInviteCopyState("copied");
    } catch {
      setInviteCopyState("error");
    }
  };

  const dismissInvite = () => {
    const dismissedInvite = inviteKey;
    if (dismissedInvite && inviteCopyState === "copied") {
      void window.janjacord.clipboardClearIfEquals(dismissedInvite).catch(() => undefined);
    }
    setInviteKey(null);
    inviteIdRef.current = null;
    setInviteError(null);
    setInviteNotice(null);
    setInviteCopyState("idle");
    setInviteFocusPending(true);
  };

  const send = async () => {
    if (!draft.trim() || !channelId) return;
    const text = draft.trim();
    setDraft("");
    setBusySend(true);
    setMessageError(null);
    try {
      const result = await window.janjacord.sendMessage(channelId, text);
      if (!result.ok) {
        setDraft(text);
        setMessageError(friendlyIpcError(result.error, "A mensagem não foi enviada."));
      }
    } catch (error) {
      setDraft(text);
      setMessageError(rejectedIpcError(error, "A mensagem não foi enviada."));
    } finally {
      setBusySend(false);
    }
  };

  const attach = async (file: File) => {
    if (!channelId) return;
    if (!attachmentSizeIsAllowed(file.size)) {
      setMessageError("O arquivo está vazio ou excede o limite de 50 MB por anexo.");
      if (fileRef.current) fileRef.current.value = "";
      return;
    }
    setBusySend(true);
    setMessageError(null);
    try {
      let dataB64 = encodeAttachmentBytes(await file.arrayBuffer());
      const request = window.janjacord.attachmentSend(channelId, file.name, file.type || "application/octet-stream", dataB64);
      dataB64 = "";
      const res = await request;
      if (!res.ok) {
        setMessageError(friendlyIpcError(res.error, "O anexo não foi enviado."));
      }
    } catch (error) {
      setMessageError(rejectedIpcError(error, "O anexo não foi enviado."));
    } finally {
      setBusySend(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const activeChannel = useMemo(() => server?.channels.find((c) => c.id === channelId) ?? null, [server, channelId]);
  const hasLocalCommunity = communities.some((community) => community.connectionKind === "primary");

  if (bootState !== "ready") {
    return (
      <div className="flex max-w-sm flex-col items-center gap-3 px-6 text-center" role={bootState === "error" ? "alert" : "status"}>
        {bootState === "loading" ? <LoaderCircle className="h-6 w-6 animate-spin text-sky-400" aria-hidden /> : <TriangleAlert className="h-6 w-6 text-red-400" aria-hidden />}
        <p className="text-sm text-zinc-300">{bootError ?? "Recuperando sua comunidade..."}</p>
        {bootState === "error" && (
          <button className="flex items-center gap-2 rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-900" onClick={loadBootState}>
            <RefreshCw className="h-4 w-4" aria-hidden />
            Tentar novamente
          </button>
        )}
      </div>
    );
  }

  if (view === "home") {
    return (
      <div className="home-shell h-full max-h-screen w-full overflow-y-auto px-5 py-6 sm:px-8 sm:py-8" data-smoke-screen="home">
        <header className="mx-auto flex w-full max-w-5xl items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-sky-500/30 bg-sky-500/10">
              <ServerIcon className="h-5 w-5 text-sky-300" aria-hidden />
            </div>
            <div>
              <p className="text-xs font-medium uppercase tracking-[0.18em] text-sky-300/80">JanjaCord</p>
              <h1 className="mt-1 text-2xl font-semibold tracking-tight text-white">Suas comunidades</h1>
              <p className="mt-1 max-w-xl text-sm leading-5 text-zinc-400">Entre direto no espaço certo ou prepare uma nova comunidade em poucos passos.</p>
            </div>
          </div>
          <button className="icon-button" onClick={loadCommunities} title="Atualizar comunidades" aria-label="Atualizar comunidades">
            <RefreshCw className={`h-4 w-4 ${communityState === "loading" ? "animate-spin" : ""}`} aria-hidden />
          </button>
        </header>
        {recoveryKey && (
          <div className="mx-auto mt-5 w-full max-w-5xl rounded-xl border border-amber-700/40 bg-amber-950/40 p-3">
            <p className="text-[11px] font-medium text-amber-300">Sua chave de recuperação (anote!)</p>
            <p className="mt-1 font-mono text-xs break-all text-amber-100">{recoveryKey}</p>
          </div>
        )}
        <div className="mx-auto mt-7 grid w-full max-w-5xl gap-5 lg:grid-cols-[1.1fr_0.9fr]">
          <section className="rounded-2xl border border-zinc-800 bg-zinc-900/70 p-4 shadow-2xl shadow-black/10" aria-labelledby="community-list-title">
            <div className="flex items-center justify-between gap-3">
              <div>
                <h2 id="community-list-title" className="text-sm font-semibold text-white">Comunidades salvas neste dispositivo</h2>
                <p className="mt-1 text-xs text-zinc-500">Você entra nelas sem procurar o convite de novo.</p>
              </div>
              <Users className="h-4 w-4 text-zinc-500" aria-hidden />
            </div>
            {communityState === "error" && (
              <div className="mt-4 rounded-lg border border-red-900/70 bg-red-950/20 p-3" role="alert">
                <p className="text-xs leading-5 text-red-300">{communityError}</p>
                <button className="mt-2 text-xs font-medium text-zinc-200 hover:text-white" onClick={loadCommunities}>Tentar novamente</button>
              </div>
            )}
            {communityState === "loading" && communities.length === 0 && (
              <div className="mt-4 flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 text-xs text-zinc-400" role="status">
                <LoaderCircle className="h-4 w-4 animate-spin text-sky-400" aria-hidden /> Carregando comunidades...
              </div>
            )}
            {communityState === "ready" && communities.length === 0 && (
              <div className="mt-4 rounded-xl border border-dashed border-zinc-700 bg-zinc-950/40 p-6 text-center">
                <Home className="mx-auto h-6 w-6 text-zinc-600" aria-hidden />
                <p className="mt-3 text-sm font-medium text-zinc-200">Ainda não há comunidades aqui</p>
                <p className="mx-auto mt-1 max-w-xs text-xs leading-5 text-zinc-500">Crie uma comunidade ou entre com um convite. Depois ela aparecerá automaticamente nesta lista.</p>
              </div>
            )}
            <div className="mt-4 space-y-2">
              {communities.map((community) => (
                <button
                  key={community.serverId}
                  className={`flex w-full items-center gap-3 rounded-xl border px-3 py-3 text-left transition ${community.status === "active" ? "border-sky-500/50 bg-sky-500/10" : "border-zinc-800 bg-zinc-950/50 hover:border-zinc-700 hover:bg-zinc-900"}`}
                  onClick={() => void activateCommunity(community)}
                  disabled={communityAction !== null}
                  aria-current={community.status === "active" ? "page" : undefined}
                >
                  <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl text-sm font-semibold ${community.status === "active" ? "bg-sky-500 text-slate-950" : "bg-indigo-500/20 text-indigo-200"}`}>
                    {community.serverName.slice(0, 2).toUpperCase()}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-2 text-sm font-medium text-zinc-100">
                      <span className="truncate">{community.serverName}</span>
                      {community.status === "active" && <span className="rounded-full bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-medium text-emerald-300">aberta</span>}
                    </span>
                    <span className="mt-1 block text-xs text-zinc-500">{community.connectionKind === "primary" ? "Host neste dispositivo" : "Comunidade compartilhada"}</span>
                  </span>
                  {communityAction === community.serverId ? <LoaderCircle className="h-4 w-4 animate-spin text-sky-300" aria-label="Abrindo" /> : <span className="text-xs text-zinc-500">Abrir</span>}
                </button>
              ))}
            </div>
            {communityError && communityState !== "error" && <p className="mt-3 text-xs leading-5 text-red-400" role="alert">{communityError}</p>}
          </section>

          <section className="space-y-4" aria-label="Ações de comunidade">
            <div className="rounded-2xl border border-sky-500/30 bg-gradient-to-br from-sky-500/10 to-indigo-500/5 p-4">
              <div className="flex items-start gap-3">
                <Plus className="mt-0.5 h-5 w-5 text-sky-300" aria-hidden />
                <div>
                  <h2 className="text-sm font-semibold text-white">Criar comunidade</h2>
                  <p className="mt-1 text-xs leading-5 text-zinc-400">Comece localmente e configure o acesso externo quando quiser.</p>
                </div>
              </div>
              <label className="mt-4 block text-xs font-medium text-zinc-300" htmlFor="community-name">Nome da comunidade</label>
              <input id="community-name" className="mt-2 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 text-sm text-zinc-100 outline-none focus:border-sky-500" placeholder="Ex.: Equipe Janja" value={communityName} onChange={(event) => setCommunityName(event.target.value)} maxLength={64} />
              <button className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg bg-sky-500 py-2.5 text-sm font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50" onClick={createServer} disabled={activeAction !== null || hasLocalCommunity}>
                {activeAction === "create" ? <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden /> : <Plus className="h-4 w-4" aria-hidden />}
                {activeAction === "create" ? "Criando comunidade..." : hasLocalCommunity ? "Host local já configurado" : "Criar comunidade"}
              </button>
              {hasLocalCommunity && <p className="mt-2 text-[11px] leading-4 text-zinc-500">Para adicionar outra, entre com um convite. O primeiro host local continua protegido neste dispositivo.</p>}
              {createError && <p className="mt-2 text-xs leading-5 text-red-400" role="alert">{createError}</p>}
            </div>

            <div className="rounded-2xl border border-zinc-800 bg-zinc-900/70 p-4">
              <div className="flex items-start gap-3">
                <UserPlus className="mt-0.5 h-5 w-5 text-indigo-300" aria-hidden />
                <div>
                  <h2 className="text-sm font-semibold text-white">Entrar com convite</h2>
                  <p className="mt-1 text-xs leading-5 text-zinc-500">Cole o convite que o administrador enviou para você.</p>
                </div>
              </div>
              <input id="invite-key" className="mt-4 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 font-mono text-sm outline-none focus:border-sky-500" placeholder="JC3-... ou JC2-..." value={joinKey} onChange={(event) => { setJoinKey(event.target.value); setLegacyChallenge(null); setJoinError(null); }} aria-invalid={Boolean(joinError)} aria-describedby={[joinError ? "invite-error" : null, legacyChallenge ? "legacy-fingerprint" : null].filter(Boolean).join(" ") || undefined} />
              {joinError && <p id="invite-error" className="mt-2 text-xs leading-5 text-red-400" role="alert">{joinError}</p>}
              {legacyChallenge && legacyChallenge.invite === joinKey.trim() && (
                <div id="legacy-fingerprint" className="mt-3 rounded-lg border border-amber-800/60 bg-amber-950/30 p-3">
                  <div className="flex items-start gap-2"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" aria-hidden /><div className="min-w-0"><p className="text-xs font-medium text-amber-200">Confirmação do host legado</p><p className="mt-1 text-xs leading-5 text-zinc-300">Compare esta fingerprint exatamente com a enviada pelo administrador:</p><code className="mt-2 block select-all break-all rounded bg-zinc-950 px-2 py-2 font-mono text-xs text-amber-100">{legacyChallenge.fingerprint}</code></div></div>
                  <button className="mt-3 w-full rounded-lg border border-amber-700 px-3 py-2 text-xs font-medium text-amber-100 hover:bg-amber-950 disabled:opacity-50" onClick={() => void joinServer(true)} disabled={activeAction !== null}>{activeAction === "join" ? "Confirmando e conectando..." : "A fingerprint confere — conectar"}</button>
                </div>
              )}
              <button className="mt-3 w-full rounded-lg border border-zinc-600 py-2.5 text-sm font-medium text-zinc-200 hover:bg-zinc-800 disabled:opacity-50" onClick={() => void joinServer(false)} disabled={activeAction !== null || !joinKey.trim()}>{activeAction === "join" ? "Entrando na comunidade..." : "Entrar com convite"}</button>
              <button className="mt-3 flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-200" onClick={() => setShowAdvancedJoin((value) => !value)} aria-expanded={showAdvancedJoin} aria-controls="advanced-join-fields"><ChevronDown className={`h-3.5 w-3.5 transition-transform ${showAdvancedJoin ? "rotate-180" : ""}`} aria-hidden /> Diagnóstico avançado</button>
              {showAdvancedJoin && <div id="advanced-join-fields" className="mt-2"><label className="sr-only" htmlFor="manual-host-endpoint">Endpoint manual do host</label><input id="manual-host-endpoint" className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs outline-none focus:border-sky-500" placeholder="Endpoint manual do host" value={hostUrl} onChange={(event) => setHostUrl(event.target.value)} /></div>}
            </div>

            <div className="flex w-full items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-900/40 p-3 hover:border-zinc-700 hover:bg-zinc-900">
              <Link2 className="h-4 w-4 shrink-0 text-zinc-400" aria-hidden />
              <button className="min-w-0 flex-1 text-left" onClick={() => setShowBridgeTutorial(true)}>
                <span className="block text-xs font-medium text-zinc-200">JanjaBridge</span>
                <span className="mt-0.5 block truncate text-[11px] text-zinc-500">{connectivityState === "loading" ? "Verificando..." : bridgeCount && bridgeCount > 0 ? `${bridgeCount} configurado${bridgeCount > 1 ? "s" : ""}` : "Aprenda a colocar um servidor no ar"}</span>
              </button>
              <button className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-zinc-700 px-2.5 py-1.5 text-[11px] text-zinc-300 hover:bg-zinc-800" onClick={() => setShowBridgeTutorial(true)}>
                <BookOpen className="h-3.5 w-3.5" aria-hidden />
                Tutorial
              </button>
            </div>
            {connectivityState === "error" && <div className="flex items-start justify-between gap-3" role="alert"><p className="text-xs leading-5 text-amber-300">{connectivityError}</p><button className="flex shrink-0 items-center gap-1 text-xs text-zinc-300 hover:text-white" onClick={loadConnectivity}><RefreshCw className="h-3.5 w-3.5" aria-hidden /> Repetir</button></div>}
          </section>
        </div>
        <div className="mx-auto mt-5 w-full max-w-5xl">
          {setupSteps.length > 0 && (
            <div ref={setupRegionRef} tabIndex={-1} data-smoke-section="setup" aria-label="Progresso da preparação da comunidade" className="outline-none">
              <SetupProgress steps={setupSteps} onRetry={createServer} onAction={(step) => step === "bridge" && setShowBridgeTutorial(true)} />
              {pendingServer && (
                <div className="flex flex-col gap-2 border-t border-zinc-800 pt-4 sm:flex-row">
                  <button ref={addBridgeRef} className="flex flex-1 items-center justify-center gap-2 rounded-md border border-sky-500 bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500" onClick={() => setShowBridgeTutorial(true)}>
                    <BookOpen className="h-4 w-4" aria-hidden />
                    Tutorial servidor JanjaBridge
                  </button>
                  <button className="flex-1 rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100" onClick={() => setShowBridgePairing(true)}>
                    <Link2 className="mr-2 inline h-4 w-4" aria-hidden />
                    Já tenho pairing
                  </button>
                  <button className="flex-1 rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200" onClick={() => { activateServer(pendingServer); setShowSetupChecklist(true); }}>
                    Continuar nesta rede
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
        {showBridgeTutorial && <JanjaBridgeTutorial onClose={() => setShowBridgeTutorial(false)} onOpenPairing={() => { setShowBridgeTutorial(false); setShowBridgePairing(true); }} />}
        {showBridgePairing && <BridgePairingDialog onClose={() => setShowBridgePairing(false)} onCompleted={() => {
          if (pendingServer) {
            activateServer(pendingServer);
            setShowSetupChecklist(true);
          }
        }} onAdded={(result) => {
          void loadConnectivity();
          setSetupSteps((steps) => steps.map((item) => item.step === "bridge"
            ? result.warning
              ? { ...item, status: "warning", detail: result.warning }
              : { ...item, status: "done", detail: "JanjaBridge validado" }
            : result.warning && item.step === "access"
              ? { ...item, status: "warning", detail: "Host local não confirmado após ativação" }
            : !result.warning && item.step === "access"
              ? { ...item, status: "done", detail: "Conexão pronta" }
            : item));
        }} />}
      </div>
    );
  }

  // view === server
  return (
    <div className="server-shell flex h-full min-h-0 w-full min-w-0" data-smoke-screen="server">
      {/* rail de comunidades */}
      <aside className="server-rail flex w-16 shrink-0 flex-col items-center gap-2 border-r border-zinc-800 bg-zinc-950 py-3" aria-label="Comunidades">
        <button className="icon-button !h-9 !w-9 !rounded-xl border border-zinc-800 bg-zinc-900 text-zinc-300 hover:border-sky-500/50" title="Voltar para suas comunidades" aria-label="Voltar para suas comunidades" onClick={() => setView("home")}>
          <Home className="h-4 w-4" aria-hidden />
        </button>
        <div className="my-1 h-px w-8 bg-zinc-800" aria-hidden />
        <div className="flex min-h-0 flex-1 flex-col items-center gap-2 overflow-y-auto">
          {communities.map((community) => (
            <button
              key={community.serverId}
              className={`relative flex h-10 w-10 shrink-0 items-center justify-center rounded-xl text-xs font-bold transition ${community.serverId === server?.serverId ? "bg-sky-500 text-slate-950 shadow-lg shadow-sky-500/20" : "bg-indigo-500/20 text-indigo-200 hover:rounded-lg hover:bg-indigo-500/35"}`}
              title={community.serverName}
              aria-label={`Abrir ${community.serverName}`}
              aria-current={community.serverId === server?.serverId ? "page" : undefined}
              onClick={() => community.serverId !== server?.serverId && void activateCommunity(community)}
              disabled={communityAction !== null}
            >
              {community.serverName.slice(0, 2).toUpperCase()}
            </button>
          ))}
        </div>
        <button className="icon-button !h-10 !w-10 !rounded-xl border border-dashed border-zinc-700 text-zinc-400 hover:border-sky-500 hover:text-sky-300" title="Criar ou entrar em outra comunidade" aria-label="Criar ou entrar em outra comunidade" onClick={() => setView("home")}>
          <Plus className="h-4 w-4" aria-hidden />
        </button>
        <div className="mt-1 flex h-8 w-8 items-center justify-center rounded-full border border-zinc-700 bg-zinc-900 text-[10px] font-semibold text-zinc-300" title={identity?.nickname ?? "Sua conta"}>
          {identity?.nickname?.slice(0, 2).toUpperCase() ?? "EU"}
        </div>
        </aside>
      {/* canais */}
      <div className="channel-sidebar flex w-64 min-w-0 shrink-0 flex-col border-r border-zinc-800 bg-zinc-900/40">
        <div className="border-b border-zinc-800 px-3 py-3">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold text-white">{server?.serverName}</p>
              <p className="mt-0.5 text-[11px] text-zinc-500">{server?.members.length ?? 0} membro{(server?.members.length ?? 0) === 1 ? "" : "s"}</p>
            </div>
            <button className="icon-button !h-8 !w-8" onClick={() => setShowSettings(true)} title="Abrir configurações da comunidade" aria-label="Abrir configurações da comunidade">
              <Settings className="h-4 w-4" aria-hidden />
            </button>
          </div>
          <div className="mt-3 grid grid-cols-2 gap-2">
            <button ref={inviteButtonRef} className="flex items-center justify-center gap-1.5 rounded-md border border-zinc-700 px-2 py-1.5 text-[11px] font-medium text-zinc-300 hover:border-zinc-500 hover:bg-zinc-800 disabled:opacity-50" onClick={makeInvite} title="Criar convite" aria-label="Criar convite" disabled={activeAction !== null}>
              <UserPlus className="h-3.5 w-3.5" aria-hidden /> {activeAction === "invite" ? "Criando..." : "Convidar"}
            </button>
            <button className="flex items-center justify-center gap-1.5 rounded-md border border-zinc-700 px-2 py-1.5 text-[11px] font-medium text-zinc-300 hover:border-zinc-500 hover:bg-zinc-800" onClick={() => setShowSettings(true)} title="Configurações da comunidade">
              <Settings className="h-3.5 w-3.5" aria-hidden /> Configurar
            </button>
          </div>
          {activeRoute && (
            <button
              className="mt-2 flex w-full items-center gap-1.5 rounded-md border border-emerald-900/70 bg-zinc-950/60 px-2 py-1.5 text-left"
              title={`Rota externa ativa · ${activeRoute.endpoint} · ${activeRoute.media === "turn" ? "mídia via TURN" : "mídia direta"}`}
              aria-label="Rota externa ativa — abrir conectividade"
              data-smoke-critical="active-route-badge"
              onClick={() => { setSettingsInitialTab("connectivity"); setShowSettings(true); }}
            >
              <span className="relative flex h-2 w-2 shrink-0">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" aria-hidden />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" aria-hidden />
              </span>
              <span className="min-w-0 flex-1 truncate text-[10px] font-medium text-emerald-200">
                {activeRoute.provider === "tailscale" ? "Tailscale" : activeRoute.provider === "ngrok" ? "ngrok" : activeRoute.provider === "cloudflare" ? "Cloudflare" : "Nginx"} · rota ativa
              </span>
              <span className={`shrink-0 rounded px-1 py-0.5 text-[9px] font-medium uppercase tracking-wide ${activeRoute.media === "turn" ? "bg-emerald-900/60 text-emerald-200" : "bg-amber-900/50 text-amber-200"}`}>
                {activeRoute.media === "turn" ? "TURN" : "direta"}
              </span>
            </button>
          )}
          {inviteKey && (
            <div className="invite-share-card mt-2 rounded-md border border-emerald-900/70 bg-zinc-950 p-2.5" role="region" aria-label="Convite de uso único">
              <div className="flex items-center justify-between gap-2">
                <p className="text-[10px] font-medium text-emerald-300">Convite de uso único</p>
                <button className="icon-button !h-6 !w-6" onClick={dismissInvite} title="Fechar convite" aria-label="Fechar convite">
                  <X className="h-3.5 w-3.5" aria-hidden />
                </button>
              </div>
              <code className="invite-share-token mt-1 block overflow-auto rounded bg-black/30 px-2 py-1.5 font-mono text-[10px] leading-4 text-zinc-300" title={inviteKey}>{inviteKey}</code>
              <button className="mt-2 flex w-full items-center justify-center gap-1.5 rounded border border-zinc-700 px-2 py-1.5 text-[11px] font-medium text-zinc-200 hover:bg-zinc-800" onClick={() => void copyInvite()}>
                {inviteCopyState === "copied" ? <Check className="h-3.5 w-3.5 text-emerald-400" aria-hidden /> : <Copy className="h-3.5 w-3.5" aria-hidden />}
                {inviteCopyState === "copied" ? "Copiado" : "Copiar convite"}
              </button>
              <p className={`mt-1 min-h-4 text-[10px] leading-4 ${inviteCopyState === "error" ? "text-red-400" : "text-zinc-500"}`} role={inviteCopyState === "error" ? "alert" : "status"} aria-live="polite">
                {inviteCopyState === "error" ? "Não foi possível copiar. Tente novamente." : inviteCopyState === "copied" ? "Pronto para compartilhar." : "Compartilhe apenas com a pessoa convidada."}
              </p>
            </div>
          )}
          {inviteError && <p className="mt-2 text-[11px] leading-4 text-red-400" role="alert">{inviteError}</p>}
          {inviteNotice && <p className="mt-2 text-[11px] leading-4 text-emerald-300" role="status">{inviteNotice}</p>}
        </div>
        <div className="flex-1 overflow-y-auto p-2">
          <div className="mb-2 flex items-center justify-between px-2">
            <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">Canais</p>
            <button className="icon-button !h-6 !w-6" onClick={() => { setShowQuickCreate((value) => !value); setQuickChannelError(null); }} title="Criar canal" aria-label="Criar canal" aria-expanded={showQuickCreate}>
              <Plus className="h-3.5 w-3.5" aria-hidden />
            </button>
          </div>
          {showQuickCreate && (
            <div className="mb-3 rounded-lg border border-sky-500/30 bg-sky-500/5 p-2" role="dialog" aria-label="Criar canal">
              <div className="grid grid-cols-2 gap-1">
                <button className={`flex items-center justify-center gap-1 rounded px-2 py-1.5 text-[11px] ${quickChannelType === "text" ? "bg-sky-500/20 text-sky-200" : "text-zinc-500 hover:bg-zinc-800"}`} onClick={() => setQuickChannelType("text")}><Hash className="h-3 w-3" aria-hidden /> Texto</button>
                <button className={`flex items-center justify-center gap-1 rounded px-2 py-1.5 text-[11px] ${quickChannelType === "call" ? "bg-indigo-500/20 text-indigo-200" : "text-zinc-500 hover:bg-zinc-800"}`} onClick={() => setQuickChannelType("call")}><Volume2 className="h-3 w-3" aria-hidden /> Voz</button>
              </div>
              <input className="mt-2 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-xs text-zinc-100 outline-none focus:border-sky-500" placeholder={quickChannelType === "text" ? "nome do canal de texto" : "nome da sala de voz"} value={quickChannelName} onChange={(event) => setQuickChannelName(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void createQuickChannel(); }} maxLength={64} autoFocus />
              {quickChannelError && <p className="mt-1 text-[10px] leading-4 text-red-400" role="alert">{quickChannelError}</p>}
              <button className="mt-2 flex w-full items-center justify-center gap-1 rounded bg-sky-500 px-2 py-1.5 text-[11px] font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50" onClick={() => void createQuickChannel()} disabled={quickChannelBusy || !quickChannelName.trim()}>{quickChannelBusy ? <LoaderCircle className="h-3 w-3 animate-spin" aria-hidden /> : <Plus className="h-3 w-3" aria-hidden />} Criar canal</button>
            </div>
          )}
          {server?.channels.map((c) => (
            <button key={c.id} className={`mb-1 flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm ${channelId === c.id ? "bg-zinc-800 text-white" : "text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-200"}`} onClick={() => setChannelId(c.id)}>
              {c.type === "text" ? <Hash className="h-4 w-4 shrink-0 text-zinc-500" aria-hidden /> : <Volume2 className="h-4 w-4 shrink-0 text-zinc-500" aria-hidden />}
              <span className="truncate">{c.name}</span>
            </button>
          ))}
          {server?.channels.length === 0 && <div className="rounded-lg border border-dashed border-zinc-700 p-4 text-center"><Hash className="mx-auto h-5 w-5 text-zinc-600" aria-hidden /><p className="mt-2 text-xs leading-5 text-zinc-400">Nenhum canal ainda.</p><button className="mt-2 text-xs font-medium text-sky-300 hover:text-sky-200" onClick={() => setShowQuickCreate(true)}>Criar o primeiro</button></div>}
        </div>
        <div className="border-t border-zinc-800 p-3">
          <p className="text-[11px] text-zinc-400">Membros ({server?.members.length ?? 0})</p>
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
          canConfigureConnectivity={communities.find((community) => community.serverId === server.serverId)?.connectionKind !== "remote"}
          initialTab={settingsInitialTab}
          onClose={() => {
            setShowSettings(false);
            setSettingsInitialTab("members");
            refreshState();
            void loadConnectivity();
          }}
        />
      )}
      {/* conversa */}
      <div className="conversation-pane flex min-w-0 flex-1 flex-col bg-zinc-950" data-smoke-critical="conversation">
        <div className="border-b border-zinc-800 px-4 py-3">
          <div className="flex items-center justify-between gap-3">
            <h3 className="truncate text-sm font-medium text-white">
              {activeChannel ? (activeChannel.type === "text" ? "# " : "🔊 ") + activeChannel.name : "Conversa"}
            </h3>
            <span className="flex shrink-0 items-center gap-1.5 text-[11px] text-zinc-500"><Wifi className="h-3.5 w-3.5" aria-hidden /> {activeRoute ? "Acesso externo ativo" : "Somente nesta rede"}</span>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto p-4">
          {showSetupChecklist && (
            <section className="mb-6 max-w-3xl rounded-2xl border border-sky-500/30 bg-gradient-to-br from-sky-500/10 via-zinc-900/80 to-indigo-500/10 p-4" aria-labelledby="setup-checklist-title">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-sky-300">Primeiros passos</p>
                  <h2 id="setup-checklist-title" className="mt-1 text-lg font-semibold text-white">Prepare {server?.serverName}</h2>
                  <p className="mt-1 max-w-xl text-xs leading-5 text-zinc-400">A comunidade já está funcionando localmente. Complete só o que fizer sentido agora.</p>
                </div>
                <button className="icon-button !h-7 !w-7" onClick={() => setShowSetupChecklist(false)} title="Fechar primeiros passos" aria-label="Fechar primeiros passos"><X className="h-3.5 w-3.5" aria-hidden /></button>
              </div>
              <div className="mt-4 grid gap-2 sm:grid-cols-2">
                <button className="flex items-center gap-3 rounded-xl border border-zinc-700 bg-zinc-950/50 p-3 text-left hover:border-sky-500/60 hover:bg-zinc-900" onClick={() => { setQuickChannelType("text"); setShowQuickCreate(true); }}>
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-500/15 text-sky-300"><Hash className="h-4 w-4" aria-hidden /></span><span><span className="block text-xs font-medium text-zinc-100">Criar canal de texto</span><span className="mt-0.5 block text-[11px] text-zinc-500">Organize conversas por assunto</span></span>
                </button>
                <button className="flex items-center gap-3 rounded-xl border border-zinc-700 bg-zinc-950/50 p-3 text-left hover:border-indigo-500/60 hover:bg-zinc-900" onClick={() => { setQuickChannelType("call"); setShowQuickCreate(true); }}>
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500/15 text-indigo-300"><Volume2 className="h-4 w-4" aria-hidden /></span><span><span className="block text-xs font-medium text-zinc-100">Criar sala de voz</span><span className="mt-0.5 block text-[11px] text-zinc-500">Abra uma conversa por áudio</span></span>
                </button>
                <button className="flex items-center gap-3 rounded-xl border border-zinc-700 bg-zinc-950/50 p-3 text-left hover:border-emerald-500/60 hover:bg-zinc-900" onClick={() => { setSettingsInitialTab("connectivity"); setShowSettings(true); }}>
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-300"><Wifi className="h-4 w-4" aria-hidden /></span><span><span className="block text-xs font-medium text-zinc-100">Configurar acesso externo</span><span className="mt-0.5 block text-[11px] text-zinc-500">ngrok, Cloudflare ou Tailscale</span></span>
                </button>
                <button className="flex items-center gap-3 rounded-xl border border-zinc-700 bg-zinc-950/50 p-3 text-left hover:border-amber-500/60 hover:bg-zinc-900" onClick={makeInvite} disabled={activeAction !== null}>
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-500/15 text-amber-300"><UserPlus className="h-4 w-4" aria-hidden /></span><span><span className="block text-xs font-medium text-zinc-100">Criar primeiro convite</span><span className="mt-0.5 block text-[11px] text-zinc-500">Chame alguém para participar</span></span>
                </button>
              </div>
              <button className="mt-4 inline-flex items-center gap-2 rounded-lg border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-xs font-semibold text-sky-200 hover:border-sky-400 hover:bg-sky-500/20 hover:text-white" onClick={() => setShowSetupChecklist(false)}>Continuar para a conversa <ArrowRight className="h-3.5 w-3.5" aria-hidden /></button>
            </section>
          )}
          {channelId && (messages[channelId] ?? []).map((m) => (
            <div key={m.messageId} className="mb-3">
              <p className="text-xs">
                <span className={`font-medium ${m.self ? "text-indigo-400" : "text-zinc-300"}`}>
                  {m.self ? "você" : m.sender.slice(0, 8)}
                </span>
                <span className="ml-2 text-[10px] text-zinc-400">
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
            iceServers={callIceServers}
            connectionError={iceError}
            onRetryConnection={loadIceConfiguration}
            callJoin={(cid) => window.janjacord.callJoin(cid)}
            callLeave={(cid) => window.janjacord.callLeave(cid)}
            callSignal={(cid, to, payload) => window.janjacord.callSignal(cid, to, payload)}
            onSignal={(cb) => window.janjacord.on("call.signal", (d) => cb(d as CallSignal))}
          />
        )}
        {activeChannel?.type === "text" && (
          <div className="border-t border-zinc-800 p-3">
            {messageError && (
              <div className="mb-2 flex items-center justify-between gap-3" role="alert">
                <p className="text-xs text-red-400">{messageError}</p>
                <button className="text-xs text-zinc-300 hover:text-white" onClick={() => setMessageError(null)}>Fechar</button>
              </div>
            )}
            <div className="message-composer flex min-w-0 gap-2" data-smoke-critical="composer">
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
                disabled={busySend}
              >
                📎
              </button>
              <input
                className="min-w-0 flex-1 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm outline-none focus:border-indigo-500"
                placeholder="Mensagem (efêmera — some após todos lerem)"
                value={draft}
                onChange={(e) => {
                  setDraft(e.target.value);
                  setMessageError(null);
                }}
                onKeyDown={(e) => e.key === "Enter" && !busySend && send()}
              />
              <button
                className="rounded-md bg-indigo-600 px-4 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
                onClick={send}
                disabled={busySend}
              >
                {busySend ? "Enviando..." : "Enviar"}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
