import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { HardDrive, Link2, LoaderCircle, Network, Plus, RefreshCw, ShieldCheck, Trash2, X } from "lucide-react";
import { BridgePairingDialog } from "./BridgePairingDialog";
import { ConnectivityWizard } from "./ConnectivityWizard";
import { friendlyIpcError, rejectedIpcError } from "../ipcErrors";

interface Member {
  identityId: string;
  nickname: string;
  roleId: string;
  presence: string;
}
interface Role {
  id: string;
  name: string;
  level: number;
  permissions: string[];
}
interface ServerState {
  serverId: string;
  config?: { maxRetentionHours?: number; networkPrivacy?: "direct" | "relay" };
  channels: { id: string; type: string; name: string }[];
  members: Member[];
  roles: Role[];
  me: { identityId: string; nickname: string; roleId: string };
  hosting?: { role?: "primary" | "replica"; writer?: boolean };
  hostCandidates?: HostCandidate[];
  hostGrants?: HostGrant[];
}

interface HostCandidate {
  candidateId: string;
  subjectIdentityId: string;
  nickname: string;
  hostId: string;
  expiresAt: number;
}

interface HostGrant {
  grantId: string;
  subjectIdentityId: string;
  subjectAuthPublicKey: string;
  hostPublicKey: string;
  enrollmentPublicKey: string;
  hostId: string;
  capabilities: string[];
  expiresAt: number;
  acceptedAt?: number | null;
  revokedAt?: number | null;
  health?: string | null;
  lastActivityAt?: number | null;
}

const PERMISSION_LABELS: Record<string, string> = {
  manage_server: "Gerenciar server",
  manage_channels: "Gerenciar canais",
  manage_roles: "Gerenciar roles",
  manage_invites: "Gerenciar convites",
  manage_hosts: "Gerenciar hosts",
  kick_members: "Expulsar membros",
  ban_members: "Banir membros",
  assign_roles: "Atribuir roles",
  view_channel: "Ver canal",
  send_messages: "Enviar mensagens",
  send_files: "Enviar arquivos",
  join_call: "Entrar em call",
  speak: "Falar",
  enable_camera: "Ligar câmera",
  mute_members: "Silenciar membros",
  remove_from_call: "Remover da call",
};

type Tab = "members" | "roles" | "hosts" | "settings" | "connectivity" | "invites" | "channels";
type LoadState = "idle" | "loading" | "ready" | "error";
type HostMutation =
  | { status: "idle" }
  | { status: "running"; message: string }
  | { status: "success" | "warning"; message: string }
  | { status: "error"; message: string; kind: "accept" | "revoke"; grant: HostGrant };

const FOCUSABLE = "button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";

const TABS: [Tab, string][] = [
  ["members", "Membros"],
  ["roles", "Roles"],
  ["channels", "Canais"],
  ["hosts", "Hosts"],
  ["connectivity", "Conectividade"],
  ["settings", "Configurações"],
  ["invites", "Convites"],
];

export function ServerSettings({ server, onClose }: { server: ServerState; onClose: () => void }) {
  const [tab, setTab] = useState<Tab>("members");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [invites, setInvites] = useState<{ id: string; used: number; max_uses: number; revoked: number }[]>([]);
  const [retention, setRetention] = useState(server.config?.maxRetentionHours ?? 168);
  const [privacy, setPrivacy] = useState<"direct" | "relay">(server.config?.networkPrivacy ?? "direct");
  const [newRoleName, setNewRoleName] = useState("");
  const [newRoleLevel, setNewRoleLevel] = useState(10);
  const [newRolePerms, setNewRolePerms] = useState<string[]>([]);
  const [newChannelName, setNewChannelName] = useState("");
  const [newChannelType, setNewChannelType] = useState<"text" | "call">("call");
  const [showBridgePairing, setShowBridgePairing] = useState(false);
  const [showConnectivityWizard, setShowConnectivityWizard] = useState(false);
  const [bridges, setBridges] = useState<{ bridgeId: string; endpoint: string; expiresAt: number }[]>([]);
  const [backgroundHosting, setBackgroundHosting] = useState(false);
  const [hostGrants, setHostGrants] = useState<HostGrant[]>(server.hostGrants ?? []);
  const [hostCandidates, setHostCandidates] = useState<HostCandidate[]>(server.hostCandidates ?? []);
  const [hosting, setHosting] = useState(server.hosting);
  const [invitesState, setInvitesState] = useState<LoadState>("idle");
  const [invitesError, setInvitesError] = useState<string | null>(null);
  const [connectivityLoadState, setConnectivityLoadState] = useState<LoadState>("idle");
  const [connectivityLoadError, setConnectivityLoadError] = useState<string | null>(null);
  const [hostsState, setHostsState] = useState<LoadState>("idle");
  const [hostsError, setHostsError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [confirmGrant, setConfirmGrant] = useState<HostGrant | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState<HostGrant | null>(null);
  const [resourceAccepted, setResourceAccepted] = useState(false);
  const [hostMutation, setHostMutation] = useState<HostMutation>({ status: "idle" });
  const tabListRef = useRef<HTMLDivElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const hostMutationRef = useRef<HTMLDivElement>(null);
  const hostRetryRef = useRef<HTMLButtonElement>(null);
  const revokeDialogRef = useRef<HTMLDivElement>(null);
  const confirmRevokeButtonRef = useRef<HTMLButtonElement>(null);
  const revokeReturnFocusRef = useRef<HTMLButtonElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const closeRef = useRef(onClose);
  const nestedDialogOpenRef = useRef(false);

  closeRef.current = onClose;
  nestedDialogOpenRef.current = showBridgePairing || showConnectivityWizard || Boolean(confirmRevoke);

  const currentRole = server.roles.find((role) => role.id === server.me.roleId);
  const canManageHosts = currentRole?.permissions.includes("manage_hosts") ?? false;

  const loadInvites = async () => {
    setInvitesState("loading");
    setInvitesError(null);
    try {
      const result = await window.janjacord.listInvites();
      if (!result.ok || !result.data) {
        setInvitesError(friendlyIpcError(result.error, "Não foi possível carregar os convites."));
        setInvitesState("error");
        return;
      }
      setInvites(result.data as typeof invites);
      setInvitesState("ready");
    } catch (error) {
      setInvitesError(rejectedIpcError(error, "Não foi possível carregar os convites."));
      setInvitesState("error");
    }
  };
  const loadConnectivity = async () => {
    setConnectivityLoadState("loading");
    setConnectivityLoadError(null);
    try {
      const result = await window.janjacord.connectivityStatus();
      if (!result.ok || !result.data) {
        setConnectivityLoadError(friendlyIpcError(result.error, "Não foi possível carregar as rotas configuradas."));
        setConnectivityLoadState("error");
        return;
      }
      setBridges(result.data.bridges);
      setBackgroundHosting(result.data.backgroundHosting);
      setConnectivityLoadState("ready");
    } catch (error) {
      setConnectivityLoadError(rejectedIpcError(error, "Não foi possível carregar as rotas configuradas."));
      setConnectivityLoadState("error");
    }
  };
  const loadHosts = async (): Promise<boolean> => {
    setHostsState("loading");
    setHostsError(null);
    try {
      const stateResult = await window.janjacord.serverState();
      if (!stateResult.ok || !stateResult.data) {
        setHostsError(friendlyIpcError(stateResult.error, "Não foi possível carregar os hosts."));
        setHostsState("error");
        return false;
      }
      const next = stateResult.data as ServerState;
      let nextGrants = next.hostGrants ?? [];
      let nextCandidates = next.hostCandidates ?? [];
      if (canManageHosts) {
        const grantsResult = await window.janjacord.listHostGrants();
        if (!grantsResult.ok || !grantsResult.data) {
          setHostsError(friendlyIpcError(grantsResult.error, "Você pode gerenciar hosts, mas a lista completa não pôde ser carregada."));
          setHostsState("error");
          return false;
        }
        nextGrants = (grantsResult.data.grants ?? []) as HostGrant[];
        nextCandidates = (grantsResult.data.candidates ?? []) as HostCandidate[];
      }
      setHostGrants(nextGrants);
      setHostCandidates(nextCandidates);
      setHosting(next.hosting);
      setHostsState("ready");
      return true;
    } catch (error) {
      setHostsError(rejectedIpcError(error, "Não foi possível carregar os hosts."));
      setHostsState("error");
      return false;
    }
  };
  useEffect(() => {
    if (tab === "invites") void loadInvites();
    if (tab === "connectivity") void loadConnectivity();
    if (tab === "hosts") void loadHosts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab]);

  useEffect(() => {
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    requestAnimationFrame(() => closeButtonRef.current?.focus());

    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if (nestedDialogOpenRef.current) return;
      if (event.key === "Escape") {
        event.preventDefault();
        closeRef.current();
        return;
      }
      if (event.key !== "Tab" || !dialogRef.current) return;
      const focusable = [...dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)]
        .filter((element) => element.getAttribute("aria-hidden") !== "true" && element.offsetParent !== null);
      if (focusable.length === 0) {
        event.preventDefault();
        dialogRef.current.focus();
        return;
      }
      const first = focusable[0]!;
      const last = focusable[focusable.length - 1]!;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previousFocusRef.current?.focus();
    };
  }, []);

  useEffect(() => {
    if (hostMutation.status !== "error") return;
    requestAnimationFrame(() => {
      hostMutationRef.current?.scrollIntoView({ block: "nearest" });
      hostRetryRef.current?.focus({ preventScroll: true });
    });
  }, [hostMutation.status]);

  useEffect(() => {
    if (!confirmRevoke) return;
    requestAnimationFrame(() => {
      revokeDialogRef.current?.scrollIntoView({ block: "nearest" });
      confirmRevokeButtonRef.current?.focus({ preventScroll: true });
    });
  }, [confirmRevoke]);

  const closeRevokeConfirmation = () => {
    setConfirmRevoke(null);
    requestAnimationFrame(() => revokeReturnFocusRef.current?.focus());
  };

  const handleRevokeDialogKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      closeRevokeConfirmation();
      return;
    }
    if (event.key !== "Tab" || !revokeDialogRef.current) return;
    const focusable = [...revokeDialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)]
      .filter((element) => element.offsetParent !== null);
    if (focusable.length === 0) return;
    const first = focusable[0]!;
    const last = focusable[focusable.length - 1]!;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  };

  const run = async (fn: () => Promise<{ ok: boolean; error?: { code?: string; message: string } }>, after?: () => unknown | Promise<unknown>, successMessage?: string) => {
    setBusy(true);
    setError(null);
    setActionSuccess(null);
    try {
      const result = await fn();
      if (!result.ok) setError(friendlyIpcError(result.error, "Não foi possível concluir esta ação."));
      else {
        await after?.();
        if (successMessage) setActionSuccess(successMessage);
      }
    } catch (caught) {
      setError(rejectedIpcError(caught, "Não foi possível concluir esta ação."));
    } finally {
      setBusy(false);
    }
  };

  const acceptGrant = async (grant: HostGrant) => {
    setBusy(true);
    setError(null);
    setActionSuccess(null);
    setHostMutation({ status: "running", message: "Registrando o aceite e verificando o estado da réplica..." });
    try {
      const result = await window.janjacord.acceptHostGrant(grant as unknown as Record<string, unknown>);
      if (!result.ok) {
        setHostMutation({
          status: "error",
          message: friendlyIpcError(result.error, "Não foi possível aceitar esta autorização."),
          kind: "accept",
          grant,
        });
        return;
      }
      setConfirmGrant(null);
      setResourceAccepted(false);
      const refreshed = await loadHosts();
      setHostMutation(refreshed
        ? { status: "success", message: "Aceite registrado. O estado exibido abaixo vem da última confirmação do host; a sincronização não é presumida." }
        : { status: "warning", message: "Aceite registrado, mas não foi possível verificar a sincronização. Atualize a lista de hosts antes de confiar nesta réplica." });
    } catch (caught) {
      setHostMutation({
        status: "error",
        message: rejectedIpcError(caught, "Não foi possível aceitar esta autorização."),
        kind: "accept",
        grant,
      });
    } finally {
      setBusy(false);
    }
  };

  const revokeGrant = async (grant: HostGrant) => {
    setBusy(true);
    setError(null);
    setActionSuccess(null);
    setHostMutation({ status: "running", message: "Revogando a autorização do host..." });
    try {
      const result = await window.janjacord.revokeHostGrant(grant.grantId);
      if (!result.ok) {
        setConfirmRevoke(null);
        requestAnimationFrame(() => hostMutationRef.current?.focus());
        setHostMutation({
          status: "error",
          message: friendlyIpcError(result.error, "Não foi possível revogar esta autorização."),
          kind: "revoke",
          grant,
        });
        return;
      }
      setConfirmRevoke(null);
      requestAnimationFrame(() => hostMutationRef.current?.focus());
      const refreshed = await loadHosts();
      setHostMutation(refreshed
        ? { status: "success", message: "Revogação registrada e lista de hosts atualizada." }
        : { status: "warning", message: "Revogação registrada, mas a lista atualizada não pôde ser confirmada. Tente sincronizar novamente." });
    } catch (caught) {
      setConfirmRevoke(null);
      requestAnimationFrame(() => hostMutationRef.current?.focus());
      setHostMutation({
        status: "error",
        message: rejectedIpcError(caught, "Não foi possível revogar esta autorização."),
        kind: "revoke",
        grant,
      });
    } finally {
      setBusy(false);
    }
  };

  const isOwner = server.me.roleId === "role-owner";

  const moveTabFocus = (event: KeyboardEvent<HTMLButtonElement>, current: Tab) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const index = TABS.findIndex(([value]) => value === current);
    const nextIndex = event.key === "Home"
      ? 0
      : event.key === "End"
        ? TABS.length - 1
        : (index + (event.key === "ArrowRight" ? 1 : -1) + TABS.length) % TABS.length;
    const nextTab = TABS[nextIndex]![0];
    setTab(nextTab);
    requestAnimationFrame(() => tabListRef.current?.querySelector<HTMLElement>(`#settings-tab-${nextTab}`)?.focus());
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      data-smoke-screen="settings"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !showBridgePairing && !showConnectivityWizard) onClose();
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="server-settings-title"
        tabIndex={-1}
        className="settings-dialog flex h-[min(520px,calc(100vh-2rem))] w-[min(760px,calc(100vw-2rem))] min-w-0 flex-col overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900"
        data-smoke-critical="settings-dialog"
      >
        <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-3">
          <h2 id="server-settings-title" className="text-sm font-semibold text-white">Configurações do server</h2>
          <button ref={closeButtonRef} className="icon-button" onClick={onClose} title="Fechar" aria-label="Fechar configurações">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div ref={tabListRef} role="tablist" aria-label="Seções de configuração" className="settings-tablist flex shrink-0 gap-1 overflow-x-auto border-b border-zinc-800 px-3 py-2">
          {TABS.map(([t, label]) => (
            <button
              key={t}
              id={`settings-tab-${t}`}
              role="tab"
              aria-selected={tab === t}
              aria-controls="settings-tab-panel"
              tabIndex={tab === t ? 0 : -1}
              className={`rounded-md px-3 py-1 text-xs ${tab === t ? "bg-zinc-700 text-white" : "text-zinc-400 hover:bg-zinc-800"}`}
              onClick={() => setTab(t)}
              onKeyDown={(event) => moveTabFocus(event, t)}
            >
              {label}
            </button>
          ))}
        </div>
        <div id="settings-tab-panel" role="tabpanel" aria-labelledby={`settings-tab-${tab}`} tabIndex={0} className="min-h-0 flex-1 overflow-y-auto p-4 outline-none">
          {error && <p className="mb-2 text-xs text-red-400">{error}</p>}
          {actionSuccess && <p className="mb-2 text-xs text-emerald-400" role="status">{actionSuccess}</p>}
          {busy && (
            <p className="mb-2 flex items-center gap-2 text-xs text-sky-300" role="status">
              <LoaderCircle className="h-3.5 w-3.5 animate-spin" aria-hidden />
              Aplicando alteração...
            </p>
          )}

          {tab === "members" && (
            <div className="space-y-2">
              {server.members.map((m) => (
                <div key={m.identityId} className="flex items-center justify-between rounded-md border border-zinc-800 px-3 py-2">
                  <div>
                    <p className="text-sm text-zinc-200">{m.nickname}</p>
                    <p className="text-[10px] text-zinc-400">
                      {server.roles.find((r) => r.id === m.roleId)?.name ?? m.roleId}
                      {m.identityId === server.me.identityId ? " (você)" : ""}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {m.identityId !== server.me.identityId && (
                      <select
                        className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs text-zinc-300"
                        value={m.roleId}
                        disabled={!isOwner || busy}
                        onChange={(e) =>
                          run(() => window.janjacord.assignRole(m.identityId, e.target.value), refresh)
                        }
                      >
                        {server.roles.map((r) => (
                          <option key={r.id} value={r.id}>
                            {r.name}
                          </option>
                        ))}
                      </select>
                    )}
                    {m.identityId !== server.me.identityId && (
                      <>
                        <button
                          className="rounded border border-zinc-700 px-2 py-1 text-xs text-amber-300 hover:bg-zinc-800 disabled:opacity-40"
                          disabled={busy}
                          onClick={() => run(() => window.janjacord.memberAction(m.identityId, "kick"), refresh)}
                        >
                          Kick
                        </button>
                        <button
                          className="rounded border border-red-900/60 px-2 py-1 text-xs text-red-400 hover:bg-red-950/40 disabled:opacity-40"
                          disabled={busy}
                          onClick={() => run(() => window.janjacord.memberAction(m.identityId, "ban"), refresh)}
                        >
                          Ban
                        </button>
                      </>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {tab === "roles" && (
            <div className="space-y-3">
              <div className="rounded-md border border-zinc-800 p-3">
                <p className="mb-2 text-xs font-medium text-zinc-300">Nova role</p>
                <div className="flex gap-2">
                  <input
                    className="flex-1 rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs text-zinc-200"
                    placeholder="Nome"
                    value={newRoleName}
                    onChange={(e) => setNewRoleName(e.target.value)}
                  />
                  <input
                    type="number"
                    className="w-16 rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs text-zinc-200"
                    value={newRoleLevel}
                    min={0}
                    max={99}
                    onChange={(e) => setNewRoleLevel(Number(e.target.value))}
                  />
                  <button
                    className="rounded bg-indigo-600 px-3 text-xs text-white hover:bg-indigo-500 disabled:opacity-40"
                    disabled={busy || !newRoleName.trim()}
                    onClick={() =>
                      run(() => window.janjacord.createRole(newRoleName.trim(), newRoleLevel, newRolePerms), () => {
                        setNewRoleName("");
                        setNewRolePerms([]);
                        refresh();
                      })
                    }
                  >
                    Criar
                  </button>
                </div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {Object.entries(PERMISSION_LABELS).map(([flag, label]) => (
                    <button
                      key={flag}
                      className={`rounded-full border px-2 py-0.5 text-[10px] ${
                        newRolePerms.includes(flag)
                          ? "border-indigo-500 bg-indigo-950 text-indigo-300"
                          : "border-zinc-700 text-zinc-400 hover:border-zinc-400"
                      }`}
                      onClick={() =>
                        setNewRolePerms((p) => (p.includes(flag) ? p.filter((x) => x !== flag) : [...p, flag]))
                      }
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
              {server.roles.map((r) => (
                <div key={r.id} className="rounded-md border border-zinc-800 px-3 py-2">
                  <p className="text-sm text-zinc-200">
                    {r.name} <span className="text-[10px] text-zinc-400">nível {r.level}</span>
                  </p>
                  <p className="mt-0.5 text-[10px] text-zinc-400">
                    {r.permissions.length === 0 ? "sem permissões" : r.permissions.map((p) => PERMISSION_LABELS[p] ?? p).join(", ")}
                  </p>
                </div>
              ))}
            </div>
          )}

          {tab === "channels" && (
            <div className="space-y-3">
              <div className="flex gap-2">
                <input
                  className="flex-1 rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs text-zinc-200"
                  placeholder="Nome do canal (ex.: Geral)"
                  value={newChannelName}
                  onChange={(e) => setNewChannelName(e.target.value)}
                />
                <select
                  className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs text-zinc-300"
                  value={newChannelType}
                  onChange={(e) => setNewChannelType(e.target.value as "text" | "call")}
                >
                  <option value="call">🔊 Voz</option>
                  <option value="text"># Texto</option>
                </select>
                <button
                  className="rounded bg-indigo-600 px-3 text-xs text-white hover:bg-indigo-500 disabled:opacity-40"
                  disabled={busy || !newChannelName.trim()}
                  onClick={() =>
                    run(
                      () => window.janjacord.channelCreate(newChannelType, newChannelName.trim()),
                      () => {
                        setNewChannelName("");
                        onClose(); // fecha — o Main re-busca o estado e mostra o canal
                      },
                    )
                  }
                >
                  Criar
                </button>
              </div>
              <div className="space-y-1">
                {server.channels.map((c) => (
                  <div key={c.id} className="rounded-md border border-zinc-800 px-3 py-1.5 text-sm text-zinc-300">
                    {c.type === "text" ? "# " : "🔊 "}
                    {c.name}
                  </div>
                ))}
              </div>
            </div>
          )}

          {tab === "settings" && (
            <div className="space-y-4">
              <div>
                <label className="mb-1 block text-xs text-zinc-400">Retenção máxima de mensagens (ADR-004)</label>
                <select
                  className="w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-200"
                  value={retention}
                  onChange={(e) => setRetention(Number(e.target.value))}
                >
                  <option value={1}>1 hora</option>
                  <option value={24}>24 horas</option>
                  <option value={168}>7 dias (padrão)</option>
                  <option value={720}>30 dias</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-zinc-400">Privacidade de rede (ADR-007)</label>
                <select
                  className="w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-200"
                  value={privacy}
                  onChange={(e) => setPrivacy(e.target.value as "direct" | "relay")}
                >
                  <option value="direct">Direct preferred (P2P + TURN fallback)</option>
                  <option value="relay">Relay only (nunca rota direta)</option>
                </select>
              </div>
              <button
                className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-40"
                disabled={busy || !isOwner}
                onClick={() =>
                  run(
                    () => window.janjacord.updateServerConfig({ maxRetentionHours: retention, networkPrivacy: privacy }),
                    refresh,
                  )
                }
              >
                Salvar configurações
              </button>
              {!isOwner && <p className="text-[11px] text-zinc-400">Somente o Owner pode alterar configurações.</p>}
            </div>
          )}

          {tab === "connectivity" && (
            <div className="space-y-5">
              <div className="settings-row flex items-start justify-between gap-4 border-b border-zinc-800 pb-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <Network className="h-4 w-4 shrink-0 text-sky-400" aria-hidden />
                    <p className="text-sm font-medium text-zinc-200">Acesso externo sem VPS</p>
                  </div>
                  <p className="mt-1 text-xs leading-5 text-zinc-400">Publique este host com Tailscale, ngrok, Cloudflare ou domínio próprio.</p>
                  {!isOwner && <p className="mt-1 text-[11px] text-zinc-500">Somente o Owner pode alterar a rota pública da comunidade.</p>}
                </div>
                <button
                  className="shrink-0 rounded-md bg-sky-600 px-3 py-2 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-40"
                  onClick={() => setShowConnectivityWizard(true)}
                  disabled={!isOwner || connectivityLoadState === "loading"}
                >
                  Configurar conexão
                </button>
              </div>
              <div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-zinc-200">JanjaBridges</p>
                    <p className="mt-0.5 text-xs text-zinc-400">Até três rotas públicas para manter a comunidade alcançável.</p>
                  </div>
                  <button className="flex items-center gap-1.5 rounded-md border border-zinc-700 px-2.5 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800" onClick={() => setShowBridgePairing(true)} disabled={connectivityLoadState === "loading"}>
                    <Plus className="h-3.5 w-3.5" aria-hidden />
                    Adicionar
                  </button>
                </div>
                <div className="mt-3 space-y-2">
                  {connectivityLoadState === "loading" && (
                    <div className="flex items-center gap-2 border-y border-zinc-800 py-4 text-xs text-zinc-300" role="status">
                      <LoaderCircle className="h-4 w-4 animate-spin text-sky-400" aria-hidden />
                      Carregando rotas configuradas...
                    </div>
                  )}
                  {connectivityLoadState === "error" && (
                    <div className="flex items-start justify-between gap-3 border-y border-zinc-800 py-4" role="alert">
                      <p className="text-xs leading-5 text-red-400">{connectivityLoadError}</p>
                      <button className="flex shrink-0 items-center gap-1 text-xs text-zinc-200 hover:text-white" onClick={loadConnectivity}>
                        <RefreshCw className="h-3.5 w-3.5" aria-hidden />
                        Tentar novamente
                      </button>
                    </div>
                  )}
                  {connectivityLoadState === "ready" && bridges.length === 0 && (
                    <div className="flex items-center gap-3 border-y border-zinc-800 py-4 text-xs text-zinc-400">
                      <Link2 className="h-4 w-4" aria-hidden />
                      <span>Nenhum JanjaBridge configurado. A comunidade pode ficar inacessível entre redes restritas.</span>
                    </div>
                  )}
                  {connectivityLoadState === "ready" && bridges.map((bridge) => (
                    <div key={bridge.bridgeId} className="flex items-center justify-between border-b border-zinc-800 py-3">
                      <div className="min-w-0">
                        <p className="truncate text-xs text-zinc-200">{bridge.endpoint}</p>
                        <p className="mt-0.5 text-[10px] text-zinc-400">Válido até {new Date(bridge.expiresAt).toLocaleDateString()}</p>
                      </div>
                      <button
                        className="icon-button shrink-0"
                        title="Remover JanjaBridge"
                        aria-label="Remover JanjaBridge"
                        disabled={busy}
                        onClick={() => run(() => window.janjacord.bridgeRemove(bridge.bridgeId), loadConnectivity, "JanjaBridge removido.")}
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
              {connectivityLoadState === "ready" && <label className="flex items-start justify-between gap-5 border-t border-zinc-800 pt-4">
                <span>
                  <span className="block text-sm text-zinc-200">Iniciar com o computador</span>
                  <span className="mt-0.5 block text-xs leading-5 text-zinc-400">Mantém esta comunidade disponível quando você entrar no sistema.</span>
                </span>
                <input
                  type="checkbox"
                  className="mt-1 h-4 w-4 accent-sky-500"
                  checked={backgroundHosting}
                  disabled={busy}
                  onChange={(event) => {
                    const enabled = event.target.checked;
                    run(() => window.janjacord.setHostingAutostart(enabled), () => setBackgroundHosting(enabled), enabled ? "Inicialização automática ativada." : "Inicialização automática desativada.");
                  }}
                />
              </label>}
            </div>
          )}

          {tab === "hosts" && (
            <div className="space-y-5">
              <div className="settings-row flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm font-medium text-zinc-200">Hosts da comunidade</p>
                  <p className="mt-0.5 text-xs leading-5 text-zinc-400">Dispositivos autorizados ajudam a manter a comunidade disponível.</p>
                </div>
                {!(hosting?.role === "primary" && isOwner) && !hostCandidates.some((candidate) => candidate.subjectIdentityId === server.me.identityId && candidate.expiresAt > Date.now()) && !hostGrants.some((grant) => grant.subjectIdentityId === server.me.identityId && !grant.revokedAt && grant.expiresAt > Date.now()) && (
                  <button
                    className="rounded-md border border-sky-800 px-3 py-2 text-xs text-sky-300 hover:bg-sky-950/50"
                    disabled={busy || hostsState !== "ready"}
                    onClick={() => run(() => window.janjacord.registerHostCandidate(), loadHosts, "Este dispositivo foi apresentado aos administradores.")}
                  >
                    Ajudar a manter online
                  </button>
                )}
              </div>

              {hostsState === "ready" && !canManageHosts && (
                <p className="text-xs leading-5 text-zinc-400">Modo somente leitura: sua função {currentRole?.name ? `“${currentRole.name}”` : "atual"} não possui a permissão Gerenciar hosts.</p>
              )}

              {hostMutation.status !== "idle" && (
                <div
                  ref={hostMutationRef}
                  tabIndex={-1}
                  className={`flex items-start justify-between gap-3 rounded-md border p-3 ${
                    hostMutation.status === "error"
                      ? "border-red-900/70 bg-red-950/30 text-red-300"
                      : hostMutation.status === "warning"
                        ? "border-amber-900/70 bg-amber-950/30 text-amber-200"
                        : hostMutation.status === "success"
                          ? "border-emerald-900/70 bg-emerald-950/30 text-emerald-200"
                          : "border-sky-900/70 bg-sky-950/30 text-sky-200"
                  }`}
                  role={hostMutation.status === "error" ? "alert" : "status"}
                >
                  <p className="text-xs leading-5">{hostMutation.message}</p>
                  {hostMutation.status === "running" && <LoaderCircle className="h-4 w-4 shrink-0 animate-spin" aria-hidden />}
                  {hostMutation.status === "warning" && (
                    <button className="flex shrink-0 items-center gap-1 text-xs text-zinc-100 hover:text-white" onClick={async () => {
                      if (await loadHosts()) setHostMutation({ status: "success", message: "Lista de hosts sincronizada. Os estados exibidos são os últimos confirmados pelo host." });
                    }}>
                      <RefreshCw className="h-3.5 w-3.5" aria-hidden />
                      Verificar novamente
                    </button>
                  )}
                  {hostMutation.status === "error" && (
                    <button
                      ref={hostRetryRef}
                      className="flex shrink-0 items-center gap-1 text-xs text-zinc-100 hover:text-white"
                      onClick={() => hostMutation.kind === "accept" ? void acceptGrant(hostMutation.grant) : void revokeGrant(hostMutation.grant)}
                    >
                      <RefreshCw className="h-3.5 w-3.5" aria-hidden />
                      Tentar novamente
                    </button>
                  )}
                </div>
              )}

              {hostsState === "loading" && (
                <div className="flex items-center gap-2 border-y border-zinc-800 py-4 text-xs text-zinc-300" role="status">
                  <LoaderCircle className="h-4 w-4 animate-spin text-sky-400" aria-hidden />
                  Carregando autorizações de host...
                </div>
              )}
              {hostsState === "error" && (
                <div className="flex items-start justify-between gap-3 border-y border-zinc-800 py-4" role="alert">
                  <p className="text-xs leading-5 text-red-400">{hostsError}</p>
                  <button className="flex shrink-0 items-center gap-1 text-xs text-zinc-200 hover:text-white" onClick={loadHosts}>
                    <RefreshCw className="h-3.5 w-3.5" aria-hidden />
                    Tentar novamente
                  </button>
                </div>
              )}

              {hostsState === "ready" && hosting && !hostGrants.some((grant) => (
                grant.subjectIdentityId === server.me.identityId
                && Boolean(grant.acceptedAt)
                && !grant.revokedAt
                && grant.expiresAt > Date.now()
              )) && (
                <div className="host-row flex items-center justify-between gap-3 border-y border-zinc-800 py-3">
                  <div>
                    <p className="text-sm text-zinc-200">Host desta sessão</p>
                    <p className="text-xs text-zinc-400">{hosting.role === "primary" ? "Primary Host" : "Replica Host"}</p>
                  </div>
                  <span className={`text-xs ${hosting.writer ? "text-emerald-400" : "text-zinc-300"}`}>
                    {hosting.writer ? "Autorizado · com escrita" : "Autorizado · somente leitura"}
                  </span>
                </div>
              )}

              {hostsState === "ready" && canManageHosts && hostCandidates.map((candidate) => {
                const existing = hostGrants.find((grant) => grant.hostId === candidate.hostId && !grant.revokedAt && grant.expiresAt > Date.now());
                const expired = candidate.expiresAt <= Date.now();
                const hostIdentity = presentHostIdentity(candidate.subjectIdentityId, candidate.hostId, server.members, server.me);
                return (
                  <div key={candidate.candidateId} className="host-row flex items-center justify-between gap-3 border-b border-zinc-800 py-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm text-zinc-200" title={hostIdentity.label}>{hostIdentity.label}</p>
                      <p className={`text-xs ${expired ? "text-zinc-400" : "text-zinc-300"}`}>{expired ? "Candidatura expirada" : "Solicitou autorização para hospedar"}</p>
                    </div>
                    {existing ? (
                      <span className={`text-xs ${existing.acceptedAt ? "text-sky-300" : "text-amber-300"}`}>{existing.acceptedAt ? "Já autorizado" : "Aguardando aceite"}</span>
                    ) : !expired ? (
                      <button
                        className="rounded-md border border-zinc-700 px-2.5 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 disabled:opacity-50"
                        disabled={busy}
                        onClick={() => run(() => window.janjacord.authorizeHostCandidate(candidate.subjectIdentityId, candidate.candidateId), loadHosts, `Autorização enviada para ${hostIdentity.nickname}.`)}
                      >
                        Autorizar
                      </button>
                    ) : null}
                  </div>
                );
              })}

              {hostsState === "ready" && uniqueHostGrants(hostGrants).map((grant) => {
                const own = grant.subjectIdentityId === server.me.identityId;
                const expired = grant.expiresAt <= Date.now();
                const activeHere = own && grant.acceptedAt && Boolean(hosting);
                const hostIdentity = presentHostIdentity(grant.subjectIdentityId, grant.hostId, server.members, server.me);
                const status = grant.revokedAt
                  ? "Revogado"
                  : expired
                    ? "Expirado"
                    : !grant.acceptedAt
                      ? "Aguardando aceite"
                      : activeHere
                        ? `${hosting?.role === "primary" ? "Primary" : "Réplica"} nesta sessão · ${hosting?.writer ? "com escrita" : "somente leitura"}`
                        : "Aceite registrado · sincronização não verificada";
                return (
                  <div key={grant.grantId} data-host-grant-id={grant.grantId} className="border-b border-zinc-800 py-3">
                    <div className="host-row flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <p className="truncate text-sm text-zinc-200" title={hostIdentity.label}>{hostIdentity.label}</p>
                        <p className={`text-xs ${grant.revokedAt || expired ? "text-red-400" : grant.acceptedAt ? "text-sky-300" : "text-amber-300"}`}>{status}</p>
                        {grant.lastActivityAt && <p className="mt-0.5 text-xs text-zinc-400">Última atividade informada pelo host: {new Date(grant.lastActivityAt).toLocaleString()}</p>}
                      </div>
                      <div className="host-actions flex shrink-0 gap-2">
                        {!grant.revokedAt && !expired && !grant.acceptedAt && own && (
                          <button className="rounded-md bg-sky-600 px-2.5 py-1.5 text-xs text-white hover:bg-sky-500 disabled:opacity-50" disabled={busy} onClick={() => { setConfirmRevoke(null); setConfirmGrant(grant); setResourceAccepted(false); }}>
                            Revisar e aceitar
                          </button>
                        )}
                        {!grant.revokedAt && !expired && canManageHosts && (
                          <button className="rounded-md border border-red-900/60 px-2.5 py-1.5 text-xs text-red-400 hover:bg-red-950/40 disabled:opacity-50" disabled={busy} onClick={(event) => { revokeReturnFocusRef.current = event.currentTarget; setConfirmGrant(null); setConfirmRevoke(grant); }}>
                            Revogar
                          </button>
                        )}
                      </div>
                    </div>
                    {confirmGrant?.grantId === grant.grantId && (
                      <div className="mt-3 rounded-md border border-sky-900 bg-sky-950/30 p-3">
                        <p className="flex items-center gap-2 text-xs font-medium text-sky-200"><ShieldCheck className="h-4 w-4" aria-hidden />Antes de aceitar</p>
                        <ul className="mt-2 space-y-1.5 text-xs leading-5 text-zinc-300">
                          <li className="flex gap-2"><HardDrive className="mt-0.5 h-3.5 w-3.5 shrink-0 text-zinc-400" aria-hidden />Este dispositivo armazenará uma réplica cifrada da comunidade.</li>
                          <li className="flex gap-2"><Network className="mt-0.5 h-3.5 w-3.5 shrink-0 text-zinc-400" aria-hidden />Hospedar usa rede, disco e processamento; o consumo varia com a atividade.</li>
                          <li>Capacidades autorizadas: {grant.capabilities.join(", ") || "não informadas"}.</li>
                        </ul>
                        <label className="mt-3 flex items-start gap-2 text-xs leading-5 text-zinc-200">
                          <input type="checkbox" className="mt-1 h-4 w-4 accent-sky-500" checked={resourceAccepted} onChange={(event) => setResourceAccepted(event.target.checked)} />
                          Entendo que este dispositivo poderá operar em segundo plano e aceito disponibilizar esses recursos.
                        </label>
                        <div className="settings-actions mt-3 flex gap-2">
                          <button className="rounded-md bg-sky-600 px-3 py-2 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-40" disabled={!resourceAccepted || busy} onClick={() => void acceptGrant(grant)}>Aceitar autorização</button>
                          <button className="rounded-md border border-zinc-700 px-3 py-2 text-xs text-zinc-200 hover:bg-zinc-800" onClick={() => setConfirmGrant(null)} disabled={busy}>Cancelar</button>
                        </div>
                      </div>
                    )}
                    {confirmRevoke?.grantId === grant.grantId && (
                      <div
                        className="fixed inset-0 z-[70] flex items-center justify-center bg-black/75 p-4"
                        onMouseDown={(event) => {
                          if (event.target === event.currentTarget) confirmRevokeButtonRef.current?.focus();
                        }}
                      >
                        <div ref={revokeDialogRef} className="w-full max-w-md rounded-md border border-red-900/70 bg-zinc-950 p-4 shadow-2xl" role="alertdialog" aria-modal="true" aria-labelledby={`revoke-title-${grant.grantId}`} onKeyDown={handleRevokeDialogKeyDown}>
                          <p id={`revoke-title-${grant.grantId}`} className="text-sm font-medium text-red-200">Revogar autorização deste host?</p>
                          <p className="mt-2 text-xs leading-5 text-zinc-300">
                            O dispositivo perderá a autorização para hospedar, escrever ou ser promovido. Se esta for a única réplica disponível, a comunidade poderá ficar menos disponível.
                          </p>
                          <p className="mt-1 text-xs text-zinc-400">Host afetado: <span className="font-medium text-zinc-200">{hostIdentity.label}</span>.</p>
                          <div className="settings-actions mt-4 flex gap-2">
                            <button ref={confirmRevokeButtonRef} className="rounded-md bg-red-700 px-3 py-2 text-xs font-medium text-white hover:bg-red-600 disabled:opacity-40" disabled={busy} onClick={() => void revokeGrant(grant)}>Confirmar revogação</button>
                            <button className="rounded-md border border-zinc-700 px-3 py-2 text-xs text-zinc-200 hover:bg-zinc-800" onClick={closeRevokeConfirmation} disabled={busy}>Manter autorização</button>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
              {hostsState === "ready" && hostCandidates.length === 0 && hostGrants.length === 0 && !hosting && (
                <div className="rounded-md border border-zinc-800 p-4 text-xs leading-5 text-zinc-400">
                  {canManageHosts ? "Nenhum outro dispositivo solicitou autorização para hospedar." : "Este dispositivo ainda não recebeu autorização para hospedar a comunidade."}
                </div>
              )}
            </div>
          )}

          {tab === "invites" && (
            <div className="space-y-2">
              {invitesState === "loading" && (
                <div className="flex items-center gap-2 py-4 text-xs text-zinc-300" role="status">
                  <LoaderCircle className="h-4 w-4 animate-spin text-sky-400" aria-hidden />
                  Carregando convites...
                </div>
              )}
              {invitesState === "error" && (
                <div className="flex items-start justify-between gap-3 py-4" role="alert">
                  <p className="text-xs leading-5 text-red-400">{invitesError}</p>
                  <button className="flex shrink-0 items-center gap-1 text-xs text-zinc-200 hover:text-white" onClick={loadInvites}>
                    <RefreshCw className="h-3.5 w-3.5" aria-hidden />
                    Tentar novamente
                  </button>
                </div>
              )}
              {invitesState === "ready" && invites.length === 0 && <p className="text-xs leading-5 text-zinc-400">Nenhum convite ativo. Crie um convite pela barra lateral da comunidade.</p>}
              {invitesState === "ready" && invites.map((inv) => (
                <div key={inv.id} className="flex items-center justify-between rounded-md border border-zinc-800 px-3 py-2">
                  <p className="text-xs text-zinc-300">
                    usos {inv.used}/{inv.max_uses} {inv.revoked ? "· revogado" : "· ativo"}
                  </p>
                  <button
                    className="rounded border border-zinc-700 px-2 py-1 text-[10px] text-zinc-400 hover:bg-zinc-800 disabled:opacity-40"
                    disabled={busy || !!inv.revoked}
                    onClick={() => run(() => window.janjacord.revokeInvite(inv.id), loadInvites, "Convite revogado.")}
                  >
                    Revogar
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
      {showConnectivityWizard && (
        <ConnectivityWizard
          onClose={() => setShowConnectivityWizard(false)}
          onChanged={loadConnectivity}
          onOpenAdvanced={() => setShowBridgePairing(true)}
        />
      )}
      {showBridgePairing && <BridgePairingDialog onClose={() => setShowBridgePairing(false)} onAdded={loadConnectivity} />}
    </div>
  );

  async function refresh() {
    try {
      const result = await window.janjacord.serverState();
      if (!result.ok || !result.data) {
        setError(friendlyIpcError(result.error, "Não foi possível atualizar as configurações."));
        return;
      }
      const next = result.data as ServerState;
      setRetention(next.config?.maxRetentionHours ?? 168);
      setPrivacy(next.config?.networkPrivacy ?? "direct");
      setHostCandidates(next.hostCandidates ?? []);
      setHostGrants(next.hostGrants ?? []);
      setHosting(next.hosting);
    } catch (caught) {
      setError(rejectedIpcError(caught, "Não foi possível atualizar as configurações."));
    }
  }
}

function uniqueHostGrants(grants: HostGrant[]): HostGrant[] {
  const byHost = new Map<string, HostGrant>();
  for (const grant of grants) {
    const current = byHost.get(grant.hostId);
    if (!current || grant.expiresAt > current.expiresAt || Boolean(current.revokedAt) && !grant.revokedAt) {
      byHost.set(grant.hostId, grant);
    }
  }
  return [...byHost.values()];
}

export function shortDeviceId(hostId: string): string {
  const stablePart = hostId.trim().replace(/^(?:host|primary)-/i, "");
  const readable = stablePart.replace(/[^a-z0-9]/gi, "").toUpperCase();
  if (!readable) return "ID indisponível";
  if (readable.length <= 8) return readable;
  return `${readable.slice(0, 4)}-${readable.slice(-4)}`;
}

export function presentHostIdentity(
  subjectIdentityId: string,
  hostId: string,
  members: Pick<Member, "identityId" | "nickname">[],
  me: Pick<ServerState["me"], "identityId" | "nickname">,
): { nickname: string; deviceId: string; label: string } {
  const listedMember = members.find((member) => member.identityId === subjectIdentityId);
  const nickname = listedMember?.nickname.trim()
    || (subjectIdentityId === me.identityId ? me.nickname.trim() : "")
    || "Membro não disponível";
  const deviceId = shortDeviceId(hostId);
  return { nickname, deviceId, label: `${nickname} · dispositivo ${deviceId}` };
}
