import { useEffect, useState } from "react";

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
}

const PERMISSION_LABELS: Record<string, string> = {
  manage_server: "Gerenciar server",
  manage_channels: "Gerenciar canais",
  manage_roles: "Gerenciar roles",
  manage_invites: "Gerenciar convites",
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

type Tab = "members" | "roles" | "settings" | "invites";

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

  const loadInvites = async () => {
    const r = await window.janjacord.listInvites();
    if (r.ok && r.data) setInvites(r.data as typeof invites);
  };
  useEffect(() => {
    if (tab === "invites") loadInvites();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab]);

  const run = async (fn: () => Promise<{ ok: boolean; error?: { message: string } }>, after?: () => void) => {
    setBusy(true);
    setError(null);
    const r = await fn();
    setBusy(false);
    if (!r.ok) setError(r.error?.message ?? "Falha.");
    else after?.();
  };

  const isOwner = server.me.roleId === "role-owner";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="flex h-[520px] w-[640px] flex-col rounded-xl border border-zinc-800 bg-zinc-900"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-3">
          <h2 className="text-sm font-semibold text-white">Configurações do server</h2>
          <button className="text-zinc-500 hover:text-zinc-300" onClick={onClose}>
            ✕
          </button>
        </div>
        <div className="flex gap-1 border-b border-zinc-800 px-3 py-2">
          {(
            [
              ["members", "Membros"],
              ["roles", "Roles"],
              ["settings", "Configurações"],
              ["invites", "Convites"],
            ] as [Tab, string][]
          ).map(([t, label]) => (
            <button
              key={t}
              className={`rounded-md px-3 py-1 text-xs ${tab === t ? "bg-zinc-700 text-white" : "text-zinc-400 hover:bg-zinc-800"}`}
              onClick={() => setTab(t)}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="flex-1 overflow-y-auto p-4">
          {error && <p className="mb-2 text-xs text-red-400">{error}</p>}

          {tab === "members" && (
            <div className="space-y-2">
              {server.members.map((m) => (
                <div key={m.identityId} className="flex items-center justify-between rounded-md border border-zinc-800 px-3 py-2">
                  <div>
                    <p className="text-sm text-zinc-200">{m.nickname}</p>
                    <p className="text-[10px] text-zinc-500">
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
                          : "border-zinc-700 text-zinc-500 hover:border-zinc-500"
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
                    {r.name} <span className="text-[10px] text-zinc-500">nível {r.level}</span>
                  </p>
                  <p className="mt-0.5 text-[10px] text-zinc-500">
                    {r.permissions.length === 0 ? "sem permissões" : r.permissions.map((p) => PERMISSION_LABELS[p] ?? p).join(", ")}
                  </p>
                </div>
              ))}
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
              {!isOwner && <p className="text-[11px] text-zinc-500">Somente o Owner pode alterar configurações.</p>}
            </div>
          )}

          {tab === "invites" && (
            <div className="space-y-2">
              {invites.length === 0 && <p className="text-xs text-zinc-500">Nenhum convite ativo.</p>}
              {invites.map((inv) => (
                <div key={inv.id} className="flex items-center justify-between rounded-md border border-zinc-800 px-3 py-2">
                  <p className="text-xs text-zinc-300">
                    usos {inv.used}/{inv.max_uses} {inv.revoked ? "· revogado" : "· ativo"}
                  </p>
                  <button
                    className="rounded border border-zinc-700 px-2 py-1 text-[10px] text-zinc-400 hover:bg-zinc-800 disabled:opacity-40"
                    disabled={busy || !!inv.revoked}
                    onClick={() => run(() => window.janjacord.revokeInvite(inv.id), loadInvites)}
                  >
                    Revogar
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );

  function refresh() {
    window.janjacord.serverState().then((r) => {
      if (r.ok && r.data) {
        const s = r.data as ServerState;
        setRetention(s.config?.maxRetentionHours ?? 168);
        setPrivacy(s.config?.networkPrivacy ?? "direct");
      }
    });
  }
}
