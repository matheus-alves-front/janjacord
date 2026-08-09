import { useState } from "react";

export function Login({
  onUnlock,
  onRestore,
}: {
  onUnlock: (password: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  onRestore: (recoveryKey: string, nickname: string, password: string) => Promise<{ ok: boolean; error?: { message: string } }>;
}) {
  const [password, setPassword] = useState("");
  const [mode, setMode] = useState<"login" | "restore">("login");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [nickname, setNickname] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError(null);
    setBusy(true);
    const res =
      mode === "login"
        ? await onUnlock(password)
        : await onRestore(recoveryKey.trim(), nickname, password);
    setBusy(false);
    if (!res.ok) setError(res.error?.message ?? "Falha.");
  };

  return (
    <div className="w-[380px] rounded-xl border border-zinc-800 bg-zinc-900/60 p-8">
      <h1 className="text-xl font-semibold text-white">Desbloquear identidade</h1>
      <div className="mt-6 space-y-3">
        {mode === "restore" && (
          <>
            <input
              className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-indigo-500"
              placeholder="Recovery key (XXXX-…)"
              value={recoveryKey}
              onChange={(e) => setRecoveryKey(e.target.value)}
            />
            <input
              className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-indigo-500"
              placeholder="Nickname"
              value={nickname}
              onChange={(e) => setNickname(e.target.value)}
            />
          </>
        )}
        <input
          className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          placeholder="Nova senha"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoFocus
        />
        {error && <p className="text-xs text-red-400">{error}</p>}
        <button
          className="w-full rounded-md bg-indigo-600 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
          onClick={submit}
          disabled={busy}
        >
          {busy ? "Aguarde…" : mode === "login" ? "Desbloquear" : "Restaurar identidade"}
        </button>
        <button
          className="w-full text-xs text-zinc-500 hover:text-zinc-300"
          onClick={() => setMode(mode === "login" ? "restore" : "login")}
        >
          {mode === "login" ? "Perdeu o acesso? Restaurar com recovery key" : "Voltar para desbloqueio"}
        </button>
      </div>
    </div>
  );
}
