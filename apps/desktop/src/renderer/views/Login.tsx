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
    if (mode === "restore" && !recoveryKey.trim()) return setError("Informe a recovery key.");
    if (mode === "restore" && !nickname.trim()) return setError("Informe o nickname da identidade.");
    if (!password) return setError("Informe a senha.");
    setBusy(true);
    try {
      const res =
        mode === "login"
          ? await onUnlock(password)
          : await onRestore(recoveryKey.trim(), nickname, password);
      if (!res.ok) setError(res.error?.message ?? "Não foi possível concluir esta ação.");
    } catch {
      setError("Não foi possível acessar o cofre local.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="auth-card mx-4 w-full max-w-[380px] overflow-y-auto rounded-xl border border-zinc-800 bg-zinc-900/60 p-5 sm:p-8"
      data-smoke-screen="login"
      onSubmit={(event) => {
        event.preventDefault();
        if (!busy) void submit();
      }}
    >
      <h1 className="text-xl font-semibold text-white">Desbloquear identidade</h1>
      <div className="mt-5 space-y-3 sm:mt-6">
        {mode === "restore" && (
          <>
            <label className="block text-xs font-medium text-zinc-300" htmlFor="restore-recovery-key">Recovery key</label>
            <input
              id="restore-recovery-key"
              className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-indigo-500"
              placeholder="Recovery key (XXXX-…)"
              value={recoveryKey}
              onChange={(e) => setRecoveryKey(e.target.value)}
              autoComplete="off"
              required
            />
            <label className="block text-xs font-medium text-zinc-300" htmlFor="restore-nickname">Nickname</label>
            <input
              id="restore-nickname"
              className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-indigo-500"
              placeholder="Nickname"
              value={nickname}
              onChange={(e) => setNickname(e.target.value)}
              autoComplete="nickname"
              required
            />
          </>
        )}
        <label className="block text-xs font-medium text-zinc-300" htmlFor="login-password">
          {mode === "login" ? "Senha" : "Nova senha"}
        </label>
        <input
          id="login-password"
          className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          placeholder={mode === "login" ? "Senha" : "Nova senha"}
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete={mode === "login" ? "current-password" : "new-password"}
          required
          autoFocus
        />
        {error && <p className="text-xs text-red-400" role="alert">{error}</p>}
        <button
          type="submit"
          className="w-full rounded-md bg-indigo-600 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
          disabled={busy}
        >
          {busy ? "Aguarde…" : mode === "login" ? "Desbloquear" : "Restaurar identidade"}
        </button>
        <button
          type="button"
          className="w-full text-xs text-zinc-400 hover:text-zinc-200"
          onClick={() => {
            setError(null);
            setMode(mode === "login" ? "restore" : "login");
          }}
        >
          {mode === "login" ? "Perdeu o acesso? Restaurar com recovery key" : "Voltar para desbloqueio"}
        </button>
      </div>
    </form>
  );
}
