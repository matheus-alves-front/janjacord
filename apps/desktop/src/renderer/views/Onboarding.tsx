import { useState } from "react";

export function Onboarding({
  onCreate,
}: {
  onCreate: (nickname: string, password: string) => Promise<{ ok: boolean; error?: { message: string } }>;
}) {
  const [nickname, setNickname] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError(null);
    if (!nickname.trim()) return setError("Informe como você quer ser chamado.");
    if (password !== confirm) return setError("As senhas não conferem.");
    if (password.length < 8) return setError("Senha muito curta (mínimo 8 caracteres).");
    setBusy(true);
    try {
      const res = await onCreate(nickname, password);
      if (!res.ok) setError(res.error?.message ?? "Falha ao criar identidade.");
    } catch {
      setError("Não foi possível criar a identidade local.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="auth-card mx-4 w-full max-w-[380px] overflow-y-auto rounded-xl border border-zinc-800 bg-zinc-900/60 p-5 sm:p-8"
      data-smoke-screen="onboarding"
      onSubmit={(event) => {
        event.preventDefault();
        if (!busy) void submit();
      }}
    >
      <h1 className="text-xl font-semibold text-white">JanjaCord</h1>
      <p className="mt-1 text-sm text-zinc-400">
        Comunicador privado de comunidades. Sem email, sem telefone — sua identidade vive só no
        seu dispositivo.
      </p>
      <div className="mt-5 space-y-3 sm:mt-6">
        <label className="block text-xs font-medium text-zinc-300" htmlFor="onboarding-nickname">Nickname</label>
        <input
          id="onboarding-nickname"
          className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          placeholder="Nickname"
          value={nickname}
          onChange={(e) => setNickname(e.target.value)}
          autoComplete="nickname"
          required
          autoFocus
        />
        <label className="block text-xs font-medium text-zinc-300" htmlFor="onboarding-password">Senha</label>
        <input
          id="onboarding-password"
          className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          placeholder="Senha"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
          minLength={8}
          required
        />
        <label className="block text-xs font-medium text-zinc-300" htmlFor="onboarding-confirm">Confirmar senha</label>
        <input
          id="onboarding-confirm"
          className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          placeholder="Confirmar senha"
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password"
          minLength={8}
          required
        />
        {error && <p className="text-xs text-red-400" role="alert">{error}</p>}
        <button
          type="submit"
          className="w-full rounded-md bg-indigo-600 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
          disabled={busy}
        >
          {busy ? "Criando…" : "Criar identidade"}
        </button>
        <p className="text-[11px] leading-relaxed text-zinc-400">
          Guarde a chave de recuperação mostrada na próxima tela.
        </p>
      </div>
    </form>
  );
}
