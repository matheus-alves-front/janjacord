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
    if (password !== confirm) return setError("As senhas não conferem.");
    if (password.length < 8) return setError("Senha muito curta (mínimo 8 caracteres).");
    setBusy(true);
    const res = await onCreate(nickname, password);
    setBusy(false);
    if (!res.ok) setError(res.error?.message ?? "Falha ao criar identidade.");
  };

  return (
    <div className="w-[380px] rounded-xl border border-zinc-800 bg-zinc-900/60 p-8">
      <h1 className="text-xl font-semibold text-white">JanjaCord</h1>
      <p className="mt-1 text-sm text-zinc-400">
        Comunicador privado de comunidades. Sem email, sem telefone — sua identidade vive só no
        seu dispositivo.
      </p>
      <div className="mt-6 space-y-3">
        <input
          className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          placeholder="Nickname"
          value={nickname}
          onChange={(e) => setNickname(e.target.value)}
          autoFocus
        />
        <input
          className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          placeholder="Senha"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <input
          className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none focus:border-indigo-500"
          placeholder="Confirmar senha"
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        {error && <p className="text-xs text-red-400">{error}</p>}
        <button
          className="w-full rounded-md bg-indigo-600 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
          onClick={submit}
          disabled={busy}
        >
          {busy ? "Criando…" : "Criar identidade"}
        </button>
        <p className="text-[11px] leading-relaxed text-zinc-500">
          Sua senha protege apenas o vault local. A chave de recuperação será mostrada na próxima
          tela — anote-a, pois sem ela a identidade não pode ser recuperada.
        </p>
      </div>
    </div>
  );
}
