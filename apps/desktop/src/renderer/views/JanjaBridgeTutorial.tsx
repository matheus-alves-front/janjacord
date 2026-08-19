import { useEffect, useRef, useState } from "react";
import { ArrowLeft, ArrowRight, Check, CheckCircle2, Clipboard, HardDrive, KeyRound, Link2, Network, ShieldAlert, TriangleAlert, X } from "lucide-react";

type TutorialStepId = "prerequisites" | "network" | "deploy" | "pairing" | "connect";

interface TutorialStep {
  id: TutorialStepId;
  eyebrow: string;
  title: string;
}

const TUTORIAL_STEPS: TutorialStep[] = [
  { id: "prerequisites", eyebrow: "Antes de começar", title: "Prepare o host" },
  { id: "network", eyebrow: "DNS e firewall", title: "Abra o caminho" },
  { id: "deploy", eyebrow: "Docker Compose", title: "Suba o JanjaBridge" },
  { id: "pairing", eyebrow: "Autorização", title: "Gere o pairing" },
  { id: "connect", eyebrow: "No JanjaCord", title: "Conecte e valide" },
];

export const JANJABRIDGE_SETUP_COMMANDS = {
  initialize: `cd /caminho/para/janjacord/infra/docker
./scripts/init.sh bridge.example.com ops@example.com 203.0.113.10 turn.bridge.example.com`,
  start: `docker compose config --quiet
docker compose up -d --build
./scripts/issue-certificate.sh
docker compose ps`,
  pairing: "./scripts/mint-pairing.sh 24",
  diagnose: "docker compose logs --since=15m gateway rendezvous coturn",
} as const;

const FOCUSABLE = "button:not([disabled]), input:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";

function CodeBlock({ id, value, copied, onCopy }: { id: string; value: string; copied: boolean; onCopy: (id: string, value: string) => void }) {
  return (
    <div className="relative mt-3 overflow-hidden rounded-lg border border-zinc-700 bg-zinc-950">
      <pre className="overflow-x-auto p-3 pr-12 font-mono text-[11px] leading-5 text-sky-100"><code>{value}</code></pre>
      <button
        className="absolute right-2 top-2 inline-flex h-8 w-8 items-center justify-center rounded-md border border-zinc-700 bg-zinc-900 text-zinc-300 hover:border-sky-500 hover:text-white"
        onClick={() => onCopy(id, value)}
        title={copied ? "Comando copiado" : "Copiar comando"}
        aria-label={copied ? "Comando copiado" : "Copiar comando"}
      >
        {copied ? <Check className="h-4 w-4 text-emerald-300" aria-hidden /> : <Clipboard className="h-4 w-4" aria-hidden />}
      </button>
    </div>
  );
}

function Bullet({ children }: { children: React.ReactNode }) {
  return <li className="flex items-start gap-2 text-xs leading-5 text-zinc-300"><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" aria-hidden /><span>{children}</span></li>;
}

export function JanjaBridgeTutorial({ onClose, onOpenPairing }: { onClose: () => void; onOpenPairing: () => void }) {
  const [stepIndex, setStepIndex] = useState(0);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const requestCloseRef = useRef(onClose);
  requestCloseRef.current = onClose;
  const step = TUTORIAL_STEPS[stepIndex]!;

  useEffect(() => {
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    requestAnimationFrame(() => dialogRef.current?.focus());
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        requestCloseRef.current();
        return;
      }
      if (event.key !== "Tab" || !dialogRef.current) return;
      const focusable = [...dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((element) => element.offsetParent !== null);
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
    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      previousFocusRef.current?.focus();
    };
  }, []);

  const copy = async (id: string, value: string) => {
    try {
      const result = await window.janjacord.clipboardWriteText(value);
      if (!result.ok) throw new Error(result.error?.message ?? "clipboard_unavailable");
      setCopiedId(id);
      setCopyError(null);
      window.setTimeout(() => setCopiedId((current) => current === id ? null : current), 2200);
    } catch {
      setCopiedId(null);
      setCopyError("Não foi possível copiar. Selecione o bloco manualmente e use Ctrl/Cmd+C.");
    }
  };

  const next = () => setStepIndex((current) => Math.min(TUTORIAL_STEPS.length - 1, current + 1));
  const previous = () => setStepIndex((current) => Math.max(0, current - 1));

  return (
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center bg-black/75 p-3 sm:p-4"
      data-smoke-screen="janjabridge-tutorial"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="janjabridge-tutorial-title"
        aria-describedby="janjabridge-tutorial-description"
        tabIndex={-1}
        className="flex max-h-[calc(100vh-1.5rem)] w-full max-w-[720px] min-w-0 flex-col overflow-hidden rounded-xl border border-zinc-700 bg-zinc-900 shadow-2xl"
      >
        <header className="shrink-0 border-b border-zinc-800 px-4 py-3 sm:px-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex min-w-0 items-start gap-3">
              <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-sky-500/15 text-sky-300"><Network className="h-4 w-4" aria-hidden /></div>
              <div className="min-w-0">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-sky-400">Tutorial servidor JanjaBridge</p>
                <h2 id="janjabridge-tutorial-title" className="mt-1 text-sm font-semibold text-white">Coloque um bridge público no ar</h2>
                <p id="janjabridge-tutorial-description" className="mt-1 max-w-2xl text-xs leading-5 text-zinc-400">Siga os passos no seu host Linux e depois cole o pairing aqui. O bridge auxilia a conexão; ele não hospeda o conteúdo da comunidade.</p>
              </div>
            </div>
            <button className="icon-button shrink-0" onClick={onClose} title="Fechar tutorial" aria-label="Fechar tutorial"><X className="h-4 w-4" aria-hidden /></button>
          </div>
          <div className="mt-4 flex items-center gap-2" aria-label={`Passo ${stepIndex + 1} de ${TUTORIAL_STEPS.length}`}>
            {TUTORIAL_STEPS.map((item, index) => (
              <div key={item.id} className="flex min-w-0 flex-1 items-center gap-2">
                <span className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold ${index === stepIndex ? "bg-sky-500 text-slate-950" : index < stepIndex ? "bg-emerald-500/20 text-emerald-300" : "bg-zinc-800 text-zinc-500"}`}>{index < stepIndex ? <Check className="h-3.5 w-3.5" aria-hidden /> : index + 1}</span>
                <span className={`hidden truncate text-[10px] sm:block ${index === stepIndex ? "text-zinc-200" : "text-zinc-500"}`}>{item.title}</span>
                {index < TUTORIAL_STEPS.length - 1 && <span className={`h-px min-w-2 flex-1 ${index < stepIndex ? "bg-emerald-700" : "bg-zinc-800"}`} aria-hidden />}
              </div>
            ))}
          </div>
        </header>

        <main className="min-h-0 flex-1 overflow-y-auto px-4 py-5 sm:px-6" aria-live="polite">
          <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500"><span>Passo {stepIndex + 1} de {TUTORIAL_STEPS.length}</span><span aria-hidden>·</span><span>{step.eyebrow}</span></div>
          <h3 className="mt-2 text-lg font-semibold text-zinc-100">{step.title}</h3>

          {step.id === "prerequisites" && (
            <div className="mt-4 space-y-4">
              <div className="flex items-start gap-3 border-y border-zinc-800 py-4">
                <HardDrive className="mt-0.5 h-5 w-5 shrink-0 text-sky-300" aria-hidden />
                <div><p className="text-sm font-medium text-zinc-200">O que você precisa</p><ul className="mt-3 space-y-2"><Bullet>Um host Linux público com Docker Engine e Docker Compose v2.</Bullet><Bullet>Node.js 22+ e OpenSSL no host, executados pelo mesmo usuário não-root que usará o Compose.</Bullet><Bullet>Dois hostnames DNS A apontando para o mesmo IPv4: um para WSS e outro exclusivo para TURN.</Bullet><Bullet>Relógio sincronizado por NTP e acesso para ajustar o firewall/NAT.</Bullet></ul></div>
              </div>
              <div className="rounded-lg border border-amber-800/60 bg-amber-950/20 p-3"><div className="flex items-start gap-2"><ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" aria-hidden /><p className="text-xs leading-5 text-amber-100">O JanjaBridge é opcional e avançado. Para somente usar sua comunidade, o caminho zero-VPS do app com Tailscale, ngrok ou Cloudflare continua sendo mais simples.</p></div></div>
            </div>
          )}

          {step.id === "network" && (
            <div className="mt-4 space-y-4">
              <p className="text-xs leading-5 text-zinc-300">Crie os dois registros antes de emitir o certificado. Substitua os exemplos pelos seus valores reais.</p>
              <div className="overflow-hidden rounded-lg border border-zinc-800">
                <div className="grid grid-cols-[1fr_auto] gap-3 border-b border-zinc-800 px-3 py-3 text-xs"><span className="text-zinc-300"><strong className="font-medium text-white">WSS</strong><br /><span className="text-zinc-500">bridge.example.com</span></span><code className="text-right text-zinc-400">80/tcp · 443/tcp</code></div>
                <div className="grid grid-cols-[1fr_auto] gap-3 border-b border-zinc-800 px-3 py-3 text-xs"><span className="text-zinc-300"><strong className="font-medium text-white">STUN/TURN</strong><br /><span className="text-zinc-500">turn.bridge.example.com</span></span><code className="text-right text-zinc-400">3478/tcp+udp · 443/tcp</code></div>
                <div className="grid grid-cols-[1fr_auto] gap-3 px-3 py-3 text-xs"><span className="text-zinc-300"><strong className="font-medium text-white">Relay UDP</strong><br /><span className="text-zinc-500">alocações de mídia</span></span><code className="text-right text-zinc-400">49160–49259/udp</code></div>
              </div>
              <p className="flex items-start gap-2 text-xs leading-5 text-zinc-400"><TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" aria-hidden />Não use proxy/CDN no hostname TURN. Não exponha portas administrativas do Docker ou do coturn.</p>
            </div>
          )}

          {step.id === "deploy" && (
            <div className="mt-4 space-y-5">
              <div><p className="text-xs leading-5 text-zinc-300">No host, entre no diretório do bundle e inicialize uma instalação nova. O script recusa sobrescrever secrets existentes.</p><CodeBlock id="initialize" value={JANJABRIDGE_SETUP_COMMANDS.initialize} copied={copiedId === "initialize"} onCopy={copy} /><p className="mt-2 text-[11px] leading-5 text-zinc-500">Troque caminho, domínio WSS, email ACME, IPv4 público e domínio TURN. Execute sem <code className="text-zinc-300">sudo</code>.</p></div>
              <div><p className="text-xs leading-5 text-zinc-300">Valide a configuração, suba a stack e troque o certificado bootstrap pelo ACME público.</p><CodeBlock id="start" value={JANJABRIDGE_SETUP_COMMANDS.start} copied={copiedId === "start"} onCopy={copy} /><p className="mt-2 text-[11px] leading-5 text-zinc-500">Só compartilhe pairing depois de o certificado ACME concluir e o <code className="text-zinc-300">docker compose ps</code> mostrar os serviços saudáveis.</p></div>
            </div>
          )}

          {step.id === "pairing" && (
            <div className="mt-4 space-y-4">
              <div className="flex items-start gap-3 border-y border-zinc-800 py-4"><KeyRound className="mt-0.5 h-5 w-5 shrink-0 text-sky-300" aria-hidden /><div><p className="text-sm font-medium text-zinc-200">Crie uma autorização temporária</p><p className="mt-1 text-xs leading-5 text-zinc-400">Esse comando cria um JSON one-shot com validade de 24 horas. Compartilhe o arquivo gerado uma única vez por um canal confiável.</p><CodeBlock id="pairing" value={JANJABRIDGE_SETUP_COMMANDS.pairing} copied={copiedId === "pairing"} onCopy={copy} /></div></div>
              <ul className="space-y-2"><Bullet>Copie somente o conteúdo de <code className="break-all text-[11px] text-sky-200">state/bridge-pairing-*.json</code>.</Bullet><Bullet>Não compartilhe arquivos de <code className="text-[11px] text-red-300">secrets/</code>, o `.env` ou a chave administrativa.</Bullet><Bullet>Se expirar ou já tiver sido usado, gere outro pairing com o mesmo comando.</Bullet></ul>
              <div className="rounded-lg border border-red-900/70 bg-red-950/20 p-3"><div className="flex items-start gap-2"><ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-red-300" aria-hidden /><p className="text-xs leading-5 text-red-100">Quem possui o pairing consegue autorizar a primeira comunidade nesse bridge. Trate o JSON como uma credencial.</p></div></div>
            </div>
          )}

          {step.id === "connect" && (
            <div className="mt-4 space-y-4">
              <div className="flex items-start gap-3 border-y border-zinc-800 py-4"><Link2 className="mt-0.5 h-5 w-5 shrink-0 text-sky-300" aria-hidden /><div><p className="text-sm font-medium text-zinc-200">Valide dentro do JanjaCord</p><p className="mt-1 text-xs leading-5 text-zinc-400">Cole o JSON inteiro no diálogo de pareamento. O app verifica assinatura, validade, endpoint e só então salva a rota de forma protegida.</p><button className="mt-3 inline-flex items-center gap-2 rounded-md bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500" onClick={onOpenPairing}><Link2 className="h-4 w-4" aria-hidden />Abrir pareamento</button></div></div>
              <div><p className="text-xs font-medium text-zinc-300">Se a validação falhar no app</p><ul className="mt-2 space-y-2"><Bullet>Confirme que o certificado ACME cobre o domínio WSS e o domínio TURN.</Bullet><Bullet>Confira os containers e os últimos logs:</Bullet></ul><CodeBlock id="diagnose" value={JANJABRIDGE_SETUP_COMMANDS.diagnose} copied={copiedId === "diagnose"} onCopy={copy} /></div>
              <p className="text-xs leading-5 text-zinc-500">Depois de adicionar, a comunidade mostra a rota do bridge e pode usar TURN quando a conexão direta falhar. O operador ainda pode observar metadados de transporte, mas não recebe o plaintext E2EE.</p>
            </div>
          )}

          {copyError && <p className="mt-4 flex items-start gap-2 text-xs leading-5 text-amber-300" role="alert"><TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />{copyError}</p>}
        </main>

        <footer className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-t border-zinc-800 px-4 py-3 sm:px-5">
          <button className="inline-flex items-center gap-1.5 text-xs text-zinc-400 hover:text-white disabled:opacity-40" onClick={previous} disabled={stepIndex === 0}><ArrowLeft className="h-3.5 w-3.5" aria-hidden />Voltar</button>
          <div className="flex flex-wrap items-center justify-end gap-2">
            <button className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-2 text-xs text-zinc-300 hover:bg-zinc-800" onClick={onOpenPairing}><Link2 className="h-3.5 w-3.5" aria-hidden />Já tenho pairing</button>
            {stepIndex < TUTORIAL_STEPS.length - 1 ? <button className="inline-flex items-center gap-1.5 rounded-md bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500" onClick={next}>Próximo<ArrowRight className="h-4 w-4" aria-hidden /></button> : <button className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-800" onClick={onClose}>Concluir tutorial<Check className="h-4 w-4" aria-hidden /></button>}
          </div>
        </footer>
      </div>
    </div>
  );
}
