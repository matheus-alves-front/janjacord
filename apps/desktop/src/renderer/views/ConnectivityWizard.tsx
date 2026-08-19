import { useEffect, useRef, useState, type ComponentType } from "react";
import {
  ArrowLeft,
  Check,
  CheckCircle2,
  ChevronRight,
  Circle,
  Cloud,
  ExternalLink,
  Globe2,
  KeyRound,
  LoaderCircle,
  Network,
  OctagonX,
  Radio,
  RadioTower,
  RefreshCw,
  ShieldAlert,
  Square,
  TriangleAlert,
  X,
} from "lucide-react";
import type { ConnectivityProvider, ConnectivityProviderId, ConnectivityRoute } from "../App";
import { friendlyIpcError, rejectedIpcError, type IpcError } from "../ipcErrors";

type CloudflareMode = "quick" | "named";
type WizardPhase =
  | "detecting"
  | "choosing"
  | "configuring"
  | "starting"
  | "verifying"
  | "ready"
  | "limited"
  | "error"
  | "stopping";

interface ProviderForm {
  token: string;
  domain: string;
  cloudflareMode: CloudflareMode;
}

interface ProviderPresentation {
  label: string;
  eyebrow: string;
  summary: string;
  prerequisite: string;
  Icon: ComponentType<{ className?: string; "aria-hidden"?: boolean }>;
}

const EMPTY_FORM: ProviderForm = { token: "", domain: "", cloudflareMode: "quick" };
const FOCUSABLE = "button:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex='-1'])";
const OPERATION_TIMEOUT_MS = 60_000;

const CONNECTIVITY_ERRORS: Record<string, string> = {
  provider_not_installed: "O agente deste provedor não está instalado. Instale-o e execute a detecção novamente.",
  not_installed: "O agente deste provedor não está instalado. Instale-o e execute a detecção novamente.",
  provider_auth_required: "O provedor precisa de autenticação. Entre na conta ou informe um novo token.",
  auth_required: "O provedor precisa de autenticação. Entre na conta ou informe um novo token.",
  tailscale_funnel_disabled: "O Funnel não está habilitado na sua conta Tailscale. Habilite em https://login.tailscale.com/f/funnel e tente novamente.",
  tailscale_needs_login: "Entre no Tailscale (app ou `tailscale up`) antes de ativar o Funnel.",
  tailscale_offline: "O Tailscale não está conectado nesta máquina. Conecte-se e tente novamente.",
  zrok_env_not_enabled: "O ambiente Zrok não está habilitado. No terminal, rode `zrok2 enable <token> --headless` e tente novamente.",
  zrok_name_conflict: "Não foi possível reservar o nome da rota Zrok. Use outro nome e tente novamente.",
  invalid_name: "O nome da rota Zrok é inválido. Use minúsculas, números e hífens.",
  turn_auth_failed: "As credenciais do TURN da Cloudflare foram rejeitadas. Confira TURN Key ID e API token.",
  turn_unreachable: "Não foi possível falar com o TURN da Cloudflare. Verifique a rede e tente novamente.",
  turn_mint_failed: "O TURN da Cloudflare não retornou servidores utilizáveis. Tente novamente mais tarde.",
  quota: "A cota da conta foi atingida. Aguarde a renovação ou escolha outro provedor.",
  quota_exceeded: "A cota da conta foi atingida. Aguarde a renovação ou escolha outro provedor.",
  expired: "A rota ou credencial expirou. Revise a configuração e ative uma nova rota.",
  process_exited: "O agente do provedor foi encerrado antes da verificação. Confira a sessão e tente novamente.",
  dns_failed: "O domínio não aponta para este host. Corrija o DNS e tente novamente.",
  tls_failed: "O certificado TLS do domínio não pôde ser validado. Corrija o certificado e tente novamente.",
  wss_failed: "O proxy WebSocket não respondeu de forma segura. Revise a configuração e tente novamente.",
  verification_failed: "A rota iniciou, mas não passou pela verificação externa de DNS, TLS e WSS.",
  unavailable: "O provedor está indisponível no momento. Tente novamente ou escolha outra opção.",
};

const PROVIDERS: Record<ConnectivityProviderId, ProviderPresentation> = {
  tailscale: {
    label: "Tailscale Funnel",
    eyebrow: "Estável para uso contínuo",
    summary: "Publica o host por HTTPS/WSS sem exigir Tailscale dos membros.",
    prerequisite: "Tailscale instalado, sessão iniciada e Funnel permitido na conta.",
    Icon: RadioTower,
  },
  ngrok: {
    label: "ngrok",
    eyebrow: "Configuração rápida",
    summary: "Cria uma rota pública gerenciada pela sua conta ngrok.",
    prerequisite: "Agente ngrok instalado. Token necessário apenas se a sessão ainda não estiver autenticada.",
    Icon: Network,
  },
  cloudflare: {
    label: "Cloudflare Tunnel",
    eyebrow: "Rápido ou com hostname",
    summary: "Use uma URL temporária ou conecte um túnel nomeado ao seu domínio.",
    prerequisite: "cloudflared instalado; túnel nomeado também exige token e hostname.",
    Icon: Cloud,
  },
  manual: {
    label: "Domínio próprio / Nginx",
    eyebrow: "Avançado, sem serviço de túnel",
    summary: "Valida seu DNS, TLS e proxy WebSocket antes de publicar a rota.",
    prerequisite: "Nginx, domínio alcançável, TLS válido e proxy para 127.0.0.1:8931.",
    Icon: Globe2,
  },
  zrok: {
    label: "Zrok",
    eyebrow: "Sem abrir portas",
    summary: "Publica o host por HTTPS/WSS com endpoint estável, sem abrir portas ou configurar VPS.",
    prerequisite: "zrok2 instalado e ambiente habilitado (`zrok2 enable <token>` no terminal). O túnel é um terceiro no transporte; não substitui TURN nem JanjaBridge.",
    Icon: Radio,
  },
};

export function sanitizeEndpoint(endpoint: string): string {
  try {
    const parsed = new URL(endpoint);
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return "Endpoint protegido";
  }
}

export function isValidHostname(value: string): boolean {
  const hostname = value.trim().toLowerCase().replace(/\.$/, "");
  if (hostname.length < 1 || hostname.length > 253 || hostname.includes("://")) return false;
  return hostname.split(".").length >= 2 && hostname.split(".").every((part) => (
    part.length > 0
    && part.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part)
  ));
}

export function buildProviderConfig(provider: ConnectivityProviderId, form: ProviderForm): Record<string, string | boolean> {
  const token = form.token.trim();
  const domain = form.domain.trim().toLowerCase().replace(/\.$/, "");
  if (provider === "ngrok") return token ? { token } : {};
  if (provider === "cloudflare") {
    if (form.cloudflareMode === "quick") return { mode: "quick" };
    return { mode: "named", ...(token ? { token } : {}), ...(domain ? { hostname: domain } : {}) };
  }
  if (provider === "manual") return { domain };
  if (provider === "zrok") return domain ? { name: domain } : {};
  return {};
}

export const ZROK_NAME_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function isValidZrokName(value: string): boolean {
  const name = value.trim().toLowerCase();
  return name.length >= 1 && name.length <= 63 && ZROK_NAME_PATTERN.test(name);
}

export function clearSensitiveFields(form: ProviderForm): ProviderForm {
  return { ...form, token: "" };
}

export function connectivityErrorMessage(error: IpcError | undefined, fallback: string): string {
  return error?.code && CONNECTIVITY_ERRORS[error.code]
    ? CONNECTIVITY_ERRORS[error.code]!
    : friendlyIpcError(error, fallback);
}

export function providerBlockReason(provider: ConnectivityProvider, form: ProviderForm): string | null {
  if (!provider.installed && provider.id !== "manual") return `${PROVIDERS[provider.id].label} não foi detectado neste computador.`;
  if (provider.id === "tailscale" && provider.authenticated === false) return "Entre no Tailscale antes de ativar o Funnel.";
  if (provider.id === "ngrok" && provider.authenticated === false && !form.token.trim()) return "Informe o authtoken ou autentique o agente ngrok.";
  if (provider.id === "cloudflare" && form.cloudflareMode === "named" && provider.authenticated !== true && !form.token.trim()) return "Informe o token do túnel nomeado.";
  if (provider.id === "zrok" && provider.enabled === false) return "Habilite o ambiente Zrok antes de ativar a rota: no terminal, rode `zrok2 enable <token> --headless`.";
  if (provider.id === "zrok" && !isValidZrokName(form.domain)) return "Informe um nome para a rota (minúsculas, números e hífens; sem domínio completo).";
  if ((provider.id === "cloudflare" && form.cloudflareMode === "named") || provider.id === "manual") {
    if (!isValidHostname(form.domain)) return "Informe somente um domínio válido, sem https:// ou caminho.";
  }
  return null;
}

function withTimeout<T>(promise: Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = window.setTimeout(() => reject(new Error("connectivity_timeout")), OPERATION_TIMEOUT_MS);
    promise.then(
      (value) => {
        window.clearTimeout(timeout);
        resolve(value);
      },
      (error) => {
        window.clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

function routePhase(route: ConnectivityRoute): WizardPhase {
  if (route.status === "limited") return "limited";
  if (route.status === "error") return "error";
  return "ready";
}

function ProviderStatus({ provider }: { provider: ConnectivityProvider | undefined }) {
  if (!provider) return <span className="text-[10px] text-zinc-500">Não informado</span>;
  if (!provider.installed) return <span className="text-[10px] text-amber-300">Precisa instalar</span>;
  if (provider.authenticated === false) return <span className="text-[10px] text-amber-300">Precisa entrar</span>;
  return (
    <span className="inline-flex items-center gap-1 text-[10px] text-emerald-300">
      <Check className="h-3 w-3" aria-hidden />
      Detectado{provider.version ? ` · ${provider.version}` : ""}
    </span>
  );
}

function ProgressRows({ phase }: { phase: WizardPhase }) {
  const items = [
    {
      label: "Detectar pré-requisitos",
      status: phase === "detecting" ? "running" : "done",
    },
    {
      label: "Iniciar rota protegida",
      status: phase === "starting" ? "running" : phase === "verifying" || phase === "ready" || phase === "limited" ? "done" : "pending",
    },
    {
      label: "Verificar DNS, TLS e WSS",
      status: phase === "verifying" ? "running" : phase === "ready" || phase === "limited" ? "done" : "pending",
    },
  ] as const;

  return (
    <ol className="mt-4 divide-y divide-zinc-800 border-y border-zinc-800" aria-label="Progresso da configuração">
      {items.map((item) => (
        <li key={item.label} className="flex items-center gap-3 py-2.5 text-xs">
          {item.status === "running" ? (
            <LoaderCircle className="h-4 w-4 shrink-0 animate-spin text-sky-400" aria-hidden />
          ) : item.status === "done" ? (
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden />
          ) : (
            <Circle className="h-4 w-4 shrink-0 text-zinc-600" aria-hidden />
          )}
          <span className={item.status === "pending" ? "text-zinc-500" : "text-zinc-200"}>{item.label}</span>
          <span className="ml-auto text-[10px] text-zinc-500">
            {item.status === "running" ? "Em andamento" : item.status === "done" ? "Concluído" : "Aguardando"}
          </span>
        </li>
      ))}
    </ol>
  );
}

export function ConnectivityWizard({
  onClose,
  onChanged,
  onOpenAdvanced,
  onOpenTutorial,
}: {
  onClose: () => void;
  onChanged?: () => void | Promise<void>;
  onOpenAdvanced: () => void;
  onOpenTutorial?: () => void;
}) {
  const [phase, setPhase] = useState<WizardPhase>("detecting");
  const [providers, setProviders] = useState<ConnectivityProvider[]>([]);
  const [selectedId, setSelectedId] = useState<ConnectivityProviderId | null>(null);
  const [form, setForm] = useState<ProviderForm>(EMPTY_FORM);
  const [route, setRoute] = useState<ConnectivityRoute | null>(null);
  const [error, setError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const configBackRef = useRef<HTMLButtonElement>(null);
  const retryRef = useRef<HTMLButtonElement>(null);
  const resultCloseRef = useRef<HTMLButtonElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const requestCloseRef = useRef<() => void>(() => undefined);
  const operationRef = useRef(0);
  const busy = phase === "detecting" || phase === "starting" || phase === "verifying" || phase === "stopping";
  const closeBlocked = phase === "starting" || phase === "verifying" || phase === "stopping";
  const selected = selectedId
    ? providers.find((provider) => provider.id === selectedId) ?? {
      id: selectedId,
      installed: false,
      detail: "O provedor não respondeu à detecção. Instale-o ou tente detectar novamente.",
    }
    : undefined;

  const requestClose = () => {
    if (!closeBlocked) onClose();
  };
  requestCloseRef.current = requestClose;

  const detect = async () => {
    const operation = ++operationRef.current;
    setPhase("detecting");
    setError(null);
    try {
      const result = await withTimeout(window.janjacord.connectivityProviders());
      if (operation !== operationRef.current) return;
      if (!result.ok || !result.data) {
        setError(connectivityErrorMessage(result.error, "Não foi possível detectar as opções de conexão."));
        setPhase("error");
        return;
      }
      setProviders(result.data.providers);
      setRoute(result.data.activeRoute ?? null);
      setPhase(result.data.activeRoute ? routePhase(result.data.activeRoute) : "choosing");
    } catch (caught) {
      if (operation !== operationRef.current) return;
      setError(caught instanceof Error && caught.message === "connectivity_timeout"
        ? "A detecção levou mais de 60 segundos. Verifique a rede e tente novamente."
        : rejectedIpcError(caught, "Não foi possível detectar as opções de conexão."));
      setPhase("error");
    }
  };

  useEffect(() => {
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    requestAnimationFrame(() => dialogRef.current?.focus());
    void detect();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        requestCloseRef.current();
        return;
      }
      if (event.key !== "Tab" || !dialogRef.current) return;
      const focusable = [...dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)]
        .filter((element) => element.offsetParent !== null);
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
      operationRef.current += 1;
      document.removeEventListener("keydown", onKeyDown, true);
      previousFocusRef.current?.focus();
    };
    // The detection contract is intentionally called once per mounted wizard.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      if (phase === "configuring") configBackRef.current?.focus({ preventScroll: true });
      if (phase === "error") retryRef.current?.focus({ preventScroll: true });
      if (phase === "ready" || phase === "limited") resultCloseRef.current?.focus({ preventScroll: true });
    });
    return () => cancelAnimationFrame(frame);
  }, [phase]);

  const choose = (provider: ConnectivityProviderId) => {
    setSelectedId(provider);
    setForm(EMPTY_FORM);
    setError(null);
    setPhase("configuring");
  };

  const start = async () => {
    if (!selected) return;
    const blockReason = providerBlockReason(selected, form);
    if (blockReason) {
      setError(blockReason);
      return;
    }

    const operation = ++operationRef.current;
    const config = buildProviderConfig(selected.id, form);
    setForm(clearSensitiveFields);
    setError(null);
    setPhase("starting");
    const verifyTimer = window.setTimeout(() => {
      if (operation === operationRef.current) setPhase("verifying");
    }, 700);

    try {
      const result = await withTimeout(window.janjacord.connectivityProviderStart(selected.id, config));
      window.clearTimeout(verifyTimer);
      if (operation !== operationRef.current) return;
      if (!result.ok || !result.data) {
        setError(connectivityErrorMessage(result.error, "A rota não pôde ser iniciada ou verificada."));
        setPhase("error");
        return;
      }
      setRoute(result.data);
      setPhase(routePhase(result.data));
      await onChanged?.();
    } catch (caught) {
      window.clearTimeout(verifyTimer);
      if (operation !== operationRef.current) return;
      setError(caught instanceof Error && caught.message === "connectivity_timeout"
        ? "A configuração não terminou em 60 segundos. Confira o provedor antes de tentar novamente."
        : rejectedIpcError(caught, "A rota não pôde ser iniciada ou verificada."));
      setPhase("error");
    }
  };

  const stop = async () => {
    const operation = ++operationRef.current;
    setPhase("stopping");
    setError(null);
    try {
      const result = await withTimeout(window.janjacord.connectivityProviderStop());
      if (operation !== operationRef.current) return;
      if (!result.ok) {
        setError(connectivityErrorMessage(result.error, "Não foi possível desligar esta rota."));
        setPhase(route ? routePhase(route) : "error");
        return;
      }
      setRoute(null);
      setSelectedId(null);
      setForm(EMPTY_FORM);
      await onChanged?.();
      await detect();
    } catch (caught) {
      if (operation !== operationRef.current) return;
      setError(rejectedIpcError(caught, "Não foi possível desligar esta rota."));
      setPhase(route ? routePhase(route) : "error");
    }
  };

  const retry = () => {
    setError(null);
    if (selectedId) setPhase("configuring");
    else void detect();
  };

  const openAdvanced = () => {
    if (busy) return;
    onClose();
    onOpenAdvanced();
  };

  const configurationBlock = selected ? providerBlockReason(selected, form) : null;

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/75 p-3 sm:p-4"
      data-smoke-screen="connectivity-wizard"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) requestClose();
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="connectivity-wizard-title"
        aria-describedby="connectivity-wizard-description"
        tabIndex={-1}
        className="flex max-h-[calc(100vh-1.5rem)] w-full max-w-[680px] min-w-0 flex-col overflow-hidden rounded-xl border border-zinc-700 bg-zinc-900 shadow-2xl"
      >
        <header className="flex shrink-0 items-start justify-between gap-4 border-b border-zinc-800 px-4 py-3 sm:px-5">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <RadioTower className="h-4 w-4 shrink-0 text-sky-400" aria-hidden />
              <h2 id="connectivity-wizard-title" className="truncate text-sm font-semibold text-white">Configurar conexão externa</h2>
            </div>
            <p id="connectivity-wizard-description" className="mt-1 text-xs leading-5 text-zinc-400">
              Publique este host sem digitar endereços nos outros dispositivos.
            </p>
          </div>
          <button className="icon-button shrink-0" onClick={requestClose} disabled={closeBlocked} title="Fechar" aria-label="Fechar configuração de conexão">
            <X className="h-4 w-4" aria-hidden />
          </button>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4 sm:px-5" aria-live="polite" aria-atomic="false">
          {phase === "detecting" && (
            <div className="py-1" role="status">
              <p className="text-sm font-medium text-zinc-100">Verificando este computador</p>
              <p className="mt-1 text-xs leading-5 text-zinc-400">Procurando agentes instalados e rotas já ativas. Esta etapa termina em até 60 segundos.</p>
              <ProgressRows phase={phase} />
            </div>
          )}

          {phase === "choosing" && (
            <section aria-labelledby="provider-choice-title">
              <div className="flex items-end justify-between gap-3">
                <div>
                  <h3 id="provider-choice-title" className="text-sm font-medium text-zinc-100">Escolha como publicar</h3>
                  <p className="mt-1 text-xs leading-5 text-zinc-400">Cada opção publica texto e arquivos por WSS. O túnel não hospeda sua comunidade.</p>
                </div>
                <button className="flex shrink-0 items-center gap-1 text-xs text-zinc-300 hover:text-white" onClick={detect}>
                  <RefreshCw className="h-3.5 w-3.5" aria-hidden />
                  Detectar
                </button>
              </div>
              <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
                {(Object.keys(PROVIDERS) as ConnectivityProviderId[]).map((providerId) => {
                  const presentation = PROVIDERS[providerId];
                  const provider = providers.find((item) => item.id === providerId);
                  const Icon = presentation.Icon;
                  return (
                    <button
                      key={providerId}
                      className="group min-w-0 rounded-lg border border-zinc-800 bg-zinc-950/35 p-3 text-left transition-colors hover:border-zinc-600 hover:bg-zinc-800/55 focus-visible:border-sky-500"
                      onClick={() => choose(providerId)}
                      aria-label={`${presentation.label}. ${provider?.installed ? "Detectado" : "Ver pré-requisitos"}`}
                    >
                      <div className="flex items-start gap-3">
                        <Icon className="mt-0.5 h-5 w-5 shrink-0 text-sky-400" aria-hidden />
                        <div className="min-w-0 flex-1">
                          <div className="flex min-w-0 items-center justify-between gap-2">
                            <span className="truncate text-sm font-medium text-zinc-100">{presentation.label}</span>
                            <ChevronRight className="h-4 w-4 shrink-0 text-zinc-600 group-hover:text-zinc-300" aria-hidden />
                          </div>
                          <p className="mt-0.5 text-[10px] font-medium uppercase tracking-wide text-zinc-500">{presentation.eyebrow}</p>
                          <p className="mt-2 text-xs leading-[1.15rem] text-zinc-400">{presentation.summary}</p>
                          <div className="mt-2"><ProviderStatus provider={provider} /></div>
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </section>
          )}

          {phase === "configuring" && selected && selectedId && (
            <section aria-labelledby="provider-config-title">
              <button ref={configBackRef} className="mb-3 flex items-center gap-1 text-xs text-zinc-400 hover:text-white" onClick={() => { setError(null); setPhase("choosing"); }}>
                <ArrowLeft className="h-3.5 w-3.5" aria-hidden />
                Outras opções
              </button>
              <div className="flex items-start gap-3">
                {(() => {
                  const Icon = PROVIDERS[selectedId].Icon;
                  return <Icon className="mt-0.5 h-5 w-5 shrink-0 text-sky-400" aria-hidden />;
                })()}
                <div className="min-w-0">
                  <h3 id="provider-config-title" className="text-sm font-medium text-zinc-100">{PROVIDERS[selectedId].label}</h3>
                  <p className="mt-1 text-xs leading-5 text-zinc-400">{PROVIDERS[selectedId].prerequisite}</p>
                  {selected.detail && <p className="mt-1 text-[11px] leading-5 text-zinc-500">{selected.detail}</p>}
                </div>
              </div>

              <div className="mt-4 border-y border-zinc-800 py-4">
                {selectedId === "tailscale" && (
                  <p className="text-xs leading-5 text-zinc-300">O app ativará o Funnel para o host local e validará a URL pública antes de incluí-la em novos convites.</p>
                )}

                {selectedId === "ngrok" && (
                  <label className="block text-xs font-medium text-zinc-300" htmlFor="connectivity-ngrok-token">
                    Authtoken <span className="font-normal text-zinc-500">(opcional se já autenticado)</span>
                    <span className="relative mt-2 block">
                      <KeyRound className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-zinc-500" aria-hidden />
                      <input
                        id="connectivity-ngrok-token"
                        type="password"
                        autoComplete="off"
                        spellCheck={false}
                        className="w-full rounded-md border border-zinc-700 bg-zinc-950 py-2 pl-9 pr-3 text-sm text-zinc-100 outline-none focus:border-sky-500"
                        value={form.token}
                        onChange={(event) => { setForm((current) => ({ ...current, token: event.target.value })); setError(null); }}
                        placeholder="Cole somente se necessário"
                      />
                    </span>
                  </label>
                )}

                {selectedId === "cloudflare" && (
                  <div className="space-y-4">
                    <fieldset>
                      <legend className="text-xs font-medium text-zinc-300">Tipo de túnel</legend>
                      <div className="mt-2 inline-flex rounded-md border border-zinc-700 p-0.5">
                        {(["quick", "named"] as const).map((mode) => (
                          <button
                            key={mode}
                            type="button"
                            aria-pressed={form.cloudflareMode === mode}
                            className={`rounded px-3 py-1.5 text-xs ${form.cloudflareMode === mode ? "bg-zinc-700 text-white" : "text-zinc-400 hover:text-white"}`}
                            onClick={() => { setForm((current) => ({ ...current, cloudflareMode: mode })); setError(null); }}
                          >
                            {mode === "quick" ? "Rápido" : "Nomeado"}
                          </button>
                        ))}
                      </div>
                    </fieldset>
                    {form.cloudflareMode === "quick" ? (
                      <p className="flex items-start gap-2 text-xs leading-5 text-amber-200">
                        <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
                        A URL é temporária, pode mudar ao reiniciar e torna convites antigos indisponíveis. Use para testes ou acesso temporário.
                      </p>
                    ) : (
                      <div className="grid gap-3 sm:grid-cols-2">
                        <label className="text-xs font-medium text-zinc-300" htmlFor="connectivity-cloudflare-token">
                          Token do túnel
                          <input
                            id="connectivity-cloudflare-token"
                            type="password"
                            autoComplete="off"
                            spellCheck={false}
                            className="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-sky-500"
                            value={form.token}
                            onChange={(event) => { setForm((current) => ({ ...current, token: event.target.value })); setError(null); }}
                            placeholder="Token não será exibido depois"
                          />
                        </label>
                        <label className="text-xs font-medium text-zinc-300" htmlFor="connectivity-cloudflare-domain">
                          Hostname público
                          <input
                            id="connectivity-cloudflare-domain"
                            type="text"
                            autoCapitalize="none"
                            autoComplete="off"
                            spellCheck={false}
                            className="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-sky-500"
                            value={form.domain}
                            onChange={(event) => { setForm((current) => ({ ...current, domain: event.target.value })); setError(null); }}
                            placeholder="chat.exemplo.com"
                          />
                        </label>
                      </div>
                    )}
                  </div>
                )}

                {selectedId === "manual" && (
                  <div>
                    <label className="block text-xs font-medium text-zinc-300" htmlFor="connectivity-manual-domain">Domínio público</label>
                    <input
                      id="connectivity-manual-domain"
                      type="text"
                      autoCapitalize="none"
                      autoComplete="off"
                      spellCheck={false}
                      className="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-sky-500"
                      value={form.domain}
                      onChange={(event) => { setForm((current) => ({ ...current, domain: event.target.value })); setError(null); }}
                      placeholder="chat.exemplo.com"
                    />
                    <p className="mt-2 text-xs leading-5 text-zinc-400">O app não altera roteador, DNS nem certificado. A rota só fica pronta após uma verificação externa de TLS e WebSocket.</p>
                  </div>
                )}

                {selectedId === "zrok" && (
                  <div className="space-y-3">
                    <label className="block text-xs font-medium text-zinc-300" htmlFor="connectivity-zrok-name">
                      Nome da rota <span className="font-normal text-zinc-500">(vira o endereço público e é estável entre sessões)</span>
                      <input
                        id="connectivity-zrok-name"
                        type="text"
                        autoCapitalize="none"
                        autoComplete="off"
                        spellCheck={false}
                        className="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-sky-500"
                        value={form.domain}
                        onChange={(event) => { setForm((current) => ({ ...current, domain: event.target.value })); setError(null); }}
                        placeholder="meu-servidor"
                      />
                    </label>
                    {selected.enabled === false ? (
                      <p className="flex items-start gap-2 text-xs leading-5 text-amber-200">
                        <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
                        O ambiente Zrok ainda não está habilitado. No terminal, rode <code className="rounded bg-zinc-800 px-1">zrok2 enable &lt;token&gt; --headless</code> e volte para detectar.
                      </p>
                    ) : (
                      <p className="flex items-start gap-2 text-xs leading-5 text-zinc-400">
                        <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
                        O túnel é um terceiro no caminho de transporte e não fornece TURN. Voz e vídeo continuam em conexão direta.
                      </p>
                    )}
                  </div>
                )}
              </div>

              {(error || configurationBlock) && (
                <p className={`mt-3 flex items-start gap-2 text-xs leading-5 ${error ? "text-red-400" : "text-amber-300"}`} role={error ? "alert" : undefined}>
                  <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
                  {error ?? configurationBlock}
                </p>
              )}
              <div className="mt-4 flex flex-wrap justify-end gap-2">
                <button className="rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800" onClick={() => setPhase("choosing")}>Cancelar</button>
                <button className="rounded-md bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-40" disabled={Boolean(configurationBlock)} onClick={() => void start()}>
                  {selectedId === "manual" ? "Gerar e verificar" : "Detectar e ativar"}
                </button>
              </div>
            </section>
          )}

          {(phase === "starting" || phase === "verifying") && selectedId && (
            <section role="status" aria-labelledby="connectivity-progress-title">
              <p className="text-xs font-medium uppercase tracking-wide text-sky-400">{PROVIDERS[selectedId].label}</p>
              <h3 id="connectivity-progress-title" className="mt-1 text-sm font-medium text-zinc-100">
                {phase === "starting" ? "Iniciando a rota" : "Verificando acesso externo"}
              </h3>
              <p className="mt-1 text-xs leading-5 text-zinc-400">O app encerrará esta tentativa em até 60 segundos. Você não precisa abrir um terminal.</p>
              <ProgressRows phase={phase} />
            </section>
          )}

          {(phase === "ready" || phase === "limited" || phase === "stopping") && route && (
            <section aria-labelledby="connectivity-result-title">
              <div className="flex items-start gap-3">
                {phase === "limited" ? (
                  <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" aria-hidden />
                ) : (
                  <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-400" aria-hidden />
                )}
                <div className="min-w-0">
                  <h3 id="connectivity-result-title" className="text-sm font-medium text-zinc-100">{phase === "limited" ? "Rota pronta com limitações" : "Conexão externa pronta"}</h3>
                  <p className="mt-1 break-all text-xs leading-5 text-zinc-400">{sanitizeEndpoint(route.endpoint)}</p>
                  <p className="mt-0.5 text-[11px] text-zinc-500">{PROVIDERS[route.provider].label} · {route.stable ? "endereço estável" : "endereço pode mudar"}</p>
                </div>
              </div>
              {route.detail && <p className="mt-3 text-xs leading-5 text-zinc-300">{route.detail}</p>}
              {route.media === "turn" && (
                <div className="mt-4 flex items-start gap-3 border-y border-emerald-900/60 py-3 text-emerald-100">
                  <Radio className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" aria-hidden />
                  <div>
                    <p className="text-xs font-medium">Mídia via TURN</p>
                    <p className="mt-0.5 text-xs leading-5 text-emerald-200/80">Voz e vídeo podem passar por relay (TURN Cloudflare) quando a conexão direta falhar — funciona até atrás de NAT restritivo.</p>
                  </div>
                </div>
              )}
              {route.media === "direct-only" && (
                <div className="mt-4 flex items-start gap-3 border-y border-amber-900/60 py-3 text-amber-100">
                  <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" aria-hidden />
                  <div>
                    <p className="text-xs font-medium">Mídia somente direta</p>
                    <p className="mt-0.5 text-xs leading-5 text-amber-200/80">Texto e arquivos usam esta rota. Voz e vídeo continuam WebRTC direto e podem falhar em NAT restritivo sem TURN/JanjaBridge.</p>
                  </div>
                </div>
              )}
              <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
                <button className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-white" onClick={openAdvanced} disabled={phase === "stopping"}>
                  <ExternalLink className="h-3.5 w-3.5" aria-hidden />
                  Adicionar JanjaBridge para TURN
                </button>
                <div className="flex gap-2">
                  <button ref={resultCloseRef} className="rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800 disabled:opacity-40" onClick={requestClose} disabled={phase === "stopping"}>Concluir</button>
                  <button className="flex items-center gap-1.5 rounded-md border border-red-900/80 px-3 py-2 text-sm text-red-300 hover:bg-red-950/40 disabled:opacity-40" onClick={() => void stop()} disabled={phase === "stopping"}>
                    {phase === "stopping" ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" aria-hidden /> : <Square className="h-3.5 w-3.5" aria-hidden />}
                    {phase === "stopping" ? "Desligando..." : "Desligar rota"}
                  </button>
                </div>
              </div>
              {error && <p className="mt-3 text-xs leading-5 text-red-400" role="alert">{error}</p>}
            </section>
          )}

          {phase === "error" && (
            <section role="alert" aria-labelledby="connectivity-error-title">
              <div className="flex items-start gap-3">
                <OctagonX className="mt-0.5 h-5 w-5 shrink-0 text-red-400" aria-hidden />
                <div>
                  <h3 id="connectivity-error-title" className="text-sm font-medium text-zinc-100">Não foi possível concluir</h3>
                  <p className="mt-1 text-xs leading-5 text-red-300">{error ?? route?.detail ?? "A rota informada não passou pela verificação externa."}</p>
                  <p className="mt-2 text-xs leading-5 text-zinc-400">Nenhuma rota é marcada como pronta sem confirmação de DNS, TLS e WSS. Você pode revisar os dados ou escolher outro provedor.</p>
                </div>
              </div>
              <div className="mt-4 flex flex-wrap justify-end gap-2">
                {route && (
                  <button className="flex items-center gap-1.5 rounded-md border border-red-900/80 px-3 py-2 text-sm text-red-300 hover:bg-red-950/40" onClick={() => void stop()}>
                    <Square className="h-3.5 w-3.5" aria-hidden />
                    Desligar rota
                  </button>
                )}
                {selectedId && (
                  <button className="rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800" onClick={() => { setSelectedId(null); setRoute(null); setError(null); setPhase("choosing"); }}>Trocar opção</button>
                )}
                <button ref={retryRef} className="flex items-center gap-1.5 rounded-md bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500" onClick={retry}>
                  <RefreshCw className="h-3.5 w-3.5" aria-hidden />
                  {selectedId ? "Revisar e tentar" : "Detectar novamente"}
                </button>
              </div>
            </section>
          )}
        </div>

        <footer className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-zinc-800 px-4 py-3 sm:px-5">
          <div className="flex items-center gap-2 text-[11px] leading-4 text-zinc-500">
            <ShieldAlert className="h-3.5 w-3.5 shrink-0" aria-hidden />
            Tokens são enviados uma vez e não voltam a aparecer nesta tela.
          </div>
          {!route && (
            <div className="flex flex-wrap items-center justify-end gap-x-3 gap-y-1">
              {onOpenTutorial && <button className="text-xs text-sky-300 hover:text-sky-200 disabled:opacity-40" onClick={() => { if (!busy) { onClose(); onOpenTutorial(); } }} disabled={busy}>
                Tutorial servidor JanjaBridge
              </button>}
              <button className="text-xs text-zinc-400 hover:text-sky-300 disabled:opacity-40" onClick={openAdvanced} disabled={busy}>
                Já tenho pairing
              </button>
            </div>
          )}
        </footer>
      </div>
    </div>
  );
}
