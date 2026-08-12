import { useEffect, useRef } from "react";
import { CheckCircle2, Circle, LoaderCircle, RefreshCw, TriangleAlert } from "lucide-react";

export type SetupStepId = "host" | "direct" | "bridge" | "access";
export type SetupStepStatus = "pending" | "running" | "done" | "warning" | "action" | "error" | "skipped";

export interface SetupStepState {
  step: SetupStepId;
  status: SetupStepStatus;
  detail?: string;
}

const labels: Record<SetupStepId, string> = {
  host: "Iniciando o host",
  direct: "Verificando a conexão local",
  bridge: "Conectando ao JanjaBridge",
  access: "Verificando o acesso",
};

const statusLabels: Record<SetupStepStatus, string> = {
  pending: "Aguardando",
  running: "Em andamento",
  done: "Concluído",
  warning: "Atenção necessária",
  action: "Ação necessária",
  error: "Falhou",
  skipped: "Não executada",
};

function StatusIcon({ status }: { status: SetupStepStatus }) {
  if (status === "running") return <LoaderCircle className="h-4 w-4 animate-spin text-sky-400" aria-hidden />;
  if (status === "done") return <CheckCircle2 className="h-4 w-4 text-emerald-400" aria-hidden />;
  if (["warning", "action", "error"].includes(status)) {
    return <TriangleAlert className={`h-4 w-4 ${status === "error" ? "text-red-400" : "text-amber-400"}`} aria-hidden />;
  }
  return <Circle className="h-4 w-4 text-zinc-600" aria-hidden />;
}

export function SetupProgress({
  steps,
  onRetry,
  onAction,
}: {
  steps: SetupStepState[];
  onRetry?: () => void;
  onAction?: (step: SetupStepId) => void;
}) {
  const retryRef = useRef<HTMLButtonElement>(null);
  const hasError = steps.some((item) => item.status === "error");
  const isRunning = steps.some((item) => item.status === "running");
  const accessReady = steps.some((item) => item.step === "access" && item.status === "done");
  const hostUnconfirmed = steps.some((item) => item.step === "access" && item.status === "warning");
  const hasBridgeWarning = steps.some((item) => item.step === "bridge" && ["warning", "action"].includes(item.status));
  const externalAccessPending = hostUnconfirmed || (accessReady && hasBridgeWarning);
  const summary = hasError
    ? "A preparação foi interrompida"
    : isRunning
      ? "Preparando sua comunidade"
      : externalAccessPending
        ? "Adicione um JanjaBridge para acesso fora desta rede"
        : accessReady
          ? "Comunidade pronta para uso"
          : "Preparação aguardando uma ação";

  useEffect(() => {
    if (!hasError || !onRetry) return;
    const frame = requestAnimationFrame(() => {
      retryRef.current?.scrollIntoView({ block: "nearest" });
      retryRef.current?.focus({ preventScroll: true });
    });
    return () => cancelAnimationFrame(frame);
  }, [hasError]);

  return (
    <div className="mt-5 border-t border-zinc-800 pt-4" data-smoke-section="setup" aria-live="polite" aria-atomic="false">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-xs font-medium text-zinc-200">Preparando sua comunidade</p>
          <p className={`mt-0.5 text-xs ${hasError ? "text-red-400" : externalAccessPending ? "text-amber-300" : accessReady ? "text-emerald-400" : "text-zinc-400"}`}>{summary}</p>
        </div>
        {hasError && onRetry && (
          <button ref={retryRef} className="flex items-center gap-1.5 rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-200 hover:bg-zinc-800" onClick={onRetry}>
            <RefreshCw className="h-3.5 w-3.5" aria-hidden />
            Tentar novamente
          </button>
        )}
      </div>
      <div className="mt-3 space-y-3">
        {steps.map((item) => (
          <div key={item.step} className="grid grid-cols-[16px_1fr_auto] gap-x-3" data-setup-step={item.step} data-setup-status={item.status}>
            <StatusIcon status={item.status} />
            <div className="min-w-0">
              <p className="text-sm text-zinc-200">{labels[item.step]}</p>
              <p className={`mt-0.5 text-xs leading-5 ${item.status === "error" ? "text-red-400" : item.status === "warning" || item.status === "action" ? "text-amber-300" : "text-zinc-400"}`}>
                {statusLabels[item.status]}{item.detail ? ` · ${item.detail}` : ""}
              </p>
            </div>
            {item.status === "action" && onAction && (
              <button className="self-center rounded border border-sky-800 px-2 py-1 text-xs text-sky-300 hover:bg-sky-950/50" onClick={() => onAction(item.step)}>
                Resolver
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
