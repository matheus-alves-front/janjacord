import { useEffect, useRef, useState } from "react";
import { CheckCircle2, Link2, LoaderCircle, RotateCcw, TriangleAlert, X } from "lucide-react";
import { friendlyIpcError, rejectedIpcError } from "../ipcErrors";

type PairingState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "warning"; endpoint: string; message: string }
  | { status: "success"; endpoint: string };

const FOCUSABLE = "button:not([disabled]), textarea:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex='-1'])";

export function BridgePairingDialog({
  onClose,
  onAdded,
  onCompleted,
}: {
  onClose: () => void;
  onAdded: (result: { endpoint: string; warning?: string }) => void | Promise<void>;
  onCompleted?: () => void;
}) {
  const [code, setCode] = useState("");
  const [state, setState] = useState<PairingState>({ status: "idle" });
  const [confirmDiscard, setConfirmDiscard] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const successButtonRef = useRef<HTMLButtonElement>(null);
  const warningRetryRef = useRef<HTMLButtonElement>(null);
  const requestCloseRef = useRef<() => void>(() => undefined);
  const busy = state.status === "loading";

  const requestClose = () => {
    if (busy) return;
    if (code.trim() && state.status !== "success" && state.status !== "warning" && !confirmDiscard) {
      setConfirmDiscard(true);
      return;
    }
    onClose();
  };
  requestCloseRef.current = requestClose;

  useEffect(() => {
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    inputRef.current?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        requestCloseRef.current();
        return;
      }
      if (event.key !== "Tab" || !dialogRef.current) return;
      const focusable = [...dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
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

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previousFocusRef.current?.focus();
    };
  }, []);

  useEffect(() => {
    if (state.status !== "success" && state.status !== "warning") return;
    const frame = requestAnimationFrame(() => {
      if (state.status === "success") successButtonRef.current?.focus();
      else warningRetryRef.current?.focus();
    });
    return () => cancelAnimationFrame(frame);
  }, [state.status]);

  const add = async () => {
    setState({ status: "loading" });
    setConfirmDiscard(false);
    try {
      const result = await window.janjacord.bridgeAdd(code.trim());
      if (!result.ok || !result.data) {
        setState({ status: "error", message: friendlyIpcError(result.error, "Não foi possível validar o JanjaBridge.") });
        return;
      }
      if (result.data.warning) {
        setState({ status: "warning", endpoint: result.data.endpoint, message: result.data.warning });
      } else {
        setState({ status: "success", endpoint: result.data.endpoint });
      }
      await onAdded(result.data);
    } catch (error) {
      setState({ status: "error", message: rejectedIpcError(error, "O JanjaBridge não respondeu. Tente novamente.") });
    }
  };

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 p-4"
      data-smoke-screen="pairing"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) requestClose();
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="bridge-pairing-title"
        aria-describedby={state.status === "success" ? "bridge-pairing-success" : state.status === "warning" ? "bridge-pairing-warning" : "bridge-pairing-description"}
        className="max-h-[calc(100vh-2rem)] w-full max-w-lg overflow-y-auto rounded-md border border-zinc-700 bg-zinc-900 shadow-2xl"
      >
        <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-3">
          <div className="flex items-center gap-2">
            <Link2 className="h-4 w-4 text-sky-400" aria-hidden />
            <h2 id="bridge-pairing-title" className="text-sm font-semibold text-white">Adicionar JanjaBridge</h2>
          </div>
          <button className="icon-button" onClick={requestClose} disabled={busy} title="Fechar" aria-label="Fechar">
            <X className="h-4 w-4" aria-hidden />
          </button>
        </div>
        <div className="p-4">
          {state.status === "success" ? (
            <div id="bridge-pairing-success" role="status" className="space-y-4">
              <div className="flex items-start gap-3">
                <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-400" aria-hidden />
                <div className="min-w-0">
                  <p className="text-sm font-medium text-zinc-100">JanjaBridge adicionado</p>
                  <p className="mt-1 break-all text-xs leading-5 text-zinc-400">Rota validada: {state.endpoint}</p>
                </div>
              </div>
              <div className="flex justify-end">
                <button
                  ref={successButtonRef}
                  className="rounded-md bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500"
                  onClick={() => {
                    onCompleted?.();
                    onClose();
                  }}
                >Concluir</button>
              </div>
            </div>
          ) : state.status === "warning" ? (
            <div id="bridge-pairing-warning" role="alert" className="space-y-4">
              <div className="flex items-start gap-3">
                <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" aria-hidden />
                <div className="min-w-0">
                  <p className="text-sm font-medium text-amber-100">Rota validada; ativação pendente</p>
                  <p className="mt-1 text-xs leading-5 text-amber-200">{state.message}</p>
                  <p className="mt-1 break-all text-xs leading-5 text-zinc-400">Rota validada: {state.endpoint}</p>
                </div>
              </div>
              <p className="text-xs leading-5 text-zinc-300">A rota foi salva com segurança, mas não foi possível confirmar que o host local voltou a operar. Reabra o app ou tente a ativação novamente antes de confiar nesta comunidade.</p>
              <div className="flex flex-wrap justify-end gap-2">
                <button className="rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800" onClick={onClose}>Resolver depois</button>
                <button ref={warningRetryRef} className="flex items-center gap-1.5 rounded-md border border-amber-700 px-3 py-2 text-sm font-medium text-amber-100 hover:bg-amber-950" onClick={add}>
                  <RotateCcw className="h-3.5 w-3.5" aria-hidden />
                  Tentar ativar novamente
                </button>
              </div>
            </div>
          ) : (
            <>
              <p id="bridge-pairing-description" className="text-xs leading-5 text-zinc-400">
                Cole o código fornecido pelo operador do JanjaBridge. O app valida a assinatura, a validade e a rota antes de salvar.
              </p>
              <label className="mt-4 block text-xs font-medium text-zinc-300" htmlFor="bridge-pairing-code">Código de pareamento</label>
              <textarea
                ref={inputRef}
                id="bridge-pairing-code"
                className="mt-2 h-40 w-full resize-none rounded-md border border-zinc-700 bg-zinc-950 p-3 font-mono text-xs leading-5 text-zinc-200 outline-none focus:border-sky-500 disabled:opacity-60"
                value={code}
                onChange={(event) => {
                  setCode(event.target.value);
                  setConfirmDiscard(false);
                  if (state.status === "error") setState({ status: "idle" });
                }}
                aria-invalid={state.status === "error"}
                aria-describedby={state.status === "error" ? "bridge-pairing-error" : "bridge-pairing-description"}
                disabled={busy}
                spellCheck={false}
              />
              {state.status === "loading" && (
                <p className="mt-2 flex items-center gap-2 text-xs text-sky-300" role="status">
                  <LoaderCircle className="h-3.5 w-3.5 animate-spin" aria-hidden />
                  Validando assinatura e conectividade...
                </p>
              )}
              {state.status === "error" && (
                <div id="bridge-pairing-error" className="mt-2 flex items-start justify-between gap-3" role="alert">
                  <p className="text-xs leading-5 text-red-400">{state.message}</p>
                  <button className="flex shrink-0 items-center gap-1 text-xs text-zinc-300 hover:text-white" onClick={add} disabled={!code.trim()}>
                    <RotateCcw className="h-3.5 w-3.5" aria-hidden />
                    Tentar novamente
                  </button>
                </div>
              )}
              {confirmDiscard && (
                <div className="mt-3 rounded-md border border-amber-800/60 bg-amber-950/30 p-3" role="alert">
                  <p className="text-xs leading-5 text-amber-200">O código digitado ainda não foi salvo. Descartar mesmo assim?</p>
                  <div className="mt-2 flex gap-2">
                    <button className="rounded border border-amber-700 px-2.5 py-1.5 text-xs text-amber-100 hover:bg-amber-950" onClick={onClose}>Descartar código</button>
                    <button className="rounded border border-zinc-700 px-2.5 py-1.5 text-xs text-zinc-200 hover:bg-zinc-800" onClick={() => setConfirmDiscard(false)}>Continuar editando</button>
                  </div>
                </div>
              )}
              <div className="mt-4 flex justify-end gap-2">
                <button className="rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800 disabled:opacity-50" onClick={requestClose} disabled={busy}>Cancelar</button>
                <button className="rounded-md bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-40" disabled={busy || !code.trim()} onClick={add}>
                  {busy ? "Verificando..." : "Adicionar"}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
