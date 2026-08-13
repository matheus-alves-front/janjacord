import { useCallback, useEffect, useState } from "react";
import { LoaderCircle, RefreshCw, TriangleAlert } from "lucide-react";
import { Onboarding } from "./views/Onboarding";
import { Login } from "./views/Login";
import { Main } from "./views/Main";
import type { IpcError } from "./ipcErrors";

type Phase = "loading" | "onboarding" | "login" | "main";

interface WindowApi {
  identityStatus: () => Promise<{ exists: boolean }>;
  identityCreate: (nickname: string, password: string) => Promise<{ ok: boolean; identityId?: string; recoveryKey?: string; error?: { message: string } }>;
  identityUnlock: (password: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  identityRestore: (recoveryKey: string, nickname: string, newPassword: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  serverCreate: () => Promise<{ ok: boolean; data?: unknown; connectivity?: { bridgeReady: boolean; needsBridge: boolean }; error?: { code?: string; message: string } }>;
  serverJoin: (hostUrl: string, inviteKey: string, allowLegacyTrust?: boolean) => Promise<{ ok: boolean; data?: unknown; error?: IpcError }>;
  connectivityStatus: () => Promise<{ ok: boolean; data?: { bridges: { bridgeId: string; endpoint: string; expiresAt: number }[]; activeRoute?: ConnectivityRoute | null; backgroundHosting: boolean }; error?: IpcError }>;
  connectivityProviders: () => Promise<{ ok: boolean; data?: { providers: ConnectivityProvider[]; activeRoute?: ConnectivityRoute | null }; error?: IpcError }>;
  connectivityProviderStart: (provider: ConnectivityProviderId, config: Record<string, string | boolean>) => Promise<{ ok: boolean; data?: ConnectivityRoute; error?: IpcError }>;
  connectivityProviderStop: () => Promise<{ ok: boolean; data?: { stopped: boolean }; error?: IpcError }>;
  iceConfiguration: () => Promise<{ ok: boolean; data?: { iceServers: RTCIceServer[]; iceTransportPolicy: "all" | "relay"; expiresAt?: number }; error?: IpcError }>;
  bridgeAdd: (pairingCode: string) => Promise<{ ok: boolean; data?: { bridgeId: string; endpoint: string; expiresAt: number; warning?: string }; error?: IpcError }>;
  bridgeRemove: (bridgeId: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  setHostingAutostart: (enabled: boolean) => Promise<{ ok: boolean; data?: { enabled: boolean }; error?: { message: string } }>;
  registerHostCandidate: () => Promise<{ ok: boolean; data?: unknown; error?: { message: string } }>;
  listHostGrants: () => Promise<{ ok: boolean; data?: { grants?: unknown[]; candidates?: unknown[] }; error?: { message: string } }>;
  authorizeHostCandidate: (subjectIdentityId: string, candidateId: string) => Promise<{ ok: boolean; data?: unknown; error?: { message: string } }>;
  revokeHostGrant: (grantId: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  acceptHostGrant: (grant: Record<string, unknown>) => Promise<{ ok: boolean; data?: unknown; error?: { message: string } }>;
  serverState: () => Promise<{ ok: boolean; data?: unknown; error?: IpcError }>;
  sendMessage: (channelId: string, text: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  attachmentSend: (channelId: string, name: string, mimeType: string, dataB64: string) => Promise<{ ok: boolean; data?: { assetId: string }; error?: { message: string } }>;
  attachmentSave: (assetId: string, name: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  callJoin: (channelId: string) => Promise<{ ok: boolean; data?: { participants: string[] }; error?: { message: string } }>;
  callLeave: (channelId: string) => Promise<unknown>;
  callSignal: (channelId: string, to: string, payload: unknown) => Promise<unknown>;
  memberAction: (identityId: string, action: "kick" | "ban") => Promise<{ ok: boolean; error?: { message: string } }>;
  createRole: (name: string, level: number, permissions: string[]) => Promise<{ ok: boolean; error?: { message: string } }>;
  assignRole: (memberIdentityId: string, roleId: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  updateServerConfig: (config: Record<string, unknown>) => Promise<{ ok: boolean; error?: { message: string } }>;
  listInvites: () => Promise<{ ok: boolean; data?: unknown[]; error?: { message: string } }>;
  revokeInvite: (inviteId: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  channelCreate: (channelType: "text" | "call", name: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  inviteCreate: () => Promise<{ ok: boolean; data?: { inviteId: string; inviteKey: string }; error?: { message: string } }>;
  clipboardClearIfEquals: (text: string) => Promise<{ ok: boolean; data?: { cleared: boolean }; error?: { message: string } }>;
  hostUrl: () => Promise<string>;
  on: (channel: string, cb: (data: unknown) => void) => void;
}

export type ConnectivityProviderId = "tailscale" | "ngrok" | "cloudflare" | "manual";

export interface ConnectivityProvider {
  id: ConnectivityProviderId;
  installed: boolean;
  authenticated?: boolean;
  version?: string;
  detail?: string;
}

export interface ConnectivityRoute {
  provider: ConnectivityProviderId;
  endpoint: string;
  status: "ready" | "limited" | "error";
  media: "direct-only" | "turn";
  stable: boolean;
  startedAt: number;
  expiresAt?: number;
  detail?: string;
}

declare global {
  interface Window {
    janjacord: WindowApi;
  }
}

export function App() {
  const [phase, setPhase] = useState<Phase>("loading");
  const [bootError, setBootError] = useState<string | null>(null);
  const [identity, setIdentity] = useState<{ identityId: string; nickname: string } | null>(null);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);

  const boot = useCallback(async () => {
    setPhase("loading");
    setBootError(null);
    try {
      const status = await window.janjacord.identityStatus();
      setPhase(status.exists ? "login" : "onboarding");
    } catch {
      setBootError("Não foi possível abrir o cofre local do JanjaCord.");
    }
  }, []);

  useEffect(() => {
    void boot();
  }, [boot]);

  return (
    <div className="flex h-screen w-screen min-h-0 items-center justify-center overflow-hidden">
      {phase === "loading" && (
        <div className="flex max-w-sm flex-col items-center gap-3 px-6 text-center" role={bootError ? "alert" : "status"}>
          {bootError ? (
            <TriangleAlert className="h-6 w-6 text-red-400" aria-hidden />
          ) : (
            <LoaderCircle className="h-6 w-6 animate-spin text-sky-400" aria-hidden />
          )}
          <p className="text-sm text-zinc-300">{bootError ?? "Abrindo o JanjaCord..."}</p>
          {bootError && (
            <button className="flex items-center gap-2 rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-900" onClick={boot}>
              <RefreshCw className="h-4 w-4" aria-hidden />
              Tentar novamente
            </button>
          )}
        </div>
      )}
      {phase === "onboarding" && (
        <Onboarding
          onCreate={async (nickname, password) => {
            try {
              const res = await window.janjacord.identityCreate(nickname, password);
              if (res.ok && res.identityId) {
                setIdentity({ identityId: res.identityId, nickname });
                setRecoveryKey(res.recoveryKey ?? null);
                setPhase("main");
              }
              return res;
            } catch {
              return { ok: false, error: { message: "Não foi possível criar a identidade local." } };
            }
          }}
        />
      )}
      {phase === "login" && (
        <Login
          onUnlock={async (password) => {
            try {
              const res = await window.janjacord.identityUnlock(password);
              if (res.ok) setPhase("main");
              return res;
            } catch {
              return { ok: false, error: { message: "Não foi possível desbloquear o cofre local." } };
            }
          }}
          onRestore={async (rk, nickname, password) => {
            try {
              const res = await window.janjacord.identityRestore(rk, nickname, password);
              if (res.ok) {
                setRecoveryKey(rk);
                setPhase("main");
              }
              return res;
            } catch {
              return { ok: false, error: { message: "Não foi possível restaurar a identidade local." } };
            }
          }}
        />
      )}
      {phase === "main" && <Main identity={identity} recoveryKey={recoveryKey} />}
    </div>
  );
}
