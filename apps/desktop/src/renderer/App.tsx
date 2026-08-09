import { useEffect, useState } from "react";
import { Onboarding } from "./views/Onboarding";
import { Login } from "./views/Login";
import { Main } from "./views/Main";

type Phase = "loading" | "onboarding" | "login" | "main";

interface WindowApi {
  identityStatus: () => Promise<{ exists: boolean }>;
  identityCreate: (nickname: string, password: string) => Promise<{ ok: boolean; identityId?: string; recoveryKey?: string; error?: { message: string } }>;
  identityUnlock: (password: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  identityRestore: (recoveryKey: string, nickname: string, newPassword: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  serverCreate: () => Promise<{ ok: boolean; data?: unknown; error?: { message: string } }>;
  serverJoin: (hostUrl: string, inviteKey: string) => Promise<{ ok: boolean; data?: unknown; error?: { message: string } }>;
  serverState: () => Promise<{ ok: boolean; data?: unknown }>;
  sendMessage: (channelId: string, text: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  attachmentSend: (channelId: string, name: string, mimeType: string, dataB64: string) => Promise<{ ok: boolean; data?: { assetId: string }; error?: { message: string } }>;
  attachmentDownload: (assetId: string) => Promise<{ ok: boolean; data?: { data: string; sizeBytes: number }; error?: { message: string } }>;
  attachmentSave: (assetId: string, name: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  linkingCreate: () => Promise<{ ok: boolean; data?: { payload: string; expiresAt: number }; error?: { message: string } }>;
  callJoin: (channelId: string) => Promise<{ ok: boolean; data?: { participants: string[] }; error?: { message: string } }>;
  callLeave: (channelId: string) => Promise<unknown>;
  callSignal: (channelId: string, to: string, payload: unknown) => Promise<unknown>;
  memberAction: (identityId: string, action: "kick" | "ban") => Promise<{ ok: boolean; error?: { message: string } }>;
  createRole: (name: string, level: number, permissions: string[]) => Promise<{ ok: boolean; error?: { message: string } }>;
  assignRole: (memberIdentityId: string, roleId: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  updateServerConfig: (config: Record<string, unknown>) => Promise<{ ok: boolean; error?: { message: string } }>;
  listInvites: () => Promise<{ ok: boolean; data?: unknown[]; error?: { message: string } }>;
  revokeInvite: (inviteId: string) => Promise<{ ok: boolean; error?: { message: string } }>;
  inviteCreate: () => Promise<{ ok: boolean; data?: { inviteKey: string }; error?: { message: string } }>;
  hostUrl: () => Promise<string>;
  on: (channel: string, cb: (data: unknown) => void) => void;
}

declare global {
  interface Window {
    janjacord: WindowApi;
  }
}

export function App() {
  const [phase, setPhase] = useState<Phase>("loading");
  const [identity, setIdentity] = useState<{ identityId: string; nickname: string } | null>(null);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);

  useEffect(() => {
    window.janjacord.identityStatus().then((s) => {
      setPhase(s.exists ? "login" : "onboarding");
    });
  }, []);

  return (
    <div className="h-screen w-screen flex items-center justify-center">
      {phase === "loading" && <div className="text-zinc-500">JanjaCord…</div>}
      {phase === "onboarding" && (
        <Onboarding
          onCreate={async (nickname, password) => {
            const res = await window.janjacord.identityCreate(nickname, password);
            if (res.ok && res.identityId) {
              setIdentity({ identityId: res.identityId, nickname });
              setRecoveryKey(res.recoveryKey ?? null);
              setPhase("main");
            }
            return res;
          }}
        />
      )}
      {phase === "login" && (
        <Login
          onUnlock={async (password) => {
            const res = await window.janjacord.identityUnlock(password);
            if (res.ok) {
              setPhase("main");
            }
            return res;
          }}
          onRestore={async (rk, nickname, password) => {
            const res = await window.janjacord.identityRestore(rk, nickname, password);
            if (res.ok) {
              setRecoveryKey(rk);
              setPhase("main");
            }
            return res;
          }}
        />
      )}
      {phase === "main" && <Main identity={identity} recoveryKey={recoveryKey} />}
    </div>
  );
}
