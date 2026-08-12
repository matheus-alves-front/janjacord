export interface IpcError {
  code?: string;
  message?: string;
  fingerprint?: string;
  data?: unknown;
}

const FRIENDLY_MESSAGES: Record<string, string> = {
  invalid_invite: "Este convite não é válido. Confira se ele foi copiado por inteiro.",
  invite_expired: "Este convite expirou. Peça um novo convite à comunidade.",
  expired: "Este convite expirou. Peça um novo convite à comunidade.",
  invite_revoked: "Este convite foi revogado. Peça um novo convite à comunidade.",
  revoked: "Este convite foi revogado. Peça um novo convite à comunidade.",
  invite_exhausted: "Este convite já atingiu o limite de usos. Peça um novo convite.",
  unauthorized: "Não foi possível confirmar a identidade desta comunidade.",
  forbidden: "Sua função atual não permite realizar esta ação.",
  host_offline: "A comunidade está offline no momento. Tente novamente quando um host estiver disponível.",
  offline: "Você parece estar offline. Verifique sua conexão e tente novamente.",
  no_route: "Não há uma rota disponível até a comunidade. Tente outro JanjaBridge ou confirme se um host está online.",
  route_unavailable: "Não há uma rota disponível até a comunidade. Tente outro JanjaBridge ou confirme se um host está online.",
  rendezvous: "Nenhum JanjaBridge do convite conseguiu localizar um host disponível.",
  bridge_unavailable: "O JanjaBridge não respondeu. Confira o código e tente outra rota.",
  bridge_expired: "A configuração deste JanjaBridge expirou. Adicione um código de pareamento atualizado.",
  bridge_revoked: "Este JanjaBridge foi revogado. Adicione outra rota.",
  turn_unavailable: "Não foi possível obter uma rota TURN. Em redes restritas, configure outro JanjaBridge.",
  turn_credentials: "As credenciais TURN não estão disponíveis ou expiraram. Tente novamente.",
  turn_expired: "As credenciais TURN expiraram. Tente novamente para obter uma nova rota.",
  turn_required: "Esta rede exige uma rota TURN, mas nenhum JanjaBridge compatível está disponível.",
  relay_unavailable: "A rota relay necessária não está disponível. Tente outro JanjaBridge.",
  network_error: "A conexão de rede falhou. Verifique sua conexão e tente novamente.",
  version_mismatch: "Este convite requer uma versão diferente do JanjaCord. Atualize o app e tente novamente.",
  unsupported_version: "Este convite requer uma versão diferente do JanjaCord. Atualize o app e tente novamente.",
  timeout: "A conexão demorou além do esperado. Verifique a rede e tente novamente.",
  rate_limited: "Foram feitas muitas tentativas. Aguarde um momento e tente novamente.",
  legacy_confirmation_required: "Confira a fingerprint do host antes de continuar.",
};

export function friendlyIpcError(error: IpcError | undefined, fallback: string): string {
  if (typeof navigator !== "undefined" && !navigator.onLine) return FRIENDLY_MESSAGES.offline ?? fallback;
  if (error?.code === "invalid_input") {
    return "A entrada informada não é válida. Revise os dados e tente novamente.";
  }
  if (error?.code) {
    const friendly = FRIENDLY_MESSAGES[error.code];
    if (friendly) return friendly;
  }
  return fallback;
}

export function rejectedIpcError(error: unknown, fallback: string): string {
  if (typeof navigator !== "undefined" && !navigator.onLine) return FRIENDLY_MESSAGES.offline ?? fallback;
  if (error && typeof error === "object" && "code" in error) {
    return friendlyIpcError(error as IpcError, fallback);
  }
  return fallback;
}

/** Supports the transitional IPC shapes used while the JC2 challenge contract is rolled out. */
export function legacyFingerprint(error: IpcError | undefined): string | null {
  const candidates: unknown[] = [error?.fingerprint];
  if (error?.data && typeof error.data === "object" && !Array.isArray(error.data)) {
    const data = error.data as Record<string, unknown>;
    candidates.push(
      data.fingerprint,
      data.hostFingerprint,
      data.hostPublicKeyFingerprint,
      data.presentedFingerprint,
    );
  }
  const value = candidates.find((candidate) => typeof candidate === "string" && candidate.trim().length > 0);
  return typeof value === "string" ? value.trim() : null;
}
