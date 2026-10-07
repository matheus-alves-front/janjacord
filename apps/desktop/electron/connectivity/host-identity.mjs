import { hostAuthChallengeMismatch } from "@janjacord/protocol";

/**
 * Pergunta ao host que responde pela rota publicada qual é a identidade dele.
 *
 * Um upgrade 101 prova apenas que há um WebSocket no outro lado: não prova que ele é o host desta
 * comunidade. Era exatamente essa a lacuna — a share podia estar no ar entregando outro processo
 * (outra instância do JanjaCord na mesma porta, túnel reapontado) e o único sintoma era o join de
 * quem entra falhando com "invalid host authority", impossível de diagnosticar do lado de quem
 * hospeda. Aqui a resposta vem assinada pelo próprio host e é comparada com a identidade esperada.
 *
 * A sessão de diagnóstico usa uma chave efêmera e não autentica: o desafio é emitido antes de
 * qualquer vínculo de membro, então a sonda não cria acesso nenhum.
 */
export function probePublishedHostIdentity({
  endpoint,
  openSocket,
  probeIdentityId,
  probePublicKey,
  expectedHostPublicKey,
  expectedHostId = null,
  timeoutMs = 10_000,
}) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = openSocket(endpoint);
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.removeAllListeners();
        socket.close();
      } catch { /* já encerrado */ }
      resolve(result);
    };
    const timer = setTimeout(() => finish({ ok: false, reason: "timeout", identityMismatch: false, hostPublicKey: null, hostId: null }), timeoutMs);
    timer.unref?.();
    socket.once("error", (error) => finish({
      ok: false,
      reason: typeof error?.code === "string" && error.code ? error.code : "network_error",
      identityMismatch: false,
      hostPublicKey: null,
      hostId: null,
    }));
    socket.on("message", (raw) => {
      let frame;
      try {
        frame = JSON.parse(String(raw));
      } catch {
        return; // frame inválido de outro host não é evidência
      }
      if (frame?.event !== "auth.challenge") return;
      const expected = {
        hostPublicKey: expectedHostPublicKey,
        ...(expectedHostId ? { hostId: expectedHostId } : {}),
      };
      const mismatch = hostAuthChallengeMismatch(frame.data, expected);
      const payload = frame.data?.payload ?? {};
      finish({
        ok: mismatch === null,
        reason: mismatch,
        identityMismatch: mismatch !== null && publishedHostMismatchIsIdentity(mismatch),
        hostPublicKey: typeof frame.data?.publicKey === "string" ? frame.data.publicKey : null,
        hostId: typeof payload.hostId === "string" ? payload.hostId : null,
        serverId: typeof payload.serverId === "string" ? payload.serverId : null,
      });
    });
    socket.once("open", () => {
      socket.send(JSON.stringify({ event: "auth.begin", data: { identityId: probeIdentityId, publicKey: probePublicKey } }));
    });
  });
}

/**
 * `true` quando a divergência é de identidade (rota entregando outro host / outro par de chaves) e
 * não de rede. Divergência de identidade bloqueia a ativação da rota; falha de rede não, porque o
 * upgrade já foi validado antes.
 */
export function publishedHostMismatchIsIdentity(reason) {
  return new Set([
    "server_id",
    "authority_fingerprint",
    "host_public_key",
    "host_id",
    "grant_id",
    "signature",
  ]).has(reason);
}

/** Descrição curta da identidade recebida, para log/diagnóstico sem despejar chave inteira. */
export function shortIdentity(value) {
  return typeof value === "string" && value.length > 12 ? `${value.slice(0, 12)}…` : (value ?? "desconhecida");
}
