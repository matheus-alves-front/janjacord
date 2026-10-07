/**
 * Tradução de falha de rota em código acionável e linha de diagnóstico legível.
 *
 * Antes disto o join reportava `timeout` para qualquer coisa: o HostClient registrava o erro do
 * socket e o descartava, então TLS rejeitado, DNS quebrado ou conexão recusada chegavam ao
 * usuário como "a conexão demorou além do esperado". Este módulo usa a falha do transporte e o
 * probe por fases (dns/tcp/tls/ws) para nomear a camada que falhou.
 */

const TLS_FAILURE_PATTERN = /DEPTH_ZERO_SELF_SIGNED|SELF_SIGNED_CERT|UNABLE_TO_VERIFY_LEAF|UNABLE_TO_GET_ISSUER|CERT_HAS_EXPIRED|CERT_UNTRUSTED|CERT_REVOKED|ERR_TLS_CERT|ERR_SSL|certificate/i;
// O host respondeu, mas não é o host do convite (comunidade/authority/chave/hostId diferentes).
// Não é problema de rede: é a rota entregando outro processo.
const HOST_IDENTITY_PATTERN = /invalid host authority/i;
const DNS_FAILURE_PATTERN = /ENOTFOUND|EAI_AGAIN|EAI_FAIL|dns_empty|getaddrinfo/i;
const REFUSED_FAILURE_PATTERN = /ECONNREFUSED|tcp_refused/i;
const UNREACHABLE_FAILURE_PATTERN = /ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|ECONNRESET|EPIPE/i;

/**
 * Códigos devolvidos ao renderer. `route_*` separa "a máquina de quem entra não chegou até a
 * rota" de `timeout`, que passa a significar apenas "conectou, mas o host não completou o
 * handshake no orçamento".
 */
export function classifyRouteFailure(failure, probe) {
  const code = typeof failure?.code === "string" ? failure.code : "";
  const message = typeof failure?.message === "string" ? failure.message : "";
  const probeError = typeof probe?.error === "string" ? probe.error : "";
  const signal = [code, message, probeError].filter(Boolean).join(" ");
  if (HOST_IDENTITY_PATTERN.test(signal)) return "host_identity_mismatch";
  if (TLS_FAILURE_PATTERN.test(signal)) return "route_tls_blocked";
  if (DNS_FAILURE_PATTERN.test(signal)) return "route_dns";
  if (REFUSED_FAILURE_PATTERN.test(signal)) return "route_refused";
  if (UNREACHABLE_FAILURE_PATTERN.test(signal)) return "route_unreachable";
  // `tcp_timeout`/`ws_timeout` são sentinelas do probe: DNS resolveu, mas nada respondeu naquela
  // camada. O `timeout` do transporte, isolado, significa só que o orçamento do join acabou.
  if (probeError === "tcp_timeout" || probeError === "ws_timeout") return "route_unreachable";
  if (probe?.status === 404) return "route_missing";
  if (typeof probe?.status === "number" && probe.status >= 500) return "route_backend_down";
  if (code === "timeout" || !signal) return "timeout";
  return "route_failed";
}

/** Linha única com as fases medidas e a causa — é o que o usuário copia para o suporte. */
export function formatRouteDiagnostic(endpoint, failure, probe) {
  const phases = probe?.phases ?? {};
  const measured = [
    typeof phases.dns === "number" ? `dns ${phases.dns}ms` : null,
    typeof phases.tcp === "number" ? `tcp ${phases.tcp}ms` : null,
    typeof phases.tls === "number" ? `tls ${phases.tls}ms` : null,
    typeof phases.ws === "number" ? `ws ${phases.ws}ms` : null,
  ].filter(Boolean).join(" · ");
  const probeDetail = probe?.error
    ? `probe: ${probe.error}`
    : probe?.statusLine
      ? `probe: ${probe.statusLine}`
      : null;
  const transportDetail = failure?.code || failure?.message
    ? `transporte: ${[failure.code, failure.message].filter(Boolean).join(" ")}`
    : null;
  return [
    endpoint,
    measured || "nenhuma fase completou",
    probeDetail,
    transportDetail,
  ].filter(Boolean).join(" · ");
}

/** Detalhe de uma rota testada antes do join (botão "testar rotas do convite"). */
export function describeRouteProbe(endpoint, probe) {
  const ok = Boolean(probe?.ok);
  return {
    endpoint,
    ok,
    status: typeof probe?.status === "number" ? probe.status : null,
    phases: probe?.phases ?? {},
    error: typeof probe?.error === "string" ? probe.error : null,
    code: ok ? "ok" : classifyRouteFailure(null, probe),
    diagnostic: formatRouteDiagnostic(endpoint, null, probe),
  };
}
