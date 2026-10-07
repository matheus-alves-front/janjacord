import dns from "node:dns";
import net from "node:net";
import tls from "node:tls";
import crypto from "node:crypto";

const DOCTOR_TIMEOUT_MS = 12_000;
const ANSI_PATTERN = /\x1b\[[0-9;]*m/g;

/**
 * Probe de borda por fases (dns/tcp/tls/ws) contra um endpoint wss de rota publicada.
 * Um upgrade WebSocket bem-sucedido responde 101; 404 indica share ausente no edge,
 * 502/504 indicam túnel no ar com backend morto. Construído só com builtins do Node.
 */
export function probeEdgeDetailed(endpoint, { timeoutMs = DOCTOR_TIMEOUT_MS } = {}) {
  const parsed = new URL(endpoint);
  if (parsed.protocol !== "wss:") {
    return Promise.reject(new TypeError("endpoint must be a wss URL"));
  }
  const host = parsed.hostname;
  const port = Number(parsed.port || 443);
  const path = `${parsed.pathname}${parsed.search}` || "/";
  const phases = {};
  const totalStart = Date.now();

  return dns.promises.lookup(host, { all: true }).then((addresses) => {
    phases.dns = Date.now() - totalStart;
    if (addresses.length === 0) throw new Error("dns_empty");
    return new Promise((resolve, reject) => {
      const tcpStart = Date.now();
      const tcp = net.connect({ host, port });
      const bail = (error) => {
        tcp.destroy();
        reject(error);
      };
      tcp.setTimeout(timeoutMs, () => bail(new Error("tcp_timeout")));
      tcp.once("connect", () => {
        phases.tcp = Date.now() - tcpStart;
        tcp.destroy();
        resolve();
      });
      tcp.once("error", bail);
    });
  }).then(() => new Promise((resolve, reject) => {
    const tlsStart = Date.now();
    const key = crypto.randomBytes(16).toString("base64");
    const upgradeRequest = [
      `GET ${path} HTTP/1.1`,
      `Host: ${host}`,
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Key: ${key}`,
      "Sec-WebSocket-Version: 13",
      "\r\n",
    ].join("\r\n");
    const socket = tls.connect({ host, port, servername: host });
    let buffer = "";
    let tlsDone = false;
    const finish = (callback, value) => {
      clearTimeout(timer);
      try { socket.destroy(); } catch { /* already closed */ }
      callback(value);
    };
    const timer = setTimeout(() => finish(reject, new Error("ws_timeout")), timeoutMs);
    socket.once("error", (error) => finish(reject, error));
    socket.once("secureConnect", () => {
      phases.tls = Date.now() - tlsStart;
      tlsDone = true;
      const wsStart = Date.now();
      socket.write(upgradeRequest);
      socket.on("data", (chunk) => {
        buffer += chunk.toString("latin1");
        const lineEnd = buffer.indexOf("\r\n");
        if (lineEnd < 0) return;
        const statusLine = buffer.slice(0, lineEnd);
        const status = Number(statusLine.split(" ")[1]);
        phases.ws = Date.now() - wsStart;
        finish(resolve, {
          ok: status === 101,
          status,
          statusLine: statusLine.trim(),
          phases,
          total: Date.now() - totalStart,
        });
      });
      socket.once("close", () => {
        if (tlsDone && buffer === "") finish(reject, new Error("connection_closed_before_response"));
      });
    });
  })).catch((error) => ({
    ok: false,
    status: null,
    error: String(error?.message ?? error),
    phases,
    total: Date.now() - totalStart,
  }));
}

/** Converte uma linha da tabela `zrok2 agent status` em células limpas. */
export function parseAgentShareRow(line) {
  const cleaned = line.replace(ANSI_PATTERN, "");
  if (!cleaned.includes("│")) return null;
  const cells = cleaned.split("│").slice(1, -1).map((cell) => cell.trim());
  if (cells.length < 6) return null;
  return {
    token: cells[0],
    endpoint: cells[3] === "" ? null : cells[3],
    target: cells[4],
    status: cells[5],
  };
}

export function parseAgentShares(agentStatusText) {
  if (typeof agentStatusText !== "string") return [];
  return agentStatusText
    .split(/\r?\n/)
    .map(parseAgentShareRow)
    .filter((row) => row !== null && !/SHARE TOKEN/i.test(row.token));
}

function tcpProbe(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = net.connect({ host, port });
    const done = (result) => {
      socket.destroy();
      resolve({ ...result, ms: Date.now() - started });
    };
    socket.setTimeout(timeoutMs, () => done({ ok: false, error: "timeout" }));
    socket.once("connect", () => done({ ok: true }));
    socket.once("error", (error) => done({ ok: false, error: error?.code ?? String(error) }));
  });
}

const HINTS = {
  host_down: "O servidor da comunidade não está respondendo neste computador. Abra a comunidade ou reabra o JanjaCord.",
  route_missing: "Nenhuma rota externa está ativa. Ative um provedor em Conectividade antes de compartilhar convites.",
  agent_share_missing: "O agente do provedor não tem essa rota publicada. Desligue a rota e ative de novo.",
  agent_share_retrying: "A rota está tentando se reestabelecer no provedor. Desligue e ative de novo; se persistir, escolha outro nome.",
  edge_not_found: "O provedor não encontra essa rota no ar (ela ficou órfã na conta). Desligue e ative a rota de novo.",
  edge_backend_down: "O túnel está no ar, mas o servidor da comunidade não respondeu atrás dele. Reabra o JanjaCord.",
  edge_unreachable: "O provedor de túnel não respondeu a tempo. Pode ser instabilidade do provedor ou da rede deste computador.",
  published_host_mismatch: "A rota publicada está entregando outro host: outra instância do JanjaCord pode estar usando a mesma porta/túnel, ou a share ficou apontada para um processo antigo. Feche a outra instância, desligue e ative a rota de novo, e só então gere um convite novo.",
  ok: "Tudo certo por aqui. Se o convite ainda falha em outro dispositivo, o bloqueio está na rede ou na segurança da máquina de quem entra.",
};

/**
 * Orquestra o diagnóstico da rota ativa: backend do host, registro de rota, agente do
 * provedor e alcance pela borda. Dependências injetadas para teste.
 */
export async function runConnectivityDoctor({
  activeRoute = null,
  backendPort,
  runAgentStatus,
  probe = probeEdgeDetailed,
  hostLabel = "JanjaNode",
  trustStore = null,
  verifyPublishedHost = null,
} = {}) {
  const checks = [];
  const hints = [];

  if (trustStore) {
    checks.push({
      id: "trust",
      label: "Cofre de certificados desta máquina",
      ok: trustStore.active === true,
      detail: trustStore.active
        ? `cofre do sistema em uso · ${trustStore.system} âncoras do sistema + ${trustStore.bundled} embutidas`
        : `indisponível (${trustStore.error ?? "motivo desconhecido"}) · apenas as ${trustStore.bundled} raízes embutidas`,
    });
    if (trustStore.active !== true) {
      hints.push("Sem o cofre do sistema, antivírus/proxy que inspeciona HTTPS derruba o join nesta máquina.");
    }
  }

  const backend = await tcpProbe("127.0.0.1", backendPort, 3_000);
  checks.push({
    id: "host",
    label: `Servidor da comunidade (${hostLabel})`,
    ok: backend.ok,
    detail: backend.ok ? `respondendo em ${backend.ms}ms` : `sem resposta (${backend.error})`,
  });
  if (!backend.ok) hints.push(HINTS.host_down);

  const route = activeRoute && typeof activeRoute === "object" ? activeRoute : null;
  checks.push({
    id: "route",
    label: "Rota externa configurada",
    ok: Boolean(route?.endpoint),
    detail: route?.endpoint ? `${route.provider} · ${route.endpoint}` : "nenhuma rota ativa",
  });
  if (!route?.endpoint) hints.push(HINTS.route_missing);

  let agentShare = null;
  let zombies = [];
  if (route?.provider === "zrok" && typeof runAgentStatus === "function") {
    let shares = [];
    let agentError = null;
    try {
      shares = parseAgentShares(await runAgentStatus());
    } catch (error) {
      agentError = String(error?.message ?? error);
    }
    const routeHost = route.endpoint ? new URL(route.endpoint).hostname : null;
    agentShare = shares.find((share) => share.endpoint && routeHost && share.endpoint.includes(routeHost)) ?? null;
    const retrying = shares.filter((share) => share.status === "retrying").length;
    const state = agentError ? "error"
      : agentShare?.status === "active" ? "active"
        : shares.length > 0 ? "missing"
          : "agent_empty";
    checks.push({
      id: "agent",
      label: "Publicação no agente do provedor",
      ok: state === "active",
      detail: agentError ? `falhou: ${agentError}`
        : state === "active" ? `share ativa (${agentShare.token})`
          : state === "missing" ? `rota não está publicada${retrying > 0 ? ` · ${retrying} share(s) órfã(s) em retry` : ""}`
            : "agente sem nenhuma share",
    });
    if (state === "missing") hints.push(retrying > 0 ? HINTS.agent_share_retrying : HINTS.agent_share_missing);
    // Shares de ativações anteriores continuam publicadas e servindo URLs antigas: um convite que
    // carrega uma delas aponta para o host errado quando a porta local muda de dono.
    const staleShares = routeHost
      ? shares.filter((share) => share.status === "active" && share.endpoint && !share.endpoint.includes(routeHost))
      : [];
    if (staleShares.length > 0) {
      checks.push({
        id: "stale_shares",
        label: "Shares publicadas que não são a rota atual",
        ok: false,
        detail: staleShares.map((share) => `${share.endpoint} (token ${share.token})`).join(" · "),
      });
      hints.push(`${staleShares.length} share(s) de ativações antigas continuam no ar. Convites que carregam essas URLs não alcançam este host: remova com "zrok2 delete share <token>" ou desligue-as no painel do provedor.`);
    }
    zombies = shares
      .filter((share) => share.status === "retrying" && !share.endpoint)
      .map((share) => share.token);
    if (zombies.length > 0) {
      hints.push(`${zombies.length} share(s) órfã(s) de tentativas antigas podem ser limpas.`);
    }
  }

  let edge = null;
  if (route?.endpoint) {
    edge = await probe(route.endpoint);
    const label = edge.ok ? `rota alcançável pela internet (${edge.total}ms)` : `falhou (HTTP ${edge.status ?? edge.error})`;
    checks.push({ id: "edge", label: "Rota alcançável pela internet", ok: edge.ok, detail: label });
    if (!edge.ok) {
      if (edge.status === 404) hints.push(HINTS.edge_not_found);
      else if (edge.status === 502 || edge.status === 504) hints.push(HINTS.edge_backend_down);
      else hints.push(HINTS.edge_unreachable);
    }
  }

  let publishedHost = null;
  if (route?.endpoint && typeof verifyPublishedHost === "function") {
    publishedHost = await verifyPublishedHost();
    const identityMismatch = publishedHost?.identityMismatch === true;
    checks.push({
      id: "published_host",
      label: "Rota publicada entrega este host",
      ok: publishedHost?.ok === true,
      detail: publishedHost?.ok === true
        ? `desafio assinado por este host (${publishedHost.hostId ?? "hostId local indisponível"})`
        : identityMismatch
          ? `outro host responde por esta rota (${publishedHost.reason}) · recebido ${publishedHost.hostId ?? publishedHost.hostPublicKey ?? "desconhecido"}`
          : `não foi possível confirmar o host atrás da rota (${publishedHost?.reason ?? "sem resposta"})`,
    });
    if (identityMismatch) hints.push(HINTS.published_host_mismatch);
  }

  const failed = checks.filter((check) => !check.ok);
  return {
    overall: failed.length === 0 ? "ok" : checks.some((check) => check.ok) ? "degraded" : "down",
    checks,
    hints,
    zombies,
  };
}
