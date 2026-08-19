import {
  LOCAL_PORT,
  ProviderError,
  assertPlainOptions,
  buildEnvironment,
  endpointHostname,
  extractPublicWssEndpoint,
  normalizeWssEndpoint,
  providerStatus,
  requireEnvironmentSecret,
  sanitizedProviderError,
  startupTimeout,
  validateConfigPath,
} from "./shared.mjs";

const DETECT_KEYS = ["env", "timeoutMs"];
const PROCESS_START_KEYS = ["env", "startupTimeoutMs"];
const NAMED_START_KEYS = ["env", "endpoint", "startupTimeoutMs"];

function commandTimeout(value) {
  if (value === undefined) return 5_000;
  if (!Number.isInteger(value) || value < 1 || value > 60_000) {
    throw new TypeError("timeoutMs must be an integer between 1 and 60000.");
  }
  return value;
}

async function detectCli({ id, command, versionArgs, runner, baseEnvironment }, options = {}) {
  const input = assertPlainOptions(options, DETECT_KEYS);
  const env = buildEnvironment(baseEnvironment, input.env);
  try {
    await runner.run(command, versionArgs, { env, timeoutMs: commandTimeout(input.timeoutMs) });
    return providerStatus(id, "available", {
      installed: true,
      message: `${id} CLI is available.`,
    });
  } catch {
    return providerStatus(id, "unavailable", {
      installed: false,
      message: `${id} CLI is not installed or could not be executed.`,
    });
  }
}

function attachLifecycle(child, onExit) {
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    onExit();
  };
  child.once("exit", close);
  child.once("error", close);
}

function waitForEndpoint(child, {
  provider,
  timeoutMs,
  knownEndpoint = null,
  readyPattern = null,
  endpointPredicate = null,
  authFailurePattern = null,
}) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    let settled = false;
    let timer;
    const cleanup = () => {
      clearTimeout(timer);
      child.stdout?.off("data", onData);
      child.stderr?.off("data", onData);
      child.off("error", onError);
      child.off("exit", onExit);
    };
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      callback(value);
    };
    const onData = (chunk) => {
      buffer = `${buffer}${String(chunk)}`.slice(-128 * 1024);
      if (authFailurePattern?.test(buffer)) {
        finish(reject, new ProviderError(provider, "auth_required", `${provider} requires authentication.`));
        return;
      }
      if (!knownEndpoint) {
        const endpoint = extractPublicWssEndpoint(buffer, { predicate: endpointPredicate });
        if (endpoint) {
          finish(resolve, endpoint);
          return;
        }
      }
      if (knownEndpoint && readyPattern?.test(buffer)) finish(resolve, knownEndpoint);
    };
    const onError = () => finish(reject, new ProviderError(provider, "process_failed", `${provider} process failed during startup.`));
    const onExit = (code) => finish(reject, new ProviderError(provider, "process_exited", `${provider} process exited during startup${Number.isInteger(code) ? ` (exit ${code})` : ""}.`));

    child.stdout?.on("data", onData);
    child.stderr?.on("data", onData);
    child.once("error", onError);
    child.once("exit", onExit);
    timer = setTimeout(() => {
      finish(reject, new ProviderError(provider, "startup_timeout", `${provider} did not publish a usable endpoint before the startup timeout.`));
    }, timeoutMs);
    timer.unref?.();
  });
}

function createManagedCliProvider({
  id,
  command,
  versionArgs,
  args,
  runner,
  baseEnvironment,
  stability,
  message,
  requiredSecret,
  named = false,
  readyPattern = null,
  endpointPredicate = null,
  authFailurePattern = null,
}) {
  let child = null;
  let current = providerStatus(id, "stopped", { installed: null, message: `${id} is stopped.` });

  return Object.freeze({
    id,
    detect: (options) => detectCli({ id, command, versionArgs, runner, baseEnvironment }, options),
    async start(options = {}) {
      const input = assertPlainOptions(options, named ? NAMED_START_KEYS : PROCESS_START_KEYS);
      if (child && child.exitCode === null && !child.killed) {
        throw new ProviderError(id, "already_running", `${id} is already running.`);
      }
      const env = buildEnvironment(baseEnvironment, input.env);
      if (requiredSecret) requireEnvironmentSecret(env, requiredSecret, id);
      const knownEndpoint = named ? normalizeWssEndpoint(input.endpoint) : null;
      const timeoutMs = startupTimeout(input.startupTimeoutMs);

      try {
        child = runner.spawn(command, args, { env });
        const ownedChild = child;
        attachLifecycle(ownedChild, () => {
          if (child !== ownedChild) return;
          child = null;
          current = providerStatus(id, "stopped", { installed: true, message: `${id} process exited.` });
        });
        const endpoint = await waitForEndpoint(ownedChild, {
          provider: id,
          timeoutMs,
          knownEndpoint,
          readyPattern,
          endpointPredicate,
          authFailurePattern,
        });
        if (ownedChild.exitCode !== null || ownedChild.killed || child !== ownedChild) {
          throw new ProviderError(id, "process_exited", `${id} process exited during startup.`);
        }
        current = providerStatus(id, stability === "temporary" ? "limited" : "running", {
          installed: true,
          endpoint,
          stability,
          message,
          pid: ownedChild.pid,
        });
        return current;
      } catch (error) {
        if (child) await runner.terminate(child);
        child = null;
        current = providerStatus(id, "error", {
          installed: error?.code === "not_found" ? false : null,
          message: `${id} failed to start.`,
        });
        throw sanitizedProviderError(id, error);
      }
    },
    async status(options = {}) {
      assertPlainOptions(options, []);
      return current;
    },
    async stop(options = {}) {
      assertPlainOptions(options, []);
      const ownedChild = child;
      child = null;
      if (ownedChild) await runner.terminate(ownedChild);
      current = providerStatus(id, "stopped", { installed: null, message: `${id} is stopped.` });
      return current;
    },
  });
}

function classifyTailscaleFailure(error) {
  const combined = `${String(error?.message ?? "")}\n${String(error?.stdout ?? "")}\n${String(error?.stderr ?? "")}`;
  if (/funnel is not enabled/i.test(combined)) {
    return new ProviderError("tailscale-funnel", "tailscale_funnel_disabled", "Funnel is not enabled on the tailnet. Enable it at https://login.tailscale.com/f/funnel");
  }
  if (/NeedsLogin|logged out|unauthorized/i.test(combined)) {
    return new ProviderError("tailscale-funnel", "tailscale_needs_login", "Tailscale requires login. Run 'tailscale up' or sign in from the Tailscale app.");
  }
  if (/not connected|node is offline|state\\?['\"]?:\\s*['\"]?offline|connection lost/i.test(combined)) {
    return new ProviderError("tailscale-funnel", "tailscale_offline", "Tailscale is not connected on this machine.");
  }
  return null;
}

export function createTailscaleProvider({ id, runner, baseEnvironment }) {
  let active = false;
  let current = providerStatus(id, "stopped", { installed: null, message: "Tailscale Funnel is stopped." });

  return Object.freeze({
    id,
    detect: (options) => detectCli({ id, command: "tailscale", versionArgs: ["version"], runner, baseEnvironment }, options),
    async start(options = {}) {
      const input = assertPlainOptions(options, PROCESS_START_KEYS);
      const env = buildEnvironment(baseEnvironment, input.env);
      const timeoutMs = startupTimeout(input.startupTimeoutMs);
      let activationAttempted = false;
      if (active) throw new ProviderError(id, "already_running", "Tailscale Funnel is already running.");

      try {
        activationAttempted = true;
        await runner.run("tailscale", ["funnel", "--bg", "--yes", String(LOCAL_PORT)], { env, timeoutMs });
        active = true;
        const result = await runner.run("tailscale", ["funnel", "status", "--json"], { env, timeoutMs });
        const endpoint = extractPublicWssEndpoint(`${result.stdout}\n${result.stderr}`);
        if (!endpoint) throw new ProviderError(id, "endpoint_missing", "Tailscale Funnel did not report a usable public endpoint.");
        current = providerStatus(id, "running", {
          installed: true,
          endpoint,
          stability: "account",
          message: "Tailscale Funnel is publishing the JanjaNode endpoint.",
        });
        return current;
      } catch (error) {
        if (active || activationAttempted) {
          try {
            await runner.run("tailscale", ["funnel", "--bg", "--yes", String(LOCAL_PORT), "off"], {
              env,
              timeoutMs: Math.min(timeoutMs, 5_000),
            });
          } catch {
            // Best-effort rollback. The caller gets a sanitized failure and may retry stop.
          }
        }
        active = false;
        current = providerStatus(id, "error", { installed: null, message: "Tailscale Funnel failed to start." });
        throw classifyTailscaleFailure(error) ?? sanitizedProviderError(id, error);
      }
    },
    async status(options = {}) {
      assertPlainOptions(options, DETECT_KEYS);
      if (!active) return current;
      const env = buildEnvironment(baseEnvironment, options.env);
      try {
        const result = await runner.run("tailscale", ["funnel", "status", "--json"], {
          env,
          timeoutMs: commandTimeout(options.timeoutMs),
        });
        const endpoint = extractPublicWssEndpoint(`${result.stdout}\n${result.stderr}`);
        if (!endpoint) throw new Error("endpoint unavailable");
        current = providerStatus(id, "running", {
          installed: true,
          endpoint,
          stability: "account",
          message: "Tailscale Funnel is publishing the JanjaNode endpoint.",
        });
      } catch {
        current = providerStatus(id, "error", {
          installed: null,
          message: "Tailscale Funnel status is unavailable.",
        });
      }
      return current;
    },
    async stop(options = {}) {
      const input = assertPlainOptions(options, DETECT_KEYS);
      const env = buildEnvironment(baseEnvironment, input.env);
      if (active) {
        try {
          await runner.run("tailscale", ["funnel", "--bg", "--yes", String(LOCAL_PORT), "off"], {
            env,
            timeoutMs: commandTimeout(input.timeoutMs),
          });
        } catch (error) {
          throw sanitizedProviderError(id, error);
        }
      }
      active = false;
      current = providerStatus(id, "stopped", { installed: null, message: "Tailscale Funnel is stopped." });
      return current;
    },
  });
}

export function createNgrokProvider(dependencies) {
  return createManagedCliProvider({
    ...dependencies,
    command: "ngrok",
    versionArgs: ["version"],
    args: ["http", String(LOCAL_PORT), "--log", "stdout", "--log-format", "json"],
    // O agente ngrok pode estar autenticado pelo proprio config (~/.config/ngrok/ngrok.yml);
    // o token do app e opcional. Falhas de autenticacao sao detectadas na saida.
    authFailurePattern: /authtoken|authentication required/i,
    stability: "session",
    message: "ngrok is publishing the JanjaNode endpoint.",
  });
}

export function createCloudflaredQuickProvider(dependencies) {
  return createManagedCliProvider({
    ...dependencies,
    command: "cloudflared",
    versionArgs: ["--version"],
    args: ["tunnel", "--url", `http://127.0.0.1:${LOCAL_PORT}`],
    stability: "temporary",
    message: "Cloudflare Quick Tunnel is temporary and has no production SLA.",
    endpointPredicate: (endpoint) => endpointHostname(endpoint).endsWith(".trycloudflare.com"),
  });
}

export function createCloudflaredNamedProvider(dependencies) {
  return createManagedCliProvider({
    ...dependencies,
    command: "cloudflared",
    versionArgs: ["--version"],
    args: ["tunnel", "run"],
    requiredSecret: "TUNNEL_TOKEN",
    stability: "account",
    message: "Cloudflare Named Tunnel is publishing the configured endpoint.",
    named: true,
    readyPattern: /registered tunnel connection/i,
  });
}

function nginxConfigFor(endpoint, options) {
  const parsed = new URL(endpoint);
  const hostname = parsed.hostname;
  const certificatePath = validateConfigPath(
    options.certificatePath,
    "certificatePath",
    `/etc/letsencrypt/live/${hostname}/fullchain.pem`,
  );
  const certificateKeyPath = validateConfigPath(
    options.certificateKeyPath,
    "certificateKeyPath",
    `/etc/letsencrypt/live/${hostname}/privkey.pem`,
  );
  return `server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ${hostname};

    ssl_certificate ${certificatePath};
    ssl_certificate_key ${certificateKeyPath};

    location / {
        proxy_pass http://127.0.0.1:${LOCAL_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 90s;
    }
}
`;
}

export function createManualNginxProvider({ id, runner, baseEnvironment }) {
  let current = providerStatus(id, "stopped", { installed: null, message: "Manual domain route is not configured." });
  return Object.freeze({
    id,
    async detect(options = {}) {
      const detected = await detectCli({ id, command: "nginx", versionArgs: ["-v"], runner, baseEnvironment }, options);
      return providerStatus(id, "available", {
        installed: detected.installed,
        message: detected.installed
          ? "Nginx is available; generate and validate the domain configuration."
          : "Nginx was not detected; configuration can still be generated for another host.",
      });
    },
    async start(options = {}) {
      const input = assertPlainOptions(options, ["endpoint", "certificatePath", "certificateKeyPath"]);
      const endpoint = normalizeWssEndpoint(input.endpoint, { rootPathOnly: true });
      current = providerStatus(id, "configuration_required", {
        installed: null,
        endpoint,
        stability: "operator",
        message: "Install this Nginx configuration, then verify DNS, TLS and WSS before activating the route.",
        nginxConfig: nginxConfigFor(endpoint, input),
      });
      return current;
    },
    async status(options = {}) {
      assertPlainOptions(options, []);
      return current;
    },
    async stop(options = {}) {
      assertPlainOptions(options, []);
      current = providerStatus(id, "stopped", { installed: null, message: "Manual domain route is not configured." });
      return current;
    },
  });
}

// ---------------------------------------------------------------- Zrok (zrok2 v2)

export const ZROK_SHARE_NAME_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ZROK_ENV_ENABLED_PATTERN = /Account\s+Token[\s\S]{0,48}?<<SET>>/i;
const ZROK_ENDPOINT_PROTOBUF_PATTERN = /frontendEndpoints\s*:\s*"([^"]+)"/g;
const ZROK_ENDPOINT_LOG_PATTERN = /endpoints?\s*:\s*\r?\n\s*([A-Za-z0-9.-]+)/g;
const ZROK_ENDPOINT_HOST_PATTERN = /([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]+)+)/gi;
const ZROK_SHARE_TOKEN_PATTERN = /token\s*:\s*"([^"]+)"/;

/**
 * Detecta ambiente habilitado no output de `zrok2 status`. `zrok2 status` retorna exit 0 mesmo
 * sem ambiente; a seção `Environment` com `Account Token <<SET>>` é o marcador real.
 */
export function zrokEnvironmentEnabled(text) {
  return typeof text === "string" && ZROK_ENV_ENABLED_PATTERN.test(text);
}

/**
 * Extrai o host público do endpoint de uma share Zrok a partir do output da CLI v2.
 * Cobre o formato protobuf-text do agent (`frontendEndpoints:"host"`) e a linha
 * `access your zrok share at the following endpoints: <host>` do share local.
 */
export function zrokShareEndpointFromOutput(text) {
  if (typeof text !== "string") return null;
  const candidates = [];
  for (const match of text.matchAll(ZROK_ENDPOINT_PROTOBUF_PATTERN)) candidates.push(match[1]);
  for (const match of text.matchAll(ZROK_ENDPOINT_LOG_PATTERN)) candidates.push(match[1]);
  for (const match of text.matchAll(ZROK_ENDPOINT_HOST_PATTERN)) candidates.push(match[1]);
  for (const candidate of candidates) {
    const host = candidate.trim().toLowerCase().replace(/[),.;]+$/g, "");
    if (host.length < 4 || host.length > 253 || !/^[a-z0-9.-]+$/.test(host) || host.startsWith(".") || host.endsWith(".")) continue;
    return host;
  }
  return null;
}

/**
 * Extrai o share token de uma linha protobuf-text (`token:"..."`). Usado para parar a share
 * individual quando o agent Zrok é externo ao app (não derrubar o daemon do operador).
 */
export function zrokShareTokenFromOutput(text) {
  if (typeof text !== "string") return null;
  const match = text.match(ZROK_SHARE_TOKEN_PATTERN);
  return match ? match[1] : null;
}

export function createZrokProvider({ id, runner, baseEnvironment }) {
  let agentChild = null; // child do daemon agent que este adapter subiu (null = agent externo)
  let shareToken = null; // token da share criada por este adapter
  let current = providerStatus(id, "stopped", { installed: null, message: "Zrok is stopped." });

  async function environmentEnabled(env, timeoutMs) {
    const result = await runner.run("zrok2", ["status"], { env, timeoutMs });
    return zrokEnvironmentEnabled(`${result.stdout}\n${result.stderr}`);
  }

  async function agentActive(env, timeoutMs) {
    try {
      await runner.run("zrok2", ["agent", "status"], { env, timeoutMs });
      return true;
    } catch {
      return false;
    }
  }

  async function ensureAgent(env, timeoutMs) {
    if (await agentActive(env, timeoutMs)) return { owned: false };
    const child = runner.spawn("zrok2", ["agent", "start"], { env });
    const ownedChild = child;
    attachLifecycle(ownedChild, () => {
      if (agentChild !== ownedChild) return;
      agentChild = null;
      if (current.state === "running") {
        current = providerStatus(id, "error", { installed: true, message: "Zrok agent exited unexpectedly." });
      }
    });
    const deadline = Date.now() + Math.min(timeoutMs, 20_000);
    for (;;) {
      if (ownedChild.exitCode !== null || ownedChild.killed) {
        throw new ProviderError(id, "process_exited", "Zrok agent exited during startup.");
      }
      if (await agentActive(env, 3_000)) break;
      if (Date.now() >= deadline) {
        throw new ProviderError(id, "startup_timeout", "Zrok agent did not become ready in time.");
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    agentChild = ownedChild;
    return { owned: true, child: ownedChild };
  }

  async function ensureName(env, name, timeoutMs) {
    try {
      await runner.run("zrok2", ["create", "name", "-n", "public", name], { env, timeoutMs });
    } catch (error) {
      const combined = `${String(error?.stderr ?? "")}\n${String(error?.stdout ?? "")}`;
      if (error?.exitCode === 1 && /createShareNameConflict/i.test(combined)) return; // já reservado (idempotente)
      throw new ProviderError(id, "zrok_name_conflict", `Não foi possível reservar o nome Zrok '${name}'.`);
    }
  }

  async function startShare(env, name, timeoutMs) {
    const result = await runner.run(
      "zrok2",
      ["share", "public", `127.0.0.1:${LOCAL_PORT}`, "-n", `public:${name}`, "--open", "--headless"],
      { env, timeoutMs },
    );
    const text = `${result.stdout}\n${result.stderr}`;
    const host = zrokShareEndpointFromOutput(text);
    if (!host) throw new ProviderError(id, "endpoint_missing", "Zrok did not report a usable public endpoint.");
    const endpoint = normalizeWssEndpoint(`wss://${host}/`);
    return { endpoint, token: zrokShareTokenFromOutput(text) };
  }

  return Object.freeze({
    id,
    async detect(options = {}) {
      const input = assertPlainOptions(options, DETECT_KEYS);
      const env = buildEnvironment(baseEnvironment, input.env);
      const timeoutMs = commandTimeout(input.timeoutMs);
      try {
        await runner.run("zrok2", ["version"], { env, timeoutMs });
      } catch {
        return providerStatus(id, "unavailable", {
          installed: false,
          message: "zrok2 CLI is not installed or could not be executed.",
        });
      }
      let enabled = false;
      try {
        enabled = await environmentEnabled(env, timeoutMs);
      } catch {
        // status sem ambiente ainda retorna exit 0; falha aqui mantém enabled=false.
      }
      return providerStatus(id, "available", {
        installed: true,
        enabled,
        message: enabled
          ? "zrok2 CLI is available and the environment is enabled."
          : "zrok2 CLI is available; enable the Zrok environment to publish routes.",
      });
    },
    async start(options = {}) {
      const input = assertPlainOptions(options, ["env", "name", "startupTimeoutMs"]);
      const env = buildEnvironment(baseEnvironment, input.env);
      const timeoutMs = startupTimeout(input.startupTimeoutMs);
      const name = typeof input.name === "string" ? input.name.trim().toLowerCase() : "";
      if (!ZROK_SHARE_NAME_PATTERN.test(name) || name.length > 63) {
        throw new ProviderError(id, "invalid_name", "Zrok share name must be a 1-63 character lowercase hostname label.");
      }
      let owned = false;
      try {
        if (!(await environmentEnabled(env, timeoutMs))) {
          throw new ProviderError(id, "zrok_env_not_enabled", "O ambiente Zrok não está habilitado nesta máquina. Rode `zrok2 enable <token> --headless` no terminal e tente novamente.");
        }
        const agent = await ensureAgent(env, timeoutMs);
        owned = agent.owned;
        await ensureName(env, name, timeoutMs);
        const share = await startShare(env, name, timeoutMs);
        shareToken = share.token;
        current = providerStatus(id, "running", {
          installed: true,
          endpoint: share.endpoint,
          stability: "account",
          message: "Zrok is publishing the JanjaNode endpoint through a persistent named share.",
          ...(agent.child?.pid ? { pid: agent.child.pid } : {}),
        });
        return current;
      } catch (error) {
        if (owned && agentChild) await runner.terminate(agentChild);
        agentChild = null;
        shareToken = null;
        current = providerStatus(id, "error", { installed: null, message: "Zrok failed to start." });
        throw sanitizedProviderError(id, error);
      }
    },
    async status(options = {}) {
      const input = assertPlainOptions(options, DETECT_KEYS);
      if (current.state !== "running") return current;
      const env = buildEnvironment(baseEnvironment, input.env);
      try {
        const result = await runner.run("zrok2", ["agent", "status"], {
          env,
          timeoutMs: commandTimeout(input.timeoutMs),
        });
        const host = zrokShareEndpointFromOutput(`${result.stdout}\n${result.stderr}`);
        if (host && current.endpoint?.includes(host)) return current;
        current = providerStatus(id, "error", { installed: true, message: "Zrok share is not active on the agent." });
      } catch {
        current = providerStatus(id, "error", { installed: true, message: "Zrok agent is not responding." });
      }
      return current;
    },
    async stop(options = {}) {
      assertPlainOptions(options, []);
      const ownedChild = agentChild;
      agentChild = null;
      if (ownedChild) {
        // agent gerenciado pelo app: derrubar o daemon encerra todas as shares de forma
        // determinística; o nome reservado persiste e o endpoint volta no próximo start.
        await runner.terminate(ownedChild);
      } else if (shareToken) {
        // agent externo: parar apenas a share deste app para não derrubar o daemon do operador.
        const env = buildEnvironment(baseEnvironment, {});
        try {
          await runner.run("zrok2", ["delete", "share", shareToken], { env, timeoutMs: 8_000 });
        } catch {
          // Best-effort; a rota pode já ter expirado ou o servidor estar inacessível.
        }
      }
      shareToken = null;
      current = providerStatus(id, "stopped", { installed: null, message: "Zrok is stopped." });
      return current;
    },
  });
}
