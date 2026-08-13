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
        });
        if (ownedChild.exitCode !== null || ownedChild.killed || child !== ownedChild) {
          throw new ProviderError(id, "process_exited", `${id} process exited during startup.`);
        }
        current = providerStatus(id, stability === "temporary" ? "limited" : "running", {
          installed: true,
          endpoint,
          stability,
          message,
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
        throw sanitizedProviderError(id, error);
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
    requiredSecret: "NGROK_AUTHTOKEN",
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
