import { execFile as nodeExecFile, spawn as nodeSpawn } from "node:child_process";
import { createSubprocessRunner } from "./subprocess.mjs";
import {
  createCloudflaredNamedProvider,
  createCloudflaredQuickProvider,
  createManualNginxProvider,
  createNgrokProvider,
  createTailscaleProvider,
} from "./providers.mjs";

export const PROVIDER_IDS = Object.freeze({
  TAILSCALE_FUNNEL: "tailscale-funnel",
  NGROK: "ngrok",
  CLOUDFLARED_QUICK: "cloudflared-quick",
  CLOUDFLARED_NAMED: "cloudflared-named",
  MANUAL_NGINX: "manual-nginx",
});

const PROVIDER_ID_LIST = Object.freeze(Object.values(PROVIDER_IDS));
const BASE_ENV_ALLOWLIST = new Set([
  "APPDATA",
  "COMSPEC",
  "HOME",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "LANG",
  "LOCALAPPDATA",
  "NO_PROXY",
  "PATH",
  "PATHEXT",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "SYSTEMROOT",
  "TEMP",
  "TMP",
  "TMPDIR",
  "TZ",
  "USERPROFILE",
  "WINDIR",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "XDG_RUNTIME_DIR",
]);

function connectivityBaseEnvironment(inherited) {
  const result = {};
  for (const [key, value] of Object.entries(inherited)) {
    const normalized = key.toUpperCase();
    if (BASE_ENV_ALLOWLIST.has(normalized) || normalized.startsWith("LC_")) result[key] = value;
  }
  return result;
}

function resolveProvider(providers, provider) {
  if (typeof provider !== "string" || !Object.hasOwn(providers, provider)) {
    throw new TypeError(`Unknown connectivity provider '${String(provider)}'.`);
  }
  return providers[provider];
}

export function createProviderRegistry(injected = {}) {
  if (injected === null || typeof injected !== "object" || Array.isArray(injected)) {
    throw new TypeError("registry dependencies must be an object.");
  }
  const hasCustomSpawn = Object.hasOwn(injected, "spawn");
  const spawn = injected.spawn ?? nodeSpawn;
  const execFile = Object.hasOwn(injected, "execFile")
    ? injected.execFile
    : hasCustomSpawn ? undefined : nodeExecFile;
  const runner = createSubprocessRunner({ spawn, execFile });
  const baseEnvironment = connectivityBaseEnvironment(process.env);
  const dependencies = { runner, baseEnvironment };
  const providers = Object.freeze({
    [PROVIDER_IDS.TAILSCALE_FUNNEL]: createTailscaleProvider({
      ...dependencies,
      id: PROVIDER_IDS.TAILSCALE_FUNNEL,
    }),
    [PROVIDER_IDS.NGROK]: createNgrokProvider({
      ...dependencies,
      id: PROVIDER_IDS.NGROK,
    }),
    [PROVIDER_IDS.CLOUDFLARED_QUICK]: createCloudflaredQuickProvider({
      ...dependencies,
      id: PROVIDER_IDS.CLOUDFLARED_QUICK,
    }),
    [PROVIDER_IDS.CLOUDFLARED_NAMED]: createCloudflaredNamedProvider({
      ...dependencies,
      id: PROVIDER_IDS.CLOUDFLARED_NAMED,
    }),
    [PROVIDER_IDS.MANUAL_NGINX]: createManualNginxProvider({
      ...dependencies,
      id: PROVIDER_IDS.MANUAL_NGINX,
    }),
  });

  return Object.freeze({
    ids: PROVIDER_ID_LIST,
    providers,
    get(provider) {
      return resolveProvider(providers, provider);
    },
    detect(provider, options) {
      return resolveProvider(providers, provider).detect(options);
    },
    start(provider, options) {
      return resolveProvider(providers, provider).start(options);
    },
    status(provider, options) {
      return resolveProvider(providers, provider).status(options);
    },
    stop(provider, options) {
      return resolveProvider(providers, provider).stop(options);
    },
  });
}

const defaultRegistry = createProviderRegistry();

export function detectProvider(provider, options) {
  return defaultRegistry.detect(provider, options);
}

export function startProvider(provider, options) {
  return defaultRegistry.start(provider, options);
}

export function statusProvider(provider, options) {
  return defaultRegistry.status(provider, options);
}

export function stopProvider(provider, options) {
  return defaultRegistry.stop(provider, options);
}
