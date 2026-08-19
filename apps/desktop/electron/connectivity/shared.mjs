import { isIP } from "node:net";

export const LOCAL_PORT = 8931;
export const MAX_STARTUP_TIMEOUT_MS = 60_000;
const DEFAULT_STARTUP_TIMEOUT_MS = 15_000;
const MAX_ENV_VALUE_CHARS = 16_384;

export class ProviderError extends Error {
  constructor(provider, code, message) {
    super(message);
    this.name = "ProviderError";
    this.provider = provider;
    this.code = code;
  }
}

export function assertPlainOptions(value, allowedKeys, label = "options") {
  if (value === undefined) return {};
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  for (const key of Object.keys(value)) {
    if (!allowedKeys.includes(key)) throw new TypeError(`${label}.${key} is not supported.`);
  }
  return value;
}

export function startupTimeout(value) {
  if (value === undefined) return DEFAULT_STARTUP_TIMEOUT_MS;
  if (!Number.isInteger(value) || value < 250 || value > MAX_STARTUP_TIMEOUT_MS) {
    throw new TypeError(`startupTimeoutMs must be an integer between 250 and ${MAX_STARTUP_TIMEOUT_MS}.`);
  }
  return value;
}

export function buildEnvironment(baseEnvironment, suppliedEnvironment) {
  if (suppliedEnvironment === undefined) return { ...baseEnvironment };
  const supplied = assertPlainOptions(suppliedEnvironment, Object.keys(suppliedEnvironment), "options.env");
  const sanitized = {};
  for (const [key, value] of Object.entries(supplied)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(key)) {
      throw new TypeError("options.env contains an invalid variable name.");
    }
    if (["__proto__", "prototype", "constructor"].includes(key)) {
      throw new TypeError("options.env contains a reserved variable name.");
    }
    if (typeof value !== "string" || value.length > MAX_ENV_VALUE_CHARS || /[\u0000-\u001f\u007f]/.test(value)) {
      throw new TypeError(`options.env.${key} must be a bounded string.`);
    }
    sanitized[key] = value;
  }
  return { ...baseEnvironment, ...sanitized };
}

export function requireEnvironmentSecret(environment, key, provider) {
  if (typeof environment[key] !== "string" || environment[key].trim().length === 0) {
    throw new ProviderError(provider, "missing_secret", `${provider} requires ${key} in the supplied environment.`);
  }
}

function isPrivateIpv4(hostname) {
  const octets = hostname.split(".").map(Number);
  const [first, second] = octets;
  return first === 0 || first === 10 || first === 127 ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 100 && second >= 64 && second <= 127) ||
    first >= 224;
}

function isPrivateHost(hostname) {
  const normalized = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (normalized === "localhost" || normalized.endsWith(".localhost") || normalized.endsWith(".local")) return true;
  const family = isIP(normalized);
  if (family === 4) return isPrivateIpv4(normalized);
  if (family === 6) {
    return normalized === "::" || normalized === "::1" || normalized.startsWith("fc") ||
      normalized.startsWith("fd") || normalized.startsWith("fe8") || normalized.startsWith("fe9") ||
      normalized.startsWith("fea") || normalized.startsWith("feb") || normalized.startsWith("ff") ||
      normalized.startsWith("2001:db8:") || mappedIpv4IsPrivate(normalized);
  }
  return !normalized.includes(".");
}

function mappedIpv4IsPrivate(hostname) {
  if (!hostname.startsWith("::ffff:")) return false;
  const pieces = hostname.slice(7).split(":");
  if (pieces.length !== 2 || pieces.some((piece) => !/^[0-9a-f]{1,4}$/.test(piece))) return true;
  const high = Number.parseInt(pieces[0], 16);
  const low = Number.parseInt(pieces[1], 16);
  return isPrivateIpv4(`${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`);
}

export function normalizeWssEndpoint(value, { rootPathOnly = false } = {}) {
  if (typeof value !== "string" || value.length === 0 || value.length > 2_048 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new TypeError("endpoint must be a bounded WSS URL.");
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError("endpoint must be a valid WSS URL.");
  }
  if (parsed.protocol !== "wss:") throw new TypeError("endpoint must use wss://.");
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new TypeError("endpoint must not contain credentials, query parameters or fragments.");
  }
  if (isPrivateHost(parsed.hostname)) throw new TypeError("endpoint must use a public hostname or address.");
  if (rootPathOnly && parsed.pathname !== "/") throw new TypeError("endpoint must use the root path.");
  return parsed.toString();
}

export function toWssEndpoint(value) {
  if (typeof value !== "string") throw new TypeError("endpoint candidate must be a string.");
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError("endpoint candidate is not a URL.");
  }
  if (parsed.protocol === "https:") parsed.protocol = "wss:";
  return normalizeWssEndpoint(parsed.toString());
}

function stringsFromJson(value, result) {
  if (typeof value === "string") {
    result.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) stringsFromJson(item, result);
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      result.push(key);
      stringsFromJson(item, result);
    }
  }
}

export function extractPublicWssEndpoint(text, { predicate = null } = {}) {
  if (typeof text !== "string") return null;
  const candidates = [];
  for (const line of text.split(/\r?\n/)) {
    try {
      stringsFromJson(JSON.parse(line), candidates);
    } catch {
      // Provider logs often mix JSON and human-readable lines.
    }
  }
  candidates.push(...text.match(/(?:https|wss):\/\/[^\s"'<>]+/gi) ?? []);
  const tailscaleStatus = text.match(/"Web"\s*:\s*\{\s*"([^"/]+)"/i);
  if (tailscaleStatus) candidates.push(`https://${tailscaleStatus[1]}`);

  for (const candidate of candidates) {
    const cleaned = candidate.replace(/[),.;]+$/g, "");
    try {
      const endpoint = toWssEndpoint(cleaned);
      if (!predicate || predicate(endpoint)) return endpoint;
    } catch {
      // Keep scanning; local admin URLs and malformed provider output are expected noise.
    }
  }
  return null;
}

export function endpointHostname(endpoint) {
  return new URL(endpoint).hostname.replace(/^\[|\]$/g, "").toLowerCase();
}

export function providerStatus(provider, state, values = {}) {
  const status = {
    provider,
    state,
    installed: typeof values.installed === "boolean" ? values.installed : null,
    endpoint: values.endpoint ?? null,
    stability: values.stability ?? null,
    message: values.message ?? null,
  };
  if (typeof values.enabled === "boolean") status.enabled = values.enabled;
  if (values.nginxConfig !== undefined) status.nginxConfig = values.nginxConfig;
  if (Number.isInteger(values.pid) && values.pid > 1) status.pid = values.pid;
  return Object.freeze(status);
}

export function sanitizedProviderError(provider, error, fallbackCode = "provider_failed") {
  if (error instanceof ProviderError) return error;
  const code = error?.code === "not_found" ? "not_installed" :
    error?.code === "timeout" ? "startup_timeout" : fallbackCode;
  const messages = {
    not_installed: `${provider} CLI is not installed or not available on PATH.`,
    startup_timeout: `${provider} did not publish a usable endpoint before the startup timeout.`,
    provider_failed: `${provider} could not start the connectivity route.`,
  };
  return new ProviderError(provider, code, messages[code] ?? messages.provider_failed);
}

export function validateConfigPath(value, label, fallback) {
  const path = value ?? fallback;
  if (typeof path !== "string" || path.length === 0 || path.length > 1_024 ||
      !/^(?:\/[A-Za-z0-9._-]+)+$/.test(path) || path.split("/").includes("..")) {
    throw new TypeError(`${label} must be a safe absolute path.`);
  }
  return path;
}
