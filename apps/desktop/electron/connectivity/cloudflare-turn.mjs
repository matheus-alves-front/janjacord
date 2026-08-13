// Mint de credenciais TURN curtas via Cloudflare Realtime (sem VPS).
// Docs oficiais: https://developers.cloudflare.com/realtime/turn/generate-credentials/
// POST https://rtc.live.cloudflare.com/v1/turn/keys/{keyId}/credentials/generate-ice-servers
// Resposta 201: { iceServers: [{ urls: [...], username, credential }] } — já no formato
// RTCPeerConnection. URLs com porta 53 são removidas (timeout em navegadores, por docs).

export const CLOUDFLARE_TURN_MINT_ENDPOINT = "https://rtc.live.cloudflare.com/v1/turn/keys";
export const CLOUDFLARE_TURN_URLS = Object.freeze([
  "turn:turn.cloudflare.com:3478?transport=udp",
  "turn:turn.cloudflare.com:3478?transport=tcp",
  "turn:turn.cloudflare.com:80?transport=tcp",
  "turns:turn.cloudflare.com:5349?transport=tcp",
  "turns:turn.cloudflare.com:443?transport=tcp",
]);
export const CLOUDFLARE_STUN_URLS = Object.freeze(["stun:stun.cloudflare.com:3478"]);
export const CLOUDFLARE_TURN_TTL_MAX = 86_400;
export const CLOUDFLARE_TURN_MINT_TIMEOUT_MS = 10_000;
const TURN_KEY_ID_RE = /^[A-Za-z0-9_-]{8,128}$/;
const TURN_API_TOKEN_RE = /^[A-Za-z0-9_-]{16,256}$/;

export class TurnError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TurnError";
    this.code = code;
  }
}

export function validateCloudflareTurnConfig(keyId, apiToken) {
  if (typeof keyId !== "string" || !TURN_KEY_ID_RE.test(keyId)) {
    throw new TurnError("invalid_config", "TURN Key ID da Cloudflare inválido.");
  }
  if (typeof apiToken !== "string" || !TURN_API_TOKEN_RE.test(apiToken)) {
    throw new TurnError("invalid_config", "API token da Cloudflare inválido.");
  }
}

export function filterCloudflareTurnIceServers(iceServers) {
  if (!Array.isArray(iceServers)) return [];
  const filtered = [];
  for (const entry of iceServers) {
    if (!entry || typeof entry !== "object") continue;
    const urls = Array.isArray(entry.urls) ? entry.urls.filter((url) => !/:53(\?|$)/.test(String(url))) : [];
    if (urls.length === 0) continue;
    const next = { urls };
    if (typeof entry.username === "string" && entry.username.length > 0) next.username = entry.username;
    if (typeof entry.credential === "string" && entry.credential.length > 0) next.credential = entry.credential;
    filtered.push(next);
  }
  return filtered;
}

export async function mintCloudflareTurnIceServers({
  keyId,
  apiToken,
  ttl = 3_600,
  fetchImpl = fetch,
  now = Date.now(),
} = {}) {
  validateCloudflareTurnConfig(keyId, apiToken);
  const safeTtl = Number.isInteger(ttl) && ttl > 0 && ttl <= CLOUDFLARE_TURN_TTL_MAX ? ttl : CLOUDFLARE_TURN_TTL_MAX;
  let response;
  try {
    response = await fetchImpl(`${CLOUDFLARE_TURN_MINT_ENDPOINT}/${encodeURIComponent(keyId)}/credentials/generate-ice-servers`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ttl: safeTtl }),
      signal: AbortSignal.timeout(CLOUDFLARE_TURN_MINT_TIMEOUT_MS),
    });
  } catch (error) {
    throw new TurnError("turn_unreachable", `Não foi possível falar com o TURN da Cloudflare: ${String(error?.message ?? error)}`);
  }
  if (!response || typeof response.status !== "number") {
    throw new TurnError("turn_unreachable", "Resposta inválida do TURN da Cloudflare.");
  }
  if (response.status === 401 || response.status === 403) {
    throw new TurnError("turn_auth_failed", "Credenciais da Cloudflare rejeitadas (401/403). Confira TURN Key ID e API token.");
  }
  if (!response.ok) {
    throw new TurnError("turn_mint_failed", `O TURN da Cloudflare respondeu HTTP ${response.status}.`);
  }
  let data;
  try {
    data = await response.json();
  } catch {
    throw new TurnError("turn_mint_failed", "Resposta JSON inválida do TURN da Cloudflare.");
  }
  const minted = filterCloudflareTurnIceServers(data?.iceServers);
  if (minted.length === 0) {
    throw new TurnError("turn_mint_failed", "A Cloudflare não retornou servidores TURN utilizáveis.");
  }
  return { iceServers: minted, mintedAt: now, ttl: safeTtl };
}
