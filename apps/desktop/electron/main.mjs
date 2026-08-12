/**
 * Electron main (ESM) — JanjaCord desktop.
 * Responsabilidades: vault local (ADR-001/016), MLS via WASM (crypto-core), JanjaNode como
 * child process (host do server), cliente WS (HostClient), IPC para o renderer.
 * O renderer é sandboxed (contextIsolation) — toda crypto passa por aqui.
 */
import { app, BrowserWindow, clipboard, ipcMain, safeStorage, session, utilityProcess } from "electron";

// userData custom: permite rodar 2+ instâncias no mesmo PC (teste de 2 contas)
if (process.env.JC_USERDATA_DIR) {
  app.setPath("userData", process.env.JC_USERDATA_DIR);
}

// smoke: isola userData (identidades recriadas a cada execução geram dbKeys novas)
if ((process.env.JC_SMOKE_UI || process.env.JC_SMOKE_MEDIA || process.env.JC_SMOKE_MEDIA_PEER) && process.env.JC_SMOKE_DIR) {
  app.setPath("userData", path.join(process.env.JC_SMOKE_DIR, "userdata"));
}
// smoke media: dispositivos sintéticos do Chromium (sem hardware)
if (process.env.JC_SMOKE_MEDIA || process.env.JC_SMOKE_MEDIA_PEER) {
  app.commandLine.appendSwitch("use-fake-ui-for-media-stream");
  app.commandLine.appendSwitch("use-fake-device-for-media-stream");
}
import path from "node:path";
import { once } from "node:events";
import { chmodSync, closeSync, copyFileSync, createReadStream, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { networkInterfaces } from "node:os";
import {
  createIdentity,
  unlockIdentity,
  generateRecoveryKey,
  restoreIdentity,
} from "@janjacord/identity";
import { createCipheriv, createDecipheriv, createHash, createHmac, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { durableAtomicWrite, ensureEncryptedDatabaseKey } from "./primary-host-profile.mjs";
import {
  decodeRendererAttachment,
  decryptDownloadedAttachment,
  encryptAttachmentForUpload,
  parseDownloadChunk,
  parseDownloadManifest,
  uploadAttachmentWithResume,
} from "./attachment-transfer.mjs";
import {
  createAuthenticatedCounterAnchor,
  createAuthenticatedStoreEnvelope,
  ed25519Fingerprint,
  ed25519PublicKey,
  parseInviteKey,
  signCanonicalPayload,
  verifyAuthenticatedCounterAnchor,
  verifyAuthenticatedStoreEnvelope,
} from "@janjacord/crypto";
import { EncryptedDatabase } from "@janjacord/persistence";
import {
  HostClient,
  IceHostTransport,
  createExternalWebSocket,
  deserializeHostRegistrationHighWater,
  issueLegacyHostConfirmation,
  selectHostRegistrations,
  validateLegacyHostConfirmation,
} from "@janjacord/networking";
import {
  buildEnvelope,
  parseInviteV3,
  verifySignedBridgeDescriptor,
  verifySignedHostGrantRevocation,
} from "@janjacord/protocol";
import * as mls from "@janjacord/crypto-core";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const HOST_PORT = 8931;

// ---------------------------------------------------------------- estado
let identity = null; // { identityId, nickname, seed, dbKey }
let localDb = null; // EncryptedDatabase (estado MLS + cache local)
let hostProcess = null;
let replicaProcess = null;
let client = null; // HostClient
let serverState = null; // estado do server do host
let channelSeq = new Map();
let appQuitting = false;
let callIceConfiguration = null;
const decryptedAttachments = new Map();
const MAX_DECRYPTED_ATTACHMENT_CACHE_BYTES = 128 * 1024 * 1024;
const DECRYPTED_ATTACHMENT_TTL_MS = 15 * 60_000;
let decryptedAttachmentBytes = 0;
let trustedRendererLocation = null;
let ipcBoundaryInstalled = false;
let clientRecoveryChain = Promise.resolve();
const queuedRecoveryGenerations = new WeakMap();
const welcomeConsumptionTasks = new WeakMap();
const recentlyDeliveredMessages = new Map();
const MAX_RECENTLY_DELIVERED_MESSAGES = 2048;

function rendererLocationIsTrusted(value) {
  if (!trustedRendererLocation || !value) return false;
  try {
    const actual = new URL(value);
    const expected = new URL(trustedRendererLocation);
    if (expected.protocol === "file:") {
      actual.hash = "";
      actual.search = "";
      expected.hash = "";
      expected.search = "";
      return actual.href === expected.href;
    }
    return actual.origin === expected.origin;
  } catch {
    return false;
  }
}

function rendererRequestIsTrusted(event) {
  return Boolean(event?.senderFrame && event.senderFrame === event.sender?.mainFrame
    && rendererLocationIsTrusted(event.senderFrame.url));
}

function installIpcTrustBoundary() {
  if (ipcBoundaryInstalled) return;
  ipcBoundaryInstalled = true;
  const rawHandle = ipcMain.handle.bind(ipcMain);
  ipcMain.handle = (channel, handler) => rawHandle(channel, (event, ...args) => {
    if (!rendererRequestIsTrusted(event)) throw new Error("untrusted renderer IPC origin");
    return handler(event, ...args);
  });
}

function rememberDecryptedAttachment(assetId, attachment) {
  forgetDecryptedAttachment(assetId);
  const cached = { ...attachment, cachedAt: Date.now() };
  while (decryptedAttachments.size > 0
    && decryptedAttachmentBytes + cached.raw.length > MAX_DECRYPTED_ATTACHMENT_CACHE_BYTES) {
    forgetDecryptedAttachment(decryptedAttachments.keys().next().value);
  }
  if (cached.raw.length > MAX_DECRYPTED_ATTACHMENT_CACHE_BYTES) return false;
  decryptedAttachments.set(assetId, cached);
  decryptedAttachmentBytes += cached.raw.length;
  const timer = setTimeout(() => {
    if (decryptedAttachments.get(assetId) === cached) forgetDecryptedAttachment(assetId);
  }, DECRYPTED_ATTACHMENT_TTL_MS);
  timer.unref();
  return true;
}

function forgetDecryptedAttachment(assetId) {
  const current = decryptedAttachments.get(assetId);
  if (!current) return;
  decryptedAttachmentBytes -= current.raw.length;
  decryptedAttachments.delete(assetId);
}

function safeAttachmentName(value) {
  const leaf = String(value ?? "attachment.bin").replaceAll("\\", "/").split("/").pop() ?? "";
  let name = leaf
    .replace(/[\u0000-\u001f\u007f<>:"/\\|?*]/g, "_")
    .replace(/[. ]+$/g, "")
    .slice(0, 180);
  if (!name || name === "." || name === "..") name = "attachment.bin";
  if (/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name)) name = `_${name}`;
  return name;
}

function safeAttachmentMimeType(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 128
    && /^[\w!#$&^_.+\-]+\/[\w!#$&^_.+\-]+$/.test(value)
    ? value
    : "application/octet-stream";
}

const DEFAULT_CONNECTIVITY_CONFIG = {
  bridges: [],
  bridgePairings: [],
  backgroundHosting: false,
  hostHighWater: { version: 1, marks: [] },
  authorityTrust: { version: 1, servers: [] },
  legacyHostPins: {},
  pendingLegacyHostConfirmations: {},
};

function userData() {
  return app.getPath("userData");
}
function vaultPath() {
  return path.join(userData(), "vault.json");
}
function localDbPath() {
  return path.join(userData(), "local.db");
}
function hostDbPath() {
  return path.join(userData(), "janjanode", "server.db");
}
function connectivityConfigPath() {
  return path.join(userData(), "connectivity.json");
}
function connectivityMacKeyPath() {
  return path.join(userData(), "connectivity.mac-key.safe-storage");
}
function connectivityAnchorPath() {
  return path.join(userData(), "connectivity.counter-anchor.safe-storage");
}
function communityHostProfilePath(serverId) {
  return path.join(userData(), "community-hosts", `${serverId}.vault`);
}
function primaryHostProfilePath() {
  return path.join(userData(), "community-hosts", "primary.vault");
}
function replicaEnrollmentPath(serverId) {
  return path.join(userData(), "community-hosts", `${serverId}.enrollment.json`);
}
function replicaDbPath(serverId) {
  return path.join(userData(), "community-hosts", serverId, "server.db");
}
function backgroundHostBundlePath() {
  return path.join(userData(), "community-hosts", "background-host.safe-storage");
}

function encryptLocalSecret(serverId, value) {
  const nonce = randomBytes(12);
  const key = deriveRuntimeSeed(`janjacord-community-host-v1:${serverId}`);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(serverId, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(value), "utf8")), cipher.final()]);
  return {
    version: 1,
    nonce: nonce.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
  };
}

function decryptLocalSecret(serverId, envelope) {
  if (!envelope || envelope.version !== 1) throw new Error("community host vault inválido");
  const key = deriveRuntimeSeed(`janjacord-community-host-v1:${serverId}`);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.nonce, "base64url"));
  decipher.setAAD(Buffer.from(serverId, "utf8"));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
  return JSON.parse(Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8"));
}

function loadOrCreateCommunityHostProfile(serverId) {
  if (!identity) throw new Error("identity required");
  const file = communityHostProfilePath(serverId);
  if (existsSync(file)) return decryptLocalSecret(serverId, JSON.parse(readFileSync(file, "utf8")));
  const hostSeed = randomBytes(32);
  const enrollment = generateKeyPairSync("x25519");
  const publicJwk = enrollment.publicKey.export({ format: "jwk" });
  const privateJwk = enrollment.privateKey.export({ format: "jwk" });
  if (typeof publicJwk.x !== "string" || typeof privateJwk.d !== "string") throw new Error("falha ao gerar chave de enrollment");
  const profile = {
    hostSeed: hostSeed.toString("hex"),
    hostPublicKey: ed25519PublicKey(hostSeed).toString("base64url"),
    enrollmentPrivateKey: Buffer.from(privateJwk.d, "base64url").toString("hex"),
    enrollmentPublicKey: publicJwk.x,
    hostId: `host-${ed25519Fingerprint(ed25519PublicKey(hostSeed)).slice(0, 24)}`,
  };
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(encryptLocalSecret(serverId, profile))}\n`, { mode: 0o600 });
  chmodSync(file, 0o600);
  return profile;
}

function writePrimaryHostProfile(profile) {
  const file = primaryHostProfilePath();
  durableAtomicWrite(file, `${JSON.stringify(encryptLocalSecret("primary", profile))}\n`);
}

function loadOrCreatePrimaryHostProfile() {
  if (!identity) throw new Error("identity required");
  const file = primaryHostProfilePath();
  if (existsSync(file)) {
    const profile = decryptLocalSecret("primary", JSON.parse(readFileSync(file, "utf8")));
    if (!/^[0-9a-f]{64}$/i.test(profile.serverDbKey ?? "")) throw new Error("Community Host DB key inválida");
    ensureEncryptedDatabaseKey({
      file: hostDbPath(),
      oldKey: identity.dbKey,
      newKey: Buffer.from(profile.serverDbKey, "hex"),
    });
    return profile;
  }
  const serverDbKey = randomBytes(32);
  const profile = {
    version: 1,
    serverId: null,
    serverDbKey: serverDbKey.toString("hex"),
  };
  writePrimaryHostProfile(profile);
  ensureEncryptedDatabaseKey({
    file: hostDbPath(),
    oldKey: identity.dbKey,
    newKey: serverDbKey,
    failpoint: process.env.JC_DB_KEY_MIGRATION_FAILPOINT ?? null,
  });
  return profile;
}

function bindPrimaryHostProfileServer(serverId) {
  const profile = loadOrCreatePrimaryHostProfile();
  if (profile.serverId && profile.serverId !== serverId) throw new Error("primary Community Host profile belongs to another server");
  if (!profile.serverId) writePrimaryHostProfile({ ...profile, serverId });
}

function createPossessionProof(seed, domain, payload) {
  const proofId = randomUUID();
  const issuedAt = Date.now();
  return {
    proofId,
    issuedAt,
    signature: signCanonicalPayload(seed, domain, { ...payload, proofId, issuedAt }).toString("base64url"),
  };
}
function parseConnectivityConfigValue(value) {
  try {
    const bridges = Array.isArray(value?.bridges)
      ? value.bridges.map((entry) => verifySignedBridgeDescriptor(entry)).filter(Boolean).slice(0, 3)
      : [];
    const bridgePairings = Array.isArray(value?.bridgePairings)
      ? value.bridgePairings.filter((entry) => entry && typeof entry.bridgeId === "string"
        && typeof entry.pairingToken === "string" && /^JCP1\.[A-Za-z0-9_-]{32,384}\.[A-Za-z0-9_-]{43}$/.test(entry.pairingToken)).slice(0, 3)
      : [];
    let hostHighWater = DEFAULT_CONNECTIVITY_CONFIG.hostHighWater;
    try {
      hostHighWater = deserializeHostRegistrationHighWater(JSON.stringify(value?.hostHighWater ?? hostHighWater));
    } catch {
      // Corrupted anti-rollback state fails closed for remote selection without discarding bridges.
      hostHighWater = null;
    }
    let authorityTrust = null;
    try {
      const source = value?.authorityTrust;
      if (source === undefined) {
        if ((hostHighWater?.marks?.length ?? 0) > 0) throw new Error("missing established authority trust");
        authorityTrust = DEFAULT_CONNECTIVITY_CONFIG.authorityTrust;
      } else if (!source || source.version !== 1 || !Array.isArray(source.servers)) {
        throw new Error("invalid authority trust");
      } else {
        const servers = source.servers.map((entry) => {
          if (!entry || typeof entry.serverId !== "string" || typeof entry.authorityFingerprint !== "string"
            || !Array.isArray(entry.revocations)) throw new Error("invalid authority trust server");
          const revocations = entry.revocations.map((item) => {
            const verified = verifySignedHostGrantRevocation(item?.revocation, item?.authorityPublicKey);
            if (!verified || verified.payload.serverId !== entry.serverId
              || ed25519Fingerprint(Buffer.from(item.authorityPublicKey, "base64url")) !== entry.authorityFingerprint) {
              throw new Error("invalid persisted signed revocation");
            }
            return { authorityPublicKey: item.authorityPublicKey, revocation: verified };
          });
          return { serverId: entry.serverId, authorityFingerprint: entry.authorityFingerprint, revocations };
        });
        authorityTrust = { version: 1, servers };
      }
    } catch {
      authorityTrust = null;
    }
    const legacyHostPins = value?.legacyHostPins && typeof value.legacyHostPins === "object"
      ? Object.fromEntries(Object.entries(value.legacyHostPins).filter(([, key]) => typeof key === "string" && /^[A-Za-z0-9_-]{43}$/.test(key)))
      : {};
    const pendingLegacyHostConfirmations = value?.pendingLegacyHostConfirmations && typeof value.pendingLegacyHostConfirmations === "object"
      ? Object.fromEntries(Object.entries(value.pendingLegacyHostConfirmations).filter(([, candidate]) => (
        candidate && typeof candidate === "object" && typeof candidate.hostPublicKey === "string"
        && /^[A-Za-z0-9_-]{43}$/.test(candidate.hostPublicKey) && typeof candidate.fingerprint === "string"
        && typeof candidate.tokenHash === "string" && /^[0-9a-f]{64}$/i.test(candidate.tokenHash)
        && Number.isSafeInteger(candidate.expiresAt) && candidate.expiresAt > 0
      ))) : {};
    return { bridges, bridgePairings, backgroundHosting: value?.backgroundHosting === true, hostHighWater, authorityTrust, legacyHostPins, pendingLegacyHostConfirmations };
  } catch {
    return { ...DEFAULT_CONNECTIVITY_CONFIG, hostHighWater: null, authorityTrust: null };
  }
}

function closedConnectivityConfig(reason) {
  console.error(`[desktop] connectivity trust store rejeitado: ${reason}`);
  return { ...DEFAULT_CONNECTIVITY_CONFIG, hostHighWater: null, authorityTrust: null };
}

function writePrivateAtomic(file, data) {
  const temporary = `${file}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporary, data, { mode: 0o600 });
  renameSync(temporary, file);
  chmodSync(file, 0o600);
}

function persistConnectivityStore(config, key, counter) {
  const envelope = createAuthenticatedStoreEnvelope(key, counter, config);
  const anchor = createAuthenticatedCounterAnchor(key, counter, envelope.mac);
  mkdirSync(userData(), { recursive: true });
  // A crash between renames leaves a counter/MAC mismatch and therefore fails closed.
  if (!existsSync(connectivityMacKeyPath())) {
    writePrivateAtomic(connectivityMacKeyPath(), safeStorage.encryptString(key.toString("base64url")));
  }
  writePrivateAtomic(connectivityConfigPath(), safeStorage.encryptString(JSON.stringify(envelope)));
  writePrivateAtomic(connectivityAnchorPath(), safeStorage.encryptString(JSON.stringify(anchor)));
}

function loadAuthenticatedConnectivityStore() {
  const dataExists = existsSync(connectivityConfigPath());
  const keyExists = existsSync(connectivityMacKeyPath());
  const anchorExists = existsSync(connectivityAnchorPath());
  if (!dataExists && !keyExists && !anchorExists) return { kind: "empty", config: DEFAULT_CONNECTIVITY_CONFIG, counter: 0, key: null };

  // One-time migration of the prior mode-0600 JSON store. It is accepted only when it is
  // unmistakably JSON and immediately replaced with safeStorage + MAC + counter anchor.
  if (dataExists && !keyExists && !anchorExists) {
    try {
      const legacy = readFileSync(connectivityConfigPath(), "utf8");
      if (!legacy.trimStart().startsWith("{")) throw new Error("encrypted store lost key/anchor");
      if (!safeStorageUsable()) throw new Error("safeStorage unavailable for legacy trust-store migration");
      const config = parseConnectivityConfigValue(JSON.parse(legacy));
      if (!config.hostHighWater || !config.authorityTrust) throw new Error("legacy trust store is invalid");
      const key = randomBytes(32);
      persistConnectivityStore(config, key, 1);
      return { kind: "ready", config, counter: 1, key };
    } catch (error) {
      return { kind: "invalid", reason: String(error?.message ?? error) };
    }
  }

  if (!dataExists || !keyExists || !anchorExists) return { kind: "invalid", reason: "established store component is missing" };
  if (!safeStorageUsable()) return { kind: "invalid", reason: "safeStorage is unavailable" };
  try {
    const keyText = safeStorage.decryptString(readFileSync(connectivityMacKeyPath()));
    if (!/^[A-Za-z0-9_-]{43}$/.test(keyText)) throw new Error("MAC key is invalid");
    const key = Buffer.from(keyText, "base64url");
    const rawEnvelope = JSON.parse(safeStorage.decryptString(readFileSync(connectivityConfigPath())));
    const envelope = verifyAuthenticatedStoreEnvelope(key, rawEnvelope);
    if (!envelope) throw new Error("store MAC is invalid");
    const anchor = JSON.parse(safeStorage.decryptString(readFileSync(connectivityAnchorPath())));
    if (!verifyAuthenticatedCounterAnchor(key, anchor, envelope.counter, envelope.mac)) {
      throw new Error("store counter anchor mismatch (rollback or interrupted write)");
    }
    const config = parseConnectivityConfigValue(envelope.payload);
    if (!config.hostHighWater || !config.authorityTrust) throw new Error("authenticated trust payload is invalid");
    return { kind: "ready", config, counter: envelope.counter, key };
  } catch (error) {
    return { kind: "invalid", reason: String(error?.message ?? error) };
  }
}

function readConnectivityConfig() {
  const loaded = loadAuthenticatedConnectivityStore();
  if (loaded.kind === "invalid") return closedConnectivityConfig(loaded.reason);
  return loaded.config;
}

function writeConnectivityConfig(config) {
  if (!safeStorageUsable()) throw new Error("o cofre seguro do sistema operacional não está disponível");
  const loaded = loadAuthenticatedConnectivityStore();
  if (loaded.kind === "invalid") throw new Error(`connectivity trust store indisponível: ${loaded.reason}`);
  const parsed = parseConnectivityConfigValue(config);
  if (!parsed.hostHighWater || !parsed.authorityTrust) throw new Error("connectivity trust store payload inválido");
  const key = loaded.key ?? randomBytes(32);
  persistConnectivityStore(parsed, key, loaded.counter + 1);
}
function bridgeSummary(descriptor) {
  const rendezvous = descriptor.payload.endpoints.find((endpoint) => endpoint.startsWith("wss://") && endpoint.includes("/rendezvous"));
  return {
    bridgeId: descriptor.payload.bridgeId,
    endpoint: rendezvous ?? descriptor.payload.endpoints[0],
    expiresAt: descriptor.payload.expiresAt,
  };
}
function emitSetupStep(step, status, detail) {
  notifyRenderer("connectivity.setup", { step, status, ...(detail ? { detail } : {}) });
}
function janjanodeMainPath() {
  return app.isPackaged
    ? require.resolve("@janjacord/janjanode")
    : path.join(__dirname, "..", "..", "janjanode", "dist", "main.js");
}
const HOST_PLATFORM_ENV_ALLOWLIST = [
  "APPDATA",
  "COMSPEC",
  "HOME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "LOCALAPPDATA",
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "TEMP",
  "TMP",
  "TMPDIR",
  "TZ",
  "USERPROFILE",
  "WINDIR",
  "XDG_RUNTIME_DIR",
];
const HOST_INHERITED_JC_ENV_ALLOWLIST = [
  // Required by the real loopback operator smoke. Production descriptors remain wss-only.
  "JC_ALLOW_INSECURE_BRIDGE_LOOPBACK",
  // Explicit opt-in diagnostics; unlike generic instrumentation variables, this is JanjaNode-owned.
  "JC_HOST_DIAGNOSTICS",
];

function productionHostEnvironment(extra, inherited = process.env) {
  const env = {};
  const inheritedEntries = Object.entries(inherited);
  for (const allowedName of [...HOST_PLATFORM_ENV_ALLOWLIST, ...HOST_INHERITED_JC_ENV_ALLOWLIST]) {
    const entry = inheritedEntries.find(([name]) => name.toUpperCase() === allowedName);
    if (entry && entry[1] !== undefined) env[entry[0]] = entry[1];
  }
  for (const [name, value] of Object.entries(extra ?? {})) {
    if (!name.startsWith("JC_")) throw new Error(`host environment rejected non-JanjaCord variable ${name}`);
    if (name === "JC_ALLOW_LEGACY_AUTH") throw new Error("host environment rejected legacy authentication override");
    if (value !== undefined && value !== null) env[name] = String(value);
  }
  return env;
}

function deriveRuntimeSeed(label) {
  return createHmac("sha256", identity.seed).update(label, "utf8").digest();
}

function privateLanEndpoint(port = HOST_PORT) {
  const candidates = Object.values(networkInterfaces()).flatMap((entries) => entries ?? [])
    .filter((address) => address.family === "IPv4" && !address.internal)
    .filter((address) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(address.address));
  return candidates.length > 0 ? `${candidates[0].address}:${port}` : `127.0.0.1:${port}`;
}

async function loadMls() {
  await mls.default; // inicializa o módulo wasm
}
function groupIdHex(channelId) {
  return Buffer.from(channelId.replace(/-/g, ""), "hex").toString("hex");
}

// ---------------------------------------------------------------- MLS persistence
function mlsStateKey(serverId, channelId) {
  return `mls:${serverId}:${channelId}`;
}
function saveMlsState(serverId, channelId) {
  if (!localDb) return;
  const gid = groupIdHex(channelId);
  const state = mls.export_group(identity.identityId, gid);
  localDb.raw
    .prepare("INSERT INTO mls_groups (key, state, updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET state=excluded.state, updated_at=excluded.updated_at")
    .run(mlsStateKey(serverId, channelId), state, Date.now());
}
function loadMlsState(serverId, channelId) {
  if (!localDb) return false;
  const row = localDb.raw.prepare("SELECT state FROM mls_groups WHERE key = ?").get(mlsStateKey(serverId, channelId));
  if (!row) return false;
  const gid = groupIdHex(channelId);
  mls.import_group(identity.identityId, gid, row.state);
  return true;
}

function initLocalDb() {
  localDb = new EncryptedDatabase(localDbPath(), identity.dbKey);
  localDb.migrate(
    "CREATE TABLE IF NOT EXISTS mls_groups (key TEXT PRIMARY KEY, state TEXT NOT NULL, updated_at INTEGER NOT NULL);" +
      "CREATE TABLE IF NOT EXISTS seen_messages (message_id TEXT PRIMARY KEY, consumed INTEGER NOT NULL DEFAULT 0);" +
      "CREATE TABLE IF NOT EXISTS mls_welcome_outbox (target_identity_id TEXT PRIMARY KEY, server_id TEXT NOT NULL, channel_id TEXT NOT NULL, welcome_b64 TEXT NOT NULL, created_at INTEGER NOT NULL);" +
      "CREATE TABLE IF NOT EXISTS mls_welcome_receipts (welcome_hash TEXT PRIMARY KEY, consumed_at INTEGER NOT NULL);",
  );
}

// ---------------------------------------------------------------- janjanode (host)
function spawnHost() {
  if (hostProcess) return;
  const authoritySeed = deriveRuntimeSeed("janjacord-authority-signing-v1");
  const hostSeed = deriveRuntimeSeed("janjacord-host-signing-v1");
  const connectivity = readConnectivityConfig();
  const primaryProfile = loadOrCreatePrimaryHostProfile();
  const firstRendezvous = connectivity.bridges
    .flatMap((descriptor) => descriptor.payload.endpoints)
    .find((endpoint) => endpoint.startsWith("wss://") && endpoint.includes("/rendezvous"));
  const firstSignaling = connectivity.bridges
    .flatMap((descriptor) => descriptor.payload.endpoints)
    .find((endpoint) => endpoint.startsWith("wss://") && endpoint.includes("/signaling"));
  const env = productionHostEnvironment({
    JC_DB_KEY: primaryProfile.serverDbKey,
    JC_DB_PATH: hostDbPath(),
    JC_OWNER_IDENTITY: identity.identityId,
    JC_OWNER_NICKNAME: identity.nickname,
    JC_OWNER_PUBLIC_KEY: ed25519PublicKey(identity.seed).toString("base64url"),
    JC_AUTHORITY_SIGNING_SEED: authoritySeed.toString("hex"),
    JC_HOST_SIGNING_SEED: hostSeed.toString("hex"),
    JC_SERVER_NAME: "Meu Servidor",
    JC_PORT: String(HOST_PORT),
    JC_DIRECT_ENDPOINT: privateLanEndpoint(),
    JC_BRIDGE_DESCRIPTORS: JSON.stringify(connectivity.bridges),
    JC_BRIDGE_PAIRINGS: JSON.stringify(connectivity.bridgePairings ?? []),
    ...(firstRendezvous ? { JC_RENDEZVOUS_URL: firstRendezvous } : {}),
    ...(firstSignaling ? { JC_PUBLIC_URL: firstSignaling } : {}),
  });
  const spawnedHost = utilityProcess.fork(janjanodeMainPath(), [], {
    env,
    stdio: "pipe",
  });
  hostProcess = spawnedHost;
  spawnedHost.stdout?.on("data", (d) => console.log("[host]", d.toString().trim()));
  spawnedHost.stderr?.on("data", (d) => console.error("[host]", d.toString().trim()));
  spawnedHost.on("exit", (code) => {
    if (hostProcess === spawnedHost) hostProcess = null;
    console.log(`[host] exit ${code}`);
  });
}

function backgroundHostMaterial() {
  if (!identity) throw new Error("desbloqueie a identidade antes de habilitar hosting em segundo plano");
  const primaryProfile = loadOrCreatePrimaryHostProfile();
  if (!primaryProfile.serverId) throw new Error("crie a comunidade antes de habilitar hosting em segundo plano");
  const authoritySeed = deriveRuntimeSeed("janjacord-authority-signing-v1");
  const hostSeed = deriveRuntimeSeed("janjacord-host-signing-v1");
  if (authoritySeed.equals(hostSeed) || authoritySeed.equals(identity.seed) || hostSeed.equals(identity.seed)) {
    throw new Error("material de chave do host não é independente");
  }
  return {
    version: 1,
    serverId: primaryProfile.serverId,
    serverDbKey: primaryProfile.serverDbKey,
    authoritySeed: authoritySeed.toString("hex"),
    hostSeed: hostSeed.toString("hex"),
    ownerIdentityId: identity.identityId,
    ownerNickname: identity.nickname,
    ownerPublicKey: ed25519PublicKey(identity.seed).toString("base64url"),
    bridges: readConnectivityConfig().bridges,
    createdAt: Date.now(),
  };
}

function safeStorageUsable() {
  if (!safeStorage.isEncryptionAvailable()) return false;
  try { return safeStorage.getSelectedStorageBackend() !== "basic_text"; }
  catch { return true; }
}

function writeBackgroundHostBundle() {
  if (!safeStorageUsable()) throw new Error("o cofre seguro do sistema operacional não está disponível");
  const encrypted = safeStorage.encryptString(JSON.stringify(backgroundHostMaterial()));
  const file = backgroundHostBundlePath();
  mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.tmp`;
  writeFileSync(temporary, encrypted, { mode: 0o600 });
  renameSync(temporary, file);
  chmodSync(file, 0o600);
}

function readBackgroundHostBundle() {
  if (!safeStorageUsable()) throw new Error("o cofre seguro do sistema operacional não está disponível");
  const material = JSON.parse(safeStorage.decryptString(readFileSync(backgroundHostBundlePath())));
  if (material?.version !== 1 || typeof material.serverId !== "string"
    || !/^[0-9a-f]{64}$/i.test(material.serverDbKey ?? "")
    || !/^[0-9a-f]{64}$/i.test(material.authoritySeed ?? "")
    || !/^[0-9a-f]{64}$/i.test(material.hostSeed ?? "")
    || typeof material.ownerIdentityId !== "string" || typeof material.ownerPublicKey !== "string"
    || !Array.isArray(material.bridges)) throw new Error("bundle de hosting em segundo plano inválido");
  return material;
}

function linuxAutostartExecutable() {
  const appImage = process.env.APPIMAGE;
  const candidate = appImage || app.getPath("exe");
  if (!candidate || !path.isAbsolute(candidate) || /[\r\n]/.test(candidate)) {
    throw new Error("caminho executável de autostart ausente ou inválido");
  }
  const normalized = path.normalize(candidate);
  const unstable = normalized.startsWith(`${path.sep}tmp${path.sep}`)
    || normalized.startsWith(`${path.sep}var${path.sep}tmp${path.sep}`)
    || normalized.startsWith(`${path.sep}run${path.sep}user${path.sep}`)
    || /(?:^|[/\\])\.mount_[^/\\]+(?:[/\\]|$)/.test(normalized)
    || /(?:^|[/\\])squashfs-root(?:[/\\]|$)/.test(normalized);
  if (unstable) {
    const hint = appImage
      ? "mova o AppImage para um diretório persistente e abra-o novamente"
      : "process.env.APPIMAGE não foi fornecido pelo runtime AppImage";
    throw new Error(`autostart recusado: o caminho do AppImage é temporário (${normalized}); ${hint}`);
  }
  if (!existsSync(normalized) || !statSync(normalized).isFile()) {
    throw new Error(`autostart recusado: executável persistente não encontrado em ${normalized}`);
  }
  // In AppImage, app.getPath("exe") points inside /tmp/.mount_*. APPIMAGE is the stable
  // operator-selected file. Missing APPIMAGE therefore fails via the mount-path check above.
  return normalized;
}

function linuxAutostartEntryPath() {
  return path.join(app.getPath("home"), ".config", "autostart", "janjacord.desktop");
}

function removeAutostartArtifacts() {
  if (existsSync(backgroundHostBundlePath())) unlinkSync(backgroundHostBundlePath());
  if (process.platform === "linux") {
    const entry = linuxAutostartEntryPath();
    if (existsSync(entry)) unlinkSync(entry);
  } else {
    app.setLoginItemSettings({ openAtLogin: false, openAsHidden: false, args: [] });
  }
}

function reconcileAutostartState() {
  const config = readConnectivityConfig();
  if (!config.backgroundHosting) {
    removeAutostartArtifacts();
    return false;
  }
  const entryMissing = process.platform === "linux" && !existsSync(linuxAutostartEntryPath());
  if (!existsSync(backgroundHostBundlePath()) || entryMissing) {
    writeConnectivityConfig({ ...config, backgroundHosting: false });
    removeAutostartArtifacts();
    return false;
  }
  return true;
}

function spawnBackgroundHost() {
  if (hostProcess) return;
  const material = readBackgroundHostBundle();
  const firstRendezvous = material.bridges.flatMap((descriptor) => descriptor.payload.endpoints)
    .find((endpoint) => endpoint.startsWith("wss://") && endpoint.includes("/rendezvous"));
  const firstSignaling = material.bridges.flatMap((descriptor) => descriptor.payload.endpoints)
    .find((endpoint) => endpoint.startsWith("wss://") && endpoint.includes("/signaling"));
  const spawnedHost = utilityProcess.fork(janjanodeMainPath(), [], {
    env: productionHostEnvironment({
      JC_DB_KEY: material.serverDbKey,
      JC_DB_PATH: hostDbPath(),
      JC_OWNER_IDENTITY: material.ownerIdentityId,
      JC_OWNER_NICKNAME: material.ownerNickname,
      JC_OWNER_PUBLIC_KEY: material.ownerPublicKey,
      JC_AUTHORITY_SIGNING_SEED: material.authoritySeed,
      JC_HOST_SIGNING_SEED: material.hostSeed,
      JC_SERVER_NAME: "Meu Servidor",
      JC_PORT: String(HOST_PORT),
      JC_DIRECT_ENDPOINT: privateLanEndpoint(),
      JC_BRIDGE_DESCRIPTORS: JSON.stringify(material.bridges),
      JC_BRIDGE_PAIRINGS: "[]",
      ...(firstRendezvous ? { JC_RENDEZVOUS_URL: firstRendezvous } : {}),
      ...(firstSignaling ? { JC_PUBLIC_URL: firstSignaling } : {}),
    }),
    stdio: "pipe",
  });
  hostProcess = spawnedHost;
  spawnedHost.stdout?.on("data", (data) => {
    if (process.env.JC_HOST_DIAGNOSTICS === "1") console.debug("[host]", data.toString().trim());
  });
  spawnedHost.stderr?.on("data", (data) => console.error("[host]", data.toString().trim()));
  spawnedHost.on("exit", (code) => {
    if (code && !appQuitting) console.error(`[host] background process exited with code ${code}`);
    if (hostProcess === spawnedHost) hostProcess = null;
  });
}

async function probeBridge(descriptor, timeoutMs = 5000) {
  const endpoint = descriptor.payload.endpoints.find(
    (value) => value.startsWith("wss://") && value.includes("/rendezvous"),
  );
  if (!endpoint) throw new Error("descriptor sem endpoint de rendezvous");
  const ws = createExternalWebSocket(bridgeWebSocketEndpoint(endpoint));
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("bridge timeout")), timeoutMs);
      const onError = (error) => {
        clearTimeout(timer);
        reject(error);
      };
      ws.once("open", () => {
        clearTimeout(timer);
        ws.off("error", onError);
        resolve();
      });
      ws.once("error", onError);
    });
  } finally {
    ws.close();
  }
}

function bridgeWebSocketEndpoint(endpoint) {
  const url = new URL(endpoint);
  const loopback = ["127.0.0.1", "localhost", "::1"].includes(url.hostname);
  if (process.env.JC_ALLOW_INSECURE_BRIDGE_LOOPBACK === "1" && loopback && url.protocol === "wss:") {
    url.protocol = "ws:";
  }
  return url.toString();
}

function stopHost() {
  if (hostProcess) {
    hostProcess.kill();
    hostProcess = null;
  }
}

async function stopHostForRestart(timeoutMs = 5_000) {
  const stoppingHost = hostProcess;
  if (!stoppingHost) return false;
  hostProcess = null;
  await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    const timer = setTimeout(
      () => finish(new Error("host anterior não encerrou antes da reconfiguração")),
      timeoutMs,
    );
    stoppingHost.once("exit", () => finish());
    try {
      stoppingHost.kill();
    } catch (error) {
      finish(error);
    }
  });
  return true;
}

function spawnReplicaHost(serverId, grantId) {
  if (replicaProcess) return;
  const profile = loadOrCreateCommunityHostProfile(serverId);
  const enrollmentFile = replicaEnrollmentPath(serverId);
  if (!existsSync(enrollmentFile)) throw new Error("replica enrollment is not installed");
  replicaProcess = utilityProcess.fork(janjanodeMainPath(), [], {
    env: productionHostEnvironment({
      JC_REPLICA_OF: "auto",
      JC_REPLICA_GRANT_ID: grantId,
      JC_REPLICA_ENROLLMENT_FILE: enrollmentFile,
      JC_REPLICA_DEVICE_SEED: identity.seed.toString("hex"),
      JC_HOST_SIGNING_SEED: profile.hostSeed,
      JC_REPLICA_ENROLLMENT_PRIVATE_KEY: profile.enrollmentPrivateKey,
      JC_DB_PATH: replicaDbPath(serverId),
      JC_PORT: String(HOST_PORT + 1),
    }),
    stdio: "pipe",
  });
  replicaProcess.stdout?.on("data", (data) => console.log("[replica]", data.toString().trim()));
  replicaProcess.stderr?.on("data", (data) => console.error("[replica]", data.toString().trim()));
  replicaProcess.on("exit", (code) => {
    console.log(`[replica] exit ${code}`);
    replicaProcess = null;
  });
}

function stopReplicaHost() {
  if (!replicaProcess) return;
  replicaProcess.kill();
  replicaProcess = null;
}

async function restartHostedServer() {
  if (!identity || !hostProcess) return;
  try { client?.close(); } catch { /* already closed */ }
  client = null;
  callIceConfiguration = null;
  await stopHostForRestart();
  spawnHost();
  const authoritySeed = deriveRuntimeSeed("janjacord-authority-signing-v1");
  const hostSeed = deriveRuntimeSeed("janjacord-host-signing-v1");
  const trust = {
    authorityFingerprint: ed25519Fingerprint(ed25519PublicKey(authoritySeed)),
    expectedHostPublicKey: ed25519PublicKey(hostSeed).toString("base64url"),
  };
  const connectDeadline = Date.now() + 12_000;
  let connected = false;
  while (Date.now() < connectDeadline && hostProcess) {
    connected = await connectToHost(`ws://127.0.0.1:${HOST_PORT}/signal`, trust, 1_500).catch(() => false);
    if (connected) break;
    const failedClient = client;
    try { failedClient?.close(); } catch { /* failed opening is already closed */ }
    if (client === failedClient) client = null;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  if (!connected) throw new Error("host não reiniciou após configurar o JanjaBridge");
  const stateDeadline = Date.now() + 12_000;
  let state;
  while (Date.now() < stateDeadline) {
    state = await sendCommand({ type: "server.state" }).catch(() => null);
    if (state?.ok) break;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  if (!state?.ok) throw new Error("host reiniciado não retornou estado operacional");
  serverState = state.data;
}

function removeBridgeFromConnectivityConfig(config, bridgeId) {
  return {
    ...config,
    bridges: config.bridges.filter((entry) => entry.payload.bridgeId !== bridgeId),
    bridgePairings: (config.bridgePairings ?? []).filter((entry) => entry.bridgeId !== bridgeId),
  };
}

async function applyConnectivityConfigAndReconfigure(nextConfig, options = {}) {
  const read = options.read ?? readConnectivityConfig;
  const write = options.write ?? writeConnectivityConfig;
  const refreshBackgroundBundle = options.refreshBackgroundBundle ?? writeBackgroundHostBundle;
  const restart = options.restart ?? restartHostedServer;
  const previousConfig = read();
  write(nextConfig);
  try {
    if (nextConfig.backgroundHosting) refreshBackgroundBundle();
  } catch (error) {
    try {
      write(previousConfig);
      if (previousConfig.backgroundHosting) refreshBackgroundBundle();
    } catch (rollbackError) {
      throw new Error(`falha ao atualizar configuração e ao restaurar o estado anterior: ${String(error?.message ?? error)}; rollback: ${String(rollbackError?.message ?? rollbackError)}`);
    }
    throw error;
  }
  try {
    await restart();
    return null;
  } catch (error) {
    console.error(`[host] reconfiguration requires operator recovery: ${String(error?.message ?? error)}`);
    return error;
  }
}

async function runDesktopMainContractSelfTest() {
  const inherited = {
    HOME: "/operator/home",
    Path: "/operator/bin",
    TEMP: "/operator/tmp",
    JC_ALLOW_INSECURE_BRIDGE_LOOPBACK: "1",
    JC_HOST_DIAGNOSTICS: "1",
    NODE_OPTIONS: "--require /tmp/credential-stealer.cjs",
    NODE_PATH: "/tmp/untrusted-modules",
    CI: "true",
    GITHUB_TOKEN: "credential",
    AWS_SECRET_ACCESS_KEY: "credential",
    OTEL_EXPORTER_OTLP_ENDPOINT: "https://instrumentation.invalid",
    SENTRY_DSN: "https://instrumentation.invalid",
    JC_ALLOW_LEGACY_AUTH: "1",
    JC_ICE_SERVERS: JSON.stringify([{ urls: "turn:example.invalid", credential: "credential" }]),
  };
  const env = productionHostEnvironment({ JC_DB_KEY: "a".repeat(64), JC_PORT: "8931" }, inherited);
  for (const required of ["HOME", "Path", "TEMP", "JC_ALLOW_INSECURE_BRIDGE_LOOPBACK", "JC_HOST_DIAGNOSTICS", "JC_DB_KEY", "JC_PORT"]) {
    if (!(required in env)) throw new Error(`production host environment dropped required ${required}`);
  }
  for (const forbidden of ["NODE_OPTIONS", "NODE_PATH", "CI", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "OTEL_EXPORTER_OTLP_ENDPOINT", "SENTRY_DSN", "JC_ALLOW_LEGACY_AUTH", "JC_ICE_SERVERS"]) {
    if (forbidden in env) throw new Error(`production host environment leaked ${forbidden}`);
  }
  for (const [extra, expectedMessage] of [
    [{ NODE_OPTIONS: "--inspect" }, "non-JanjaCord"],
    [{ JC_ALLOW_LEGACY_AUTH: "1" }, "legacy authentication"],
  ]) {
    let rejected;
    try { productionHostEnvironment(extra, inherited); } catch (error) { rejected = error; }
    if (!String(rejected?.message ?? "").includes(expectedMessage)) {
      throw new Error(`production host environment accepted forbidden explicit override (${expectedMessage})`);
    }
  }

  const { WebSocketServer } = await import("ws");
  const bridgeServers = [];
  try {
    const startBridge = async (oversized) => {
      const server = new WebSocketServer({ port: 0, perMessageDeflate: true });
      bridgeServers.push(server);
      if (!server.address()) await once(server, "listening");
      let extensions;
      let rejectedCode = null;
      server.on("connection", (socket, request) => {
        extensions = request.headers["sec-websocket-extensions"];
        socket.once("close", (code) => { rejectedCode = code; });
        socket.once("message", () => socket.send(JSON.stringify(
          oversized
            ? { padding: "x".repeat(64 * 1024) }
            : { ok: true, data: { endpoint: "ws://127.0.0.1:8931/signal" } },
        )));
      });
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("runtime test bridge did not bind");
      return {
        url: `ws://127.0.0.1:${address.port}`,
        extensions: () => extensions,
        rejectedCode: () => rejectedCode,
      };
    };
    const hostile = await startBridge(true);
    const healthy = await startBridge(false);
    const [rejected, resolved] = await Promise.all([
      resolveAtBridge(hostile.url, { type: "resolve", serverId: "self-test" }, 1_000),
      resolveAtBridge(healthy.url, { type: "resolve", serverId: "self-test" }, 1_000),
    ]);
    await new Promise((resolve) => setTimeout(resolve, 25));
    if (rejected?.ok || !resolved?.ok || hostile.rejectedCode() !== 1009
      || hostile.extensions() !== undefined || healthy.extensions() !== undefined) {
      throw new Error("desktop rendezvous policy did not reject oversized/compressed input while preserving healthy resolution");
    }
  } finally {
    await Promise.all(bridgeServers.map((server) => new Promise((resolve) => {
      for (const socket of server.clients) socket.terminate();
      server.close(resolve);
    })));
  }

  const descriptor = (bridgeId) => ({ payload: { bridgeId } });
  let persisted = {
    bridges: [descriptor("bridge-1"), descriptor("bridge-2"), descriptor("bridge-3")],
    bridgePairings: ["bridge-1", "bridge-2", "bridge-3"].map((bridgeId) => ({ bridgeId, pairingToken: `token-${bridgeId}` })),
    backgroundHosting: true,
  };
  let activeHostBridgeIds = persisted.bridges.map((entry) => entry.payload.bridgeId);
  let bundleBridgeIds = [...activeHostBridgeIds];
  const operations = {
    read: () => persisted,
    write: (next) => { persisted = next; },
    refreshBackgroundBundle: () => { bundleBridgeIds = persisted.bridges.map((entry) => entry.payload.bridgeId); },
    restart: async () => { activeHostBridgeIds = persisted.bridges.map((entry) => entry.payload.bridgeId); },
  };
  for (const [removedBridgeId, expectedIds] of [
    ["bridge-1", ["bridge-2", "bridge-3"]],
    ["bridge-2", ["bridge-3"]],
  ]) {
    const restartError = await applyConnectivityConfigAndReconfigure(
      removeBridgeFromConnectivityConfig(persisted, removedBridgeId),
      operations,
    );
    if (restartError) throw restartError;
    const persistedIds = persisted.bridges.map((entry) => entry.payload.bridgeId);
    if (JSON.stringify(persistedIds) !== JSON.stringify(expectedIds)
      || JSON.stringify(bundleBridgeIds) !== JSON.stringify(expectedIds)
      || JSON.stringify(activeHostBridgeIds) !== JSON.stringify(expectedIds)) {
      throw new Error(`bridge ${expectedIds.length + 1}->${expectedIds.length} transition diverged between store, bundle, and host`);
    }
  }

  const galleryDirectory = path.join(app.getPath("userData"), "gallery-manifest-self-test");
  const screenshotName = "jc-self-test.png";
  const screenshotBytes = Buffer.from("deterministic-gallery-self-test", "utf8");
  mkdirSync(galleryDirectory, { recursive: true });
  writeFileSync(path.join(galleryDirectory, screenshotName), screenshotBytes);
  const galleryManifestPath = await writePackagedUiGalleryExecutionManifest(
    galleryDirectory,
    [screenshotName],
    "2026-08-12T00:00:00.000Z",
    { packaged: true, executable: process.execPath },
  );
  const galleryManifest = JSON.parse(readFileSync(galleryManifestPath, "utf8"));
  const expectedScreenshotHash = createHash("sha256").update(screenshotBytes).digest("hex");
  if (galleryManifest.schema !== "janjacord.ui-gallery-execution.v1"
    || galleryManifest.packaged !== true
    || galleryManifest.executableName !== path.basename(process.execPath)
    || !/^[a-f0-9]{64}$/.test(galleryManifest.executableSha256)
    || galleryManifest.screenshots?.[0]?.sha256 !== expectedScreenshotHash) {
    throw new Error("packaged UI gallery execution manifest did not bind executable and screenshot SHA-256 values");
  }
  console.log("Desktop main runtime contract self-test passed");
}

// ---------------------------------------------------------------- ws client + MLS
function connectToHost(url, trust = {}, timeoutMs = 5000) {
  const nextClient = new HostClient(url, { identityId: identity.identityId, deviceSeed: identity.seed, ...trust });
  client = nextClient;
  bindClientEvents();
  return waitForClientOpen(timeoutMs, nextClient);
}

function connectToIceHost(options) {
  const nextClient = new IceHostTransport({ ...options, identityId: identity.identityId, deviceSeed: identity.seed });
  client = nextClient;
  nextClient.onIceConfiguration((configuration) => {
    callIceConfiguration = configuration;
    notifyRenderer("connectivity.iceConfig", configuration);
  });
  bindClientEvents();
  return waitForClientOpen(15000, nextClient);
}

function bindClientEvents() {
  const boundClient = client;
  boundClient.onEvent((evt) => {
    try {
    if (evt.type === "envelope.deliver") {
      enqueueClientRecoveryWork(boundClient, `envelope ${evt.envelope?.messageId ?? "unknown"}`, () => handleDelivered(evt.envelope, boundClient));
    } else if (evt.type === "welcome.deliver") {
      enqueueClientRecoveryWork(boundClient, `Welcome ${evt.welcomeId}`, async () => {
        if (await consumeWelcome({ welcomeId: evt.welcomeId, welcomeB64: evt.welcomeB64 }, boundClient)) {
          await drainPendingMessages(boundClient);
        }
      });
    } else if (evt.type === "member.presence") {
      notifyRenderer("member.presence", evt);
    } else if (evt.type === "invite.used") {
      notifyRenderer("invite.used", evt);
    } else if (evt.type === "server.stateChanged") {
      void refreshServerState();
    } else if (evt.type === "member.removed") {
      notifyRenderer("member.removed", evt);
    } else if (evt.type === "call.members") {
      notifyRenderer("call.members", evt);
    } else if (evt.type === "call.signal") {
      notifyRenderer("call.signal", evt);
    }
    } catch (err) { console.error("[main] event handler:", err); }
  });
  boundClient.onAuthenticatedOpen?.((event) => {
    if (event.reconnected) queueAuthenticatedRecovery(boundClient, event.generation);
  });
}

function enqueueClientRecoveryWork(boundClient, label, operation) {
  clientRecoveryChain = clientRecoveryChain
    .catch(() => undefined)
    .then(async () => {
      if (boundClient !== client || !boundClient?.ready) return;
      await operation();
    })
    .catch((error) => {
      notifyRenderer("delivery.error", { message: "A recuperação da conexão não pôde ser concluída. Tentaremos novamente na próxima conexão." });
      console.error(`[main] ${label} falhou: ${String(error?.message ?? error)}`);
    });
}

function queueAuthenticatedRecovery(boundClient, generation) {
  let queued = queuedRecoveryGenerations.get(boundClient);
  if (!queued) {
    queued = new Set();
    queuedRecoveryGenerations.set(boundClient, queued);
  }
  if (queued.has(generation)) return;
  queued.add(generation);
  enqueueClientRecoveryWork(boundClient, `recuperação autenticada ${generation}`, () => recoverAuthenticatedConnection(boundClient));
}

async function recoverAuthenticatedConnection(boundClient) {
  // IceHostTransport has already repeated challenge/proof authentication before emitting the
  // lifecycle event. Never issue application commands against a stale or unauthenticated client.
  if (boundClient !== client || !boundClient.ready) return;
  const welcome = await sendClientCommand(boundClient, { type: "welcome.pending" });
  if (!welcome?.ok) throw new Error(welcome?.error?.message ?? "consulta de Welcome pendente falhou");
  if (welcome.data?.welcomeB64) {
    const consumed = await consumeWelcome(welcome.data, boundClient);
    if (!consumed) throw new Error("Welcome pendente não pôde ser consumido");
  }
  await drainPendingMessages(boundClient);
}

async function refreshServerState() {
  const refreshed = await sendCommand({ type: "server.state" });
  if (!refreshed?.ok) return;
  serverState = refreshed.data;
  syncGroupMembership();
  notifyRenderer("server.stateChanged", serverState);
}

function waitForClientOpen(timeoutMs, targetClient = client) {
  return new Promise((resolve) => {
    targetClient.onOpen(() => resolve(true));
    setTimeout(() => resolve(false), timeoutMs);
  });
}

async function resolveAtBridge(url, request, timeoutMs = 5000) {
  const ws = createExternalWebSocket(url);
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("rendezvous timeout")), timeoutMs);
      const onError = (error) => {
        clearTimeout(timer);
        reject(error);
      };
      ws.once("open", () => {
        clearTimeout(timer);
        ws.off("error", onError);
        resolve();
      });
      ws.once("error", onError);
    });
    return await new Promise((resolve) => {
      let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        ws.off("message", onMessage);
        ws.off("close", onClose);
        ws.off("error", onError);
        resolve(value);
      };
      const onMessage = (raw) => {
        try { finish(JSON.parse(raw.toString())); }
        catch { finish({ ok: false, error: { code: "invalid_response" } }); }
      };
      const onClose = () => finish({ ok: false, error: { code: "connection_closed" } });
      const onError = () => finish({ ok: false, error: { code: "connection_error" } });
      const timer = setTimeout(() => finish({ ok: false, error: { code: "timeout" } }), timeoutMs);
      ws.once("message", onMessage);
      ws.once("close", onClose);
      ws.once("error", onError);
      ws.send(JSON.stringify(request));
    });
  } finally {
    ws.close();
  }
}

function sendCommand(cmd) {
  return client?.request(cmd);
}

function sendClientCommand(boundClient, cmd) {
  if (!boundClient || boundClient !== client || !boundClient.ready) {
    return Promise.resolve({ ok: false, error: { code: "host_offline", message: "connection generation is no longer active" } });
  }
  return boundClient.request(cmd);
}

function notifyRenderer(channel, data) {
  BrowserWindow.getAllWindows().forEach((w) => w.webContents.send(channel, data));
}

function ensureGroup(serverId, channelId) {
  if (loadMlsState(serverId, channelId)) return true;
  const gid = groupIdHex(channelId);
  const created = JSON.parse(mls.create_group(identity.seed.toString("hex"), identity.identityId, gid));
  saveMlsState(serverId, channelId);
  return created.epoch >= 0;
}

async function handleWelcome({ welcomeId, welcomeB64 }, boundClient = client) {
  if (!serverState || !localDb) return false;
  const channel = serverState.channels.find((entry) => entry.type === "text") ?? serverState.channels[0];
  if (!channel) return false;
  const gid = groupIdHex(channel.id);
  const welcomeHash = createHash("sha256").update(welcomeB64).digest("hex");
  if (welcomeHash !== welcomeId) throw new Error("identificador do Welcome MLS não corresponde ao conteúdo");
  if (localDb.raw.prepare("SELECT 1 FROM mls_welcome_receipts WHERE welcome_hash = ?").get(welcomeHash)) return true;
  const joined = JSON.parse(mls.join_group(identity.seed.toString("hex"), identity.identityId, welcomeB64));
  const exported = mls.export_group(identity.identityId, gid);
  if (exported !== joined.groupStateB64) throw new Error("Welcome MLS pertence a outro grupo");
  localDb.raw.transaction(() => {
    localDb.raw
      .prepare("INSERT INTO mls_groups (key, state, updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET state=excluded.state, updated_at=excluded.updated_at")
      .run(mlsStateKey(serverState.serverId, channel.id), exported, Date.now());
    localDb.raw.prepare("INSERT INTO mls_welcome_receipts (welcome_hash, consumed_at) VALUES (?,?)")
      .run(welcomeHash, Date.now());
  })();
  // Renova o key package somente depois de persistir o estado MLS recebido.
  await publishKeyPackage(boundClient);
  notifyRenderer("mls.ready", { epoch: joined.epoch });
  return true;
}

async function acknowledgeWelcome(boundClient, delivery) {
  const acknowledged = await sendClientCommand(boundClient, { type: "welcome.ackConsumed", welcomeId: delivery.welcomeId });
  if (acknowledged?.ok) return true;
  if (boundClient !== client || !boundClient.ready) throw new Error(acknowledged?.error?.message ?? "conexão perdida durante ACK do Welcome MLS");

  // An ACK response may be lost after the host committed it. Confirm server state before retrying;
  // an absent Welcome means the original ACK succeeded, while the same ID is safe to ACK again.
  const pending = await sendClientCommand(boundClient, { type: "welcome.pending" });
  if (!pending?.ok) throw new Error(pending?.error?.message ?? acknowledged?.error?.message ?? "confirmação do ACK do Welcome MLS falhou");
  if (!pending.data?.welcomeB64) return true;
  if (pending.data.welcomeId !== delivery.welcomeId) throw new Error("Welcome pendente mudou durante confirmação do ACK");
  const retried = await sendClientCommand(boundClient, { type: "welcome.ackConsumed", welcomeId: delivery.welcomeId });
  if (!retried?.ok) throw new Error(retried?.error?.message ?? "ACK do Welcome MLS falhou");
  return true;
}

async function consumeWelcome(delivery, boundClient = client) {
  if (!boundClient) return false;
  let tasks = welcomeConsumptionTasks.get(boundClient);
  if (!tasks) {
    tasks = new Map();
    welcomeConsumptionTasks.set(boundClient, tasks);
  }
  const existing = tasks.get(delivery.welcomeId);
  if (existing) return existing;
  const task = (async () => {
    try {
      if (!await handleWelcome(delivery, boundClient)) return false;
      return await acknowledgeWelcome(boundClient, delivery);
    } catch (error) {
      notifyRenderer("delivery.error", { message: "Não foi possível validar a atualização criptográfica recebida." });
      console.error(`[main] Welcome MLS rejeitado: ${String(error?.message ?? error)}`);
      return false;
    }
  })();
  tasks.set(delivery.welcomeId, task);
  try {
    return await task;
  } finally {
    if (tasks.get(delivery.welcomeId) === task) tasks.delete(delivery.welcomeId);
  }
}

async function publishKeyPackage(boundClient = client) {
  const kp = mls.generate_key_package(identity.seed.toString("hex"), identity.identityId);
  await sendClientCommand(boundClient, { type: "keypackage.upload", keyPackageB64: kp });
}

async function drainPendingMessages(boundClient = client) {
  const pending = await sendClientCommand(boundClient, { type: "message.getPending" });
  if (!pending?.ok) throw new Error(pending?.error?.message ?? "consulta de mensagens pendentes falhou");
  if (!Array.isArray(pending.data)) throw new Error("resposta de mensagens pendentes inválida");
  for (const envelope of pending.data) await handleDelivered(envelope, boundClient);
}

async function syncGroupMembership() {
  if (!serverState || !client) return;
  const fresh = await sendCommand({ type: "server.state" });
  if (fresh?.ok && fresh.data) serverState = fresh.data;
  else if (!serverState) return;
  // owner reconcilia: para cada membro sem leaf no grupo, add
  const me = serverState.members.find((m) => m.identityId === identity.identityId);
  if (!me || me.roleId !== "role-owner") return;
  const channel = serverState.channels.find((entry) => entry.type === "text") ?? serverState.channels[0];
  if (!channel) return;
  loadMlsState(serverState.serverId, channel.id);
  const pendingTargets = new Set();
  const pendingWelcomes = localDb?.raw.prepare(
    "SELECT target_identity_id, welcome_b64 FROM mls_welcome_outbox WHERE server_id = ? AND channel_id = ?",
  ).all(serverState.serverId, channel.id) ?? [];
  for (const pending of pendingWelcomes) {
    pendingTargets.add(pending.target_identity_id);
    const pushed = await sendCommand({
      type: "welcome.push",
      targetIdentityId: pending.target_identity_id,
      welcomeB64: pending.welcome_b64,
    });
    if (pushed.ok) {
      localDb.raw.prepare("DELETE FROM mls_welcome_outbox WHERE target_identity_id = ? AND welcome_b64 = ?")
        .run(pending.target_identity_id, pending.welcome_b64);
      pendingTargets.delete(pending.target_identity_id);
    }
  }
  for (const member of serverState.members) {
    if (member.identityId === identity.identityId) continue;
    if (pendingTargets.has(member.identityId)) continue;
    const kpRes = await sendCommand({ type: "keypackage.get", targetIdentityId: member.identityId });
    if (!kpRes.ok) continue; // sem KP ainda (membro não publicou)
    const gid = groupIdHex(channel.id);
    try {
      const added = JSON.parse(mls.add_member(identity.seed.toString("hex"), identity.identityId, gid, kpRes.data.keyPackageB64));
      const state = mls.export_group(identity.identityId, gid);
      localDb.raw.transaction(() => {
        localDb.raw
          .prepare("INSERT INTO mls_groups (key, state, updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET state=excluded.state, updated_at=excluded.updated_at")
          .run(mlsStateKey(serverState.serverId, channel.id), state, Date.now());
        localDb.raw.prepare(
          "INSERT INTO mls_welcome_outbox (target_identity_id, server_id, channel_id, welcome_b64, created_at) VALUES (?,?,?,?,?) ON CONFLICT(target_identity_id) DO UPDATE SET server_id=excluded.server_id, channel_id=excluded.channel_id, welcome_b64=excluded.welcome_b64, created_at=excluded.created_at",
        ).run(member.identityId, serverState.serverId, channel.id, added.welcomeB64, Date.now());
      })();
      const pushed = await sendCommand({ type: "welcome.push", targetIdentityId: member.identityId, welcomeB64: added.welcomeB64 });
      if (pushed.ok) localDb.raw.prepare("DELETE FROM mls_welcome_outbox WHERE target_identity_id = ? AND welcome_b64 = ?")
        .run(member.identityId, added.welcomeB64);
    } catch {
      // membro já no grupo (leaf existente) — ignora
    }
  }
}

async function handleDelivered(env, boundClient = client) {
  if (!serverState) return;
  const receiptKey = `${serverState.serverId}:${env.messageId}`;
  if (recentlyDeliveredMessages.has(receiptKey)) {
    await sendClientCommand(boundClient, { type: "message.ackConsumed", messageId: env.messageId });
    return;
  }
  const gid = groupIdHex(env.channelId);
  loadMlsState(serverState.serverId, env.channelId);
  try {
    const dec = JSON.parse(mls.decrypt(identity.seed.toString("hex"), identity.identityId, gid, env.ciphertext));
    const plaintext = Buffer.from(dec.plaintextB64, "base64").toString("utf8");
    // Plain text is allowed. Once a payload declares attachment metadata, every
    // integrity failure is terminal for this delivery and must not be ACKed.
    let text = plaintext;
    let attachment = null;
    let payload = null;
    try {
      payload = JSON.parse(plaintext);
    } catch {
      // Not JSON: deliver as plain text.
    }
    if (payload && typeof payload === "object" && ("assetKeys" in payload || "attachments" in payload)) {
      try {
        if (!payload.assetKeys || !Array.isArray(payload.attachments) || payload.attachments.length < 1) {
          throw new Error("malformed attachment payload");
        }
        text = payload.text ?? "📎 anexo";
        const ref = payload.attachments[0];
        const key = payload.assetKeys[ref.assetId];
        if (typeof ref?.assetId !== "string" || typeof ref?.name !== "string"
          || typeof ref?.mimeType !== "string" || typeof key !== "string") {
          throw new Error("malformed attachment reference");
        }
        const manifestResponse = await sendClientCommand(boundClient, { type: "attachment.download", assetId: ref.assetId });
        const manifest = parseDownloadManifest(manifestResponse, ref);
        const encryptedChunks = [];
        let aggregateBytes = 0;
        for (let index = 0; index < manifest.totalChunks; index += 1) {
          const chunkResponse = await sendClientCommand(boundClient, {
            type: "attachment.download.chunk",
            assetId: ref.assetId,
            index,
          });
          const chunk = parseDownloadChunk(chunkResponse, manifest, index, aggregateBytes);
          encryptedChunks.push(chunk);
          aggregateBytes += chunk.length;
        }
        const raw = decryptDownloadedAttachment(encryptedChunks, manifest, key, ref);
        const actualHash = String(ref.hash);
        rememberDecryptedAttachment(ref.assetId, {
          raw,
          name: safeAttachmentName(ref.name),
          mimeType: safeAttachmentMimeType(ref.mimeType),
          hash: actualHash,
        });
        const canonicalMimeType = safeAttachmentMimeType(ref.mimeType);
        const isImage = canonicalMimeType.startsWith("image/");
        attachment = {
          assetId: ref.assetId,
          name: ref.name,
          mimeType: canonicalMimeType,
          dataUrl: isImage ? `data:${canonicalMimeType};base64,${raw.toString("base64")}` : null,
          sizeBytes: ref.sizeBytes,
        };
      } catch {
        notifyRenderer("delivery.error", {
          messageId: env.messageId,
          message: "Um anexo recebido falhou na verificação de integridade. A mensagem foi mantida para nova tentativa.",
        });
        return;
      }
    }
    recentlyDeliveredMessages.set(receiptKey, Date.now());
    while (recentlyDeliveredMessages.size > MAX_RECENTLY_DELIVERED_MESSAGES) {
      recentlyDeliveredMessages.delete(recentlyDeliveredMessages.keys().next().value);
    }
    notifyRenderer("message", { messageId: env.messageId, channelId: env.channelId, sender: env.sender, text, createdAt: env.createdAt, attachment });
    await sendClientCommand(boundClient, { type: "message.ackConsumed", messageId: env.messageId });
  } catch {
    // mensagem de outro epoch ou fora da audiência — ignora silenciosamente
  }
}

// ---------------------------------------------------------------- IPC
function registerIpc() {
  installIpcTrustBoundary();
  ipcMain.handle("identity.status", async () => {
    const { existsSync } = await import("node:fs");
    return { exists: existsSync(vaultPath()) };
  });

  ipcMain.handle("identity.create", async (_e, { nickname, password }) => {
    identity = await createIdentity(nickname, password, vaultPath());
    initLocalDb();
    await loadMls();
    return { ok: true, identityId: identity.identityId, recoveryKey: generateRecoveryKey(identity.seed) };
  });

  ipcMain.handle("identity.unlock", async (_e, { password }) => {
    identity = await unlockIdentity(password, vaultPath());
    initLocalDb();
    await loadMls();
    return { ok: true, identityId: identity.identityId, nickname: identity.nickname };
  });

  ipcMain.handle("identity.restore", async (_e, { recoveryKey, nickname, newPassword }) => {
    identity = await restoreIdentity(recoveryKey, nickname, newPassword, vaultPath());
    initLocalDb();
    await loadMls();
    return { ok: true, identityId: identity.identityId };
  });

  ipcMain.handle("server.create", async () => {
    if (!identity) return { ok: false, error: { code: "unauthorized", message: "identity required" } };
    try {
      emitSetupStep("host", "running");
      spawnHost();
      await new Promise((r) => setTimeout(r, 1500));
      const authoritySeed = deriveRuntimeSeed("janjacord-authority-signing-v1");
      const hostSeed = deriveRuntimeSeed("janjacord-host-signing-v1");
      const connected = await connectToHost(`ws://127.0.0.1:${HOST_PORT}/signal`, {
        authorityFingerprint: ed25519Fingerprint(ed25519PublicKey(authoritySeed)),
        expectedHostPublicKey: ed25519PublicKey(hostSeed).toString("base64url"),
      });
      if (!connected) throw Object.assign(new Error("host não respondeu"), { code: "host_offline" });
      emitSetupStep("host", "done");

      emitSetupStep("direct", "running");
      client.send("hello", { identityId: identity.identityId });
      const stateRes = await new Promise((resolve) => {
        client.onEventOnce("result", (f) => resolve(f.data));
        setTimeout(() => resolve(null), 8000);
      });
      if (!stateRes?.ok) throw Object.assign(new Error("host local não autenticou"), { code: "host_offline" });
      emitSetupStep("direct", "done", "Host local autenticado");

      const connectivity = readConnectivityConfig();
      let bridgeReady = false;
      if (connectivity.bridges.length > 0) {
        emitSetupStep("bridge", "running");
        for (const descriptor of connectivity.bridges) {
          try {
            await probeBridge(descriptor);
            bridgeReady = true;
            break;
          } catch {
            // Tenta o próximo descriptor configurado.
          }
        }
        emitSetupStep("bridge", bridgeReady ? "done" : "warning", bridgeReady ? "JanjaBridge alcançável" : "Bridges configurados não responderam");
      } else {
        emitSetupStep("bridge", "action", "Adicione um JanjaBridge para conexões entre redes restritas");
      }

      emitSetupStep("access", "running");
      serverState = stateRes.data;
      bindPrimaryHostProfileServer(serverState.serverId);
      const general = serverState.channels.find((c) => c.type === "text") ?? serverState.channels[0];
      ensureGroup(serverState.serverId, general.id);
      publishKeyPackage();
      syncGroupMembership();
      emitSetupStep("access", "done", bridgeReady ? "Conexão pronta" : "Pronto nesta rede");
      return { ok: true, data: serverState, connectivity: { bridgeReady, needsBridge: !bridgeReady } };
    } catch (error) {
      const code = error?.code ?? "internal";
      const message = String(error?.message ?? error);
      emitSetupStep("access", "error", message);
      return { ok: false, error: { code, message } };
    }
  });

  ipcMain.handle("server.join", async (_e, {
    hostUrl,
    inviteKey,
    allowLegacyTrust,
    legacyConfirmationToken,
    expectedHostPublicKey,
    expectedHostFingerprint,
  }) => {
    if (!identity) return { ok: false, error: { code: "unauthorized", message: "identity required" } };
    // descoberta via rendezvous quando possível (invite carrega serverId)
    const parsedV3 = parseInviteV3(inviteKey);
    const parsed = parsedV3 ? { serverId: parsedV3.payload.serverId } : parseInviteKey(inviteKey);
    if (!parsed) return { ok: false, error: { code: "invalid_invite", message: "invite inválido" } };
    // convite autocontido (JC2): o endpoint do host viaja no convite — um campo só
    let target = hostUrl || (parsed?.endpoint ? `ws://${parsed.endpoint}/signal` : "");
    const bridgeEndpoints = parsedV3?.payload.bridgeHints.flatMap((hint) => hint.payload.endpoints) ?? [];
    const rendezvousUrls = [...new Set([
      ...(process.env.JC_RENDEZVOUS_URL ? [process.env.JC_RENDEZVOUS_URL] : []),
      ...bridgeEndpoints.filter((endpoint) => endpoint.startsWith("wss://") && endpoint.includes("/rendezvous")),
    ].map(bridgeWebSocketEndpoint))];
    if (parsedV3 && rendezvousUrls.length > 0) {
      try {
        const results = await Promise.allSettled(rendezvousUrls.map((url) => resolveAtBridge(url, {
            type: "resolve",
            serverId: parsed.serverId,
            authorityFingerprint: parsedV3.payload.authorityFingerprint,
        })));
        const resolved = results
          .filter((result) => result.status === "fulfilled" && result.value?.ok)
          .map((result) => result.value.data);
        if (resolved.length === 0) return { ok: false, error: { code: "rendezvous", message: "nenhum JanjaBridge respondeu" } };

        const connectivity = readConnectivityConfig();
        if (!connectivity.hostHighWater || !connectivity.authorityTrust) {
          return { ok: false, error: { code: "unauthorized", message: "estado local de confiança anti-rollback inválido ou ausente" } };
        }
        const trustedServer = connectivity.authorityTrust.servers.find((entry) => (
          entry.serverId === parsed.serverId && entry.authorityFingerprint === parsedV3.payload.authorityFingerprint
        ));
        const verifiedRevocations = [...(trustedServer?.revocations ?? [])];
        for (const item of resolved.flatMap((data) => data?.revocations ?? [])) {
          const verified = verifySignedHostGrantRevocation(item?.revocation, item?.authorityPublicKey);
          if (!verified || verified.payload.serverId !== parsed.serverId) continue;
          try {
            if (ed25519Fingerprint(Buffer.from(item.authorityPublicKey, "base64url")) !== parsedV3.payload.authorityFingerprint) continue;
          } catch {
            continue;
          }
          verifiedRevocations.push({ authorityPublicKey: item.authorityPublicKey, revocation: verified });
        }
        const revocationsByGrant = new Map();
        for (const item of verifiedRevocations) {
          const current = revocationsByGrant.get(item.revocation.payload.grantId);
          if (!current || item.revocation.payload.generation > current.revocation.payload.generation
            || (item.revocation.payload.generation === current.revocation.payload.generation
              && item.revocation.payload.revokedAt > current.revocation.payload.revokedAt)) {
            revocationsByGrant.set(item.revocation.payload.grantId, item);
          }
        }
        const revokedGrantIds = new Set(revocationsByGrant.keys());
        const generationFloors = new Map();
        for (const { revocation } of revocationsByGrant.values()) {
          generationFloors.set(
            revocation.payload.hostId,
            Math.max(generationFloors.get(revocation.payload.hostId) ?? 0, revocation.payload.generation),
          );
        }
        const selection = selectHostRegistrations(
          resolved.flatMap((data) => data?.records ?? data?.registrations ?? []),
          {
            serverId: parsed.serverId,
            authorityFingerprint: parsedV3.payload.authorityFingerprint,
            highWater: connectivity.hostHighWater,
            verifiedRevokedGrantIds: revokedGrantIds,
            verifiedGenerationFloors: generationFloors,
          },
        );
        const selected = selection.registrations.find((candidate) => candidate.record.payload.role === "primary")
          ?? selection.registrations[0];
        if (!selected) return { ok: false, error: { code: "host_offline", message: "nenhum host autorizado está online" } };
        const signalingUrls = [...new Set(bridgeEndpoints
          .filter((endpoint) => endpoint.startsWith("wss://") && endpoint.includes("/signaling"))
          .map(bridgeWebSocketEndpoint))];
        const stunServers = [...new Set(bridgeEndpoints.filter((endpoint) => endpoint.startsWith("stun:") || endpoint.startsWith("stuns:")))];
        if (signalingUrls.length === 0) return { ok: false, error: { code: "rendezvous", message: "invite sem signaling válido" } };
        const connected = await connectToIceHost({
          bridgeUrls: signalingUrls,
          serverId: parsed.serverId,
          authorityFingerprint: parsedV3.payload.authorityFingerprint,
          hostId: selected.hostId,
          hostRegistration: selected.registration,
          iceServers: stunServers,
          networkPrivacy: "direct",
          inviteAccessHash: createHash("sha256")
            .update(Buffer.from(parsedV3.payload.inviteSecret, "base64url"))
            .digest("hex"),
        });
        if (!connected) return { ok: false, error: { code: "host_offline", message: "conexão ICE não respondeu" } };
        const authorityTrust = {
          version: 1,
          servers: [
            ...connectivity.authorityTrust.servers.filter((entry) => !(
              entry.serverId === parsed.serverId && entry.authorityFingerprint === parsedV3.payload.authorityFingerprint
            )),
            {
              serverId: parsed.serverId,
              authorityFingerprint: parsedV3.payload.authorityFingerprint,
              revocations: [...revocationsByGrant.values()],
            },
          ],
        };
        writeConnectivityConfig({ ...connectivity, hostHighWater: selection.highWater, authorityTrust });
        target = null;
      } catch (e) {
        return { ok: false, error: { code: "rendezvous", message: `falha no rendezvous: ${(e).message}` } };
      }
    } else if (parsedV3) {
      return { ok: false, error: { code: "rendezvous", message: "invite sem JanjaBridge alcançável" } };
    }
    if (target) {
      const connectivity = readConnectivityConfig();
      const persistedPin = parsed?.serverId ? connectivity.legacyHostPins?.[parsed.serverId] : undefined;
      if (!parsedV3 && !persistedPin && allowLegacyTrust !== true) {
        let observed = null;
        const probe = new HostClient(target, {
          identityId: identity.identityId,
          deviceSeed: identity.seed,
          serverId: parsed.serverId,
          onLegacyHostFirstUse: async (candidate) => {
            observed = candidate;
            return false;
          },
        });
        await new Promise((resolve) => {
          const timer = setTimeout(resolve, 5_000);
          probe.onClose(() => { clearTimeout(timer); resolve(); });
        });
        probe.close();
        if (!observed) return { ok: false, error: { code: "host_offline", message: "host legado não apresentou identidade verificável" } };
        const issued = issueLegacyHostConfirmation(observed);
        const current = readConnectivityConfig();
        writeConnectivityConfig({
          ...current,
          pendingLegacyHostConfirmations: {
            ...(current.pendingLegacyHostConfirmations ?? {}),
            [parsed.serverId]: issued.pending,
          },
        });
        return {
          ok: false,
          error: {
            code: "legacy_confirmation_required",
            message: "confirme a chave observada do host legado",
            fingerprint: observed.hostKeyFingerprint,
            data: {
              serverId: parsed.serverId,
              ...issued.challenge,
            },
          },
        };
      }
      const pendingConfirmation = !parsedV3 && !persistedPin
        ? connectivity.pendingLegacyHostConfirmations?.[parsed.serverId]
        : null;
      const validConfirmation = allowLegacyTrust === true && validateLegacyHostConfirmation(pendingConfirmation, {
        confirmationToken: legacyConfirmationToken,
        hostPublicKey: expectedHostPublicKey,
        fingerprint: expectedHostFingerprint,
      });
      if (!parsedV3 && !persistedPin && !validConfirmation) {
        return { ok: false, error: { code: "legacy_confirmation_required", message: "primeira observação do host expirou; tente novamente" } };
      }
      let exactLegacyMatch = false;
      const connected = await connectToHost(target, parsedV3 ? {} : {
        serverId: parsed.serverId,
        ...(persistedPin ? { expectedHostPublicKey: persistedPin } : {
          onLegacyHostFirstUse: async (candidate) => {
            exactLegacyMatch = candidate.serverId === parsed.serverId
              && candidate.hostPublicKey === pendingConfirmation.hostPublicKey
              && candidate.hostKeyFingerprint === pendingConfirmation.fingerprint
              && candidate.hostId === pendingConfirmation.hostId
              && candidate.grantId === pendingConfirmation.grantId;
            return exactLegacyMatch;
          },
        }),
      });
      if (!connected) return { ok: false, error: { code: "host_offline", message: "host não respondeu" } };
      if (!parsedV3 && !persistedPin) {
        if (!exactLegacyMatch) return { ok: false, error: { code: "unauthorized", message: "chave do host mudou entre observação e confirmação" } };
        const current = readConnectivityConfig();
        const pending = { ...(current.pendingLegacyHostConfirmations ?? {}) };
        delete pending[parsed.serverId];
        writeConnectivityConfig({
          ...current,
          legacyHostPins: { ...(current.legacyHostPins ?? {}), [parsed.serverId]: pendingConfirmation.hostPublicKey },
          pendingLegacyHostConfirmations: pending,
        });
      }
    }
    client.send("hello", { identityId: identity.identityId });
    await new Promise((r) => setTimeout(r, 300));
    const joinRes = await sendCommand({ type: "server.join", inviteKey, nickname: identity.nickname });
    if (!joinRes.ok) return joinRes;
    serverState = joinRes.data;
    const general = serverState.channels.find((c) => c.type === "text") ?? serverState.channels[0];
    publishKeyPackage();
    const welcome = await sendCommand({ type: "welcome.pending" });
    if (welcome.ok && welcome.data?.welcomeB64) {
      if (await consumeWelcome(welcome.data)) await drainPendingMessages();
    } else {
      notifyRenderer("mls.ready", { epoch: 0 });
    }
    return { ok: true, data: serverState };
  });

  ipcMain.handle("server.state", () => ({ ok: true, data: serverState }));

  ipcMain.handle("message.send", async (_e, { channelId, text }) => {
    if (!identity || !serverState) return { ok: false, error: { code: "unauthorized", message: "no server" } };
    const gid = groupIdHex(channelId);
    loadMlsState(serverState.serverId, channelId);
    try {
      const enc = JSON.parse(mls.encrypt(identity.seed.toString("hex"), identity.identityId, gid, Buffer.from(text).toString("base64")));
      saveMlsState(serverState.serverId, channelId);
      const seq = (channelSeq.get(channelId) ?? 0) + 1;
      channelSeq.set(channelId, seq);
      const env = buildEnvelope({
        serverId: serverState.serverId,
        channelId,
        sender: identity.identityId,
        cryptoEpoch: enc.epoch,
        audience: { algo: "sha256", commitment: "", members: serverState.members.map((m) => m.identityId) },
        ciphertext: enc.ciphertextB64,
        ordering: { seq },
      });
      const res = await sendCommand({ type: "message.send", envelope: env });
      if (res.ok) notifyRenderer("message", { messageId: env.messageId, channelId, sender: identity.identityId, text, createdAt: env.createdAt, self: true });
      return res;
    } catch (e) {
      return { ok: false, error: { code: "internal", message: String(e?.message ?? e) } };
    }
  });

  ipcMain.handle("invite.create", async () => {
    return sendCommand({ type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
  });

  ipcMain.handle("clipboard.clearIfEquals", (_e, { text }) => {
    if (typeof text !== "string" || text.length > 16 * 1024 || !/^JC[23]-/.test(text)) {
      return { ok: false, error: { code: "invalid_input", message: "invalid invite clipboard value" } };
    }
    const cleared = clipboard.readText() === text;
    if (cleared) clipboard.clear();
    return { ok: true, data: { cleared } };
  });

  ipcMain.handle("channel.create", async (_e, { channelType, name }) => {
    return sendCommand({ type: "channel.create", channelType, name });
  });

  ipcMain.handle("attachment.send", async (_e, { channelId, name, mimeType, dataB64 }) => {
    if (!identity || !serverState) return { ok: false, error: { code: "unauthorized", message: "no server" } };
    let assetId = null;
    let transferStarted = false;
    let attachmentLinked = false;
    try {
      const raw = decodeRendererAttachment(dataB64);
      dataB64 = "";
      const canonicalName = safeAttachmentName(name);
      const canonicalMimeType = safeAttachmentMimeType(mimeType);
      const encrypted = encryptAttachmentForUpload(raw);
      assetId = randomUUID();
      const audienceMembers = serverState.members.map((m) => m.identityId);
      transferStarted = true;
      const uploaded = await uploadAttachmentWithResume({
        chunks: encrypted.chunks,
        begin: () => sendCommand({
          type: "attachment.upload.begin",
          assetId,
          channelId,
          audienceMembers,
          sizeBytes: encrypted.encryptedSizeBytes,
          totalChunks: encrypted.chunks.length,
          hash: encrypted.ciphertextHash,
        }),
        uploadChunk: (chunk) => sendCommand({
          type: "attachment.upload.chunk",
          assetId,
          index: chunk.index,
          data: chunk.data,
          sizeBytes: chunk.sizeBytes,
          hash: chunk.hash,
        }),
        complete: () => sendCommand({ type: "attachment.upload.complete", assetId }),
      });
      if (!uploaded?.ok) return uploaded;
      // mensagem MLS com assetKey dentro do ciphertext (só a audiência decifra)
      const attachmentRef = {
        assetId,
        name: canonicalName,
        mimeType: canonicalMimeType,
        sizeBytes: raw.length,
        totalChunks: encrypted.chunks.length,
        hash: encrypted.plaintextHash,
      };
      const payload = JSON.stringify({
        text: `📎 ${canonicalName}`,
        attachments: [attachmentRef],
        assetKeys: { [assetId]: encrypted.assetKey.toString("base64") },
      });
      const gid = groupIdHex(channelId);
      loadMlsState(serverState.serverId, channelId);
      const enc = JSON.parse(mls.encrypt(identity.seed.toString("hex"), identity.identityId, gid, Buffer.from(payload).toString("base64")));
      saveMlsState(serverState.serverId, channelId);
      const env = buildEnvelope({
        serverId: serverState.serverId,
        channelId,
        sender: identity.identityId,
        cryptoEpoch: enc.epoch,
        audience: { algo: "sha256", commitment: "", members: audienceMembers },
        ciphertext: enc.ciphertextB64,
        attachments: [attachmentRef],
        ordering: { seq: (channelSeq.get(channelId) ?? 0) + 1 },
      });
      const result = await sendCommand({ type: "message.send", envelope: env });
      if (result?.ok) {
        attachmentLinked = true;
        rememberDecryptedAttachment(assetId, {
          raw,
          name: canonicalName,
          mimeType: canonicalMimeType,
          hash: encrypted.plaintextHash,
        });
        channelSeq.set(channelId, env.ordering.seq);
        notifyRenderer("message", {
          messageId: env.messageId,
          channelId,
          sender: identity.identityId,
          text: `📎 ${canonicalName}`,
          createdAt: env.createdAt,
          self: true,
          attachment: {
            assetId,
            name: canonicalName,
            mimeType: canonicalMimeType,
            dataUrl: canonicalMimeType.startsWith("image/") ? `data:${canonicalMimeType};base64,${raw.toString("base64")}` : null,
            sizeBytes: raw.length,
          },
        });
      }
      return result ?? { ok: false, error: { code: "host_offline", message: "host unavailable" } };
    } catch (e) {
      return { ok: false, error: { code: "invalid_input", message: String(e?.message ?? e) } };
    } finally {
      if (assetId && transferStarted && !attachmentLinked) {
        try { await sendCommand({ type: "attachment.upload.abort", assetId }); } catch { /* TTL cleanup remains the fallback. */ }
      }
    }
  });

  ipcMain.handle("attachment.save", async (_e, { assetId }) => {
    try {
      if (typeof assetId !== "string" || !/^[0-9a-f-]{36}$/i.test(assetId)) {
        return { ok: false, error: { code: "invalid_input", message: "Anexo inválido" } };
      }
      const attachment = decryptedAttachments.get(assetId);
      if (!attachment) return { ok: false, error: { code: "not_found", message: "Anexo não está mais disponível nesta sessão" } };
      const { dialog, shell } = await import("electron");
      let dest;
      const smokeDestination = process.env.JC_OPERATOR_ATTACHMENT_SAVE_PATH;
      if (process.env.JC_OPERATOR_SMOKE_ROLE && process.env.JC_OPERATOR_SMOKE_DIR && smokeDestination) {
        const root = path.resolve(process.env.JC_OPERATOR_SMOKE_DIR);
        const candidate = path.resolve(smokeDestination);
        if (!candidate.startsWith(`${root}${path.sep}`)) throw new Error("operator attachment destination escaped smoke directory");
        dest = candidate;
      } else {
        const selected = await dialog.showSaveDialog({
          defaultPath: path.join(app.getPath("downloads"), safeAttachmentName(attachment.name)),
          properties: ["createDirectory", "showOverwriteConfirmation"],
        });
        if (selected.canceled || !selected.filePath) return { ok: false, error: { code: "cancelled", message: "Salvamento cancelado" } };
        dest = selected.filePath;
      }
      writeFileSync(dest, attachment.raw);
      forgetDecryptedAttachment(assetId);
      shell.showItemInFolder(dest);
      return { ok: true, data: { path: dest } };
    } catch (e) {
      return { ok: false, error: { code: "internal", message: String(e?.message ?? e) } };
    }
  });

  ipcMain.handle("call.join", async (_e, { channelId }) => {
    return sendCommand({ type: "call.join", channelId });
  });
  ipcMain.handle("call.leave", async (_e, { channelId }) => {
    return sendCommand({ type: "call.leave", channelId });
  });
  ipcMain.handle("call.signal", async (_e, { channelId, to, payload }) => {
    return sendCommand({ type: "call.signal", channelId, to, payload });
  });

  ipcMain.handle("host.url", () => `ws://127.0.0.1:${HOST_PORT}/signal`);

  ipcMain.handle("connectivity.status", () => {
    const config = readConnectivityConfig();
    return {
      ok: true,
      data: {
        bridges: config.bridges.map(bridgeSummary),
        backgroundHosting: config.backgroundHosting,
      },
    };
  });
  ipcMain.handle("connectivity.ice-config", async () => {
    if (callIceConfiguration) return { ok: true, data: callIceConfiguration };
    const issued = await sendCommand({ type: "connectivity.iceConfig" });
    if (issued?.ok && issued.data?.iceServers) {
      callIceConfiguration = issued.data;
      return issued;
    }
    return issued?.ok === false
      ? issued
      : { ok: false, error: { code: "host_offline", message: "Nenhuma credencial ICE/TURN temporária está disponível" } };
  });
  ipcMain.handle("connectivity.bridge.add", async (_e, { pairingCode }) => {
    try {
      const value = JSON.parse(String(pairingCode ?? "").trim());
      const descriptorValue = value?.schema === "janjacord.bridge-pairing.v1" ? value.descriptor : value;
      if (value?.schema === "janjacord.bridge-pairing.v1") {
        const token = String(value.pairingToken ?? "");
        const expectedKeyId = `sha256:${createHash("sha256").update(token).digest("hex")}`;
        if (!/^JCP1\.[A-Za-z0-9_-]{32,384}\.[A-Za-z0-9_-]{43}$/.test(token) || value.pairingKeyId !== expectedKeyId) {
          return { ok: false, error: { code: "invalid_input", message: "Código de pareamento inválido" } };
        }
      }
      const descriptor = verifySignedBridgeDescriptor(descriptorValue);
      if (!descriptor) return { ok: false, error: { code: "invalid_input", message: "Descriptor do JanjaBridge inválido ou expirado" } };
      await probeBridge(descriptor);
      const config = readConnectivityConfig();
      const bridges = [descriptor, ...config.bridges.filter((entry) => entry.payload.bridgeId !== descriptor.payload.bridgeId)].slice(0, 3);
      const pairingToken = value?.schema === "janjacord.bridge-pairing.v1" ? String(value.pairingToken) : null;
      const bridgePairings = pairingToken
        ? [{ bridgeId: descriptor.payload.bridgeId, pairingToken }, ...(config.bridgePairings ?? []).filter((entry) => entry.bridgeId !== descriptor.payload.bridgeId)].slice(0, 3)
        : config.bridgePairings ?? [];
      const restartError = await applyConnectivityConfigAndReconfigure({ ...config, bridges, bridgePairings });
      const restartWarning = restartError
        ? "JanjaBridge salvo; reabra o app para ativar o hosting externo"
        : null;
      return { ok: true, data: { ...bridgeSummary(descriptor), ...(restartWarning ? { warning: restartWarning } : {}) } };
    } catch (error) {
      return { ok: false, error: { code: "bridge_unavailable", message: `JanjaBridge não respondeu: ${String(error?.message ?? error)}` } };
    }
  });
  ipcMain.handle("connectivity.bridge.remove", async (_e, { bridgeId }) => {
    try {
      if (typeof bridgeId !== "string" || bridgeId.length < 1 || bridgeId.length > 256) {
        return { ok: false, error: { code: "invalid_input", message: "JanjaBridge inválido" } };
      }
      const config = readConnectivityConfig();
      if (!config.bridges.some((entry) => entry.payload.bridgeId === bridgeId)) {
        return { ok: false, error: { code: "not_found", message: "JanjaBridge não está configurado" } };
      }
      const nextConfig = removeBridgeFromConnectivityConfig(config, bridgeId);
      const restartError = await applyConnectivityConfigAndReconfigure(nextConfig);
      return {
        ok: true,
        data: {
          bridges: nextConfig.bridges.map(bridgeSummary),
          ...(restartError ? { warning: "JanjaBridge removido; reabra o app para concluir a reconfiguração do host" } : {}),
        },
      };
    } catch (error) {
      return { ok: false, error: { code: "internal", message: `Não foi possível remover o JanjaBridge: ${String(error?.message ?? error)}` } };
    }
  });
  ipcMain.handle("hosting.autostart", (_e, { enabled }) => {
    const config = readConnectivityConfig();
    const nextEnabled = enabled === true;
    const file = process.platform === "linux" ? linuxAutostartEntryPath() : null;
    try {
      if (nextEnabled && config.backgroundHosting && reconcileAutostartState()) {
        return { ok: true, data: { enabled: true } };
      }
      if (!nextEnabled) {
        // The authenticated intent is committed first. A crash or unlink failure after
        // this point still leaves --background-host fail-closed on the next launch.
        writeConnectivityConfig({ ...config, backgroundHosting: false });
        removeAutostartArtifacts();
      } else {
        const executable = process.platform === "linux" ? linuxAutostartExecutable() : null;
        writeBackgroundHostBundle();
        if (process.platform === "linux") {
          mkdirSync(path.dirname(file), { recursive: true });
          const launchedAppImage = process.env.APPIMAGE;
          if (launchedAppImage && executable !== path.normalize(launchedAppImage)) {
            throw new Error("autostart recusado: o caminho persistente do AppImage mudou durante a configuração");
          }
          const escaped = executable.replace(/([\\"`$])/g, "\\$1");
          durableAtomicWrite(file, `[Desktop Entry]\nType=Application\nName=JanjaCord Community Host\nTryExec=${escaped}\nExec="${escaped}" --background-host\nX-GNOME-Autostart-enabled=true\nX-JanjaCord-Autostart=true\n`);
          chmodSync(file, 0o600);
        } else {
          app.setLoginItemSettings({ openAtLogin: true, openAsHidden: true, args: ["--background-host"] });
        }
        // This is the commit point: both launch artifacts already exist.
        writeConnectivityConfig({ ...config, backgroundHosting: true });
      }
    } catch (error) {
      try { writeConnectivityConfig({ ...config, backgroundHosting: false }); }
      catch (rollbackError) { console.error(`[desktop] autostart rollback falhou: ${String(rollbackError?.message ?? rollbackError)}`); }
      try { removeAutostartArtifacts(); }
      catch (cleanupError) { console.error(`[desktop] limpeza de autostart falhou: ${String(cleanupError?.message ?? cleanupError)}`); }
      return { ok: false, error: { code: "unavailable", message: String(error?.message ?? error) } };
    }
    return { ok: true, data: { enabled: nextEnabled } };
  });
  ipcMain.handle("hosting.candidate.register", async () => {
    if (!identity || !serverState) return { ok: false, error: { code: "unauthorized", message: "active community required" } };
    const profile = loadOrCreateCommunityHostProfile(serverState.serverId);
    const subjectAuthPublicKey = ed25519PublicKey(identity.seed).toString("base64url");
    const common = {
      serverId: serverState.serverId,
      subjectIdentityId: identity.identityId,
      subjectAuthPublicKey,
      hostPublicKey: profile.hostPublicKey,
      enrollmentPublicKey: profile.enrollmentPublicKey,
      hostId: profile.hostId,
    };
    return sendCommand({
      type: "host.candidate.register",
      hostPublicKey: profile.hostPublicKey,
      enrollmentPublicKey: profile.enrollmentPublicKey,
      hostId: profile.hostId,
      deviceProof: createPossessionProof(identity.seed, "janjacord.host-candidate-device.v1", common),
      hostProof: createPossessionProof(Buffer.from(profile.hostSeed, "hex"), "janjacord.host-candidate-possession.v1", common),
    });
  });
  ipcMain.handle("hosting.grant.list", () => sendCommand({ type: "host.grant.list" }));
  ipcMain.handle("hosting.grant.authorize", (_e, { subjectIdentityId, candidateId }) => sendCommand({
    type: "host.grant.create",
    subjectIdentityId,
    candidateId,
    capabilities: ["register", "replicate", "promote"],
  }));
  ipcMain.handle("hosting.grant.revoke", (_e, { grantId }) => sendCommand({ type: "host.grant.revoke", grantId, reason: "revoked by community administrator" }));
  ipcMain.handle("hosting.grant.accept", async (_e, { grant }) => {
    if (!identity || !serverState || !grant?.grantId) return { ok: false, error: { code: "invalid_input", message: "host grant required" } };
    try {
      const profile = loadOrCreateCommunityHostProfile(serverState.serverId);
      if (grant.hostPublicKey !== profile.hostPublicKey || grant.enrollmentPublicKey !== profile.enrollmentPublicKey) {
        return { ok: false, error: { code: "unauthorized", message: "grant is bound to another host profile" } };
      }
      const proofPayload = {
        purpose: "accept",
        serverId: serverState.serverId,
        grantId: grant.grantId,
        subjectIdentityId: grant.subjectIdentityId,
        subjectAuthPublicKey: grant.subjectAuthPublicKey,
        hostPublicKey: grant.hostPublicKey,
        enrollmentPublicKey: grant.enrollmentPublicKey,
      };
      const accepted = await sendCommand({
        type: "host.grant.accept",
        grantId: grant.grantId,
        hostProof: createPossessionProof(Buffer.from(profile.hostSeed, "hex"), "janjacord.host-possession.v1", proofPayload),
      });
      if (!accepted?.ok) return accepted;
      const enrollment = await sendCommand({
        type: "replica.enroll",
        grantId: grant.grantId,
        hostProof: createPossessionProof(Buffer.from(profile.hostSeed, "hex"), "janjacord.host-possession.v1", { ...proofPayload, purpose: "enroll" }),
      });
      if (!enrollment?.ok || !enrollment.data?.sealedEnrollment) return enrollment;
      const file = replicaEnrollmentPath(serverState.serverId);
      mkdirSync(path.dirname(file), { recursive: true });
      writeFileSync(file, `${JSON.stringify({ sealedEnrollment: enrollment.data.sealedEnrollment })}\n`, { mode: 0o600 });
      chmodSync(file, 0o600);
      spawnReplicaHost(serverState.serverId, grant.grantId);
      return { ok: true, data: { grantId: grant.grantId, status: "syncing" } };
    } catch (error) {
      return { ok: false, error: { code: "internal", message: String(error?.message ?? error) } };
    }
  });

  ipcMain.handle("member.action", async (_e, { identityId, action }) => {
    if (action === "kick") return sendCommand({ type: "member.kick", memberIdentityId: identityId });
    return sendCommand({ type: "member.ban", memberIdentityId: identityId });
  });
  ipcMain.handle("role.create", async (_e, { name, level, permissions }) => {
    return sendCommand({ type: "role.create", name, level, permissions });
  });
  ipcMain.handle("role.assign", async (_e, { memberIdentityId, roleId }) => {
    return sendCommand({ type: "role.assign", memberIdentityId, roleId });
  });
  ipcMain.handle("server.updateConfig", async (_e, { config }) => {
    return sendCommand({ type: "server.updateConfig", config });
  });
  ipcMain.handle("invite.list", async () => {
    return sendCommand({ type: "invite.list" });
  });
  ipcMain.handle("invite.revoke", async (_e, { inviteId }) => {
    return sendCommand({ type: "invite.revoke", inviteId });
  });

}

async function sha256FileStream(file) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

async function writePackagedUiGalleryExecutionManifest(shotDir, screenshotNames, startedAt, testOverride = null) {
  const packaged = testOverride?.packaged ?? app.isPackaged;
  if (!packaged) return null;
  const executable = path.resolve(testOverride?.executable ?? (process.platform === "linux" && process.env.APPIMAGE
    ? process.env.APPIMAGE
    : process.execPath));
  if (!existsSync(executable) || !statSync(executable).isFile()) {
    throw new Error(`[smoke-ui] packaged executable is not a regular file: ${executable}`);
  }
  const screenshots = [];
  for (const name of screenshotNames) {
    const file = path.join(shotDir, name);
    screenshots.push({ name, sha256: await sha256FileStream(file) });
  }
  const manifestPath = path.join(shotDir, "jc-ui-gallery-execution.json");
  durableAtomicWrite(manifestPath, `${JSON.stringify({
    schema: "janjacord.ui-gallery-execution.v1",
    startedAt,
    completedAt: new Date().toISOString(),
    packaged: true,
    executableName: path.basename(executable),
    executableSha256: await sha256FileStream(executable),
    result: "passed",
    screenshots,
  }, null, 2)}\n`);
  return manifestPath;
}

// ---------------------------------------------------------------- smoke UI
async function runUiSmoke(win) {
  const fs = await import("node:fs");
  const shotDir = process.env.JC_SMOKE_DIR ?? "/tmp";
  const startedAt = new Date().toISOString();
  const screenshotNames = [];
  const js = (code) => win.webContents.executeJavaScript(code);
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const waitForText = async (expected, timeoutMs = 10_000) => {
    const startedAt = Date.now();
    while (Date.now() - startedAt < timeoutMs) {
      if (await js(`document.body.innerText.includes(${JSON.stringify(expected)})`)) return;
      await pause(80);
    }
    throw new Error(`[smoke-ui] timed out waiting for text: ${expected}`);
  };
  const waitFor = async (expression, label, timeoutMs = 10_000) => {
    const startedAt = Date.now();
    while (Date.now() - startedAt < timeoutMs) {
      if (await js(`Boolean(${expression})`)) return;
      await pause(80);
    }
    throw new Error(`[smoke-ui] timed out waiting for ${label}`);
  };
  const assertText = async (expected) => {
    const found = await js(`document.body.innerText.includes(${JSON.stringify(expected)})`);
    if (!found) throw new Error(`[smoke-ui] expected text not found: ${expected}`);
  };
  const assertNoText = async (unexpected) => {
    const found = await js(`document.body.innerText.includes(${JSON.stringify(unexpected)})`);
    if (found) throw new Error(`[smoke-ui] unexpected text found: ${unexpected}`);
  };
  const assertSelector = async (selector, message = selector) => {
    const found = await js(`!!document.querySelector(${JSON.stringify(selector)})`);
    if (!found) throw new Error(`[smoke-ui] expected element not found: ${message}`);
  };
  const assertGeometry = async (label, selectors = []) => {
    const issues = await js(`(() => {
      const issues = [];
      const width = window.innerWidth;
      const height = window.innerHeight;
      const root = document.documentElement;
      if (root.scrollWidth > width + 1) issues.push('document horizontal overflow: ' + root.scrollWidth + ' > ' + width);
      if (root.scrollHeight > height + 1) issues.push('document vertical overflow: ' + root.scrollHeight + ' > ' + height);
      const targets = [...document.querySelectorAll('[data-smoke-critical]'), ...${JSON.stringify(selectors)}.flatMap((selector) => [...document.querySelectorAll(selector)])];
      for (const element of [...new Set(targets)]) {
        if (!(element instanceof HTMLElement) || element.offsetParent === null) continue;
        const rect = element.getBoundingClientRect();
        const name = element.getAttribute('data-smoke-critical') || element.getAttribute('data-smoke-screen') || element.tagName.toLowerCase();
        if (rect.left < -1 || rect.right > width + 1 || rect.top < -1 || rect.bottom > height + 1) {
          issues.push(name + ' clipped at ' + JSON.stringify({ left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom, width, height }));
        }
        const style = getComputedStyle(element);
        if (element.scrollWidth > element.clientWidth + 1 && !['auto', 'scroll'].includes(style.overflowX)) {
          issues.push(name + ' has hidden horizontal overflow: ' + element.scrollWidth + ' > ' + element.clientWidth);
        }
      }
      return issues;
    })()`);
    if (issues.length > 0) throw new Error(`[smoke-ui] geometry failed (${label}): ${issues.join(" | ")}`);
    console.log(`[smoke-ui] geometry OK ${label} @ ${await js(`window.innerWidth + 'x' + window.innerHeight`)}`);
  };
  let expectedViewport = { width: 640, height: 480 };
  const shot = async (name, selectors = []) => {
    win.unmaximize();
    win.setContentSize(expectedViewport.width, expectedViewport.height);
    await pause(220);
    const viewport = await js(`[window.innerWidth, window.innerHeight]`);
    if (viewport[0] !== expectedViewport.width || viewport[1] !== expectedViewport.height) {
      throw new Error(`[smoke-ui] expected ${expectedViewport.width}x${expectedViewport.height} content viewport, got ${viewport.join("x")}`);
    }
    await assertGeometry(name, selectors);
    fs.mkdirSync(shotDir, { recursive: true });
    let img = null;
    let captureError = null;
    for (let attempt = 0; attempt < 3 && !img; attempt += 1) {
      try { img = await win.webContents.capturePage(); }
      catch (error) { captureError = error; await pause(300); }
    }
    if (!img) throw captureError ?? new Error(`[smoke-ui] capture failed: ${name}`);
    const screenshotName = `jc-${name}.png`;
    fs.writeFileSync(path.join(shotDir, screenshotName), img.toPNG());
    screenshotNames.push(screenshotName);
    const text = await js(`document.body.innerText.slice(0, 420)`);
    console.log(`[smoke-ui] screenshot ${name} | texto: ${JSON.stringify(text)}`);
  };
  const clickText = async (text, occurrence = 0) => {
    const clicked = await js(`(() => {
      const visible = [...document.querySelectorAll('button')].filter((item) => item.offsetParent !== null && !item.disabled);
      const exact = visible.filter((item) => item.textContent.trim() === ${JSON.stringify(text)});
      const buttons = exact.length > 0 ? exact : visible.filter((item) => item.textContent.includes(${JSON.stringify(text)}));
      const button = buttons[${Number(occurrence)}];
      if (!button) return false;
      button.focus();
      button.click();
      return true;
    })()`);
    if (!clicked) throw new Error(`[smoke-ui] button not found: ${text}`);
  };
  const clickTitle = async (title) => {
    const clicked = await js(`(() => {
      const button = document.querySelector('button[title=${JSON.stringify(title)}]');
      if (!button) return false;
      button.focus();
      button.click();
      return true;
    })()`);
    if (!clicked) throw new Error(`[smoke-ui] titled button not found: ${title}`);
  };
  const clickInRow = async (rowText, buttonText) => {
    const clicked = await js(`(() => {
      const marker = [...document.querySelectorAll('p, code, span')].find((item) => item.offsetParent !== null && item.textContent.includes(${JSON.stringify(rowText)}));
      let row = marker;
      for (let depth = 0; row && depth < 8; depth += 1, row = row.parentElement) {
        const button = [...row.querySelectorAll('button')].find((item) => !item.disabled && item.textContent.includes(${JSON.stringify(buttonText)}));
        if (button) { button.focus(); button.click(); return true; }
      }
      return false;
    })()`);
    if (!clicked) throw new Error(`[smoke-ui] button ${buttonText} not found in row ${rowText}`);
  };
  const clickInHostGrant = async (grantId, buttonText) => {
    const clicked = await js(`(() => {
      const row = document.querySelector('[data-host-grant-id=${JSON.stringify(grantId)}]');
      const button = row && [...row.querySelectorAll('button')].find((item) => !item.disabled && item.textContent.includes(${JSON.stringify(buttonText)}));
      if (!button) return false;
      button.focus();
      button.click();
      return true;
    })()`);
    if (!clicked) throw new Error(`[smoke-ui] button ${buttonText} not found for host grant ${grantId}`);
  };
  const setValue = async (selector, value) => {
    const changed = await js(`(() => {
      const input = document.querySelector(${JSON.stringify(selector)});
      if (!input) return false;
      const proto = input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
      setter.call(input, ${JSON.stringify(value)});
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.focus();
      return true;
    })()`);
    if (!changed) throw new Error(`[smoke-ui] input not found: ${selector}`);
  };
  const pressEnter = async () => {
    await pause(100);
    const delivered = await js(`(() => {
      const target = document.activeElement;
      if (!(target instanceof HTMLElement)) return false;
      const event = new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true });
      const useNativeDefault = target.dispatchEvent(event);
      if (useNativeDefault && target instanceof HTMLInputElement && target.form) target.form.requestSubmit();
      return true;
    })()`);
    if (!delivered) throw new Error("[smoke-ui] Enter had no focused target");
  };
  const pressEscape = async () => {
    const delivered = await js(`(() => {
      const target = document.activeElement instanceof HTMLElement ? document.activeElement : document.body;
      return target.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true, cancelable: true }));
    })()`);
    if (delivered) throw new Error("[smoke-ui] Escape was not handled by the active modal");
  };
  const reload = async () => {
    const loaded = new Promise((resolve) => win.webContents.once("did-finish-load", resolve));
    win.reload();
    await loaded;
  };

  // IPCs abaixo substituem apenas o processo JC_SMOKE_UI. Eles tornam estados de UI
  // determinísticos sem adicionar mocks ou caminhos alternativos ao renderer de produção.
  let serverVisible = false;
  let bridgeConfigured = false;
  let roleMode = "owner";
  let acceptedOwnGrant = false;
  let hostListFails = false;
  let createAttempts = 0;
  const revokedGrants = new Set();
  const revokeAttempts = new Map();
  const now = Date.now();
  const grants = () => {
    const selfId = identity?.identityId ?? "identity-smoke";
    const base = {
      subjectAuthPublicKey: "auth-public-key-smoke",
      hostPublicKey: "host-public-key-smoke",
      enrollmentPublicKey: "enrollment-public-key-smoke",
      capabilities: ["replicate", "promote"],
      expiresAt: now + 86_400_000,
    };
    return [
      { ...base, grantId: "grant-own", subjectIdentityId: selfId, hostId: "host-deste-dispositivo", acceptedAt: acceptedOwnGrant ? now : null, revokedAt: revokedGrants.has("grant-own") ? now : null },
      { ...base, grantId: "grant-remote", subjectIdentityId: "identity-remote", hostId: "host-remoto-aceito", acceptedAt: now - 2_000, revokedAt: revokedGrants.has("grant-remote") ? now : null },
      { ...base, grantId: "grant-error", subjectIdentityId: "identity-error", hostId: "host-com-falha", acceptedAt: now - 1_000, revokedAt: revokedGrants.has("grant-error") ? now : null },
    ];
  };
  const smokeServer = () => {
    const selfId = identity?.identityId ?? "identity-smoke";
    return {
      serverId: "server-ui-smoke",
      serverName: "Comunidade Smoke",
      config: { networkPrivacy: "direct", maxRetentionHours: 168 },
      channels: [{ id: "channel-general", type: "text", name: "general" }],
      members: [{ identityId: selfId, nickname: "matheus", roleId: roleMode === "owner" ? "role-owner" : "role-member", presence: "online" }],
      roles: [
        { id: "role-owner", name: "Owner", level: 100, permissions: ["manage_server", "manage_hosts", "manage_channels", "manage_invites"] },
        { id: "role-member", name: "Membro", level: 10, permissions: ["view_channel", "send_messages"] },
      ],
      me: { identityId: selfId, nickname: "matheus", roleId: roleMode === "owner" ? "role-owner" : "role-member" },
      hosting: acceptedOwnGrant ? { role: "replica", writer: false } : undefined,
      hostCandidates: [],
      hostGrants: grants(),
    };
  };
  const replaceHandler = (channel, handler) => {
    ipcMain.removeHandler(channel);
    ipcMain.handle(channel, handler);
  };
  replaceHandler("server.state", () => ({ ok: true, data: serverVisible ? smokeServer() : null }));
  replaceHandler("connectivity.status", () => ({ ok: true, data: { bridges: bridgeConfigured ? [{ bridgeId: "bridge-smoke", endpoint: "wss://bridge.smoke.invalid/rendezvous", expiresAt: now + 86_400_000 }] : [], backgroundHosting: false } }));
  replaceHandler("connectivity.ice-config", () => ({ ok: true, data: { iceServers: [], iceTransportPolicy: "all" } }));
  replaceHandler("server.create", async () => {
    createAttempts += 1;
    win.webContents.send("connectivity.setup", { step: "host", status: "running", detail: "Iniciando processo local" });
    await pause(300);
    win.webContents.send("connectivity.setup", { step: "host", status: "done", detail: "Host local iniciado" });
    if (createAttempts === 1) {
      win.webContents.send("connectivity.setup", { step: "access", status: "error", detail: "Acesso indisponível: token=setup-secret-smoke" });
      return { ok: false, error: { code: "host_offline", message: "host offline: token=setup-secret-smoke" } };
    }
    win.webContents.send("connectivity.setup", { step: "direct", status: "running", detail: "Testando acesso local" });
    await pause(300);
    win.webContents.send("connectivity.setup", { step: "direct", status: "done", detail: "Host local autenticado" });
    win.webContents.send("connectivity.setup", { step: "bridge", status: "action", detail: "Adicione um JanjaBridge" });
    win.webContents.send("connectivity.setup", { step: "access", status: "running", detail: "Verificando acesso" });
    await pause(300);
    win.webContents.send("connectivity.setup", { step: "access", status: "done", detail: "Acesso local confirmado" });
    return { ok: true, data: smokeServer(), connectivity: { bridgeReady: false, needsBridge: true } };
  });
  replaceHandler("connectivity.bridge.add", async (_event, { pairingCode }) => {
    const code = String(pairingCode ?? "");
    await pause(120);
    if (code.includes("ERROR")) return { ok: false, error: { code: "invalid_input", message: "Código inválido: token=super-secret-smoke\nat internal stack" } };
    bridgeConfigured = true;
    if (code.includes("WARNING")) return { ok: true, data: { bridgeId: "bridge-smoke", endpoint: "wss://bridge.smoke.invalid/rendezvous", expiresAt: now + 86_400_000, warning: "JanjaBridge salvo; reabra o app para concluir a ativação" } };
    return { ok: true, data: { bridgeId: "bridge-smoke", endpoint: "wss://bridge.smoke.invalid/rendezvous", expiresAt: now + 86_400_000 } };
  });
  replaceHandler("server.join", async (_event, { inviteKey, allowLegacyTrust }) => {
    await pause(120);
    if (String(inviteKey).includes("ERROR")) {
      return { ok: false, error: { code: "invite_expired", message: "invite expired: token=join-secret-smoke" } };
    }
    if (!allowLegacyTrust) {
      return { ok: false, error: { code: "legacy_confirmation_required", message: "confirme a chave observada", fingerprint: "SHA256:JC2-SMOKE-FINGERPRINT-7A31", data: { confirmationToken: "confirmation-smoke", hostPublicKey: "host-public-key-smoke", fingerprint: "SHA256:JC2-SMOKE-FINGERPRINT-7A31" } } };
    }
    serverVisible = true;
    return { ok: true, data: smokeServer() };
  });
  replaceHandler("message.send", async (_event, { channelId, text }) => {
    win.webContents.send("message", { messageId: `message-${Date.now()}`, channelId, sender: identity?.identityId ?? "identity-smoke", text, createdAt: Date.now(), self: true });
    return { ok: true };
  });
  replaceHandler("hosting.grant.list", () => hostListFails
    ? { ok: false, error: { code: "host_offline", message: "falha controlada ao carregar hosts" } }
    : { ok: true, data: { grants: grants(), candidates: [] } });
  replaceHandler("hosting.grant.accept", async () => {
    await pause(120);
    acceptedOwnGrant = true;
    return { ok: true };
  });
  replaceHandler("hosting.grant.revoke", async (_event, { grantId }) => {
    await pause(120);
    const attempts = (revokeAttempts.get(grantId) ?? 0) + 1;
    revokeAttempts.set(grantId, attempts);
    if (grantId === "grant-error" && attempts === 1) return { ok: false, error: { code: "invalid_input", message: "Revogação recusada: token=revocation-secret-smoke" } };
    revokedGrants.add(grantId);
    return { ok: true };
  });

  win.unmaximize();
  win.setContentSize(640, 480);
  await pause(500);
  const initialViewport = await js(`[window.innerWidth, window.innerHeight]`);
  if (initialViewport[0] !== 640 || initialViewport[1] !== 480) throw new Error(`[smoke-ui] expected 640x480 content viewport, got ${initialViewport.join("x")}`);
  await waitForText("Comunicador privado de comunidades");
  await assertSelector('form[data-smoke-screen="onboarding"]', "form de onboarding");
  await assertSelector('label[for="onboarding-nickname"]');
  await assertSelector('label[for="onboarding-password"]');
  await assertSelector('label[for="onboarding-confirm"]');
  await shot("01-onboarding-640x480", ['[data-smoke-screen="onboarding"]']);
  await setValue("#onboarding-nickname", "matheus");
  await setValue("#onboarding-password", "senha-teste-123");
  await setValue("#onboarding-confirm", "senha-teste-123");
  await pressEnter();
  await waitForText("Comunidades", 20_000);
  await reload();
  await waitForText("Desbloquear identidade");
  await assertSelector('form[data-smoke-screen="login"]', "form de login");
  await shot("02-login-640x480", ['[data-smoke-screen="login"]']);
  await setValue("#login-password", "senha-teste-123");
  await pressEnter();
  await waitForText("Comunidades", 20_000);
  await shot("03-home-640x480", ['[data-smoke-screen="home"]']);

  await clickText("Criar comunidade");
  await waitForText("Em andamento");
  await assertSelector('[data-setup-step="host"][data-setup-status="running"]', "setup host running");
  if (!await js(`document.activeElement?.getAttribute('data-smoke-section') === 'setup'`)) throw new Error("[smoke-ui] setup progress did not receive focus");
  await shot("04-setup-running-640x480", ['[data-smoke-section="setup"]']);
  await waitForText("A preparação foi interrompida");
  await waitFor(`document.querySelectorAll('[data-setup-status="skipped"]').length === 2`, "setup pending steps settled");
  if (await js(`[...document.querySelectorAll('[data-setup-step]')].some((step) => ['pending', 'running'].includes(step.getAttribute('data-setup-status')))`)) {
    throw new Error("[smoke-ui] setup failure left a non-terminal step");
  }
  await assertNoText("setup-secret-smoke");
  await assertText("Tentar novamente");
  await shot("04b-setup-error-640x480", ['[data-smoke-section="setup"]']);
  await clickText("Tentar novamente");
  await waitFor(`document.activeElement?.getAttribute('data-smoke-section') === 'setup'`, "setup retry focus");
  await waitForText("Continuar nesta rede");
  await assertSelector('[data-setup-step="bridge"][data-setup-status="action"]', "setup bridge action");
  await shot("04c-setup-no-route-640x480", ['[data-smoke-section="setup"]']);

  await clickText("Adicionar JanjaBridge");
  await waitForText("Código de pareamento");
  if (!await js(`document.activeElement?.id === 'bridge-pairing-code'`)) throw new Error("[smoke-ui] pairing did not focus its textarea");
  await shot("05-pairing-default-640x480", ['[data-smoke-screen="pairing"]']);
  await setValue("#bridge-pairing-code", "ERROR");
  await clickText("Adicionar");
  await waitForText("A entrada informada não é válida.");
  await assertNoText("super-secret-smoke");
  await assertText("Tentar novamente");
  await shot("06-pairing-error-640x480", ['[data-smoke-screen="pairing"]']);
  await setValue("#bridge-pairing-code", "WARNING");
  await clickText("Adicionar");
  await waitForText("Rota validada; ativação pendente");
  await assertNoText("JanjaBridge adicionado");
  await assertNoText("Comunidade pronta para uso");
  await assertText("Tentar ativar novamente");
  if (!await js(`document.activeElement?.textContent.includes('Tentar ativar novamente')`)) throw new Error("[smoke-ui] warning action did not receive focus");
  await shot("07-pairing-warning-640x480", ['[data-smoke-screen="pairing"]']);
  await clickText("Resolver depois");
  await assertSelector('[data-setup-step="bridge"][data-setup-status="warning"]', "warning preservado no setup");
  await assertText("Adicione um JanjaBridge para acesso fora desta rede");
  await assertNoText("Comunidade pronta para uso");
  await clickText("JanjaBridge configurado");
  await setValue("#bridge-pairing-code", "VALID");
  await clickText("Adicionar");
  await waitForText("JanjaBridge adicionado");
  if (!await js(`document.activeElement?.textContent.trim() === 'Concluir'`)) throw new Error("[smoke-ui] success action did not receive focus");
  await shot("08-pairing-success-640x480", ['[data-smoke-screen="pairing"]']);
  await assertSelector('[data-setup-step="bridge"][data-setup-status="done"]', "bridge done após validação limpa");
  await clickText("Concluir");
  await assertSelector('[data-smoke-screen="server"]', "setup concluiu entrando na comunidade");
  await assertNoText("Continuar nesta rede");
  await shot("08a-setup-success-640x480", ['[data-smoke-screen="server"]']);
  await clickTitle("Voltar");
  await assertSelector('[data-smoke-screen="home"]', "retorno para testar ingresso");

  await setValue("#invite-key", "ERROR");
  await clickText("Entrar com convite");
  await waitForText("Este convite expirou");
  await assertNoText("join-secret-smoke");
  await shot("08b-join-error-640x480", ['[data-smoke-screen="home"]']);
  await setValue("#invite-key", "JC2-SMOKE");
  await clickText("Entrar com convite");
  await waitForText("SHA256:JC2-SMOKE-FINGERPRINT-7A31");
  await js(`document.querySelector('#legacy-fingerprint')?.scrollIntoView({ block: 'center' })`);
  await shot("09-jc2-fingerprint-640x480", ['#legacy-fingerprint']);
  await clickText("A fingerprint confere");
  await waitForText("Membros (1)");
  await clickText("general");
  await setValue('input[placeholder^="Mensagem"]', "olá do smoke responsivo");
  await pressEnter();
  await waitForText("olá do smoke responsivo");
  await shot("10-conversation-640x480", ['[data-smoke-critical="composer"]']);

  await clickTitle("Configurações do server");
  await waitForText("Configurações do server");
  if (!await js(`document.activeElement?.getAttribute('aria-label') === 'Fechar configurações'`)) throw new Error("[smoke-ui] settings initial focus missing");
  const trapped = await js(`(() => {
    const dialog = document.querySelector('[role="dialog"][aria-labelledby="server-settings-title"]');
    const items = [...dialog.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')].filter((item) => item.offsetParent !== null);
    const first = items[0]; const last = items[items.length - 1];
    last.focus();
    last.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true }));
    return document.activeElement === first;
  })()`);
  if (!trapped) throw new Error("[smoke-ui] settings focus trap failed");
  await shot("11-settings-members-640x480", ['[data-smoke-critical="settings-dialog"]']);
  await clickText("Hosts");
  await waitForText("Aguardando aceite");
  await assertText("Aceite registrado · sincronização não verificada");
  await shot("12-hosts-lifecycle-640x480", ['[data-smoke-critical="settings-dialog"]']);

  await clickInHostGrant("grant-own", "Revisar e aceitar");
  await waitForText("Antes de aceitar");
  await js(`document.querySelector('[role="tabpanel"] input[type="checkbox"]')?.click()`);
  await clickText("Aceitar autorização");
  await waitForText("Réplica nesta sessão · somente leitura");
  await assertText("sincronização não é presumida");
  await js(`document.querySelector('[role="tabpanel"]')?.scrollTo({ top: 0 })`);
  await shot("13-host-accepted-readonly-640x480", ['[data-smoke-critical="settings-dialog"]']);

  await clickInHostGrant("grant-remote", "Revogar");
  await waitForText("O dispositivo perderá a autorização");
  if (!await js(`document.querySelector('[role="alertdialog"]')?.contains(document.activeElement)`)) {
    throw new Error("[smoke-ui] revoke confirmation did not receive initial focus");
  }
  await shot("14-host-revoke-confirmation-640x480", ['[data-smoke-critical="settings-dialog"]', '[role="alertdialog"]']);
  await pressEscape();
  if (await js(`!!document.querySelector('[role="alertdialog"]')`)) throw new Error("[smoke-ui] Escape did not close revoke confirmation");
  if (!await js(`document.activeElement?.textContent?.includes('Revogar')`)) throw new Error("[smoke-ui] revoke trigger focus was not restored");
  await clickInHostGrant("grant-remote", "Revogar");
  await clickInHostGrant("grant-remote", "Confirmar revogação");
  await waitForText("Revogação registrada e lista de hosts atualizada");
  await clickInHostGrant("grant-error", "Revogar");
  await clickInHostGrant("grant-error", "Confirmar revogação");
  await waitForText("A entrada informada não é válida.");
  await assertNoText("revocation-secret-smoke");
  await assertText("Tentar novamente");
  await shot("15-host-error-retry-640x480", ['[data-smoke-critical="settings-dialog"]']);
  await clickText("Tentar novamente");
  await waitForText("Revogação registrada e lista de hosts atualizada");

  await pressEscape();
  await pause(180);
  if (await js(`!!document.querySelector('[role="dialog"][aria-labelledby="server-settings-title"]')`)) throw new Error("[smoke-ui] Escape did not close settings");
  if (!await js(`document.activeElement?.getAttribute('title') === 'Configurações do server'`)) throw new Error("[smoke-ui] settings focus was not restored");

  roleMode = "member";
  win.webContents.send("server.stateChanged", {});
  await pause(180);
  await clickTitle("Configurações do server");
  await clickText("Hosts");
  await waitForText("Modo somente leitura");
  await shot("16-hosts-permission-readonly-640x480", ['[data-smoke-critical="settings-dialog"]']);
  await pressEscape();
  roleMode = "owner";
  hostListFails = true;
  await reload();
  await waitForText("Desbloquear identidade");
  await setValue("#login-password", "senha-teste-123");
  await pressEnter();
  await waitForText("Membros (1)", 20_000);
  await clickTitle("Configurações do server");
  await clickText("Hosts");
  await waitForText("A comunidade está offline no momento");
  await assertText("Tentar novamente");
  await shot("17-hosts-load-error-640x480", ['[data-smoke-critical="settings-dialog"]']);

  expectedViewport = { width: 960, height: 600 };
  win.unmaximize();
  win.setContentSize(expectedViewport.width, expectedViewport.height);
  await pause(180);
  const resizedViewport = await js(`[window.innerWidth, window.innerHeight]`);
  if (resizedViewport[0] !== 960 || resizedViewport[1] !== 600) throw new Error(`[smoke-ui] expected resized 960x600 content viewport, got ${resizedViewport.join("x")}`);
  await assertText("Configurações do server");
  await shot("18-settings-responsive-960x600", ['[data-smoke-critical="settings-dialog"]']);
  const galleryManifest = await writePackagedUiGalleryExecutionManifest(shotDir, screenshotNames, startedAt);
  if (galleryManifest) console.log(`[smoke-ui] packaged execution manifest ${galleryManifest}`);
  console.log("[smoke-ui] DONE");
  app.quit();
}

async function runOperatorSmoke(win) {
  const role = process.env.JC_OPERATOR_SMOKE_ROLE;
  const directory = process.env.JC_OPERATOR_SMOKE_DIR;
  if (!directory || !["owner", "member"].includes(role)) throw new Error("operator smoke role/directory required");
  mkdirSync(directory, { recursive: true });
  const js = (code) => win.webContents.executeJavaScript(code);
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const waitFor = async (condition, label, timeoutMs = 30_000) => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (await js(condition)) return;
      await pause(100);
    }
    throw new Error(`[operator-smoke:${role}] timeout waiting for ${label}`);
  };
  const setValue = async (selector, value) => {
    const changed = await js(`(() => {
      const input = document.querySelector(${JSON.stringify(selector)});
      if (!input) return false;
      const proto = input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, 'value').set.call(input, ${JSON.stringify(value)});
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
    if (!changed) throw new Error(`[operator-smoke:${role}] missing input ${selector}`);
  };
  const clickText = async (text) => {
    const clicked = await js(`(() => {
      const button = [...document.querySelectorAll('button')].find((entry) => entry.offsetParent !== null && entry.textContent.includes(${JSON.stringify(text)}));
      if (!button) return false;
      button.click();
      return true;
    })()`);
    if (!clicked) throw new Error(`[operator-smoke:${role}] missing button ${text}`);
  };
  const clickTitle = async (title) => {
    const clicked = await js(`(() => {
      const button = document.querySelector('button[title=${JSON.stringify(title)}]');
      if (!button || button.offsetParent === null || button.disabled) return false;
      button.click();
      return true;
    })()`);
    if (!clicked) throw new Error(`[operator-smoke:${role}] missing titled button ${title}`);
  };
  const clickExactText = async (text, scope = "body") => {
    const clicked = await js(`(() => {
      const root = document.querySelector(${JSON.stringify(scope)});
      const button = root && [...root.querySelectorAll('button')].find((entry) => entry.offsetParent !== null && entry.textContent.trim() === ${JSON.stringify(text)});
      if (!button) return false;
      button.click();
      return true;
    })()`);
    if (!clicked) throw new Error(`[operator-smoke:${role}] missing exact button ${text} in ${scope}`);
  };
  const clickHumanText = async (text) => {
    const point = await js(`(() => {
      const button = [...document.querySelectorAll('button')].find((entry) => entry.offsetParent !== null && entry.textContent.trim() === ${JSON.stringify(text)});
      if (!button) return null;
      const rect = button.getBoundingClientRect();
      return { x: Math.round(rect.left + rect.width / 2), y: Math.round(rect.top + rect.height / 2) };
    })()`);
    if (!point) throw new Error(`[operator-smoke:${role}] missing human-click button ${text}`);
    win.webContents.sendInputEvent({ type: "mouseMove", x: point.x, y: point.y });
    win.webContents.sendInputEvent({ type: "mouseDown", x: point.x, y: point.y, button: "left", clickCount: 1 });
    win.webContents.sendInputEvent({ type: "mouseUp", x: point.x, y: point.y, button: "left", clickCount: 1 });
    await pause(100);
  };
  const screenshot = async (name) => {
    const image = await win.webContents.capturePage();
    writeFileSync(path.join(directory, `${role}-${name}.png`), image.toPNG());
  };
  const waitForFile = async (file, timeoutMs = 30_000) => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (existsSync(file)) return readFileSync(file, "utf8").trim();
      await pause(100);
    }
    throw new Error(`[operator-smoke:${role}] timeout waiting for ${path.basename(file)}`);
  };

  await waitFor(`!!document.querySelector('#onboarding-nickname')`, "onboarding");
  await setValue("#onboarding-nickname", role === "owner" ? "owner-real-ipc" : "member-real-ipc");
  await setValue("#onboarding-password", "operator-smoke-password-123");
  await setValue("#onboarding-confirm", "operator-smoke-password-123");
  await clickText("Criar identidade");
  await waitFor(`document.body.innerText.includes('Comunidades')`, "home", 45_000);

  if (role === "owner") {
    let pairingFiles;
    try {
      pairingFiles = JSON.parse(process.env.JC_OPERATOR_PAIRING_FILES ?? "[]");
    } catch {
      pairingFiles = [];
    }
    if (!Array.isArray(pairingFiles) || pairingFiles.length === 0) {
      pairingFiles = process.env.JC_OPERATOR_PAIRING_FILE ? [process.env.JC_OPERATOR_PAIRING_FILE] : [];
    }
    if (pairingFiles.length !== 3 || pairingFiles.some((file) => typeof file !== "string" || !existsSync(file))) {
      throw new Error("[operator-smoke:owner] three pairing files are required");
    }
    for (const pairingFile of pairingFiles) {
      const openedPairing = await js(`(() => {
        const home = document.querySelector('[data-smoke-screen="home"]');
        const button = home && [...home.querySelectorAll('button')].find((entry) => entry.offsetParent !== null && entry.textContent.includes('JanjaBridge'));
        if (!button) return false;
        button.click();
        return true;
      })()`);
      if (!openedPairing) throw new Error("[operator-smoke:owner] missing JanjaBridge home action");
      await waitFor(`!!document.querySelector('#bridge-pairing-code')`, "bridge pairing");
      await setValue("#bridge-pairing-code", readFileSync(pairingFile, "utf8"));
      await clickExactText("Adicionar", '[data-smoke-screen="pairing"]');
      try {
        await waitFor(`document.body.innerText.includes('JanjaBridge adicionado') || document.querySelector('#bridge-pairing-error')`, "bridge result", 30_000);
      } catch (error) {
        await screenshot("bridge-result-timeout");
        const visibleState = await js(`document.querySelector('[data-smoke-screen="pairing"]')?.innerText.trim() ?? ''`);
        throw new Error(`${String(error?.message ?? error)}; visible state: ${visibleState}`);
      }
      const bridgeError = await js(`document.querySelector('#bridge-pairing-error')?.innerText.trim() ?? ''`);
      if (bridgeError) throw new Error(`[operator-smoke:owner] bridge pairing rejected: ${bridgeError}`);
      await clickExactText("Concluir", '[data-smoke-screen="pairing"]');
    }
    await waitFor(`document.body.innerText.includes('3 JanjaBridges configurados')`, "three bridges configured");
    await clickText("Criar comunidade");
    await waitFor(`!!document.querySelector('[data-smoke-screen="server"]')`, "owner server", 30_000);
    if (await js(`document.body.innerText.includes('Continuar nesta rede')`)) {
      throw new Error("[operator-smoke:owner] production flow fell back to local-only hosting");
    }
    await pause(2_500);
    const createAndCopyInvite = async () => {
      await clickText("+ convite");
      await waitFor(`document.body.innerText.includes('Convite de uso único')`, "invite");
      clipboard.clear();
      let copied = "";
      for (let attempt = 0; attempt < 2 && !copied.startsWith("JC3-"); attempt += 1) {
        await clickHumanText("Copiar convite");
        const clipboardDeadline = Date.now() + 5_000;
        while (Date.now() < clipboardDeadline) {
          copied = clipboard.readText().trim();
          if (copied.startsWith("JC3-")) break;
          await pause(50);
        }
      }
      if (!copied.startsWith("JC3-") || !parseInviteV3(copied)) {
        throw new Error("[operator-smoke:owner] Copy action did not place a complete JC3 invite on the Electron clipboard");
      }
      return copied;
    };
    const dismissInvite = async () => {
      await js(`document.querySelector('[aria-label="Fechar convite"]')?.click()`);
      await waitFor(`!document.querySelector('[aria-label="Fechar convite"]')`, "invite dismissed");
      await waitFor(`document.activeElement?.getAttribute('title') === 'Criar convite'`, "invite focus restored");
    };

    await createAndCopyInvite();
    await dismissInvite();
    const clearDeadline = Date.now() + 5_000;
    while (clipboard.readText() !== "" && Date.now() < clearDeadline) await pause(50);
    if (clipboard.readText() !== "") throw new Error("[operator-smoke:owner] dismiss did not clear the matching invite clipboard value");

    await createAndCopyInvite();
    clipboard.writeText("operator-newer-content");
    await dismissInvite();
    await pause(250);
    if (clipboard.readText() !== "operator-newer-content") {
      throw new Error("[operator-smoke:owner] dismiss erased newer clipboard content");
    }

    const invite = await createAndCopyInvite();
    durableAtomicWrite(path.join(directory, "invite.txt"), `${invite}\n`);
    await screenshot("invite-created");
    await waitFor(`document.body.innerText.includes('Membros (2)')`, "member joined", 45_000);
    await waitFor(`document.body.innerText.includes('member-real-ipc')`, "member nickname preserved", 15_000);
    await waitFor(`document.body.innerText.includes('Convite utilizado. Crie outro para convidar mais alguém.') && !document.body.innerText.includes('Pronto para compartilhar.')`, "consumed invite retired", 15_000);
    await waitFor(`document.activeElement?.getAttribute('title') === 'Criar convite'`, "consumed invite focus restored");
    const consumedClearDeadline = Date.now() + 5_000;
    while (clipboard.readText() !== "" && Date.now() < consumedClearDeadline) await pause(50);
    if (clipboard.readText() !== "") throw new Error("[operator-smoke:owner] consumed invite remained in the clipboard");
    if (await js(`document.body.innerText.includes('member-real-ipc')`) !== true) {
      throw new Error("[operator-smoke:owner] JC3 member nickname was not preserved");
    }
    await screenshot("two-members");
    const sent = await js(`(async () => {
      const state = await window.janjacord.serverState();
      const channelId = state?.data?.channels?.find((entry) => entry.type === 'text')?.id;
      if (!channelId) return false;
      const bytes = new TextEncoder().encode('plaintext-through-real-ipc');
      let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
      const result = await window.janjacord.attachmentSend(channelId, '../outside.txt', 'text/plain', btoa(binary));
      return result?.ok === true;
    })()`);
    if (!sent) throw new Error("[operator-smoke:owner] attachment send failed");
    await waitFor(`(() => {
      const messages = [...document.querySelectorAll('p')].filter((entry) => entry.textContent.trim() === '📎 outside.txt');
      const attachmentActions = [...document.querySelectorAll('button')].filter((entry) => entry.textContent.includes('outside.txt'));
      return messages.length === 1 && attachmentActions.length === 1;
    })()`, "one canonical self attachment message");
    await waitForFile(path.join(directory, "attachment.done"), 45_000);

    // A 2->1 reduction may intentionally leave a restarted writer read-only under quorum
    // policy. Exercise it only after the invite/member/attachment acceptance path is complete.
    await clickTitle("Configurações do server");
    await clickText("Conectividade");
    await waitFor(`document.querySelectorAll('button[aria-label="Remover JanjaBridge"]').length === 3`, "three bridge rows");
    for (const expectedCount of [2, 1]) {
      const transition = await js(`(async () => {
        const status = await window.janjacord.connectivityStatus();
        if (!status?.ok || status.data.bridges.length !== ${expectedCount + 1}) return { ok: false, stage: 'before', status };
        const result = await window.janjacord.bridgeRemove(status.data.bridges[0].bridgeId);
        if (!result?.ok || result.data?.warning) return { ok: false, stage: 'remove', result };
        const after = await window.janjacord.connectivityStatus();
        return { ok: after?.ok === true && after.data.bridges.length === ${expectedCount}, stage: 'after', after };
      })()`);
      if (transition?.ok !== true) {
        throw new Error(`[operator-smoke:owner] bridge ${expectedCount + 1}->${expectedCount} reconfiguration failed at ${String(transition?.stage)}`);
      }
      await clickText("Membros");
      await clickText("Conectividade");
      await waitFor(`document.querySelectorAll('button[aria-label="Remover JanjaBridge"]').length === ${expectedCount}`, `bridge UI refreshed to ${expectedCount}`);
    }
    durableAtomicWrite(path.join(directory, "bridge-removal-transitions.done"), "ok\n");
    await js(`document.querySelector('[aria-label="Fechar configurações"]')?.click()`);
    await waitFor(`!document.querySelector('[role="dialog"][aria-labelledby="server-settings-title"]')`, "settings closed after bridge transitions");

    const autostartFile = path.join(app.getPath("home"), ".config", "autostart", "janjacord.desktop");
    if (process.env.APPIMAGE) {
      const enabled = await js(`window.janjacord.setHostingAutostart(true)`);
      if (enabled?.ok !== true || !existsSync(backgroundHostBundlePath()) || !existsSync(autostartFile)) {
        throw new Error("[operator-smoke:owner] packaged autostart enable did not commit every artifact");
      }
      const enabledAgain = await js(`window.janjacord.setHostingAutostart(true)`);
      if (enabledAgain?.ok !== true || !existsSync(backgroundHostBundlePath()) || !existsSync(autostartFile)) {
        throw new Error("[operator-smoke:owner] idempotent autostart enable damaged active artifacts");
      }
      const disabled = await js(`window.janjacord.setHostingAutostart(false)`);
      if (disabled?.ok !== true || existsSync(backgroundHostBundlePath()) || existsSync(autostartFile)
        || readConnectivityConfig().backgroundHosting) {
        throw new Error("[operator-smoke:owner] packaged autostart disable did not cleanly fail closed");
      }
    }
    if (existsSync(connectivityAnchorPath())) unlinkSync(connectivityAnchorPath());
    const autostart = await js(`window.janjacord.setHostingAutostart(true)`);
    if (autostart?.ok !== false) throw new Error("[operator-smoke:owner] corrupted trust store did not reject autostart");
    if (existsSync(backgroundHostBundlePath()) || existsSync(autostartFile)) {
      throw new Error("[operator-smoke:owner] failed autostart left active artifacts");
    }
    durableAtomicWrite(path.join(directory, "clipboard-conditional.done"), "ok\n");
    durableAtomicWrite(path.join(directory, "autostart-atomic.done"), "ok\n");
    durableAtomicWrite(path.join(directory, "owner.done"), "ok\n");
  } else {
    const invite = await waitForFile(path.join(directory, "invite.txt"));
    await setValue("#invite-key", invite);
    await clickText("Entrar com convite");
    await waitFor(`!!document.querySelector('[data-smoke-screen="server"]')`, "member server", 30_000);
    if (await js(`document.body.innerText.includes('Confirmação do host legado')`)) {
      throw new Error("[operator-smoke:member] JC3 unexpectedly requested legacy host confirmation");
    }
    const joinedState = await js(`window.janjacord.serverState()`);
    if (joinedState?.data?.me?.nickname !== "member-real-ipc") {
      throw new Error(`[operator-smoke:member] expected nickname member-real-ipc, got ${String(joinedState?.data?.me?.nickname)}`);
    }
    await screenshot("joined-with-one-invite");
    await waitFor(`document.body.innerText.includes('outside.txt')`, "attachment delivery", 45_000);
    await clickText("outside.txt");
    await waitForFile(path.join(directory, "member-download.txt"), 15_000);
    durableAtomicWrite(path.join(directory, "attachment.done"), "ok\n");
    durableAtomicWrite(path.join(directory, "member.done"), "ok\n");
    await waitForFile(path.join(directory, "owner.done"), 45_000);
  }
  console.log(`[operator-smoke:${role}] DONE`);
  app.quit();
}

async function getServerStateForSmoke() {
  if (!serverState) return null;
  const fresh = await sendCommand({ type: "server.state" }).catch(() => null);
  return fresh?.ok ? fresh.data : serverState;
}

// ---------------------------------------------------------------- smoke media
async function runMediaSmoke(win) {
  const fs = await import("node:fs");
  const dir = process.env.JC_SMOKE_DIR ?? "/tmp";
  const js = (code) => win.webContents.executeJavaScript(code);
  const shot = async (name) => {
    await new Promise((r) => setTimeout(r, 1200));
    fs.mkdirSync(dir, { recursive: true });
    const img = await win.webContents.capturePage();
    fs.writeFileSync(path.join(dir, `media-${name}.png`), img.toPNG());
    console.log(`[smoke-media] screenshot ${name}`);
  };
  // pré-cria identidade e entra no fluxo até o server (reusa helpers)
  identity = await createIdentity("media", "senha-media-123", vaultPath());
  initLocalDb();
  await loadMls();
  win.reload();
  await new Promise((r) => setTimeout(r, 1500));
  await js(`(() => {
    const input = document.querySelector('input[type="password"]');
    if (!input) return false;
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, 'senha-media-123');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`);
  await new Promise((r) => setTimeout(r, 300));
  await js(`document.querySelector('button')?.click()`);
  await new Promise((r) => setTimeout(r, 1500));
  await js(`[...document.querySelectorAll('button')].find(b => b.textContent.includes('Criar server'))?.click()`);
  await new Promise((r) => setTimeout(r, 3500));
  // cria canal de call e abre
  const st = await getServerStateForSmoke();
  const chRes = await sendCommand({ type: "channel.create", channelType: "call", name: "geral-call" });
  if (chRes.ok) {
    // recarrega para o renderer obter o estado atualizado (com o canal de call)
    win.reload();
    await new Promise((r) => setTimeout(r, 1500));
    await js(`(() => {
      const input = document.querySelector('input[type="password"]');
      if (!input) return false;
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
      setter.call(input, 'senha-media-123');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
    await new Promise((r) => setTimeout(r, 300));
    await js(`document.querySelector('button')?.click()`);
    await new Promise((r) => setTimeout(r, 2000));
    await js(`[...document.querySelectorAll('button')].find(b => b.textContent.includes('geral-call'))?.click()`);
    await new Promise((r) => setTimeout(r, 4000)); // join + getUserMedia
    await shot("01-call-media");
    const text = await js(`document.body.innerText.slice(0, 200)`);
    console.log(`[smoke-media] call UI: ${JSON.stringify(text)}`);
    // verifica stream local ativo
    const hasStream = await js(`!!window.janjacordMediaSmoke`);
    void hasStream;
  }
  console.log("[smoke-media] DONE");
  app.quit();
}

// ---------------------------------------------------------------- smoke media peer (mesh 2 peers)
async function runMediaPeerSmoke(win) {
  const fs = await import("node:fs");
  const dir = process.env.JC_SMOKE_DIR ?? "/tmp";
  const js = (code) => win.webContents.executeJavaScript(code);
  const shot = async (name) => {
    await new Promise((r) => setTimeout(r, 2500));
    fs.mkdirSync(dir, { recursive: true });
    const img = await win.webContents.capturePage();
    fs.writeFileSync(path.join(dir, `peer${process.env.JC_SMOKE_MEDIA_PEER}-${name}.png`), img.toPNG());
    const text = await js(`document.body.innerText.slice(0, 300)`);
    console.log(`[smoke-media-peer${process.env.JC_SMOKE_MEDIA_PEER}] ${name} | ${JSON.stringify(text)}`);
  };
  const unlock = async (pw) => {
    await js(`(() => {
      const input = document.querySelector('input[type="password"]');
      if (!input) return false;
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
      setter.call(input, '${pw}');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
    await new Promise((r) => setTimeout(r, 300));
    await js(`document.querySelector('button')?.click()`);
    await new Promise((r) => setTimeout(r, 2000));
  };
  const peer = process.env.JC_SMOKE_MEDIA_PEER;
  const pw = `senha-peer-${peer}`;

  identity = await createIdentity(`peer${peer}`, pw, vaultPath());
  initLocalDb();
  await loadMls();

  if (peer === "1") {
    // cria o host e o canal de call via main (sem depender do renderer)
    spawnHost();
    await new Promise((r) => setTimeout(r, 1800));
    await connectToHost(`ws://127.0.0.1:${HOST_PORT}/signal`, {
      authorityFingerprint: ed25519Fingerprint(ed25519PublicKey(deriveRuntimeSeed("janjacord-authority-signing-v1"))),
      expectedHostPublicKey: ed25519PublicKey(deriveRuntimeSeed("janjacord-host-signing-v1")).toString("base64url"),
    });
    client.send("hello", { identityId: identity.identityId });
    await new Promise((r) => setTimeout(r, 600));
    const st = await sendCommand({ type: "server.state" });
    if (!st.ok) throw new Error("host sem estado");
    serverState = st.data;
    await sendCommand({ type: "channel.create", channelType: "call", name: "geral-call" });
    // renderer: reload → unlock → main (com o canal call) → abre a call
    win.reload();
    await new Promise((r) => setTimeout(r, 1800));
    await unlock(pw);
    await js(`[...document.querySelectorAll('button')].find(b => b.textContent.includes('geral-call'))?.click()`);
    await new Promise((r) => setTimeout(r, 5000)); // join + getUserMedia fake
    await shot("in-call");
    const inv = await sendCommand({ type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
    if (inv.ok) fs.writeFileSync(process.env.JC_INVITE_FILE ?? path.join(dir, "invite.txt"), inv.data.inviteKey);
    console.log("[smoke-media-peer1] aguardando peer 2…");
    await new Promise((r) => setTimeout(r, 30000));
    await shot("final");
    app.quit();
  } else {
    // entra via invite (descoberta no rendezvous) + call
    const invitePath = process.env.JC_INVITE_FILE ?? path.join(dir, "invite.txt");
    let tries = 0;
    while (!fs.existsSync(invitePath) && tries < 25) {
      await new Promise((r) => setTimeout(r, 1000));
      tries++;
    }
    if (!fs.existsSync(invitePath)) throw new Error("invite do peer 1 não encontrado");
    const inviteKey = fs.readFileSync(invitePath, "utf8").trim();
    const { parseInviteKey } = await import("@janjacord/crypto");
    const parsed = parseInviteKey(inviteKey);
    let target = null;
    if (parsed && process.env.JC_RENDEZVOUS_URL) {
      const resolved = await resolveAtBridge(
        process.env.JC_RENDEZVOUS_URL,
        { type: "resolve", serverId: parsed.serverId },
      );
      if (resolved.ok) target = resolved.data.endpoint;
    }
    if (!target) throw new Error("rendezvous não resolveu o peer 1");
    await connectToHost(target, { allowUnverifiedLegacyHost: true });
    client.send("hello", { identityId: identity.identityId });
    await new Promise((r) => setTimeout(r, 600));
    const joinRes = await sendCommand({ type: "server.join", inviteKey, nickname: identity.nickname });
    if (!joinRes.ok) throw new Error(`join falhou: ${joinRes.error?.message}`);
    serverState = joinRes.data;
    win.reload();
    await new Promise((r) => setTimeout(r, 1800));
    await unlock(pw);
    await js(`[...document.querySelectorAll('button')].find(b => b.textContent.includes('geral-call'))?.click()`);
    await new Promise((r) => setTimeout(r, 7000)); // join + getUserMedia + mesh
    await shot("in-call");
    await new Promise((r) => setTimeout(r, 10000));
    await shot("final");
    app.quit();
  }
}

// ---------------------------------------------------------------- janela
function setupAutoUpdater() {
  const configuredFeed = process.env.JC_UPDATE_FEED_URL;
  if (process.env.JC_DISABLE_UPDATES === "1" || !configuredFeed) return;
  try {
    const feed = new URL(configuredFeed);
    if (feed.protocol !== "https:" || feed.hostname === "example.com" || feed.hostname.endsWith(".example.com")) {
      throw new Error("JC_UPDATE_FEED_URL must be a real HTTPS endpoint");
    }
    const { autoUpdater } = require("electron-updater");
    autoUpdater.setFeedURL({ provider: "generic", url: feed.toString() });
    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = false;
    autoUpdater.on("update-downloaded", () => {
      // Never restart an active host automatically. Installation requires a separate,
      // explicit user-approved action that can first drain hosted processes.
      notifyRenderer("updater.downloaded", { readyForUserApprovedRestart: true });
    });
    autoUpdater.on("error", (err) => console.warn("[updater]", err.message));
    setTimeout(() => autoUpdater.checkForUpdates().catch(() => {}), 30000);
  } catch (e) {
    console.warn("[updater] disabled:", (e).message);
  }
}

function createWindow() {
  // Permissões estritamente locais: câmera/mic e escrita sanitizada na clipboard. Leitura da
  // clipboard continua negada ao renderer; o smoke a verifica pelo main process.
  session.defaultSession.setPermissionCheckHandler((webContents, permission, _requestingOrigin, details) => {
    if (!["clipboard-sanitized-write", "media"].includes(permission) || details?.isMainFrame === false) return false;
    return rendererLocationIsTrusted(webContents?.getURL());
  });
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback, details) => {
    if (permission === "clipboard-sanitized-write" && details?.isMainFrame !== false
      && rendererLocationIsTrusted(details?.requestingUrl ?? webContents?.getURL())) {
      callback(true);
      return;
    }
    if (permission === "media") {
      try {
        const origin = new URL(details?.securityOrigin ?? "");
        const allowed = origin.protocol === "file:"
          || (["http:", "https:"].includes(origin.protocol) && ["localhost", "127.0.0.1", "::1"].includes(origin.hostname));
        if (allowed) { callback(true); return; }
      } catch { /* deny malformed origins */ }
    }
    callback(false);
  });
  const win = new BrowserWindow({
    width: 1100,
    height: 720,
    minWidth: 640,
    minHeight: 480,
    useContentSize: true,
    backgroundColor: "#0b0d10",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
    },
  });
  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  win.webContents.on("will-navigate", (event) => event.preventDefault());
  win.on("close", (event) => {
    if (!appQuitting && hostProcess && readConnectivityConfig().backgroundHosting) {
      event.preventDefault();
      win.hide();
    }
  });
  const rendererFile = path.join(__dirname, "..", "dist", "index.html");
  let devServerUrl = null;
  if (!app.isPackaged && process.env.VITE_DEV_SERVER_URL) {
    const candidate = new URL(process.env.VITE_DEV_SERVER_URL);
    if (candidate.protocol !== "http:" || !["localhost", "127.0.0.1", "::1"].includes(candidate.hostname)) {
      throw new Error("VITE_DEV_SERVER_URL must be an HTTP loopback origin");
    }
    devServerUrl = candidate.href;
  }
  trustedRendererLocation = devServerUrl ?? pathToFileURL(rendererFile).href;
  if (devServerUrl) win.loadURL(devServerUrl);
  else win.loadFile(rendererFile);
  if (process.env.JC_SMOKE_UI) {
    win.webContents.once("did-finish-load", () => runUiSmoke(win).catch((error) => {
      console.error("[smoke-ui] FAILED", error);
      app.exit(1);
    }));
  }
  if (process.env.JC_SMOKE_MEDIA) {
    win.webContents.once("did-finish-load", () => runMediaSmoke(win));
  }
  if (process.env.JC_SMOKE_MEDIA_PEER) {
    win.webContents.once("did-finish-load", () => runMediaPeerSmoke(win));
  }
  if (process.env.JC_OPERATOR_SMOKE_ROLE) {
    win.webContents.once("did-finish-load", () => runOperatorSmoke(win).catch((error) => {
      console.error(`[operator-smoke:${process.env.JC_OPERATOR_SMOKE_ROLE}] FAILED`, error);
      app.exit(1);
    }));
  }
  return win;
}

const ownsInstance = app.requestSingleInstanceLock();
if (!ownsInstance) app.quit();

app.on("second-instance", () => {
  const existing = BrowserWindow.getAllWindows()[0];
  if (existing) {
    existing.show();
    existing.focus();
  } else if (app.isReady()) {
    createWindow();
  }
});

app.whenReady().then(() => {
  if (!ownsInstance) return;
  if (!app.isPackaged && process.env.JC_DESKTOP_MAIN_SELF_TEST === "1") {
    runDesktopMainContractSelfTest()
      .then(() => app.exit(0))
      .catch((error) => {
        console.error(`[main-self-test] FAILED ${String(error?.stack ?? error)}`);
        app.exit(1);
      });
    return;
  }
  if (process.argv.includes("--background-host")) {
    try {
      if (!reconcileAutostartState()) {
        app.exit(0);
        return;
      }
      spawnBackgroundHost();
    }
    catch (error) {
      console.error(`[host] background startup unavailable: ${String(error?.message ?? error)}`);
      app.exit(1);
    }
    return;
  }
  try { reconcileAutostartState(); }
  catch (error) { console.error(`[host] autostart reconciliation failed closed: ${String(error?.message ?? error)}`); }
  registerIpc();
  createWindow();
  setupAutoUpdater();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (hostProcess && readConnectivityConfig().backgroundHosting) return;
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  appQuitting = true;
  stopHost();
  stopReplicaHost();
  localDb?.close();
});
