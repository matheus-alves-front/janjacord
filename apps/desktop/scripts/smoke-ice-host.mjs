import { fork } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createIdentity } from "@janjacord/identity";
import { ed25519Fingerprint, ed25519PublicKey } from "@janjacord/crypto";
import { createSignedBridgeDescriptor } from "@janjacord/protocol";
import { HostClient, IceHostTransport, verifyHostAuthenticationContext } from "@janjacord/networking";
import { WebSocket } from "ws";
import { mintPairingToken } from "./pairing-fixture.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const bridgeMain = join(root, "rendezvous", "dist", "main.js");
const hostMain = join(root, "janjanode", "dist", "main.js");
const bridgePorts = [8992, 9002];
const hostPort = 8993;
const failover = process.env.JC_SMOKE_ICE_FAILOVER === "1";
const resources = { dir: null, host: null, bridges: [], local: null, ice: null };
let cleanupPromise = null;

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function withTimeout(promise, timeoutMs, message) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); },
    );
  });
}

async function terminateChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGTERM");
  await Promise.race([exited, wait(2_000)]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await Promise.race([exited, wait(2_000)]);
  }
}

function cleanup() {
  if (cleanupPromise) return cleanupPromise;
  cleanupPromise = (async () => {
    try { resources.ice?.close(); } catch { /* already closed */ }
    try { resources.local?.close(); } catch { /* already closed */ }
    await terminateChild(resources.host);
    await Promise.all(resources.bridges.map(terminateChild));
    if (resources.dir) rmSync(resources.dir, { recursive: true, force: true });
  })();
  return cleanupPromise;
}

function bridgeDescriptor(port, seed) {
  const now = Date.now();
  const publicKey = ed25519PublicKey(seed);
  return createSignedBridgeDescriptor({
    version: 1,
    bridgeId: ed25519Fingerprint(publicKey),
    endpoints: [`wss://127.0.0.1:${port}`],
    issuedAt: now,
    expiresAt: now + 120_000,
  }, seed);
}

function spawnBridge(port, extraEnv = {}) {
  const bridge = fork(bridgeMain, [], {
    env: { ...process.env, JC_RENDEZVOUS_PORT: String(port), ...extraEnv },
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    execArgv: [],
  });
  resources.bridges.push(bridge);
  bridge.stdout?.on("data", (data) => process.stdout.write(data));
  bridge.stderr?.on("data", (data) => process.stderr.write(data));
  return bridge;
}

async function resolveHost(port, serverId, authorityFingerprint) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/rendezvous`);
  try {
    await withTimeout(new Promise((resolve, reject) => {
      ws.once("open", resolve);
      ws.once("error", reject);
    }), 2_000, `bridge ${port} resolve connection timeout`);
    return await withTimeout(new Promise((resolve) => {
      ws.once("message", (raw) => resolve(JSON.parse(raw.toString())));
      ws.send(JSON.stringify({ type: "resolve", serverId, authorityFingerprint }));
    }), 2_000, `bridge ${port} resolve timeout`);
  } finally {
    ws.close();
  }
}

async function pollResolve(port, serverId, authorityFingerprint, timeoutMs = 12_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const result = await resolveHost(port, serverId, authorityFingerprint);
      if (result?.ok) return result;
    } catch {
      // Registration may still be converging.
    }
    await wait(200);
  }
  throw new Error(`bridge ${port} did not resolve the signed host registration`);
}

function waitResult(transport, timeoutMs = 8_000) {
  return withTimeout(new Promise((resolve) => {
    transport.onEventOnce("result", (frame) => resolve(frame.data));
  }), timeoutMs, "host result timeout");
}

async function sendHello(transport, identityId) {
  const resultPromise = waitResult(transport);
  transport.send("hello", { identityId });
  return resultPromise;
}

async function waitCandidatePair(ice, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const pair = ice.diagnostics().selectedCandidatePair;
    if (pair) return pair;
    await wait(100);
  }
  return null;
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), failover ? "jc-ice-failover-" : "jc-ice-host-"));
  resources.dir = dir;
  const owner = await createIdentity("owner", "password-123", join(dir, "owner.json"));
  const authoritySeed = createHmac("sha256", owner.seed).update("janjacord-authority-signing-v1").digest();
  const hostSeed = createHmac("sha256", owner.seed).update("janjacord-host-signing-v1").digest();
  const child = { stdio: ["ignore", "pipe", "pipe", "ipc"], execArgv: [] };
  const activeBridgePorts = bridgePorts.slice(0, failover ? 2 : 1);
  const descriptors = activeBridgePorts.map((port, index) => bridgeDescriptor(port, Buffer.alloc(32, 61 + index)));
  const turnSecret = randomBytes(32).toString("base64url");
  const turnPath = join(dir, "turn-secret");
  writeFileSync(turnPath, `${turnSecret}\n`, { mode: 0o600 });
  const bridgePairings = descriptors.map((descriptor, index) => {
    const adminKey = randomBytes(32).toString("base64url");
    const adminKeyPath = join(dir, `bridge-${index}-pairing-admin-key`);
    writeFileSync(adminKeyPath, `${adminKey}\n`, { mode: 0o600 });
    spawnBridge(activeBridgePorts[index], {
      JC_TURN_SHARED_SECRET_FILE: turnPath,
      JC_BRIDGE_PAIRING_ADMIN_KEY_FILE: adminKeyPath,
      JC_BRIDGE_DOMAIN: "127.0.0.1",
    });
    return {
      bridgeId: descriptor.payload.bridgeId,
      pairingToken: mintPairingToken(descriptor.payload.bridgeId, adminKey),
    };
  });
  await wait(800);

  resources.host = fork(hostMain, [], {
    ...child,
    env: {
      ...process.env,
      JC_DB_KEY: owner.dbKey.toString("hex"),
      JC_DB_PATH: join(dir, "server.db"),
      JC_OWNER_IDENTITY: owner.identityId,
      JC_OWNER_NICKNAME: owner.nickname,
      JC_OWNER_PUBLIC_KEY: ed25519PublicKey(owner.seed).toString("base64url"),
      JC_AUTHORITY_SIGNING_SEED: authoritySeed.toString("hex"),
      JC_HOST_SIGNING_SEED: hostSeed.toString("hex"),
      JC_SERVER_NAME: failover ? "ICE Failover Smoke" : "ICE Direct Smoke",
      JC_PORT: String(hostPort),
      JC_BRIDGE_DESCRIPTORS: JSON.stringify(descriptors),
      JC_BRIDGE_PAIRINGS: JSON.stringify(bridgePairings),
      JC_ALLOW_INSECURE_BRIDGE_LOOPBACK: "1",
      JC_RENDEZVOUS_RENEW_MS: "3000",
      ...(failover ? { JC_PRIMARY_FENCE_MS: "60000" } : {}),
    },
  });
  resources.host.stdout?.on("data", (data) => process.stdout.write(data));
  resources.host.stderr?.on("data", (data) => process.stderr.write(data));
  await wait(1_800);

  const authorityFingerprint = ed25519Fingerprint(ed25519PublicKey(authoritySeed));
  resources.local = new HostClient(`ws://127.0.0.1:${hostPort}/signal`, {
    identityId: owner.identityId,
    deviceSeed: owner.seed,
    authorityFingerprint,
    expectedHostPublicKey: ed25519PublicKey(hostSeed).toString("base64url"),
  });
  await withTimeout(new Promise((resolve) => resources.local.onOpen(resolve)), 5_000, "local auth timeout");
  const localState = await sendHello(resources.local, owner.identityId);
  if (!localState?.ok) throw new Error(`local state failed: ${JSON.stringify(localState)}`);

  const registrations = await Promise.all(
    bridgePorts.slice(0, failover ? 2 : 1).map((port) => pollResolve(port, localState.data.serverId, authorityFingerprint)),
  );
  const registration = registrations[0].data.registrations?.[0] ?? registrations[0].data.records?.[0];
  const verified = verifyHostAuthenticationContext(registration, {
    serverId: localState.data.serverId,
    authorityFingerprint,
  });
  if (!verified) throw new Error("resolved authority/grant/record chain failed verification");
  if (failover) {
    const secondary = registrations[1].data.registrations?.[0] ?? registrations[1].data.records?.[0];
    if (JSON.stringify(registration.record) !== JSON.stringify(secondary.record)) {
      throw new Error("Bridge A and Bridge B did not hold the same signed host checkpoint");
    }
  }

  resources.ice = new IceHostTransport({
    bridgeUrls: bridgePorts.slice(0, failover ? 2 : 1).map((port) => `ws://127.0.0.1:${port}/signaling`),
    serverId: localState.data.serverId,
    authorityFingerprint,
    hostId: verified.hostId,
    hostRegistration: registration,
    identityId: owner.identityId,
    deviceSeed: owner.seed,
    iceServers: [],
    connectionTimeoutMs: 5_000,
    reconnectBaseDelayMs: 100,
    reconnectMaxDelayMs: 500,
  });
  const authenticatedOpenings = [];
  resources.ice.onAuthenticatedOpen((event) => authenticatedOpenings.push(event));
  await withTimeout(new Promise((resolve) => resources.ice.onOpen(resolve)), 15_000, "initial ICE auth timeout");
  if (authenticatedOpenings.length !== 1 || authenticatedOpenings[0].generation !== 1 || authenticatedOpenings[0].reconnected) {
    throw new Error(`initial authenticated lifecycle signal invalid: ${JSON.stringify(authenticatedOpenings)}`);
  }
  if (resources.ice.diagnostics().bridgeIndex !== 0) throw new Error("initial authenticated transport did not use live Bridge A");

  const initialChannel = await resources.ice.request({ type: "channel.create", channelType: "text", name: failover ? "before-bridge-a-loss" : "direct-local-write" });
  if (!initialChannel?.ok) throw new Error(`initial authenticated write failed: ${JSON.stringify(initialChannel)}`);

  if (failover) {
    console.log("[smoke-ice-failover] authenticated write completed through live Bridge A");
    const disconnected = withTimeout(new Promise((resolve) => resources.ice.onClose(resolve)), 8_000, "transport did not observe Bridge A loss");
    await terminateChild(resources.bridges[0]);
    await disconnected;
    await withTimeout(new Promise((resolve) => resources.ice.onOpen(resolve)), 15_000, "authenticated reconnect through Bridge B timeout");
    if (authenticatedOpenings.length !== 2 || authenticatedOpenings[1].generation !== 2 || !authenticatedOpenings[1].reconnected) {
      throw new Error(`persistent authenticated reconnect signal invalid: ${JSON.stringify(authenticatedOpenings)}`);
    }
    if (resources.ice.diagnostics().bridgeIndex !== 1) throw new Error("reconnect/backoff did not select live Bridge B");
    const reconnectedState = await sendHello(resources.ice, owner.identityId);
    if (!reconnectedState?.ok) throw new Error(`Bridge B authenticated command failed: ${JSON.stringify(reconnectedState)}`);
    const afterFailover = await resources.ice.request({ type: "channel.create", channelType: "text", name: "after-bridge-a-loss" });
    if (!afterFailover?.ok) throw new Error(`post-failover authenticated write failed: ${JSON.stringify(afterFailover)}`);
    console.log("[smoke-ice-failover] LIVE A AUTH/WRITE + A DISCONNECT + BACKOFF + LIVE B REAUTH/WRITE OK");
    return;
  }

  const pair = await waitCandidatePair(resources.ice);
  if (!pair || pair.local.type.toLowerCase() === "relay" || pair.remote.type.toLowerCase() === "relay") {
    throw new Error(`direct mode selected an unexpected relay pair: ${JSON.stringify(pair)}`);
  }
  const rtc = resources.ice.rtcIceConfiguration();
  if (!rtc || rtc.iceTransportPolicy !== "all") throw new Error("direct call ICE configuration missing");
  console.log(`[smoke-ice-host] candidate-pair=${pair.local.type}/${pair.remote.type}`);
  console.log("[smoke-ice-host] LOCAL DIRECT TRANSPORT (SEPARATE PROCESSES, SHARED LOOPBACK NAMESPACE; NOT WAN) OK");
}

for (const [signal, exitCode] of [["SIGINT", 130], ["SIGTERM", 143]]) {
  process.once(signal, () => cleanup().finally(() => process.exit(exitCode)));
}

main()
  .catch((error) => {
    console.error(failover ? "[smoke-ice-failover]" : "[smoke-ice-host]", error.message);
    process.exitCode = 1;
  })
  .finally(cleanup);
